"""FastMCP server implementation for the Codex MCP project."""

from __future__ import annotations

import json
import os
import queue
import re
import shutil
import signal
import subprocess
import threading
import time
from collections import OrderedDict, deque
from pathlib import Path
from typing import Annotated, Any, Deque, Dict, List, Literal, Optional

import anyio
from mcp.server.fastmcp import FastMCP
from pydantic import Field

mcp = FastMCP("Codex MCP Server-from guda.studio")


def _env_int(name: str, default: int) -> int:
    try:
        return max(0, int(os.environ.get(name, default)))
    except ValueError:
        return default


DEFAULT_TIMEOUT_SEC = _env_int("CODEXMCP_TIMEOUT", 3600)
LINGER_GRACE_SEC = 5.0      # time Codex gets to exit by itself after the turn ends
KILL_GRACE_SEC = 2.0        # SIGTERM -> SIGKILL escalation delay
DRAIN_AFTER_KILL_SEC = 1.0  # how long to keep collecting events after a kill
MAX_COMMANDS = 20
MAX_EXTRA_FAILED_COMMANDS = 10
MAX_COMMAND_CHARS = 200
MAX_OUTPUT_TAILS = 3
OUTPUT_TAIL_CHARS = 600
STDERR_TAIL_LINES = 20

_RECONNECTING = re.compile(r"^Reconnecting\.\.\.\s+\d+/\d+")
_SHELL_WRAPPER = re.compile(
    r"""^(?:\S*[/\\])?(?:(?:ba|z|da)?sh|powershell|pwsh)(?:\.exe)?"""
    r"""(?:\s+-NoProfile)?\s+(?:-l?c|-Command)\s+(['"])(.*)\1$""",
    re.S | re.I,
)


# --------------------------------------------------------------------------- #
# Process handling
# --------------------------------------------------------------------------- #
class CodexProcess:
    """One `codex exec --json` invocation.

    `run()` blocks and is meant to be executed in a worker thread, so the MCP
    event loop stays free and several tool calls can run in parallel.
    The prompt is written to stdin (as the official Codex SDK does), which
    avoids command-line escaping and length limits on every platform.
    """

    def __init__(self, cmd: List[str], prompt: str, timeout: float) -> None:
        self.cmd = cmd
        self.prompt = prompt
        self.timeout = timeout
        self.events: List[Dict[str, Any]] = []
        self.non_json: Deque[str] = deque(maxlen=STDERR_TAIL_LINES)
        self.stderr_tail: Deque[str] = deque(maxlen=STDERR_TAIL_LINES)
        self.timed_out = False
        self.cancelled = False
        self.launch_error: Optional[str] = None
        self.returncode: Optional[int] = None
        self.elapsed = 0.0
        self._proc: Optional[subprocess.Popen[bytes]] = None
        self._lock = threading.Lock()

    # -- public ------------------------------------------------------------ #
    def run(self) -> None:
        start = time.monotonic()
        try:
            self._run()
        finally:
            self.elapsed = time.monotonic() - start

    def cancel(self) -> None:
        """Stop the run from another thread (client cancelled the tool call)."""
        with self._lock:
            self.cancelled = True
        self._kill_tree()

    # -- internals --------------------------------------------------------- #
    def _run(self) -> None:
        popen_kwargs: Dict[str, Any] = {}
        if os.name == "nt":
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            popen_kwargs["start_new_session"] = True

        with self._lock:
            if self.cancelled:
                return
            try:
                self._proc = subprocess.Popen(
                    self.cmd,
                    shell=False,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    **popen_kwargs,
                )
            except OSError as exc:
                self.launch_error = f"Failed to start Codex CLI ({self.cmd[0]}): {exc}"
                return
        proc = self._proc

        lines: "queue.Queue[Optional[bytes]]" = queue.Queue()
        threading.Thread(target=self._pump, args=(proc.stdout, lines), daemon=True).start()
        threading.Thread(target=self._drain_stderr, args=(proc.stderr,), daemon=True).start()
        threading.Thread(target=self._write_prompt, args=(proc,), daemon=True).start()

        deadline = time.monotonic() + self.timeout if self.timeout > 0 else None
        turn_finished = False
        eof = False
        while True:
            if self.cancelled:
                break
            wait = 0.5
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self.timed_out = True
                    break
                wait = min(wait, remaining)
            try:
                raw = lines.get(timeout=wait)
            except queue.Empty:
                continue
            if raw is None:
                eof = True
                break
            if self._handle_line(raw) in ("turn.completed", "turn.failed"):
                turn_finished = True
                break

        if turn_finished:
            # Give Codex time to flush its session file (needed for resume).
            try:
                proc.wait(timeout=LINGER_GRACE_SEC)
            except subprocess.TimeoutExpired:
                self._terminate_lingering()
        elif not eof:
            # Timed out or cancelled while Codex was still working.
            self._kill_tree()

        # Collect whatever Codex printed before it went away.
        drain_until = time.monotonic() + DRAIN_AFTER_KILL_SEC
        while not eof and time.monotonic() < drain_until:
            try:
                raw = lines.get(timeout=0.1)
            except queue.Empty:
                continue
            if raw is None:
                break
            self._handle_line(raw)

        try:
            self.returncode = proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self._kill_tree()
            try:
                self.returncode = proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass

    def _handle_line(self, raw: bytes) -> str:
        line = raw.decode("utf-8", errors="replace").strip()
        if not line:
            return ""
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            self.non_json.append(line[:500])
            return ""
        if not isinstance(event, dict):
            return ""
        self.events.append(event)
        return str(event.get("type", ""))

    @staticmethod
    def _pump(stream: Any, out: "queue.Queue[Optional[bytes]]") -> None:
        try:
            for raw in iter(stream.readline, b""):
                out.put(raw)
        except (OSError, ValueError):
            pass
        finally:
            out.put(None)

    def _drain_stderr(self, stream: Any) -> None:
        try:
            for raw in iter(stream.readline, b""):
                text = raw.decode("utf-8", errors="replace").rstrip()
                if text:
                    self.stderr_tail.append(text[:500])
        except (OSError, ValueError):
            pass

    def _write_prompt(self, proc: "subprocess.Popen[bytes]") -> None:
        try:
            assert proc.stdin is not None
            proc.stdin.write(self.prompt.encode("utf-8"))
            proc.stdin.close()
        except (OSError, ValueError):
            pass  # Codex exited before reading the prompt; stderr tells why.

    def _terminate_lingering(self) -> None:
        """Codex finished the turn but did not exit: stop it like upstream did."""
        proc = self._proc
        if proc is None or proc.poll() is not None:
            return
        if os.name == "nt":
            self._kill_tree()
            return
        proc.terminate()
        try:
            proc.wait(timeout=KILL_GRACE_SEC)
        except subprocess.TimeoutExpired:
            proc.kill()

    def _kill_tree(self) -> None:
        """Stop Codex together with the commands it spawned."""
        proc = self._proc
        if proc is None or proc.poll() is not None:
            return
        if os.name == "nt":
            # `codex` is usually a .cmd shim; kill cmd.exe, node and codex.exe.
            try:
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=15,
                )
            except (OSError, subprocess.SubprocessError):
                pass
            if proc.poll() is None:
                proc.kill()
            return
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            return
        try:
            proc.wait(timeout=KILL_GRACE_SEC)
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


# --------------------------------------------------------------------------- #
# Turning the event stream into a compact report
# --------------------------------------------------------------------------- #
def _short_command(command: str) -> str:
    match = _SHELL_WRAPPER.match(command.strip())
    text = match.group(2) if match else command.strip()
    if len(text) > MAX_COMMAND_CHARS:
        text = text[: MAX_COMMAND_CHARS - 1] + "…"
    return text


def _relative_path(path: str, cd: Path) -> str:
    candidates = [cd]
    try:
        candidates.append(cd.resolve())
    except OSError:
        pass
    p = Path(path)
    for base in candidates:
        try:
            return p.relative_to(base).as_posix()
        except ValueError:
            continue
    return path


def summarize_events(events: List[Dict[str, Any]], cd: Path) -> Dict[str, Any]:
    """Extract the final reply and objective execution evidence from Codex events."""
    thread_id: Optional[str] = None
    messages: "OrderedDict[str, str]" = OrderedDict()
    commands: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
    files: "OrderedDict[str, Dict[str, str]]" = OrderedDict()
    usage: Optional[Dict[str, Any]] = None
    fatal: List[str] = []
    warnings: List[str] = []
    turn_completed = False
    turn_failed = False

    for idx, event in enumerate(events):
        etype = str(event.get("type", ""))
        if event.get("thread_id"):
            thread_id = str(event["thread_id"])
        if etype.startswith("item."):
            item = event.get("item") or {}
            itype = item.get("type")
            key = str(item.get("id") or f"_{idx}")
            if itype == "agent_message":
                messages[key] = str(item.get("text", ""))
            elif itype == "command_execution":
                commands[key] = item
            elif itype == "file_change" and etype == "item.completed":
                failed = item.get("status") == "failed"
                for change in item.get("changes") or []:
                    path = _relative_path(str(change.get("path", "")), cd)
                    kind = str(change.get("kind", "update"))
                    entry = files.get(path)
                    if entry is None:
                        entry = files[path] = {"path": path, "kind": kind}
                    elif entry["kind"] == "add" and kind == "update":
                        pass  # still a new file
                    elif entry["kind"] == "add" and kind == "delete":
                        entry["kind"] = "added then deleted"
                    else:
                        entry["kind"] = kind
                    if failed:
                        entry["status"] = "failed"
            elif itype == "error" and etype == "item.completed":
                warnings.append(str(item.get("message", "")))
        elif etype == "turn.completed":
            turn_completed = True
            usage = event.get("usage") or usage
        elif etype == "turn.failed":
            turn_failed = True
            fatal.append(str((event.get("error") or {}).get("message", "turn failed")))
        elif etype == "error":
            message = str(event.get("message", ""))
            if not _RECONNECTING.match(message):
                fatal.append(message)

    # Commands: keep the most recent ones plus earlier failures, in order.
    cmd_items = list(commands.values())

    def is_failed(item: Dict[str, Any]) -> bool:
        code = item.get("exit_code")
        return item.get("status") == "failed" or (code is not None and code != 0)

    keep = set(range(max(0, len(cmd_items) - MAX_COMMANDS), len(cmd_items)))
    extra = [i for i in range(len(cmd_items)) if i not in keep and is_failed(cmd_items[i])]
    keep.update(extra[-MAX_EXTRA_FAILED_COMMANDS:])
    tail_slots = set([i for i in sorted(keep) if is_failed(cmd_items[i])][-MAX_OUTPUT_TAILS:])
    command_list: List[Dict[str, Any]] = []
    for i in sorted(keep):
        item = cmd_items[i]
        entry: Dict[str, Any] = {
            "cmd": _short_command(str(item.get("command", ""))),
            "exit_code": item.get("exit_code"),
        }
        if item.get("exit_code") is None:
            entry["status"] = item.get("status")  # e.g. still in_progress at timeout
        output = str(item.get("aggregated_output") or "").strip()
        if i in tail_slots and output:
            entry["output_tail"] = output[-OUTPUT_TAIL_CHARS:]
        command_list.append(entry)

    agent_texts = [m for m in messages.values() if m.strip()]
    return {
        "thread_id": thread_id,
        "final_message": agent_texts[-1] if agent_texts else "",
        "message_count": len(agent_texts),
        "files_changed": list(files.values()),
        "commands": command_list,
        "commands_omitted": len(cmd_items) - len(command_list),
        "usage": usage,
        "fatal_errors": list(dict.fromkeys(m for m in fatal if m)),
        "warnings": list(dict.fromkeys(m for m in warnings if m)),
        "turn_completed": turn_completed,
        "turn_failed": turn_failed,
    }


def build_command(
    codex_bin: str,
    cd: Path,
    sandbox: str,
    session_id: str,
    skip_git_repo_check: bool,
    images: List[Path],
    model: str,
    yolo: bool,
    profile: str,
) -> List[str]:
    """Build the argv. The prompt itself is sent on stdin, never on the command line."""
    cmd = [codex_bin, "exec", "--json", "--sandbox", sandbox, "--cd", str(cd)]
    if model:
        cmd += ["--model", model]
    if profile:
        cmd += ["--profile", profile]
    if yolo:
        cmd.append("--yolo")
    if skip_git_repo_check:
        cmd.append("--skip-git-repo-check")
    if session_id:
        cmd += ["resume", session_id]
    for image in images:
        cmd += ["--image", str(image)]
    return cmd


def _codex_binary() -> str:
    override = os.environ.get("CODEXMCP_CODEX_PATH")
    if override:
        return override
    return shutil.which("codex") or "codex"


# --------------------------------------------------------------------------- #
# MCP tool
# --------------------------------------------------------------------------- #
@mcp.tool(
    name="codex",
    description="""
    Run a Codex CLI session (`codex exec`) in a workspace and return Codex's final reply
    together with objective execution evidence taken from Codex's event stream.

    **Choosing the sandbox:**
        - "read-only" (default): investigation, code reading, bug localisation, review, planning help.
          Codex cannot modify files.
        - "workspace-write": implementing changes, fixing bugs, running tests/builds. Codex may edit
          files under `cd` and run commands (network is off unless the user's Codex config enables it).
        - "danger-full-access": only when the user explicitly asks for it.

    **Multi-turn:** pass the returned `SESSION_ID` to continue the same Codex session (rework,
    follow-up questions) so Codex keeps its context. Omit it to start a fresh session.

    **Result fields:**
        - `success`, `SESSION_ID`, `agent_messages` (Codex's final reply; intermediate progress
          messages are dropped unless `return_all_messages` is true).
        - `files_changed`: files Codex edited through its patch tool, relative to `cd`
          (kind: add / update / delete). Files changed by shell commands (formatters, code
          generators, `sed -i`) are NOT listed, so verify with `git status` / `git diff`.
        - `commands`: shell commands Codex ran with exit code and status; the last failing ones
          include `output_tail`. `commands_omitted` counts entries left out for brevity.
        - `usage` (token usage of the turn), `elapsed_sec`, and `warnings` when present.
        - On failure (including `timeout`) `error` is set, and `SESSION_ID` plus the evidence
          collected so far are still returned, so the session can be inspected or resumed.

    **Notes:**
        - `cd` must be an existing directory.
        - The prompt is passed to Codex verbatim via stdin (no escaping or length limits).
        - Calls run concurrently; do not run parallel "workspace-write" calls on the same files.
    """,
    meta={"version": "0.8.0", "author": "guda.studio"},
)
async def codex(
    PROMPT: Annotated[str, "Instruction for the task to send to codex."],
    cd: Annotated[Path, "Set the workspace root for codex before executing the task."],
    sandbox: Annotated[
        Literal["read-only", "workspace-write", "danger-full-access"],
        Field(
            description="Sandbox policy for model-generated commands. Defaults to `read-only`."
        ),
    ] = "read-only",
    SESSION_ID: Annotated[
        str,
        "Resume the specified session of the codex. Defaults to empty: start a new session.",
    ] = "",
    skip_git_repo_check: Annotated[
        bool,
        "Allow codex running outside a Git repository (useful for one-off directories).",
    ] = True,
    return_all_messages: Annotated[
        bool,
        "Also return every raw Codex event (reasoning, tool calls, ...) in `all_messages`. Large; off by default.",
    ] = False,
    image: Annotated[
        List[Path],
        Field(
            description="Attach one or more image files to the prompt. Relative paths are resolved against `cd`.",
        ),
    ] = [],
    model: Annotated[
        str,
        Field(
            description="The model to use for the codex session. This parameter is strictly prohibited unless explicitly specified by the user.",
        ),
    ] = "",
    yolo: Annotated[
        bool,
        Field(
            description="Run every command without approvals or sandboxing. Only use when `sandbox` couldn't be applied.",
        ),
    ] = False,
    profile: Annotated[
        str,
        "Configuration profile name to load from `~/.codex/config.toml`. This parameter is strictly prohibited unless explicitly specified by the user.",
    ] = "",
    timeout: Annotated[
        int,
        Field(
            ge=0,
            description="Stop Codex after this many seconds (0 = no limit). Defaults to 3600, or $CODEXMCP_TIMEOUT.",
        ),
    ] = DEFAULT_TIMEOUT_SEC,
) -> Dict[str, Any]:
    """Execute a Codex CLI session and return the results."""
    cd = Path(cd).expanduser()
    if not cd.is_dir():
        return {"success": False, "error": f"`cd` is not an existing directory: {cd}"}

    images: List[Path] = []
    for raw in image or []:
        path = Path(raw).expanduser()
        if not path.is_absolute():
            path = cd / path
        if not path.is_file():
            return {"success": False, "error": f"Image file not found: {path}"}
        images.append(path)

    session_id = (SESSION_ID or "").strip()
    cmd = build_command(
        _codex_binary(), cd, sandbox, session_id, skip_git_repo_check,
        images, model, yolo, profile,
    )
    runner = CodexProcess(cmd, PROMPT, float(timeout))
    try:
        await anyio.to_thread.run_sync(runner.run, abandon_on_cancel=True)
    except BaseException:
        # The client cancelled the call (or the server is shutting down).
        runner.cancel()
        raise

    summary = summarize_events(runner.events, cd)
    thread_id = summary["thread_id"] or session_id or None

    errors: List[str] = []
    if runner.launch_error:
        errors.append(runner.launch_error)
    if runner.timed_out:
        errors.append(
            f"Codex did not finish within {timeout}s and was stopped. "
            "Changes made before the timeout stay in the workspace; check files_changed / git status."
        )
    errors.extend(summary["fatal_errors"])
    if not errors and summary["thread_id"] is None:
        errors.append("Failed to get `SESSION_ID` from the codex session.")
    if not errors and not summary["final_message"]:
        errors.append("Failed to get `agent_messages` from the codex session.")

    success = (
        not runner.launch_error
        and not runner.timed_out
        and summary["thread_id"] is not None
        and bool(summary["final_message"])
        and not summary["turn_failed"]
        and (summary["turn_completed"] or (runner.returncode == 0 and not summary["fatal_errors"]))
    )

    result: Dict[str, Any] = {"success": success, "SESSION_ID": thread_id}
    if summary["final_message"]:
        result["agent_messages"] = summary["final_message"]
    if not success:
        details = list(runner.stderr_tail) or list(runner.non_json)
        if details:
            errors.append("[codex stderr]\n" + "\n".join(details[-10:]))
        result["error"] = "\n\n".join(errors) or f"Codex exited with code {runner.returncode}."
    result["files_changed"] = summary["files_changed"]
    result["commands"] = summary["commands"]
    if summary["commands_omitted"]:
        result["commands_omitted"] = summary["commands_omitted"]
    result["usage"] = summary["usage"]
    result["elapsed_sec"] = round(runner.elapsed, 1)
    if summary["warnings"]:
        result["warnings"] = summary["warnings"]
    if return_all_messages:
        result["all_messages"] = runner.events
    return result


def run() -> None:
    """Start the MCP server over stdio transport."""
    mcp.run(transport="stdio")
