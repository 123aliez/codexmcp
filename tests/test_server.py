"""Tests for the codex MCP tool, run against tests/fake_codex.py instead of the real CLI."""

from __future__ import annotations

import json
import os
import stat
import sys
import time
from pathlib import Path

import anyio
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from codexmcp import server
from codexmcp.server import build_command, codex, summarize_events

FAKE = Path(__file__).with_name("fake_codex.py")


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def env(tmp_path, monkeypatch):
    FAKE.chmod(FAKE.stat().st_mode | stat.S_IXUSR)
    log = tmp_path / "fake.log"
    monkeypatch.setenv("CODEXMCP_CODEX_PATH", str(FAKE))
    monkeypatch.setenv("FAKE_CODEX_LOG", str(log))
    proj = tmp_path / "proj"
    (proj / "src").mkdir(parents=True)
    return proj, log


def calls(log: Path) -> list[dict]:
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # A zombie still answers kill(0); treat it as dead.
    try:
        with open(f"/proc/{pid}/stat") as fh:
            return fh.read().split()[2] != "Z"
    except OSError:
        return True


async def run_tool(proj: Path, **kwargs):
    args = dict(PROMPT="SCENARIO:ok", cd=proj)
    args.update(kwargs)
    return await codex(**args)


# --------------------------------------------------------------------------- #
# Pure functions
# --------------------------------------------------------------------------- #
def test_build_command_never_puts_prompt_on_command_line(tmp_path):
    cmd = build_command("codex", tmp_path, "workspace-write", "abc", True,
                        [tmp_path / "a.png", tmp_path / "b.png"], "", False, "")
    assert cmd[:3] == ["codex", "exec", "--json"]
    assert "--" not in cmd
    # Images belong to the resumed prompt, so they come after `resume <id>`.
    assert cmd.index("resume") < cmd.index("--image")
    assert cmd.count("--image") == 2


def test_summarize_events(tmp_path):
    events = [
        {"type": "thread.started", "thread_id": "t-1"},
        {"type": "error", "message": "Reconnecting... 1/5 (stream disconnected)"},
        {"type": "item.completed", "item": {"id": "1", "type": "agent_message", "text": "looking"}},
        {"type": "item.completed", "item": {"id": "2", "type": "file_change", "status": "completed",
                                            "changes": [{"path": str(tmp_path / "a.py"), "kind": "add"}]}},
        {"type": "item.completed", "item": {"id": "3", "type": "file_change", "status": "completed",
                                            "changes": [{"path": str(tmp_path / "a.py"), "kind": "update"},
                                                        {"path": "/elsewhere/b.py", "kind": "delete"}]}},
        {"type": "item.started", "item": {"id": "4", "type": "command_execution",
                                          "command": "/bin/zsh -lc 'pytest -q'", "status": "in_progress"}},
        {"type": "item.completed", "item": {"id": "4", "type": "command_execution", "exit_code": 1,
                                            "command": "/bin/zsh -lc 'pytest -q'", "status": "failed",
                                            "aggregated_output": "1 failed"}},
        {"type": "item.completed", "item": {"id": "5", "type": "agent_message", "text": "final"}},
        {"type": "turn.completed", "usage": {"input_tokens": 3, "output_tokens": 1}},
    ]
    s = summarize_events(events, tmp_path)
    assert s["thread_id"] == "t-1"
    assert s["final_message"] == "final"
    assert s["files_changed"] == [{"path": "a.py", "kind": "add"},
                                  {"path": "/elsewhere/b.py", "kind": "delete"}]
    assert s["commands"] == [{"cmd": "pytest -q", "exit_code": 1, "output_tail": "1 failed"}]
    assert s["fatal_errors"] == []  # reconnect notices are not errors
    assert s["turn_completed"] and s["usage"]["input_tokens"] == 3


# --------------------------------------------------------------------------- #
# Tool behaviour (in-process)
# --------------------------------------------------------------------------- #
@pytest.mark.anyio
async def test_success_returns_final_message_and_evidence(env):
    proj, log = env
    prompt = 'Multi-line spec:\n  - keep "strict" mode\n  - path C:\\data\\in.csv\n中文 $HOME %PATH%'
    res = await run_tool(proj, PROMPT=prompt)
    assert res["success"] is True
    assert res["agent_messages"].startswith("DONE")          # final reply only
    assert "inspect src/app.py first" not in res["agent_messages"]
    assert res["files_changed"] == [{"path": "src/app.py", "kind": "update"},
                                    {"path": "tests/test_app.py", "kind": "add"}]
    assert [c["exit_code"] for c in res["commands"]] == [1, 1, 0]
    assert "1 failed, 4 passed" in res["commands"][1]["output_tail"]
    assert res["usage"]["output_tokens"] == 300
    call = calls(log)[0]
    assert call["prompt"] == prompt                           # delivered verbatim via stdin
    assert prompt not in call["argv"]


@pytest.mark.anyio
async def test_resume_and_relative_image(env):
    proj, log = env
    (proj / "shot.png").write_bytes(b"\x89PNG")
    res = await run_tool(proj, SESSION_ID="11111111-2222-3333-4444-555555555555",
                         image=[Path("shot.png")], sandbox="workspace-write")
    assert res["success"] and res["SESSION_ID"] == "11111111-2222-3333-4444-555555555555"
    argv = calls(log)[0]["argv"]
    assert argv[argv.index("resume") + 1] == "11111111-2222-3333-4444-555555555555"
    assert argv[argv.index("--image") + 1] == str(proj / "shot.png")
    assert argv[argv.index("--sandbox") + 1] == "workspace-write"


@pytest.mark.anyio
async def test_failure_keeps_session_id(env):
    proj, _ = env
    res = await run_tool(proj, PROMPT="SCENARIO:fail")
    assert res["success"] is False
    assert res["SESSION_ID"]
    assert res["error"].count("401 Unauthorized") == 1


@pytest.mark.anyio
async def test_bad_inputs(env, tmp_path):
    proj, _ = env
    res = await run_tool(tmp_path / "missing")
    assert res["success"] is False and "not an existing directory" in res["error"]
    res = await run_tool(proj, image=[Path("nope.png")])
    assert res["success"] is False and "Image file not found" in res["error"]


@pytest.mark.anyio
async def test_codex_not_installed(env, monkeypatch):
    proj, _ = env
    monkeypatch.setenv("CODEXMCP_CODEX_PATH", "/definitely/not/codex")
    res = await run_tool(proj)
    assert res["success"] is False and "Failed to start Codex CLI" in res["error"]


@pytest.mark.anyio
async def test_timeout_kills_codex_and_its_children(env):
    proj, log = env
    start = time.monotonic()
    res = await run_tool(proj, PROMPT="SCENARIO:hang", timeout=2)
    assert time.monotonic() - start < 10
    assert res["success"] is False and "did not finish within 2s" in res["error"]
    assert res["SESSION_ID"]
    assert res["commands"][0]["status"] == "in_progress"      # partial evidence survives
    call = calls(log)[0]
    await anyio.sleep(0.5)
    assert not alive(call["pid"]) and not alive(call["child_pid"])


@pytest.mark.anyio
async def test_cancellation_kills_codex(env):
    proj, log = env
    with anyio.move_on_after(2):
        await run_tool(proj, PROMPT="SCENARIO:hang", timeout=0)
    await anyio.sleep(3)
    call = calls(log)[0]
    assert not alive(call["pid"]) and not alive(call["child_pid"])


@pytest.mark.anyio
async def test_lingering_process_is_stopped(env):
    proj, _ = env
    start = time.monotonic()
    res = await run_tool(proj, PROMPT="SCENARIO:linger")
    assert res["success"] is True
    assert time.monotonic() - start < server.LINGER_GRACE_SEC + 5


@pytest.mark.anyio
async def test_huge_event_line(env):
    proj, _ = env
    res = await run_tool(proj, PROMPT="SCENARIO:bigline")
    assert res["success"] is True
    assert any(c["cmd"] == "cat big.log" for c in res["commands"])


@pytest.mark.anyio
async def test_command_list_is_capped_but_keeps_failures(env):
    proj, _ = env
    res = await run_tool(proj, PROMPT="SCENARIO:many")
    assert len(res["commands"]) == server.MAX_COMMANDS + 2    # + the 2 earlier failures
    assert res["commands_omitted"] == 53 - len(res["commands"])
    assert res["commands"][0]["exit_code"] == 1
    assert sum("output_tail" in c for c in res["commands"]) == 1  # rg had no output


# --------------------------------------------------------------------------- #
# Through the real MCP stdio transport
# --------------------------------------------------------------------------- #
@pytest.mark.anyio
async def test_parallel_calls_over_stdio(env):
    proj, _ = env
    params = StdioServerParameters(
        command=sys.executable,
        args=["-c", "from codexmcp.server import run; run()"],
        env=dict(os.environ),
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            assert [t.name for t in tools.tools] == ["codex"]
            results = []

            async def one(i: int) -> None:
                res = await session.call_tool("codex", {"PROMPT": f"SLEEP:2 task {i}", "cd": str(proj)})
                results.append(json.loads(res.content[0].text))

            start = time.monotonic()
            async with anyio.create_task_group() as tg:
                for i in range(3):
                    tg.start_soon(one, i)
            elapsed = time.monotonic() - start

    assert all(r["success"] for r in results)
    assert len({r["SESSION_ID"] for r in results}) == 3
    assert elapsed < 4.5, f"calls were serialised ({elapsed:.1f}s for 3 x 2s)"
