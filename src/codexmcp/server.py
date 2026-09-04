"""FastMCP server implementation for the Codex MCP project."""

from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Annotated, Any, Dict, Generator, List, Literal, Optional

from mcp.server.fastmcp import FastMCP
from pydantic import BeforeValidator, Field
import shutil

mcp = FastMCP("Codex MCP Server-from guda.studio")

# 并发信号量（run() 中按 CODEX_MAX_CONCURRENCY 初始化）：多 agent 共享网关时限制同时运行的 codex 子进程数
_CODEX_SEMAPHORE: threading.Semaphore | None = None

# ── provider 优先级与降级（ChatGPT 登录额度优先，第三方 API 保底）──
# CODEX_PROVIDER_ORDER：逗号分隔的尝试顺序，默认 "chatgpt,custom"
#   chatgpt = 登录态（config.toml 无 model_provider 时的官方通道）
#   custom  = 第三方 API（[model_providers.custom]）
# 触发降级的错误形态：usage limit / 401 / 429 / rate limit / insufficient（从 codex 0.153 二进制提取的特征串）
_FALLBACK_PATTERNS = (
    "usage limit", "you've hit your", "rate limit", "too many requests",
    "429", "401", "unauthorized", "insufficient", "quota", "exceeded",
    "not logged in", "sign in again", "please sign in",
)


def _should_fallback(err_text: str) -> bool:
    t = (err_text or "").lower()
    return any(p in t for p in _FALLBACK_PATTERNS)


def _provider_order() -> list[str]:
    order = [s.strip() for s in os.getenv("CODEX_PROVIDER_ORDER", "chatgpt,custom").split(",") if s.strip()]
    return [p for p in order if p in ("chatgpt", "custom")] or ["chatgpt", "custom"]


def _cd_allowed(cd: Path) -> bool:
    """cd 参数 allowlist（容器化部署：仅允许挂载的工作区内），逗号分隔环境变量 CODEX_CD_ALLOWLIST 可覆盖。
    审查修复：resolve 后用 is_relative_to 判定，防 .. 与符号链接逃逸。"""
    allowlist = [p.strip() for p in os.getenv("CODEX_CD_ALLOWLIST", "/workspace").split(",") if p.strip()]
    try:
        real_cd = Path(cd).resolve(strict=True)
    except (OSError, RuntimeError):
        return False  # 路径不存在也拒绝（工具约定调用方给已存在的工作区）
    for allowed in allowlist:
        try:
            real_allowed = Path(allowed).resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if real_cd == real_allowed or real_cd.is_relative_to(real_allowed):
            return True
    return False


def _empty_str_to_none(value: str | None) -> str | None:
    """Convert empty strings to None for optional UUID parameters."""
    if isinstance(value, str) and not value.strip():
        return None
    return value


def run_shell_command(cmd: list[str]) -> Generator[str, None, None]:
    """Execute a command and stream its output line-by-line.

    Args:
        cmd: Command and arguments as a list (e.g., ["codex", "exec", "prompt"])

    Yields:
        Output lines from the command
    """
    # On Windows, codex is exposed via a *.cmd shim. Use cmd.exe with /s so
    # user prompts containing quotes/newlines aren't reinterpreted as shell syntax.
    popen_cmd = cmd.copy()
    codex_path = shutil.which('codex') or cmd[0]
    popen_cmd[0] = codex_path

    process = subprocess.Popen(
        popen_cmd,
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        encoding='utf-8',
    )

    output_queue: queue.Queue[str | None] = queue.Queue()
    GRACEFUL_SHUTDOWN_DELAY = 0.3

    def is_turn_completed(line: str) -> bool:
        """Check if the line indicates turn completion via JSON parsing."""
        try:
            data = json.loads(line)
            return data.get("type") == "turn.completed"
        except (json.JSONDecodeError, AttributeError, TypeError):
            return False

    def read_output() -> None:
        """Read process output in a separate thread."""
        if process.stdout:
            for line in iter(process.stdout.readline, ""):
                stripped = line.strip()
                output_queue.put(stripped)
                if is_turn_completed(stripped):
                    time.sleep(GRACEFUL_SHUTDOWN_DELAY)
                    process.terminate()
                    break
            process.stdout.close()
        output_queue.put(None)

    thread = threading.Thread(target=read_output)
    thread.start()

    # Yield lines while process is running
    while True:
        try:
            line = output_queue.get(timeout=0.5)
            if line is None:
                break
            yield line
        except queue.Empty:
            if process.poll() is not None and not thread.is_alive():
                break

    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
    thread.join(timeout=5)

    while not output_queue.empty():
        try:
            line = output_queue.get_nowait()
            if line is not None:
                yield line
        except queue.Empty:
            break

def windows_escape(prompt):
    """
    Windows 风格的字符串转义函数。
    把常见特殊字符转义成 \\ 形式，适合命令行、JSON 或路径使用。
    比如：\n 变成 \\n，" 变成 \\"。
    """
    # 先处理反斜杠，避免它干扰其他替换
    result = prompt.replace('\\', '\\\\')
    # 双引号，转义成 \"，防止字符串边界乱套
    result = result.replace('"', '\\"')
    # 换行符，Windows 常用 \r\n，但我们分开转义
    result = result.replace('\n', '\\n')
    result = result.replace('\r', '\\r')
    # 制表符，空格的“超级版”
    result = result.replace('\t', '\\t')
    # 其他常见：退格符（像按了后退键）、换页符（打印机跳页用）
    result = result.replace('\b', '\\b')
    result = result.replace('\f', '\\f')
    # 如果有单引号，也转义下（不过 Windows 命令行不那么严格，但保险起见）
    result = result.replace("'", "\\'")
    
    return result

@mcp.tool(
    name="codex",
    description="""
    Executes a non-interactive Codex session via CLI to perform AI-assisted coding tasks in a secure workspace.
    This tool wraps the `codex exec` command, enabling model-driven code generation, debugging, or automation based on natural language prompts.
    It supports resuming ongoing sessions for continuity and enforces sandbox policies to prevent unsafe operations. Ideal for integrating Codex into MCP servers for agentic workflows, such as code reviews or repo modifications.

    **Key Features:**
        - **Prompt-Driven Execution:** Send task instructions to Codex for step-by-step code handling.
        - **Workspace Isolation:** Operate within a specified directory, with optional Git repo skipping.
        - **Security Controls:** Three sandbox levels balance functionality and safety.
        - **Session Persistence:** Resume prior conversations via `SESSION_ID` for iterative tasks.

    **Edge Cases & Best Practices:**
        - Ensure `cd` exists and is accessible; tool fails silently on invalid paths.
        - For most repos, prefer "read-only" to avoid accidental changes.
        - If needed, set `return_all_messages` to `True` to parse "all_messages" for detailed tracing (e.g., reasoning, tool calls, etc.).
    """,
    meta={"version": "0.0.0", "author": "guda.studio"},
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
        "Resume the specified session of the codex. Defaults to `None`, start a new session.",
    ] = "",
    skip_git_repo_check: Annotated[
        bool,
        "Allow codex running outside a Git repository (useful for one-off directories).",
    ] = True,
    return_all_messages: Annotated[
        bool,
        "Return all messages (e.g. reasoning, tool calls, etc.) from the codex session. Set to `False` by default, only the agent's final reply message is returned.",
    ] = False,
    image: Annotated[
        List[Path],
        Field(
            description="Attach one or more image files to the initial prompt. Separate multiple paths with commas or repeat the flag.",
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
) -> Dict[str, Any]:
    """Execute a Codex CLI session and return the results."""
    # cd allowlist：容器化部署仅允许挂载工作区，拒绝任意目录
    if not _cd_allowed(cd):
        return {
            "success": False,
            "error": f"cd 路径不在允许列表内（CODEX_CD_ALLOWLIST，默认 /workspace）: {cd}",
        }

    # Build command as list to avoid injection
    # 服务端安全上限：部署方可用 CODEX_MAX_SANDBOX 限制允许的最高 sandbox 级别与 yolo
    #   read-only（默认）| workspace-write | danger-full-access
    _max_sandbox = os.getenv("CODEX_MAX_SANDBOX", "danger-full-access")
    _levels = ["read-only", "workspace-write", "danger-full-access"]
    if yolo and _max_sandbox == "read-only":
        yolo = False
    if _levels.index(sandbox) > _levels.index(_max_sandbox):
        sandbox = _max_sandbox

    def build_cmd(provider: str) -> list[str]:
        c = ["codex", "exec", "--sandbox", sandbox, "--cd", str(cd), "--json"]
        if provider == "custom":
            # 第三方保底通道：运行时覆盖 model_provider，不改 config.toml
            c.extend(["-c", 'model_provider="custom"'])
        if len(image):
            c.extend(["--image", ",".join(image)])
        if model:
            c.extend(["--model", model])
        if profile:
            c.extend(["--profile", profile])
        if yolo:
            c.append("--yolo")
        if skip_git_repo_check:
            c.append("--skip-git-repo-check")
        if SESSION_ID:
            c.extend(["resume", str(SESSION_ID)])
        return c
        
    if os.name == "nt":
        PROMPT = windows_escape(PROMPT)
    else:
        PROMPT = PROMPT

    # 并发限制：信号量满时直接返回提示，不排队阻塞（MCP 客户端可自行重试）
    global _CODEX_SEMAPHORE
    if _CODEX_SEMAPHORE is None:
        _CODEX_SEMAPHORE = threading.Semaphore(2)
    if not _CODEX_SEMAPHORE.acquire(blocking=False):
        return {
            "success": False,
            "error": "并发已满（CODEX_MAX_CONCURRENCY）：当前有其他 codex 任务在运行，请稍后重试。",
        }

    try:
        def run_once(provider: str):
            """单 provider 执行一轮，返回 (result, err_text)。err_text 用于降级判定。"""
            cmd = build_cmd(provider) + ['--', PROMPT]
            msgs: list[Dict[str, Any]] = []
            agent_out = ""
            ok = True
            err_parts: list[str] = []
            tid: Optional[str] = None
            for line in run_shell_command(cmd):
                try:
                    line_dict = json.loads(line.strip())
                    msgs.append(line_dict)
                    item = line_dict.get("item", {})
                    if item.get("type") == "agent_message":
                        agent_out += item.get("text", "")
                    if line_dict.get("thread_id") is not None:
                        tid = line_dict.get("thread_id")
                    if "fail" in line_dict.get("type", ""):
                        if len(agent_out) == 0:
                            ok = False
                        err_parts.append(line_dict.get("error", {}).get("message", ""))
                    if "error" in line_dict.get("type", ""):
                        error_msg = line_dict.get("message", "")
                        import re
                        if not re.match(r'^Reconnecting\.\.\.\s+\d+/\d+', error_msg):
                            if len(agent_out) == 0:
                                ok = False
                            err_parts.append(error_msg)
                except json.JSONDecodeError:
                    err_parts.append(line)
                    continue
                except Exception as error:
                    err_parts.append(f"Unexpected error: {error}. Line: {line!r}")
                    ok = False
                    break
            if tid is None:
                ok = False
                err_parts.insert(0, "Failed to get `SESSION_ID` from the codex session.")
            if len(agent_out) == 0:
                ok = False
                err_parts.insert(0, "Failed to get `agent_messages` from the codex session.")
            res = {
                "success": ok,
                "SESSION_ID": tid,
                "agent_messages": agent_out,
                "provider_used": provider,
            }
            if not ok:
                res["error"] = "\n\n".join(err_parts)
            if return_all_messages:
                res["all_messages"] = msgs
            return res, "\n".join(err_parts)

        # provider 优先级循环：chatgpt（登录额度）优先 → 命中额度/认证类失败时降级 custom（第三方保底）
        result = None
        err_text = ""
        for provider in _provider_order():
            result, err_text = run_once(provider)
            if result["success"]:
                break
            # resume 属于上一 provider 的会话，降级后无法续（custom 侧无该 thread），自动去掉重开
            if _should_fallback(err_text) and provider != _provider_order()[-1]:
                SESSION_ID = ""
                continue
            break

        return result
    finally:
        _CODEX_SEMAPHORE.release()


def build_review_cmd(provider: str, cd: Path, session_id: str) -> list[str]:
    """review_tool 专用：固定参数的 codex exec 命令（客户端不可指定 sandbox/yolo/model/profile）。
    sandbox=workspace-write 允许 Codex 写 scratch，但 §14 系统约束禁止修改项目文件；
    工作区是临时快照，审查结束即删。"""
    c = ["codex", "exec", "--sandbox", "workspace-write", "--cd", str(cd), "--json", "--skip-git-repo-check"]
    if os.getenv("CODEXMCP_CODEX_EXECUTION_MODE", "yolo") == "yolo":
        # 容器内 bwrap 不可用（apparmor+seccomp 双封），容器即沙箱（与现有 /codex 行为一致）
        c.append("--yolo")
    if provider == "custom":
        c.extend(["-c", 'model_provider="custom"'])
    if session_id:
        c.extend(["resume", str(session_id)])
    return c


@mcp.custom_route("/healthz", methods=["GET"])
async def healthz(request):
    from starlette.responses import JSONResponse
    return JSONResponse({"status": "ok", "version": "0.8.0-remote-review", "service": "codexmcp"})


def run() -> None:
    """HTTP 传输改造：设置 MCP_HTTP_HOST/MCP_HTTP_PORT 任一即走 streamable HTTP（容器化部署），
    否则保持上游 stdio 行为。并发通过全局信号量限制（CODEX_MAX_CONCURRENCY，默认 2），
    防止多 agent 共享时 codex 子进程数打爆宿主机。"""
    import os

    global _CODEX_SEMAPHORE
    limit = max(1, int(os.getenv("CODEX_MAX_CONCURRENCY", "2")))
    _CODEX_SEMAPHORE = threading.Semaphore(limit)

    host = os.getenv("MCP_HTTP_HOST")
    port = os.getenv("MCP_HTTP_PORT")
    if host or port:
        # 官方 SDK FastMCP.run() 不收 host/port，Settings 字段无默认（init 显式参数压过 env），
        # 因此在构造实例上直接覆盖 settings（run_streamable_http_async 读取的是 self.settings）
        mcp.settings.host = host or "0.0.0.0"
        mcp.settings.port = int(port or "8322")
        # 容器化反代部署：DNS rebinding 防护需放行上游 Nginx 传入的 Host（默认仅允许 localhost）
        from mcp.server.transport_security import TransportSecuritySettings
        extra_hosts = [h.strip() for h in os.getenv("MCP_ALLOWED_HOSTS", "").split(",") if h.strip()]
        mcp.settings.transport_security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=["localhost", "127.0.0.1", *extra_hosts],
            allowed_origins=[],
        )

        # 远程审查模块：上传接口（custom_route）+ 审查三工具 + TTL 清理线程
        from . import review_tool  # noqa: F401  注册 codex_project_review/continue/finalize
        from . import upload_api
        from . import workspace_manager

        @mcp.custom_route("/v1/uploads", methods=["POST"])
        async def _uploads(request):
            return await upload_api.uploads_endpoint(request)

        @mcp.custom_route("/v1/health", methods=["GET"])
        async def _v1_health(request):
            from starlette.responses import JSONResponse
            return JSONResponse({"status": "ok", "remote_review": True})

        workspace_manager.start_background_cleanup()

        mcp.run(transport="streamable-http")
    else:
        mcp.run(transport="stdio")
