#!/usr/bin/env python3
"""Stand-in for `codex exec --json`, used by the test-suite.

It emits the same JSONL event shapes as Codex CLI 0.165 (see the TypeScript
types in `@openai/codex-sdk`). The prompt is read from argv (after `--`, as the
upstream server passes it) or from stdin (as this fork passes it).

Behaviour is selected by tokens in the prompt:
    SCENARIO:ok       normal run (default)
    SCENARIO:fail     turn.failed
    SCENARIO:hang     never finishes; spawns a grandchild process
    SCENARIO:linger   finishes the turn but keeps running afterwards
    SCENARIO:bigline  one event line larger than 200 KB
    SCENARIO:many     50 shell commands
    SLEEP:<seconds>   sleep before doing the work

When $FAKE_CODEX_LOG is set, every call appends {"argv", "prompt", "pid",
"child_pid"} as one JSON line to that file.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import uuid


def emit(obj: dict) -> None:
    print(json.dumps(obj, ensure_ascii=False), flush=True)


def read_prompt(argv: list[str]) -> str:
    if "--" in argv:
        return argv[argv.index("--") + 1]
    return sys.stdin.read()


def log(record: dict) -> None:
    path = os.environ.get("FAKE_CODEX_LOG")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def command(idx: int, cmd: str, exit_code: int, output: str) -> None:
    item = {"id": f"item_{idx}", "type": "command_execution", "command": cmd,
            "aggregated_output": "", "status": "in_progress"}
    emit({"type": "item.started", "item": item})
    item = dict(item, aggregated_output=output, exit_code=exit_code,
                status="completed" if exit_code == 0 else "failed")
    emit({"type": "item.completed", "item": item})


def main() -> int:
    argv = sys.argv[1:]
    prompt = read_prompt(argv)
    cd = argv[argv.index("--cd") + 1] if "--cd" in argv else os.getcwd()
    thread_id = argv[argv.index("resume") + 1] if "resume" in argv else str(uuid.uuid4())
    scenario = (re.search(r"SCENARIO:(\w+)", prompt) or [None, "ok"])[1]
    sleep = float((re.search(r"SLEEP:([\d.]+)", prompt) or [None, "0"])[1])

    child_pid = None
    if scenario == "hang":
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(300)"])
        child_pid = child.pid
    log({"argv": argv, "prompt": prompt, "pid": os.getpid(), "child_pid": child_pid})

    print("2026-10-28T00:00:00Z WARN fake codex stderr noise", file=sys.stderr, flush=True)
    emit({"type": "thread.started", "thread_id": thread_id})
    emit({"type": "turn.started"})

    if scenario == "hang":
        emit({"type": "item.started", "item": {"id": "item_0", "type": "command_execution",
                                               "command": "bash -lc 'pytest -q'",
                                               "aggregated_output": "", "status": "in_progress"}})
        time.sleep(300)
        return 0

    time.sleep(sleep)

    if scenario == "fail":
        emit({"type": "error", "message": "unexpected status 401 Unauthorized"})
        emit({"type": "turn.failed", "error": {"message": "unexpected status 401 Unauthorized"}})
        return 1

    emit({"type": "error", "message": "Reconnecting... 1/5 (stream disconnected before completion)"})
    command(1, "bash -lc 'rg -n \"def parse\" src'", 1, "")
    emit({"type": "item.completed", "item": {"id": "item_2", "type": "agent_message",
                                             "text": "I'll inspect src/app.py first."}})
    emit({"type": "item.completed", "item": {
        "id": "item_3", "type": "file_change", "status": "completed",
        "changes": [{"path": os.path.join(cd, "src", "app.py"), "kind": "update"},
                    {"path": os.path.join(cd, "tests", "test_app.py"), "kind": "add"}]}})
    command(4, "bash -lc 'pytest -q'", 1,
            "....F\nFAILED tests/test_app.py::test_parse - assert 1 == 2\n1 failed, 4 passed in 0.12s\n")
    emit({"type": "item.completed", "item": {
        "id": "item_5", "type": "file_change", "status": "completed",
        "changes": [{"path": os.path.join(cd, "src", "app.py"), "kind": "update"}]}})
    command(6, "bash -lc 'pytest -q'", 0, ".....\n5 passed in 0.10s\n")
    if scenario == "bigline":
        command(7, "bash -lc 'cat big.log'", 0, "x" * 250_000)
    if scenario == "many":
        for i in range(50):
            command(100 + i, f"bash -lc 'sed -n {i},+40p src/app.py'", 0, "...")
    emit({"type": "item.completed", "item": {"id": "item_9", "type": "agent_message",
                                             "text": f"DONE {thread_id[:8]}: fixed parse(); 5 passed."}})
    emit({"type": "turn.completed", "usage": {"input_tokens": 1200, "cached_input_tokens": 800,
                                              "output_tokens": 300, "reasoning_output_tokens": 50}})
    if scenario == "linger":
        time.sleep(60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
