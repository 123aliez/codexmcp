"""storage.py — SQLite 状态持久化（uploads / reviews 两张表 + 状态机）。

状态机（方案 §13）：
  UPLOADING → VALIDATING → READY → (审查占用) → EXPIRED/PURGED
  REVIEWING → COMPLETED → PURGED ；异常 REJECTED/FAILED/EXPIRED

身份绑定（方案 §12）：uploads.token_id 记录 Nginx 注入的 X-Authenticated-Token-Id，
跨 Token 使用 upload_id 在 SQL 层即拒绝。
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path

_DB_LOCK = threading.Lock()
_CONN: sqlite3.Connection | None = None

UPLOAD_STATES = ("UPLOADING", "VALIDATING", "READY", "REVIEWING", "EXPIRED", "REJECTED", "PURGED")
REVIEW_STATES = ("REVIEWING", "COMPLETED", "FAILED", "PURGED")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS uploads (
    upload_id     TEXT PRIMARY KEY,
    token_id      TEXT NOT NULL,
    state         TEXT NOT NULL,
    archive_sha256 TEXT NOT NULL,
    archive_path  TEXT NOT NULL,
    project_name  TEXT DEFAULT '',
    file_count    INTEGER DEFAULT 0,
    compressed_bytes   INTEGER DEFAULT 0,
    uncompressed_bytes INTEGER DEFAULT 0,
    created_at    REAL NOT NULL,
    expires_at    REAL NOT NULL,
    error_code    TEXT DEFAULT '',
    client_meta   TEXT DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS reviews (
    review_id     TEXT PRIMARY KEY,
    upload_id     TEXT NOT NULL,
    token_id      TEXT NOT NULL,
    state         TEXT NOT NULL,
    mode          TEXT DEFAULT 'review',
    prev_review_id TEXT DEFAULT '',
    workspace     TEXT NOT NULL,
    codex_session TEXT DEFAULT '',
    agent_text    TEXT DEFAULT '',
    created_at    REAL NOT NULL,
    last_active   REAL NOT NULL,
    hard_deadline REAL NOT NULL,
    error_code    TEXT DEFAULT '',
    previous_summary TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_uploads_token ON uploads(token_id);
CREATE INDEX IF NOT EXISTS idx_reviews_token ON reviews(token_id);
CREATE INDEX IF NOT EXISTS idx_reviews_upload ON reviews(upload_id);
"""


def _connect() -> sqlite3.Connection:
    global _CONN
    if _CONN is None:
        path = os.environ.get("CODEXMCP_STATE_DB", "/var/lib/codexmcp/state/codexmcp.sqlite3")
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        _CONN = sqlite3.connect(path, check_same_thread=False)
        _CONN.row_factory = sqlite3.Row
        _CONN.execute("PRAGMA journal_mode=WAL")
        _CONN.execute("PRAGMA synchronous=NORMAL")
        _CONN.executescript(_SCHEMA)
        _CONN.commit()
    return _CONN


def new_upload(token_id: str, archive_path: str, archive_sha: str, ttl: float) -> str:
    upload_id = f"upl_{uuid.uuid4().hex}"
    now = time.time()
    with _DB_LOCK:
        _connect().execute(
            "INSERT INTO uploads (upload_id, token_id, state, archive_sha256, archive_path, created_at, expires_at) VALUES (?,?,?,?,?,?,?)",
            (upload_id, token_id, "VALIDATING", archive_sha, archive_path, now, now + ttl),
        )
        _connect().commit()
    return upload_id


def set_upload_state(upload_id: str, state: str, error_code: str = "", **cols) -> None:
    sets = ["state=?", "error_code=?"]
    vals: list = [state, error_code]
    for k, v in cols.items():
        sets.append(f"{k}=?")
        vals.append(v)
    vals.append(upload_id)
    with _DB_LOCK:
        _connect().execute(f"UPDATE uploads SET {', '.join(sets)} WHERE upload_id=?", vals)
        _connect().commit()


def get_upload(upload_id: str) -> dict | None:
    with _DB_LOCK:
        row = _connect().execute("SELECT * FROM uploads WHERE upload_id=?", (upload_id,)).fetchone()
    return dict(row) if row else None


def claim_ready_upload(upload_id: str, token_id: str) -> tuple[dict | None, str]:
    """原子占用 READY upload（审查修复#5：SELECT-then-UPDATE 竞态改为条件更新 CAS）。
    只有 state=READY 且未过期且归属该 token 时才转为 REVIEWING 并返回记录。"""
    now = time.time()
    with _DB_LOCK:
        conn = _connect()
        cur = conn.execute(
            "UPDATE uploads SET state='REVIEWING' WHERE upload_id=? AND token_id=? AND state='READY' AND expires_at>?",
            (upload_id, token_id, now),
        )
        if cur.rowcount != 1:
            conn.commit()
            # 占用失败：区分原因供调用方返回准确错误
            row = conn.execute("SELECT state, token_id, expires_at FROM uploads WHERE upload_id=?", (upload_id,)).fetchone()
            if row is None:
                return None, "UPLOAD_NOT_FOUND"
            if row["token_id"] != token_id:
                return None, "UPLOAD_FORBIDDEN"
            if row["state"] in ("EXPIRED", "PURGED", "REVIEWING") or row["expires_at"] <= now:
                return None, "UPLOAD_EXPIRED"
            return None, "UPLOAD_NOT_READY"
        row = conn.execute("SELECT * FROM uploads WHERE upload_id=?", (upload_id,)).fetchone()
        conn.commit()
    return dict(row), ""


def get_ready_upload(upload_id: str, token_id: str) -> tuple[dict | None, str]:
    """（保留：只读检查，不占用）取 READY 且未过期且归属该 token 的 upload。"""
    up = get_upload(upload_id)
    if up is None:
        return None, "UPLOAD_NOT_FOUND"
    if up["token_id"] != token_id:
        return None, "UPLOAD_FORBIDDEN"          # 跨 Token 使用（方案 §12）
    if up["state"] in ("EXPIRED", "PURGED"):
        return None, "UPLOAD_EXPIRED"
    if up["state"] != "READY":
        return None, "UPLOAD_NOT_READY"
    if time.time() > up["expires_at"]:
        set_upload_state(upload_id, "EXPIRED")
        return None, "UPLOAD_EXPIRED"
    return up, ""


def new_review(upload: dict, workspace: str, mode: str, prev_review_id: str, hard_ttl: float) -> str:
    review_id = f"rev_{uuid.uuid4().hex}"
    now = time.time()
    with _DB_LOCK:
        _connect().execute(
            "INSERT INTO reviews (review_id, upload_id, token_id, state, mode, prev_review_id, workspace, created_at, last_active, hard_deadline) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (review_id, upload["upload_id"], upload["token_id"], "REVIEWING", mode, prev_review_id, workspace, now, now, now + hard_ttl),
        )
        _connect().execute("UPDATE uploads SET state='REVIEWING' WHERE upload_id=?", (upload["upload_id"],))
        _connect().commit()
    return review_id


def set_review_workspace(review_id: str, workspace: str) -> None:
    with _DB_LOCK:
        _connect().execute("UPDATE reviews SET workspace=? WHERE review_id=?", (workspace, review_id))
        _connect().commit()


def get_review(review_id: str, token_id: str) -> tuple[dict | None, str]:
    with _DB_LOCK:
        row = _connect().execute("SELECT * FROM reviews WHERE review_id=?", (review_id,)).fetchone()
    if row is None:
        return None, "REVIEW_NOT_FOUND"
    rv = dict(row)
    if rv["token_id"] != token_id:
        return None, "REVIEW_FORBIDDEN"
    if rv["state"] == "PURGED":
        return None, "REVIEW_PURGED"
    if time.time() > rv["hard_deadline"]:
        return None, "REVIEW_EXPIRED"
    return rv, ""


def touch_review(review_id: str, idle_ttl: float, **cols) -> None:
    """续活 + 可选更新列（codex_session/agent_text/state/error_code）。"""
    sets = ["last_active=?"]
    vals: list = [time.time()]
    for k, v in cols.items():
        sets.append(f"{k}=?")
        vals.append(v)
    vals.append(review_id)
    with _DB_LOCK:
        # 单进程单写者（uvicorn 单 worker），直接更新无竞态
        _connect().execute(f"UPDATE reviews SET {', '.join(sets)} WHERE review_id=?", vals)
        _connect().commit()


def list_stale_uploads(ttl: float) -> list[dict]:
    """需要清理的 uploads（审查修复#7：覆盖全部非终态/失败态，不留永久残留）。"""
    now = time.time()
    with _DB_LOCK:
        rows = _connect().execute(
            "SELECT * FROM uploads WHERE "
            # READY/VALIDATING 超时
            "((state IN ('READY','VALIDATING')) AND expires_at < ?) OR "
            # REVIEWING 但没有对应活动 review（孤儿，如容器崩溃中断）
            "(state='REVIEWING' AND upload_id NOT IN (SELECT upload_id FROM reviews WHERE state='REVIEWING')) OR "
            # 失败态给 10 分钟保留期（排查窗口）后清理
            "(state='REJECTED' AND created_at < ?)",
            (now, now - 600),
        ).fetchall()
    return [dict(r) for r in rows]


def list_stale_reviews(idle_ttl: float) -> list[dict]:
    """需要清理的 reviews（审查修复#7：含 FAILED，不留永久残留源码）。"""
    cutoff = time.time() - idle_ttl
    with _DB_LOCK:
        rows = _connect().execute(
            "SELECT * FROM reviews WHERE state IN ('REVIEWING','COMPLETED','FAILED') "
            "AND (last_active < ? OR hard_deadline < ?)",
            (cutoff, time.time()),
        ).fetchall()
    return [dict(r) for r in rows]


def mark_purged(kind: str, obj_id: str) -> None:
    table = "uploads" if kind == "upload" else "reviews"
    with _DB_LOCK:
        _connect().execute(f"UPDATE {table} SET state='PURGED' WHERE {'upload_id' if kind=='upload' else 'review_id'}=?", (obj_id,))
        _connect().commit()
