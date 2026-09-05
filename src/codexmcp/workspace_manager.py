"""workspace_manager.py — 临时目录与 TTL 管理（方案 §13/§21）。

目录布局（容器内卷）：
  $CODEXMCP_UPLOAD_ROOT/{staging,ready}/<upload_id>.tar.gz
  $CODEXMCP_REVIEW_ROOT/<review_id>/{workspace,meta,result.json}

清理：
  · 启动时孤儿目录清理（DB 无记录或状态 PURGED 的目录直接删）
  · 后台每 CODEXMCP_CLEANUP_INTERVAL_SECONDS 秒：
      - READY 超过 TTL 未使用的 upload 包删除 → EXPIRED
      - review 空闲超过 idle TTL / 超过 hard deadline → 删 workspace+包 → PURGED
  · finalize 立即删除（同步调用，返回前删完）
"""

from __future__ import annotations

import os
import shutil
import threading
import time
from pathlib import Path

from . import storage

UPLOAD_ROOT = Path(os.environ.get("CODEXMCP_UPLOAD_ROOT", "/var/lib/codexmcp/uploads"))
REVIEW_ROOT = Path(os.environ.get("CODEXMCP_REVIEW_ROOT", "/var/lib/codexmcp/reviews"))

UPLOAD_TTL = float(os.environ.get("CODEXMCP_UPLOAD_TTL_SECONDS", "1800"))
REVIEW_IDLE_TTL = float(os.environ.get("CODEXMCP_REVIEW_IDLE_TTL_SECONDS", "3600"))
REVIEW_HARD_TTL = float(os.environ.get("CODEXMCP_REVIEW_HARD_TTL_SECONDS", "7200"))
CLEANUP_INTERVAL = float(os.environ.get("CODEXMCP_CLEANUP_INTERVAL_SECONDS", "300"))

_stop = threading.Event()
_thread: threading.Thread | None = None


def staging_path(upload_id: str) -> Path:
    return UPLOAD_ROOT / "staging" / f"{upload_id}.tar.gz"


def ready_path(upload_id: str) -> Path:
    return UPLOAD_ROOT / "ready" / f"{upload_id}.tar.gz"


def ensure_dirs() -> None:
    for p in (UPLOAD_ROOT / "staging", UPLOAD_ROOT / "ready", REVIEW_ROOT):
        p.mkdir(parents=True, exist_ok=True)


def promote_to_ready(upload_id: str) -> Path:
    """staging → ready 原子移动（同卷 rename）。"""
    src, dst = staging_path(upload_id), ready_path(upload_id)
    os.replace(src, dst)
    return dst


def create_review_dirs(review_id: str) -> tuple[Path, Path]:
    ws = REVIEW_ROOT / review_id / "workspace"
    meta = REVIEW_ROOT / review_id / "meta"
    ws.mkdir(parents=True, exist_ok=True)
    meta.mkdir(parents=True, exist_ok=True)
    return ws, meta


def purge_review(review_id: str, also_upload: bool = False, upload_id: str = "") -> None:
    """删除 review 目录（+可选 upload 包）。
    审查修复#8：删除失败不标 PURGED——目录仍存在时保持原状态，下一轮清理重试。"""
    d = REVIEW_ROOT / review_id
    shutil.rmtree(d, ignore_errors=True)
    if d.exists():  # 删除失败：不标 PURGED，留待重试
        return
    if also_upload and upload_id:
        _purge_upload_files(upload_id)
        storage.mark_purged("upload", upload_id)
    storage.mark_purged("review", review_id)


def _purge_upload_files(upload_id: str) -> bool:
    """删除 upload 包文件；全部确认消失返回 True。"""
    ok = True
    for p in (ready_path(upload_id), staging_path(upload_id)):
        try:
            p.unlink(missing_ok=True)
        except OSError:
            ok = False
    return ok


def purge_upload(upload_id: str) -> None:
    _purge_upload_files(upload_id)


def startup_orphan_cleanup() -> None:
    """容器启动清孤儿（审查修复#8：含 PURGED/EXPIRED/REJECTED/FAILED 记录的残留路径重删）。"""
    ensure_dirs()
    uploads = _all_uploads()
    known_uploads = {r["upload_id"] for r in uploads}
    # 终态记录：文件应已不存在，残留即上次删除失败——重删
    dead_uploads = {r["upload_id"] for r in uploads if r["state"] in ("PURGED", "EXPIRED", "REJECTED")}
    for uid in dead_uploads:
        _purge_upload_files(uid)
    for sub in ("staging", "ready"):
        for f in (UPLOAD_ROOT / sub).glob("*.tar.gz"):
            uid = f.name.removesuffix(".tar.gz")
            if uid not in known_uploads:
                f.unlink(missing_ok=True)
    reviews = _all_reviews()
    known_reviews = {r["review_id"] for r in reviews}
    for rv in reviews:
        if rv["state"] in ("PURGED", "FAILED"):
            d = REVIEW_ROOT / rv["review_id"]
            if d.exists():
                shutil.rmtree(d, ignore_errors=True)
    for d in REVIEW_ROOT.iterdir():
        if d.is_dir() and d.name not in known_reviews:
            shutil.rmtree(d, ignore_errors=True)


def _all_uploads() -> list[dict]:
    with storage._DB_LOCK:
        rows = storage._connect().execute("SELECT upload_id, state FROM uploads").fetchall()
    return [dict(r) for r in rows]


def _all_reviews() -> list[dict]:
    with storage._DB_LOCK:
        rows = storage._connect().execute("SELECT review_id, state FROM reviews").fetchall()
    return [dict(r) for r in rows]


def cleanup_once() -> dict:
    """一轮 TTL 清理，返回统计（供测试与日志）。"""
    stats = {"uploads_expired": 0, "reviews_purged": 0}
    for up in storage.list_stale_uploads(UPLOAD_TTL):
        purge_upload(up["upload_id"])
        storage.set_upload_state(up["upload_id"], "EXPIRED")
        stats["uploads_expired"] += 1
    for rv in storage.list_stale_reviews(REVIEW_IDLE_TTL):
        purge_review(rv["review_id"], also_upload=True, upload_id=rv["upload_id"])
        stats["reviews_purged"] += 1
    return stats


def _loop() -> None:
    while not _stop.wait(CLEANUP_INTERVAL):
        try:
            cleanup_once()
        except Exception as e:  # noqa
            import traceback
            traceback.print_exc()


def start_background_cleanup() -> None:
    global _thread
    ensure_dirs()
    startup_orphan_cleanup()
    if _thread is None or not _thread.is_alive():
        _stop.clear()
        _thread = threading.Thread(target=_loop, name="codexmcp-cleanup", daemon=True)
        _thread.start()
