"""upload_api.py — POST /v1/uploads 上传接口（方案 §9）。

挂载在 FastMCP custom_route 上（与 /mcp 同一 Starlette 应用、同一端口），
Nginx /codex-remote/ 尾斜杠剥前缀后，容器内收到的是 POST /v1/uploads。

multipart 流式接收：starlette MultiPartParser 的 UploadFile 底层是
SpooledTemporaryFile（>1MB 落盘），300MB 上传不会占满内存。
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

from starlette.requests import Request
from starlette.responses import JSONResponse

from . import auth_context, bundle_validator, storage, workspace_manager

MAX_UPLOAD_BYTES = int(os.environ.get("CODEXMCP_MAX_UPLOAD_BYTES", str(300 * 1024 * 1024)))
UPLOAD_TTL = float(os.environ.get("CODEXMCP_UPLOAD_TTL_SECONDS", "1800"))


def _err(code: str, message: str, status: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "error_code": code, "message": message}, status_code=status)


async def uploads_endpoint(request: Request) -> JSONResponse:
    # 1. Token 鉴权（Nginx 已验，这里只取身份；fail-closed）
    try:
        token_id = auth_context.require_token_id(request.headers)
    except PermissionError as e:
        return _err("AUTH_FAILED", str(e), 401)

    # 2. 大小预检（Nginx client_max_body_size 之外的应用层兜底）
    cl = request.headers.get("Content-Length")
    if cl and cl.isdigit() and int(cl) > MAX_UPLOAD_BYTES * 1.1:
        return _err("UPLOAD_TOO_LARGE", f"content-length {cl} > {MAX_UPLOAD_BYTES}", 413)

    # 3. multipart 解析（流式落盘）
    try:
        form = await request.form(max_files=2, max_fields=10)
    except Exception as e:
        return _err("ARCHIVE_INVALID", f"multipart parse failed: {e}")

    bundle = form.get("bundle")
    sha_field = (form.get("sha256") or "").strip().lower()
    client_meta_raw = form.get("client_meta") or "{}"
    if bundle is None or not hasattr(bundle, "file"):
        return _err("ARCHIVE_INVALID", "missing form field 'bundle'")
    if not sha_field or len(sha_field) != 64 or not all(c in "0123456789abcdef" for c in sha_field):
        return _err("ARCHIVE_INVALID", "missing or malformed form field 'sha256'")

    # 4. 流式写 staging + SHA-256 单遍计算（staging 文件名先随机占位，
    #    校验全过后才用 DB 分配的 upload_id 登记，避免 ID 错位）
    workspace_manager.ensure_dirs()
    staging_id = f"upl_{_rand_hex()}"
    staging = workspace_manager.staging_path(staging_id)
    hasher = hashlib.sha256()
    total = 0
    try:
        with open(staging, "wb") as out:
            file = bundle.file
            file.seek(0)
            while True:
                chunk = file.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_UPLOAD_BYTES:
                    raise bundle_validator.ValidationError("UPLOAD_TOO_LARGE", f"stream exceeded {MAX_UPLOAD_BYTES}")
                hasher.update(chunk)
                out.write(chunk)
        if total == 0:
            raise bundle_validator.ValidationError("ARCHIVE_INVALID", "empty bundle")
    except bundle_validator.ValidationError as e:
        staging.unlink(missing_ok=True)
        return _err(e.code, e.message, 413 if "TOO_LARGE" in e.code else 400)
    except OSError as e:
        staging.unlink(missing_ok=True)
        return _err("INTERNAL_ERROR", f"write failed: {e}", 500)
    finally:
        try:
            await bundle.close()
        except Exception:
            pass

    # 5. 压缩包 SHA-256 校验
    actual_sha = hasher.hexdigest()
    if actual_sha != sha_field:
        staging.unlink(missing_ok=True)
        return _err("ARCHIVE_SHA256_MISMATCH", f"expected {sha_field}, got {actual_sha}")

    # 6. 校验通过再登记 DB（校验失败不入库——失败请求无需状态记录，避免 VALIDATING 残留）
    try:
        client_meta = json.loads(client_meta_raw) if isinstance(client_meta_raw, str) else {}
    except json.JSONDecodeError:
        client_meta = {}
    upload_id = storage.new_upload(token_id, str(ready_path := workspace_manager.ready_path(f"_tmp_{_rand_hex()}")), actual_sha, UPLOAD_TTL)
    # ↑ 先拿 DB 分配的 upload_id；archive_path 稍后用最终 ready 路径回写
    _ = ready_path

    # 7. 安全校验（tar 逐项检查 + manifest 对账 + 敏感二次检测）——校验只读包，
    #    解出的临时校验目录用完即删（workspace 在 review 启动时才正式解出）
    tmp_ws = staging.parent / f".validate-{staging_id}"
    tmp_meta = tmp_ws / "meta"
    try:
        manifest = bundle_validator.validate_and_extract(staging, tmp_ws / "workspace", tmp_meta)
    except bundle_validator.ValidationError as e:
        staging.unlink(missing_ok=True)
        return _err(e.code, e.message)
    finally:
        import shutil
        shutil.rmtree(tmp_ws, ignore_errors=True)

    # 8. 换名原子移动到 ready（DB 分配的 upload_id）+ 登记 READY（无 VALIDATING 残留）
    ready = workspace_manager.ready_path(upload_id)
    os.replace(staging, ready)
    storage.set_upload_state(
        upload_id, "READY",
        archive_path=str(ready),
        project_name=str(manifest.get("project_name", ""))[:200],
        file_count=int(manifest.get("snapshot", {}).get("file_count", 0)),
        compressed_bytes=Path(ready).stat().st_size,
        uncompressed_bytes=int(manifest.get("snapshot", {}).get("uncompressed_bytes", 0)),
        client_meta=json.dumps(client_meta)[:1000],
    )

    return JSONResponse({
        "success": True,
        "upload_id": upload_id,
        "state": "READY",
        "snapshot_sha256": actual_sha,
        "file_count": int(manifest.get("snapshot", {}).get("file_count", 0)),
        "compressed_bytes": Path(ready).stat().st_size,
        "uncompressed_bytes": int(manifest.get("snapshot", {}).get("uncompressed_bytes", 0)),
        "expires_at": _iso(time.time() + UPLOAD_TTL),
    })


def _rand_hex() -> str:
    import secrets
    return secrets.token_hex(12)


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ts))
