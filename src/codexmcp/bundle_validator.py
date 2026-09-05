"""bundle_validator.py — 上传压缩包安全校验（方案 §10 顺序执行，程序化解压，绝不解压后信任）。

校验链：
  1. tar.gz 可读性（gzip + tar 格式）
  2. Manifest 存在且 schema 合法
  3. 逐项路径检查（绝对路径/..//Windows 盘符/控制字符/重复路径）
  4. 文件类型限制（仅普通文件；symlink/hardlink/dev/fifo/socket/setuid 一律拒绝）
  5. 数量/单文件/总体积/压缩比限制
  6. Manifest files[] 与 tar 实际内容双向对账（size + sha256）
  7. 敏感文件二次检测（服务端兜底，不信任客户端过滤）
全部通过后按受限模式（0o600/0o700、不保留任何特殊位）原子落盘到 ready 目录。
"""

from __future__ import annotations

import hashlib
import io
import os
import stat
import tarfile
from pathlib import Path

_MAX_TAR_MEMBERS = int(os.environ.get("CODEXMCP_MAX_FILE_COUNT", "100000"))
_MAX_SINGLE_FILE = int(os.environ.get("CODEXMCP_MAX_SINGLE_FILE_BYTES", str(20 * 1024 * 1024)))
_MAX_UNPACKED = int(os.environ.get("CODEXMCP_MAX_UNPACKED_BYTES", str(2 * 1024 * 1024 * 1024)))
_MAX_RATIO = float(os.environ.get("CODEXMCP_MAX_COMPRESSION_RATIO", "100"))

_BUNDLE_ROOT = "review-bundle"
_SENSITIVE_NAMES = {
    ".env", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "credentials.json",
    ".npmrc", ".netrc", ".pypirc", ".htpasswd", "kubeconfig",
}
_SENSITIVE_DIR_SEGMENTS = {".ssh", ".aws", ".gnupg", ".gcloud", ".azure", ".kube", ".docker"}


class ValidationError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _check_member_path(name: str, seen: set[str]) -> None:
    if name.startswith("/") or name.startswith("\\"):
        raise ValidationError("ARCHIVE_PATH_TRAVERSAL", f"absolute path: {name}")
    parts = name.split("/")
    if any(p == ".." for p in parts):
        raise ValidationError("ARCHIVE_PATH_TRAVERSAL", f"path traversal: {name}")
    # 审查修复#1：空段（a//b 去前缀后成绝对路径，Path 拼接丢弃左边 = 任意写）与 . 段一律拒绝
    if any(p == "" or p == "." for p in parts):
        raise ValidationError("ARCHIVE_PATH_TRAVERSAL", f"empty or dot path segment: {name!r}")
    # Windows 盘符（C:\ 或 C:/ 各种形态）：任意段中带 X: 形态都拒
    if any(len(p) >= 2 and p[1] == ":" for p in parts):
        raise ValidationError("ARCHIVE_PATH_TRAVERSAL", f"windows drive path: {name}")
    if "\\" in name:
        raise ValidationError("ARCHIVE_PATH_TRAVERSAL", f"backslash in path: {name!r}")
    if any(ord(c) < 32 or ord(c) == 127 for c in name):
        raise ValidationError("ARCHIVE_INVALID", f"control character in path: {name!r}")
    if name in seen:
        raise ValidationError("ARCHIVE_INVALID", f"duplicate path: {name}")
    seen.add(name)
    if not name.startswith(_BUNDLE_ROOT + "/"):
        raise ValidationError("ARCHIVE_INVALID", f"unexpected entry outside review-bundle/: {name}")


def _is_sensitive(rel_in_bundle: str) -> bool:
    """rel_in_bundle: 相对 review-bundle/ 的路径。"""
    rel = rel_in_bundle.removeprefix(_BUNDLE_ROOT + "/")
    parts = rel.split("/")
    for seg in parts[:-1]:
        if seg in _SENSITIVE_DIR_SEGMENTS:
            return True
    name = parts[-1]
    if name in _SENSITIVE_NAMES or name.startswith(".env.") or name == ".env":
        return True
    if name.startswith("id_rsa") or name.startswith("id_ed25519") or name.startswith("service-account") or name.startswith("service_account"):
        return True
    for suf in (".pem", ".key", ".p12", ".pfx"):
        if name.endswith(suf):
            return True
    if name == "secrets" or name.startswith("secrets."):
        return True
    return False


def _validate_file_hashes(tf: tarfile.TarFile, manifest: dict) -> None:
    """workspace/ 文件与 manifest.files[] 双向对账（含量/长/哈希；不加解压计数——
    首轮 member.size 已计过，重复计会误拒正常包，审查修复#13）。"""
    files = manifest.get("files")
    # 审查修复#12：manifest 结构严格校验（畸形输入此前会 500）
    if not isinstance(files, list) or not files:
        raise ValidationError("MANIFEST_INVALID", "manifest.files must be a non-empty list")
    declared: dict[str, dict] = {}
    for f in files:
        if not isinstance(f, dict):
            raise ValidationError("MANIFEST_INVALID", "manifest.files entry must be an object")
        p = f.get("path")
        sz = f.get("size")
        sh = f.get("sha256")
        if not isinstance(p, str) or not p or p.startswith("/") or ".." in p.split("/") or "\\" in p:
            raise ValidationError("MANIFEST_INVALID", f"invalid manifest path: {p!r}")
        if not isinstance(sz, int) or isinstance(sz, bool) or sz < 0 or sz > _MAX_SINGLE_FILE:
            raise ValidationError("MANIFEST_INVALID", f"invalid manifest size: {p}={sz!r}")
        if not isinstance(sh, str) or len(sh) != 64 or not all(c in "0123456789abcdef" for c in sh.lower()):
            raise ValidationError("MANIFEST_INVALID", f"invalid manifest sha256: {p}")
        if p in declared:
            raise ValidationError("MANIFEST_INVALID", f"duplicate manifest path: {p}")
        declared[p] = {"size": sz, "sha256": sh.lower()}
    if len(declared) > _MAX_TAR_MEMBERS:
        raise ValidationError("ARCHIVE_TOO_MANY_FILES", f"declared {len(declared)} > {_MAX_TAR_MEMBERS}")
    seen_ws: set[str] = set()
    for member in tf.getmembers():
        rel = member.name.removeprefix(_BUNDLE_ROOT + "/")
        if not rel.startswith("workspace/") or not member.isfile():
            continue
        ws_rel = rel.removeprefix("workspace/")
        _check_member_path(member.name, seen_ws)
        seen_ws.add(ws_rel)
        d = declared.get(ws_rel)
        if d is None:
            raise ValidationError("MANIFEST_INVALID", f"archive file not in manifest: {ws_rel}")
        extracted = tf.extractfile(member)
        data = extracted.read() if extracted else b""
        if len(data) != d["size"]:
            raise ValidationError("MANIFEST_INVALID", f"size mismatch: {ws_rel}")
        if hashlib.sha256(data).hexdigest() != d["sha256"]:
            raise ValidationError("MANIFEST_INVALID", f"sha256 mismatch: {ws_rel}")
    missing = set(declared) - seen_ws
    if missing:
        raise ValidationError("MANIFEST_INVALID", f"manifest files missing from archive: {sorted(missing)[:5]}")


def validate_and_extract(archive_path: Path, dest_workspace: Path, dest_meta: Path) -> dict:
    """校验并将 workspace/ 与 meta/ 安全解出。返回 manifest dict。
    失败抛 ValidationError；调用方负责清理半成品目录。"""
    archive_bytes = archive_path.stat().st_size
    if archive_bytes == 0:
        raise ValidationError("ARCHIVE_INVALID", "empty archive")

    seen: set[str] = set()
    limits = {"unpacked": 0}
    manifest: dict = {}

    try:
        tf = tarfile.open(archive_path, "r:gz")
    except (tarfile.TarError, OSError) as e:
        raise ValidationError("ARCHIVE_INVALID", f"not a valid tar.gz: {e}")

    with tf:
        members = tf.getmembers()
        if len(members) > _MAX_TAR_MEMBERS + 200:  # workspace + meta + 目录项余量
            raise ValidationError("ARCHIVE_TOO_MANY_FILES", f"{len(members)} members")

        for member in members:
            _check_member_path(member.name, seen)
            mtype = member.type
            if member.isdir():
                continue
            if member.issym() or member.islnk():
                raise ValidationError("ARCHIVE_SYMLINK_REJECTED", f"symlink/hardlink: {member.name} -> {member.linkname!r}")
            if member.ischr() or member.isblk() or member.isfifo() or member.isdev():
                raise ValidationError("ARCHIVE_INVALID", f"special file: {member.name}")
            if not member.isfile():
                raise ValidationError("ARCHIVE_INVALID", f"unknown member type: {member.name}")
            if member.mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
                raise ValidationError("ARCHIVE_INVALID", f"setuid/setgid/sticky bits: {member.name} mode={oct(member.mode)}")
            if member.size > _MAX_SINGLE_FILE:
                raise ValidationError("ARCHIVE_EXPANSION_LIMIT", f"single file too large: {member.name} {member.size}")
            limits["unpacked"] += member.size
            if limits["unpacked"] > _MAX_UNPACKED:
                raise ValidationError("ARCHIVE_EXPANSION_LIMIT", f"unpacked total > {_MAX_UNPACKED}")

            rel = member.name.removeprefix(_BUNDLE_ROOT + "/")
            if _is_sensitive(member.name):
                raise ValidationError("SENSITIVE_FILE_DETECTED", f"sensitive file in archive: {rel}")

            if rel == "meta/manifest.json":
                extracted = tf.extractfile(member)
                try:
                    manifest = json_loads(extracted.read() if extracted else b"")
                except Exception as e:
                    raise ValidationError("MANIFEST_INVALID", f"manifest parse error: {e}")
                if manifest.get("schema_version") != "1.0":
                    raise ValidationError("MANIFEST_INVALID", f"unsupported schema_version: {manifest.get('schema_version')}")
            elif rel.startswith("meta/tests/"):
                if member.size > 10 * 1024 * 1024:
                    raise ValidationError("ARCHIVE_EXPANSION_LIMIT", f"test log too large: {rel}")
                _safe_extract_file(tf, member, dest_meta / rel.removeprefix("meta/"))
        if not manifest:
            raise ValidationError("MANIFEST_MISSING", "meta/manifest.json not found")

        # 审查修复#13：总压缩比 = 解压总量/包体积（逐成员 ratio 可被小文件拆分绕过）
        if archive_bytes > 0 and limits["unpacked"] / archive_bytes > _MAX_RATIO:
            raise ValidationError("ARCHIVE_EXPANSION_LIMIT", f"total compression ratio {limits['unpacked']}/{archive_bytes}")

        # workspace 校验 + 解出
        _validate_file_hashes(tf, manifest)

        # meta 其余文件（git-*）
        for member in members:
            rel = member.name.removeprefix(_BUNDLE_ROOT + "/")
            if member.isfile() and rel.startswith("meta/") and not rel.startswith("meta/tests/"):
                if member.size > 20 * 1024 * 1024:
                    raise ValidationError("ARCHIVE_EXPANSION_LIMIT", f"meta file too large: {rel}")
                _safe_extract_file(tf, member, dest_meta / rel.removeprefix("meta/"))

        # workspace 文件最后统一解出（hash 已对账，直接落盘）
        for member in members:
            rel = member.name.removeprefix(_BUNDLE_ROOT + "/")
            if member.isfile() and rel.startswith("workspace/"):
                _safe_extract_file(tf, member, dest_workspace / rel.removeprefix("workspace/"))

    return manifest


def json_loads(b: bytes) -> dict:
    import json
    return json.loads(b.decode("utf-8"))


def _safe_extract_file(tf: tarfile.TarFile, member: tarfile.TarInfo, dest: Path) -> None:
    """受限写出：父目录按需创建，普通文件 0o600，不保留任何特殊位/属主。
    审查修复#11：临时名带随机后缀，不与项目合法文件（如真实存在的 foo.part）冲突。"""
    dest_parent = dest.parent
    dest_parent.mkdir(parents=True, exist_ok=True)
    extracted = tf.extractfile(member)
    if extracted is None:
        raise ValidationError("ARCHIVE_INVALID", f"cannot extract: {member.name}")
    import secrets as _secrets
    tmp = dest.with_name(f".{dest.name}.{_secrets.token_hex(6)}.part")
    while tmp.exists():  # 极小概率碰撞
        tmp = dest.with_name(f".{dest.name}.{_secrets.token_hex(6)}.part")
    try:
        with open(tmp, "xb") as f:
            while True:
                chunk = extracted.read(1024 * 1024)
                if not chunk:
                    break
                f.write(chunk)
        os.chmod(tmp, 0o600)
        os.replace(tmp, dest)
    finally:
        tmp.unlink(missing_ok=True)
