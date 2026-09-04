#!/usr/bin/env python3
"""codex-review-client — 完整项目审查快照打包与上传工具（纯 Python 标准库，Linux/Mac 通用）。

用法：
  codex-review-client inspect  --repo /path/to/project [--test-profile unit]
  codex-review-client bundle   --repo /path/to/project --output /tmp/review-bundle.tar.gz
  codex-review-client upload   --repo /path/to/project --endpoint URL --token-env VAR [--test-profile unit]

Bundle 结构（v1.0）：
  review-bundle/workspace/<完整项目文件>
  review-bundle/meta/manifest.json
  review-bundle/meta/git-status.txt | git-diff-*.patch | git-log.txt
  review-bundle/meta/tests/<profile>.{stdout.log,stderr.log,result.json}

项目可选配置 .codex-review.toml（测试 Profile 与 base_ref，见 --help 或方案文档）。
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
from pathlib import Path

CLIENT_VERSION = "0.1.0"
SCHEMA_VERSION = "1.0"
DEFAULT_MAX_ARCHIVE_MB = 300

# ── 系统级排除：无论 .gitignore 如何配置一律排除（方案 §5.1）──
DEFAULT_EXCLUDE_DIR_NAMES = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", ".tox", ".nox", ".eggs", "dist", "build",
    ".next", ".nuxt", ".turbo", ".parcel-cache", "coverage", "htmlcov",
    ".gradle", "target", ".terraform", ".serverless",
}
DEFAULT_EXCLUDE_FILE_GLOBS = [
    "*.log", "*.tmp", "*.cache", "*.swp", "*.sqlite", "*.sqlite3", "*.db",
    "*.parquet", "*.npy", "*.npz", "*.pt", "*.pth", "*.ckpt", "*.safetensors",
    "*.onnx", "*.bin", "*.iso", "*.zip", "*.tar", "*.tar.gz", "*.tgz", "*.7z",
    "*.rar", "*.gz", "*.bz2", "*.xz", "*.jar", "*.war", "*.whl", "*.egg",
    "*.pyc", "*.pyo", "*.so.*", "*.dylib", "*.dll", "*.exe", "*.class",
    "*.o", "*.a", "*.woff", "*.woff2", "*.ttf", "*.eot",
    "*.png", "*.jpg", "*.jpeg", "*.gif", "*.bmp", "*.ico", "*.webp", "*.svgz",
    "*.pdf", "*.doc", "*.docx", "*.xls", "*.xlsx", "*.ppt", "*.pptx",
    "*.mp3", "*.mp4", "*.avi", "*.mkv", "*.mov", "*.wav",
    ".DS_Store", "Thumbs.db",
]

# ── 系统级凭据保护：不可被 .codex-reviewignore 取消（方案 §5.2）──
SENSITIVE_FILE_GLOBS = [
    ".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx",
    "id_rsa*", "id_ed25519*", "id_ecdsa*", "id_dsa*",
    "kubeconfig*", "kubeconfig.*", "credentials.json",
    "service-account*.json", "service_account*.json", "secrets.*",
    ".npmrc", ".netrc", ".pypirc", ".htpasswd",
]
SENSITIVE_DIR_NAMES = {".ssh", ".aws", ".gnupg", ".gcloud", ".azure", ".kube", ".docker"}

# ── 密钥特征扫描（方案 §5.2：发现疑似凭据默认终止上传）──
SECRET_PATTERNS = [
    (re.compile(r"sk-[A-Za-z0-9_-]{20,}"), "OpenAI-style API key"),
    (re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"), "Anthropic API key"),
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"), "GitHub token"),
    (re.compile(r"glpat-[A-Za-z0-9_-]{20,}"), "GitLab token"),
    (re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,}"), "Slack token"),
    (re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"), "PEM private key"),
    (re.compile(r"(?i)aws_access_key_id\s*[:=]\s*[\"']?AKIA[0-9A-Z]{16}"), "AWS access key"),
    (re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*[\"']?[A-Za-z0-9/+=]{40}"), "AWS secret key"),
    (re.compile(r"(?i)(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp)://[^\s\"'<>]+:[^\s\"'<>]+@"), "database connection string with credentials"),
]
HIGH_ENTROPY_MIN_LEN = 40
HIGH_ENTROPY_THRESHOLD = 4.5  # bits/char（32hex≈4bit、随机base64≈6bit；手写代码串通常 <3.5）
MAX_SCAN_BYTES = 2 * 1024 * 1024  # 单文件只扫前 2MB（超大文件截断扫描，防止挂钟爆炸）

LARGE_FILE_SKIP_BYTES = 20 * 1024 * 1024  # 单文件 >20MB 跳过并记录（与中心 CODEXMCP_MAX_SINGLE_FILE_BYTES 对齐）


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    import math
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def load_reviewignore(repo: Path) -> list[str]:
    """读取项目 .codex-reviewignore（gitignore 风格，一行一 glob；# 注释）。
    注意：该文件只能增加排除，不能放行系统级凭据规则。"""
    patterns: list[str] = []
    f = repo / ".codex-reviewignore"
    if f.is_file():
        for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                patterns.append(line)
    return patterns


def parse_toml_min(text: str) -> dict:
    """极简 TOML 解析（仅 [table] + key = "value" / [list, of, strings] / 整数），
    避免客户端依赖 tomllib（macOS 系统 Python 3.9/3.10/3.11 没有 tomllib）。
    解析失败时返回 {}（向后兼容：无配置即无测试）。"""
    result: dict = {}
    current: dict = result
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^\[([A-Za-z0-9_.-]+)\]$", line)
        if m:
            parts = m.group(1).split(".")
            current = result
            for p in parts:
                current = current.setdefault(p, {})
            continue
        m = re.match(r'^([A-Za-z0-9_-]+)\s*=\s*(.+)$', line)
        if not m or not isinstance(current, dict):
            continue
        key, val = m.group(1), m.group(2).strip()
        if val.startswith("[") and val.endswith("]"):
            items = [v.strip().strip('"').strip("'") for v in val[1:-1].split(",") if v.strip()]
            current[key] = items
        elif val.startswith('"') and val.endswith('"') and len(val) >= 2:
            current[key] = val[1:-1]
        elif val.startswith("'") and val.endswith("'") and len(val) >= 2:
            current[key] = val[1:-1]
        elif re.match(r"^-?\d+$", val):
            current[key] = int(val)
        elif val in ("true", "false"):
            current[key] = val == "true"
    return result


def load_review_config(repo: Path) -> dict:
    f = repo / ".codex-review.toml"
    if f.is_file():
        try:
            return parse_toml_min(f.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            return {}
    return {}


def is_sensitive_path(rel_posix: str) -> bool:
    parts = rel_posix.split("/")
    for seg in parts[:-1]:
        if seg in SENSITIVE_DIR_NAMES:
            return True
    name = parts[-1]
    for pat in SENSITIVE_FILE_GLOBS:
        if fnmatch.fnmatch(name, pat.split("/")[-1]):
            return True
    return True if name in (".env",) else False


def scan_content_secrets(rel_posix: str, data: bytes) -> list[str]:
    """对文本文件内容做密钥特征扫描，返回命中描述列表。"""
    hits: list[str] = []
    if b"\x00" in data[:1024]:
        return hits  # 二进制
    text = data.decode("utf-8", errors="replace")
    for pattern, label in SECRET_PATTERNS:
        m = pattern.search(text)
        if m:
            hits.append(f"{label}: ...{m.group(0)[:24]}...")
    # 高熵长串（只在含 = 或 : 的行内找，减少误报）
    for line in text.splitlines():
        if "=" not in line and ":" not in line:
            continue
        for tok in re.findall(r"[A-Za-z0-9+/=_-]{40,}", line):
            core = tok.strip("=_-")
            if len(core) >= HIGH_ENTROPY_MIN_LEN:
                if shannon_entropy(core.encode()) >= HIGH_ENTROPY_THRESHOLD:
                    hits.append(f"high-entropy secret-like string ({len(core)} chars)")
                    break
    return hits


class Collector:
    """文件收集器：git ls-files + 默认排除 + reviewignore + 敏感阻断。"""

    def __init__(self, repo: Path, base_ref: str | None = None):
        self.repo = repo
        self.base_ref = base_ref
        self.extra_ignore = load_reviewignore(repo)
        self.files: list[dict] = []        # 收集的文件（rel, abs, size, sha256）
        self.skipped_large: list[str] = []  # 因超 20MB 跳过的文件
        self.sensitive_hits: list[str] = []  # 疑似敏感（默认阻断上传）
        self.symlinks: list[dict] = []      # 仅记录，不打包
        self.excluded_count = 0

    def git_files(self) -> list[str]:
        """git ls-files -co --exclude-standard：已跟踪 + 未忽略的未跟踪文件。"""
        try:
            out = subprocess.run(
                ["git", "ls-files", "-co", "--exclude-standard", "-z"],
                cwd=self.repo, capture_output=True, text=True, timeout=120,
            )
            if out.returncode != 0:
                die(f"git ls-files 失败: {out.stderr.strip()}")
            return [p for p in out.stdout.split("\0") if p]
        except FileNotFoundError:
            die("未找到 git 命令（客户端需要 git）")
        except subprocess.TimeoutExpired:
            die("git ls-files 超时")

    def excluded(self, rel_posix: str) -> bool:
        parts = rel_posix.split("/")
        # 系统级目录名排除（路径中任一段命中）
        for seg in parts:
            if seg in DEFAULT_EXCLUDE_DIR_NAMES:
                return True
        name = parts[-1]
        # 系统级文件 glob 排除
        for pat in DEFAULT_EXCLUDE_FILE_GLOBS:
            if fnmatch.fnmatch(name, pat):
                return True
        # 项目自定义忽略
        for pat in self.extra_ignore:
            p = pat.rstrip("/")
            if p and (fnmatch.fnmatch(rel_posix, p) or fnmatch.fnmatch(name, p.split("/")[-1])):
                return True
        return False

    def collect(self) -> None:
        for rel in self.git_files():
            rel_posix = rel.replace(os.sep, "/")
            # 路径安全：拒绝 git 输出里的异常路径
            if rel_posix.startswith("/") or ".." in rel_posix.split("/") or rel_posix == "":
                continue
            if self.excluded(rel_posix):
                self.excluded_count += 1
                continue
            abs_path = self.repo / rel
            try:
                st = abs_path.lstat()
            except OSError:
                continue
            mode = st.st_mode
            if stat.S_ISLNK(mode):
                # 方案 §7.4：符号链接默认拒绝进入上传包，仅记录
                try:
                    target = os.readlink(abs_path)
                except OSError:
                    target = "?"
                self.symlinks.append({"path": rel_posix, "target": target})
                continue
            if not stat.S_ISREG(mode):
                continue  # 设备/管道等不打包
            if is_sensitive_path(rel_posix):
                self.sensitive_hits.append(f"敏感文件名: {rel_posix}")
                continue
            size = st.st_size
            if size > LARGE_FILE_SKIP_BYTES:
                self.skipped_large.append(rel_posix)
                continue
            # 读取内容：hash + 密钥扫描（>2MB 截断扫描）
            try:
                data = abs_path.read_bytes()
            except OSError as e:
                print(f"  ! 跳过不可读文件 {rel_posix}: {e}", file=sys.stderr)
                self.excluded_count += 1
                continue
            sha = hashlib.sha256(data).hexdigest()
            hits = scan_content_secrets(rel_posix, data[:MAX_SCAN_BYTES])
            if hits:
                self.sensitive_hits.append(f"{rel_posix}: {'; '.join(hits)}")
                continue
            self.files.append({
                "path": rel_posix,
                "size": size,
                "sha256": sha,
                "abs": abs_path,
                "data": data,
            })

    def stats(self) -> dict:
        return {
            "file_count": len(self.files),
            "uncompressed_bytes": sum(f["size"] for f in self.files),
            "excluded_count": self.excluded_count,
            "skipped_large": self.skipped_large,
            "sensitive_hits": self.sensitive_hits,
            "symlink_count": len(self.symlinks),
        }


def git_info(repo: Path, base_ref: str | None) -> dict:
    """收集 git 元信息（方案 §7.2），任何一项失败不阻断打包。"""
    def run(args: list[str]) -> tuple[int, str]:
        try:
            r = subprocess.run(args, cwd=repo, capture_output=True, text=True, timeout=120)
            return r.returncode, (r.stdout if r.returncode == 0 else r.stdout + r.stderr)
        except Exception as e:  # noqa
            return 1, str(e)

    branch = ""
    head = ""
    dirty = False
    rc, out = run(["git", "rev-parse", "--abbrev-ref", "HEAD"])
    if rc == 0:
        branch = out.strip()
    rc, out = run(["git", "rev-parse", "HEAD"])
    if rc == 0:
        head = out.strip()
    rc, out = run(["git", "status", "--porcelain"])
    if rc == 0 and out.strip():
        dirty = True
    return {"branch": branch, "head_commit": head, "base_ref": base_ref or "", "dirty": dirty}


def git_meta_files(repo: Path, base_ref: str | None) -> dict[str, bytes]:
    """生成 meta/ 下的 git 文本文件。"""
    def run(args: list[str]) -> bytes:
        try:
            r = subprocess.run(args, cwd=repo, capture_output=True, timeout=180)
            return (r.stdout + (b"\n--stderr--\n" + r.stderr if r.stderr.strip() else b""))
        except Exception as e:
            return f"__command_failed__: {e}".encode()

    meta: dict[str, bytes] = {}
    meta["git-status.txt"] = run(["git", "status", "--porcelain=v2", "--branch"])
    meta["git-diff-working.patch"] = run(["git", "diff", "--no-ext-diff"])
    meta["git-diff-staged.patch"] = run(["git", "diff", "--cached", "--no-ext-diff"])
    if base_ref:
        meta["git-diff-base.patch"] = run(["git", "diff", f"{base_ref}...HEAD", "--no-ext-diff"])
    meta["git-log.txt"] = run(["git", "log", "-n", "30", "--oneline", "--decorate"])
    return meta


def run_test_profile(repo: Path, profile_name: str, cfg: dict) -> dict | None:
    """执行 .codex-review.toml 中固定测试 Profile（方案 §7.3）。
    命令只能来自本地配置文件，不接受任何远端下发。"""
    tests_cfg = (cfg.get("tests") or {})
    prof = tests_cfg.get(profile_name)
    if not isinstance(prof, dict) or not prof.get("command"):
        print(f"  ! 测试 Profile '{profile_name}' 未在 .codex-review.toml 定义，跳过测试", file=sys.stderr)
        return None
    cmd = prof["command"]
    if isinstance(cmd, str):
        cmd = [cmd]
    timeout = int(prof.get("timeout_seconds", 900))
    print(f"  · 运行测试 Profile [{profile_name}]: {' '.join(cmd)}（超时 {timeout}s）", file=sys.stderr)
    t0 = time.monotonic()
    try:
        r = subprocess.run(cmd, cwd=repo, capture_output=True, timeout=timeout)
        rc, out, err = r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired as e:
        rc, out, err = 124, e.stdout or b"", e.stderr or b""
        err += f"\n__timeout_after_{timeout}s__".encode()
    except FileNotFoundError as e:
        rc, out, err = 127, b"", str(e).encode()
    dur = round(time.monotonic() - t0, 1)
    return {
        "stdout": out, "stderr": err,
        "result": {
            "profile": profile_name,
            "command": cmd,
            "exit_code": rc,
            "duration_seconds": dur,
            "timeout_seconds": timeout,
        },
    }


def build_manifest(repo: Path, collector: Collector, git: dict, tests_meta: list[dict], archive_sha: str, archive_path: Path) -> bytes:
    name = repo.resolve().name
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "project_name": name,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "client_version": CLIENT_VERSION,
        "git": git,
        "snapshot": {
            "file_count": len(collector.files),
            "uncompressed_bytes": sum(f["size"] for f in collector.files),
            "archive_bytes": archive_path.stat().st_size,
            "archive_sha256": archive_sha,
        },
        "files": [{"path": f["path"], "size": f["size"], "sha256": f["sha256"]} for f in collector.files],
        "skipped_large_files": collector.skipped_large,
        "symlinks_not_packed": collector.symlinks,
        "excluded_patterns": DEFAULT_EXCLUDE_FILE_GLOBS[:0] + sorted(set(DEFAULT_EXCLUDE_DIR_NAMES)) + collector.extra_ignore,
        "tests": tests_meta,
    }
    return json.dumps(manifest, ensure_ascii=False, indent=1).encode()


def make_bundle(repo: Path, output: Path, base_ref: str | None, test_profile: str | None, cfg: dict, quiet: bool = False) -> dict:
    if not quiet:
        print(f"· 收集文件: {repo}", file=sys.stderr)
    collector = Collector(repo, base_ref)
    collector.collect()
    st = collector.stats()
    if not quiet:
        print(f"  文件 {st['file_count']} 个 / 未压缩 {st['uncompressed_bytes']/1e6:.1f}MB / 排除 {st['excluded_count']} / 符号链接 {st['symlink_count']}（仅记录）", file=sys.stderr)

    git = git_info(repo, base_ref)
    tests_meta: list[dict] = []
    tests_files: dict[str, bytes] = {}
    if test_profile:
        res = run_test_profile(repo, test_profile, cfg)
        if res:
            tests_meta.append(res["result"])
            tests_files[f"tests/{test_profile}.stdout.log"] = res["stdout"][:5*1024*1024]
            tests_files[f"tests/{test_profile}.stderr.log"] = res["stderr"][:5*1024*1024]
            tests_files[f"tests/{test_profile}.result.json"] = json.dumps(res["result"], ensure_ascii=False, indent=1).encode()

    # 两阶段打包：先写 tar.gz（manifest 占位），再算 hash 回填 manifest 重写
    tmpdir = output.parent / f".{output.name}.{uuid.uuid4().hex[:8]}.tmp"
    tmpdir.mkdir(parents=True, exist_ok=True)
    try:
        stage1 = tmpdir / "review-bundle.tar.gz"

        def add_tree(tf: tarfile.TarFile, manifest_data: bytes) -> None:
            root = "review-bundle"
            def norminfo(arcname: str, size: int) -> tarfile.TarInfo:
                ti = tarfile.TarInfo(f"{root}/{arcname}")
                ti.size = size
                ti.mtime = int(time.time())
                ti.mode = 0o644
                ti.uid = ti.gid = 0
                ti.uname = ti.gname = ""
                return ti
            # workspace/
            for f in collector.files:
                ti = norminfo(f"workspace/{f['path']}", len(f["data"]))
                tf.addfile(ti, io.BytesIO(f["data"]))
            # meta/
            for name, data in git_meta_files(repo, base_ref).items():
                ti = norminfo(f"meta/{name}", len(data))
                tf.addfile(ti, io.BytesIO(data))
            for name, data in tests_files.items():
                ti = norminfo(f"meta/{name}", len(data))
                tf.addfile(ti, io.BytesIO(data))
            ti = norminfo("meta/manifest.json", len(manifest_data))
            tf.addfile(ti, io.BytesIO(manifest_data))

        # stage1：manifest 不含 archive hash（占位）
        m1 = build_manifest(repo, collector, git, tests_meta, "PLACEHOLDER", stage1)
        with tarfile.open(stage1, "w:gz", compresslevel=6) as tf:
            add_tree(tf, m1)
        sha1 = hashlib.sha256(stage1.read_bytes()).hexdigest()

        # stage2：回填真实 hash 重打包（gzip 时间戳非确定性，hash 必然变化 → 以 stage2 为准）
        final = tmpdir / "final.tar.gz"
        m2 = build_manifest(repo, collector, git, tests_meta, sha1, stage1)
        # manifest 的 archive_sha256 指向 stage1 但最终包是 stage2 —— 自引用不可能精确，
        # 规范改为：manifest 记录 snapshot 文件集合的 merkle（文件级 hash 已在 files[] 中），
        # archive_sha256 由上传表单单独携带（中心双端校验），manifest 内省略该字段。
        m2_obj = json.loads(m2)
        m2_obj["snapshot"].pop("archive_sha256", None)
        m2_obj["snapshot"]["archive_sha256_note"] = "carried in upload form field, verified server-side"
        m2 = json.dumps(m2_obj, ensure_ascii=False, indent=1).encode()
        with tarfile.open(final, "w:gz", compresslevel=6) as tf:
            add_tree(tf, m2)
        final_sha = hashlib.sha256(final.read_bytes()).hexdigest()
        shutil.move(str(final), str(output))
        (tmpdir / "review-bundle.tar.gz").unlink(missing_ok=True)
        return {
            "output": output,
            "archive_bytes": output.stat().st_size,
            "archive_sha256": final_sha,
            "manifest": json.loads(m2),
            "stats": st,
        }
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def cmd_inspect(args) -> int:
    repo = Path(args.repo).resolve()
    cfg = load_review_config(repo)
    base_ref = args.base_ref or (cfg.get("project") or {}).get("base_ref") or "origin/main"
    collector = Collector(repo, base_ref)
    collector.collect()
    st = collector.stats()
    print(f"仓库: {repo}")
    print(f"包含文件数: {st['file_count']}")
    print(f"排除文件数: {st['excluded_count']}")
    print(f"符号链接: {st['symlink_count']}（记录不打包）")
    print(f"压缩前体积估算: {st['uncompressed_bytes']/1e6:.1f} MB")
    if st["skipped_large"]:
        print(f"超大跳过 (>20MB): {st['skipped_large']}")
    if st["sensitive_hits"]:
        print(f"疑似敏感（将被排除/阻断上传）:")
        for h in st["sensitive_hits"]:
            print(f"  - {h}")
    tests_cfg = cfg.get("tests") or {}
    if tests_cfg:
        print("测试 Profile:")
        for k, v in tests_cfg.items():
            print(f"  [{k}] {' '.join(v.get('command', [])) if isinstance(v, dict) else '?'}")
    else:
        print("测试 Profile: 无（.codex-review.toml 未定义）")
    return 0


def cmd_bundle(args) -> int:
    repo = Path(args.repo).resolve()
    cfg = load_review_config(repo)
    base_ref = args.base_ref or (cfg.get("project") or {}).get("base_ref") or "origin/main"
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    res = make_bundle(repo, output, base_ref, args.test_profile, cfg)
    print(json.dumps({
        "success": True,
        "output": str(output),
        "archive_bytes": res["archive_bytes"],
        "archive_sha256": res["archive_sha256"],
        "file_count": res["manifest"]["snapshot"]["file_count"],
    }, ensure_ascii=False, indent=2))
    return 0


def cmd_upload(args) -> int:
    repo = Path(args.repo).resolve()
    cfg = load_review_config(repo)
    base_ref = args.base_ref or (cfg.get("project") or {}).get("base_ref") or "origin/main"
    endpoint = args.endpoint or (cfg.get("upload") or {}).get("endpoint") or ""
    if not endpoint:
        die("缺少 --endpoint（或 .codex-review.toml [upload].endpoint）")
    token = os.environ.get(args.token_env, "")
    if not token:
        die(f"环境变量 {args.token_env} 未设置")

    # 敏感命中默认阻断（方案 §5.2）：列出后终止，需 --allow-sensitive 显式放行
    collector_probe = Collector(repo, base_ref)
    collector_probe.collect()
    if collector_probe.sensitive_hits and not args.allow_sensitive:
        print("疑似敏感文件/内容（默认阻断上传）：", file=sys.stderr)
        for h in collector_probe.sensitive_hits:
            print(f"  - {h}", file=sys.stderr)
        die("修正来源或使用 --allow-sensitive 显式放行后重试")

    tmpdir = Path(tempfile.gettempdir()) / "codex-review-client" / uuid.uuid4().hex
    tmpdir.mkdir(parents=True, exist_ok=True)
    bundle_path = tmpdir / "review-bundle.tar.gz"
    try:
        max_mb = int((cfg.get("upload") or {}).get("max_archive_mb", DEFAULT_MAX_ARCHIVE_MB))
        res = make_bundle(repo, bundle_path, base_ref, args.test_profile, cfg)
        if res["archive_bytes"] > max_mb * 1024 * 1024:
            die(f"压缩包 {res['archive_bytes']/1e6:.1f}MB 超过上限 {max_mb}MB（.codex-reviewignore 排除更多文件）")
        sha = res["archive_sha256"]

        # urllib multipart 上传（标准库，无 requests 依赖）
        boundary = f"----codexreview{uuid.uuid4().hex}"
        body = io.BytesIO()
        def part_field(name: str, value: str):
            body.write(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n".encode())
        body.write(f"--{boundary}\r\nContent-Disposition: form-data; name=\"sha256\"\r\n\r\n{sha}\r\n".encode())
        body.write(f"--{boundary}\r\nContent-Disposition: form-data; name=\"client_meta\"\r\n\r\n{json.dumps({'client_version': CLIENT_VERSION, 'platform': sys.platform})}\r\n".encode())
        body.write(f"--{boundary}\r\nContent-Disposition: form-data; name=\"bundle\"; filename=\"review-bundle.tar.gz\"\r\nContent-Type: application/gzip\r\n\r\n".encode())
        with open(bundle_path, "rb") as f:
            shutil.copyfileobj(f, body)
        body.write(f"\r\n--{boundary}--\r\n".encode())
        payload = body.getvalue()

        print(f"· 上传 {res['archive_bytes']/1e6:.1f}MB → {endpoint}", file=sys.stderr)
        import urllib.request
        import urllib.error
        req = urllib.request.Request(
            endpoint, data=payload, method="POST",
            headers={
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Authorization": f"Bearer {token}",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=1800) as resp:
                out = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            try:
                out = json.loads(e.read().decode())
            except Exception:
                out = {"success": False, "error_code": "HTTP_ERROR", "message": f"HTTP {e.code}"}
        if not out.get("success"):
            print(json.dumps(out, ensure_ascii=False, indent=2))
            return 1
        out["_local"] = {"bundle_sha256": sha, "file_count": res["manifest"]["snapshot"]["file_count"]}
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return 0
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def die(msg: str, code: int = 1) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def main() -> None:
    ap = argparse.ArgumentParser(prog="codex-review-client", description="完整项目审查快照打包与上传")
    sub = ap.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--repo", default=".", help="项目路径（默认当前目录）")
    common.add_argument("--base-ref", default="", help="对比基线（默认 origin/main，可用 .codex-review.toml 覆盖）")
    common.add_argument("--test-profile", default="", help="打包前执行的测试 Profile 名（定义在 .codex-review.toml [tests.*]）")

    p_inspect = sub.add_parser("inspect", parents=[common], help="检查将被上传的文件")
    p_inspect.set_defaults(func=cmd_inspect)

    p_bundle = sub.add_parser("bundle", parents=[common], help="只打包不上传")
    p_bundle.add_argument("--output", required=True, help="输出 tar.gz 路径")
    p_bundle.set_defaults(func=cmd_bundle)

    p_upload = sub.add_parser("upload", parents=[common], help="打包并上传")
    p_upload.add_argument("--endpoint", default="", help="上传地址 https://.../codex-remote/v1/uploads")
    p_upload.add_argument("--token-env", default="CODEXMCP_TOKEN", help="Bearer Token 的环境变量名")
    p_upload.add_argument("--allow-sensitive", action="store_true", help="密钥扫描命中时仍继续（默认阻断）")
    p_upload.set_defaults(func=cmd_upload)

    args = ap.parse_args()
    repo = Path(args.repo).resolve()
    if not repo.is_dir():
        die(f"项目目录不存在: {repo}")
    if not (repo / ".git").exists():
        die(f"不是 Git 仓库（无 .git）: {repo}")
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
