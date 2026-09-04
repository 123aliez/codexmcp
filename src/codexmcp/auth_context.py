"""auth_context.py — 上传与 MCP 调用的身份绑定（方案 §12）。

身份来源：Nginx auth_request 通过 `auth_request_set $auth_token_id $upstream_http_x_auth_token_id`
注入的 `X-Authenticated-Token-Id` 头。该头仅 Nginx 可设（公网直连容器不可能——容器只绑
127.0.0.1），且 mcp-admin /verify 已校验 Token 有效性与路径授权，容器内不再重复校验签名。

无 token_id 即拒绝（fail-closed）：防止 Nginx 配置失误时匿名上传。
"""

from __future__ import annotations

import os

_TRUSTED_PROXIES = ["127.0.0.1", "::1", "localhost"]


def token_id_from_headers(headers) -> str:
    """从 Starlette Headers 提取身份。仅当 remote addr 是本机 Nginx 时信任。"""
    tid = headers.get("X-Authenticated-Token-Id", "").strip()
    return tid


def require_token_id(headers, client_addr: str = "") -> str:
    tid = token_id_from_headers(headers)
    if not tid:
        raise PermissionError("missing X-Authenticated-Token-Id (auth_request misconfigured?)")
    return tid
