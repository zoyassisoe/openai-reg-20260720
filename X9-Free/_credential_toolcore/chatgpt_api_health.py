"""
模块功能说明：
    - ChatGPT Team/Workspace 账号“API 检活”工具集（不依赖打开 /admin/members 页面）。
    - 设计目标：
        1) 优先使用 OAuth refresh_token 刷新得到 access_token，再调用 ChatGPT backend-api 获取成员数/邀请数。
        2) 若无 OAuth，则尝试复用浏览器 session（https://chatgpt.com/api/auth/session）获取 accessToken 并解析 account_id。
        3) 全程避免把 access_token/refresh_token 写入日志；refresh_token 可选写入 DPAPI 密文字段用于本机复用。

安全提示（重要）：
    - access_token / refresh_token 属于敏感信息：严禁写入日志。
    - refresh_token 若需要落盘，请使用 Windows DPAPI 加密（windows_dpapi.encrypt_text）。
"""

from __future__ import annotations

import asyncio
import base64
from collections import Counter
import dataclasses
import datetime
import hashlib
import hmac
import http.client
import inspect
import json
import os
import re
import socket
import ssl
import struct
import time
import urllib.parse
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Callable, Optional, TYPE_CHECKING

from codex_auth_mirror import write_codex_auth_text
from windows_dpapi import decrypt_text, encrypt_text
try:
    from curl_cffi import requests as curl_cffi_requests
except Exception:
    curl_cffi_requests = None  # type: ignore[assignment]

try:
    from http_stage_features import get_http_stage_browser_headers, get_http_stage_device_id
except Exception:
    def get_http_stage_browser_headers(*, impersonate: str = "") -> dict[str, str]:
        return {}

    def get_http_stage_device_id() -> str:
        return ""

if TYPE_CHECKING:  # pragma: no cover
    from playwright.async_api import APIRequestContext


TOKEN_URL = "https://auth.openai.com/oauth/token"
SESSION_URL = "https://chatgpt.com/api/auth/session"
MFA_ENROLL_URL = "https://chatgpt.com/backend-api/accounts/mfa/enroll"
MFA_ACTIVATE_URL = "https://chatgpt.com/backend-api/accounts/mfa/user/activate_enrollment"
MFA_INFO_URL = "https://chatgpt.com/backend-api/accounts/mfa_info"

# 说明：与现有 Node/Python 逻辑对齐的 client_id（若后续变更，可通过环境变量覆盖）。
DEFAULT_OPENAI_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"

# 说明：ChatGPT backend-api 调用常见 header；client-version 可随时间变化，因此允许通过 env 覆盖。
DEFAULT_OAI_CLIENT_VERSION = "prod-eddc2f6ff65fee2d0d6439e379eab94fe3047f72"

_CHATGPT_CURL_IMPERSONATE_CANDIDATES: tuple[str, ...] = ("chrome142", "chrome136", "chrome133a", "chrome131")
_CHATGPT_HTTP_BROWSER_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/142.0.0.0 Safari/537.36"
)
_CHATGPT_HTTP_BROWSER_SEC_CH_UA = '"Chromium";v="142", "Not-A.Brand";v="24", "Google Chrome";v="142"'
_CHATGPT_HTTP_BROWSER_SEC_CH_UA_MOBILE = "?0"
_CHATGPT_HTTP_BROWSER_SEC_CH_UA_PLATFORM = '"Windows"'
_CHATGPT_HTTP_BROWSER_ACCEPT_LANGUAGE = "zh-CN,zh;q=0.9"
_CHATGPT_HTTP_BROWSER_ACCEPT_ENCODING = "gzip, deflate, br, zstd"


def _mask_totp_secret(secret: str) -> str:
    raw = re.sub(r"\s+", "", str(secret or "").strip()).upper()
    if not raw:
        return ""
    if len(raw) <= 8:
        return raw[0] + ("*" * max(0, len(raw) - 2)) + raw[-1:]
    return f"{raw[:4]}{'*' * max(4, len(raw) - 8)}{raw[-4:]}"


def _read_access_token_from_storage_state(*, storage_state_path: str) -> str:
    p = Path(str(storage_state_path or "").strip()).expanduser()
    if not str(p) or (not p.exists()):
        return ""
    try:
        payload = json.loads(p.read_text(encoding="utf-8") or "{}")
    except Exception:
        return ""
    if not isinstance(payload, dict):
        return ""
    return str(payload.get("session_access_token") or payload.get("accessToken") or "").strip()


@dataclasses.dataclass(frozen=True, slots=True)
class CodexOAuthTokens:
    """
    功能目的：
        描述 Codex OAuth 文件中与“检活”相关的最小字段集合。
    """

    account_id: str
    refresh_token: str
    raw_payload: dict[str, Any]


@dataclasses.dataclass(frozen=True, slots=True)
class ChatGptApiCounts:
    """
    功能目的：
        backend-api 检活后可得到的统计数据。
    """

    user_total: int
    invite_total: Optional[int] = None


@dataclasses.dataclass(frozen=True, slots=True)
class ChatGptApiMembers:
    """
    功能目的：
        backend-api 成员列表读取后的结构化结果。
    """

    account_id: str
    total: int
    members: list[dict[str, str]]
    user_total: int = 0
    invite_total: int = 0


@dataclasses.dataclass(frozen=True, slots=True)
class ChatGptApiInviteResult:
    """
    功能目的：
        记录 Team 邀请接口调用结果（API 模式）。
    """

    account_id: str
    requested_count: int
    endpoint: str
    raw: dict[str, Any]


@dataclasses.dataclass(frozen=True, slots=True)
class ChatGptCodexQuotaSnapshot:
    """
    功能目的：
        描述一次 Codex 配额读取结果，保留“是否耗尽”和原始窗口数据。
    """

    account_id: str
    plan_type: str
    windows: list[dict[str, Any]]
    exhausted: bool
    raw: dict[str, Any]


@dataclasses.dataclass(frozen=True, slots=True)
class ChatGptApiMutationResult:
    """
    ?????
        ?? Team ????/???????????????
    """

    account_id: str
    target_id: str
    email: str
    endpoint: str
    raw: dict[str, Any]


class ChatGptApiHealthError(RuntimeError):
    """
    功能目的：
        统一封装 API 检活异常，保留 status/code/stage 便于调用方做降级策略。
    """

    def __init__(self, message: str, *, status: int = 0, code: str = "", stage: str = "") -> None:
        super().__init__(message)
        self.status = int(status or 0)
        self.code = str(code or "").strip()
        self.stage = str(stage or "").strip()


def _wrap_api_health_error(error: Exception, *, stage: str, prefix: str, code: str = "") -> ChatGptApiHealthError:
    """
    功能目的：
        为底层异常补充上层阶段信息，便于 UI/日志快速定位是在 cached token、
        refresh_token 还是 session 兜底哪一层失败。
    """

    base_message = str(error or "").strip() or type(error).__name__
    status = 0
    resolved_code = str(code or "").strip()
    if isinstance(error, ChatGptApiHealthError):
        status = int(getattr(error, "status", 0) or 0)
        resolved_code = str(getattr(error, "code", "") or "").strip() or resolved_code
    message = f"{str(prefix or '').strip()}：{base_message}" if str(prefix or "").strip() else base_message
    return ChatGptApiHealthError(message, status=status, code=resolved_code, stage=stage)


def _safe_log(log: Any, message: str, *, level: str = "info") -> None:
    """
    功能目的：
        安全输出步骤日志（不抛异常，避免影响主流程）。
    """

    if log is None:
        return
    text = str(message or "").strip()
    if not text:
        return
    try:
        emit = getattr(log, "emit", None)
        if callable(emit):
            maybe = emit(level, text)
            if inspect.isawaitable(maybe):
                asyncio.create_task(maybe)
            return
    except Exception:
        pass
    try:
        if callable(log):
            log(text)
            return
    except Exception:
        pass
    try:
        if str(level or "").strip().lower() == "warn":
            fn = getattr(log, "warn", None) or getattr(log, "warning", None)
        elif str(level or "").strip().lower() == "error":
            fn = getattr(log, "error", None)
        elif str(level or "").strip().lower() == "success":
            fn = getattr(log, "success", None) or getattr(log, "info", None)
        else:
            fn = getattr(log, "info", None)
        if callable(fn):
            fn(text)
    except Exception:
        return


def _strip_playwright_call_log(text: str) -> str:
    """
    功能目的：
        Playwright 的异常文本通常包含 “Call log:” 段落，其中可能出现 cookie/authorization 等敏感 header。
        该函数用于移除 call log 并压缩空白，避免敏感信息进入日志。
    """

    raw = str(text or "").strip()
    if not raw:
        return ""
    if "Call log:" in raw:
        raw = raw.split("Call log:", 1)[0].rstrip()
    raw = re.sub(r"\s+", " ", raw).strip()
    # 防御性兜底：若异常文本仍包含 token/cookie 片段，尽量做一次弱脱敏
    raw = re.sub(r"(?i)\b(cookie|authorization)\b\s*[:=]\s*[^ ]+", r"\1=<redacted>", raw)
    if len(raw) > 320:
        raw = raw[:320] + "…"
    return raw


def _infer_network_code_from_message(message: str) -> str:
    low = str(message or "").lower()
    # Windows socket error codes
    if "10060" in low:
        return "timeout"
    if "10054" in low:
        return "conn_reset"
    if "10061" in low:
        return "conn_refused"
    if "10065" in low:
        return "unreachable"

    if ("timed out" in low) or ("timeout" in low):
        return "timeout"
    if ("etimedout" in low) or ("err_timed_out" in low):
        return "timeout"
    if ("enotfound" in low) or ("getaddrinfo" in low):
        return "dns"
    if "econnreset" in low:
        return "conn_reset"
    if "econnrefused" in low:
        return "conn_refused"
    if ("ehostunreach" in low) or ("enetunreach" in low):
        return "unreachable"
    return "network"


def _read_timeout_ms(env_key: str, fallback_ms: int, *, min_ms: int = 1_000, max_ms: int = 300_000) -> int:
    """
    功能目的：
        读取环境变量超时配置（毫秒），并做上下限保护。

    说明：
        - 若 env 未设置或非法，则回退到 fallback_ms（调用方传入的默认值）。
    """

    try:
        raw = str(os.getenv(env_key, "") or "").strip()
        if not raw:
            return int(max(min_ms, min(max_ms, int(fallback_ms))))
        n = int(raw)
        return int(max(min_ms, min(max_ms, n)))
    except Exception:
        try:
            return int(max(min_ms, min(max_ms, int(fallback_ms))))
        except Exception:
            return int(min_ms)


class _IPv4HTTPSConnection(http.client.HTTPSConnection):
    """
    功能目的：
        强制只使用 IPv4 解析结果建立 HTTPS 连接，规避部分环境下 IPv6 不可达导致的长时间超时。

    说明：
        - 只用于“直连目标站点”的场景，不处理 HTTP 代理隧道（CONNECT）。
    """

    def connect(self) -> None:  # noqa: D401
        host = str(self.host or "").strip()
        port = int(self.port or 443)
        if not host:
            raise OSError("host 为空，无法建立连接")

        # 仅解析 IPv4（A 记录）
        infos = socket.getaddrinfo(host, port, family=socket.AF_INET, type=socket.SOCK_STREAM)
        last_err: Exception | None = None
        for family, socktype, proto, _canonname, sockaddr in infos:
            sock: socket.socket | None = None
            try:
                sock = socket.socket(family, socktype, proto)
                if self.timeout is not None:
                    sock.settimeout(float(self.timeout))
                sock.connect(sockaddr)
                self.sock = self._context.wrap_socket(sock, server_hostname=host)  # type: ignore[assignment]
                return
            except Exception as error:
                last_err = error
                if sock is not None:
                    try:
                        sock.close()
                    except Exception:
                        pass
                continue

        if last_err is not None:
            raise last_err
        raise OSError("无法建立 IPv4 连接")


def _sync_https_request_ipv4(
    *,
    url: str,
    method: str,
    headers: dict[str, str],
    data: bytes | None,
    timeout_sec: float,
) -> tuple[int, dict[str, str], bytes]:
    parsed = urllib.parse.urlparse(str(url or "").strip())
    if parsed.scheme.lower() != "https":
        raise ValueError("仅支持 https URL")
    host = str(parsed.hostname or "").strip()
    if not host:
        raise ValueError("URL 缺少 host")
    port = int(parsed.port or 443)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    # 说明：使用系统默认 CA，确保 TLS 校验正常进行
    ctx = ssl.create_default_context()
    conn = _IPv4HTTPSConnection(host, port=port, timeout=float(max(1.0, timeout_sec)), context=ctx)
    try:
        conn.request(str(method or "GET").upper(), path, body=data, headers=headers)
        resp = conn.getresponse()
        body = resp.read() or b""
        out_headers = {str(k).lower(): str(v) for k, v in (resp.getheaders() or [])}
        return int(resp.status or 0), out_headers, body
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _try_compact_proxy_to_url(value: str) -> str:
    """
    将 `host:port:user:pass` 转为标准代理 URL。

    说明：
    - 常见于动态 IP 供应商导出的四段式文本。
    - 若不是该格式，返回空字符串，交由上层按原逻辑处理。
    """

    raw = str(value or "").strip()
    if (not raw) or ("://" in raw):
        return ""

    parts = raw.split(":")
    if len(parts) < 4:
        return ""

    host = str(parts[0] or "").strip()
    port_text = str(parts[1] or "").strip()
    username = str(parts[2] or "").strip()
    password = ":".join(parts[3:]).strip()
    if (not host) or (not port_text) or (not username) or (not password):
        return ""
    if not port_text.isdigit():
        return ""
    port = int(port_text)
    if port < 1 or port > 65535:
        return ""

    user_enc = urllib.parse.quote(username, safe="")
    pass_enc = urllib.parse.quote(password, safe="")
    return f"http://{user_enc}:{pass_enc}@{host}:{port}"


def _normalize_proxy_url(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    low = raw.lower()
    if low in {"direct", "none", "off", "0", "false", "no"}:
        return ""

    compact_url = _try_compact_proxy_to_url(raw)
    if compact_url:
        return compact_url

    if "://" not in raw:
        # 兼容：用户只填 host:port 的情况
        return "http://" + raw
    try:
        parsed = urllib.parse.urlsplit(raw)
    except Exception:
        return raw
    if str(parsed.scheme or "").lower() == "socks5":
        return urllib.parse.urlunsplit(
            ("socks5h", parsed.netloc, parsed.path, parsed.query, parsed.fragment)
        )
    return raw


def _resolve_windows_dev_local_http_proxy_url() -> str:
    """
    功能目的：
        复用浏览器侧的 Windows 开发环境默认代理推导规则，避免纯 API 链路与浏览器链路行为不一致。
    """

    try:
        from browser_manager_local import resolve_windows_dev_local_http_proxy_url as resolver
    except Exception:
        return ""

    try:
        return _normalize_proxy_url(str(resolver() or ""))
    except Exception:
        return ""


@dataclasses.dataclass(frozen=True, slots=True)
class ProxyDecision:
    """
    功能目的：
        表示一次“API 请求应如何使用代理”的决策结果。

    字段说明：
        - proxy_url：规范化后的代理地址；为空表示不使用代理（直连）。
        - source：env/system/""（无）。用于在失败时生成更可诊断的提示。
        - explicit：是否显式设置了 AIO_API_PROXY（即使为空也算显式覆盖）。
    """

    proxy_url: str
    source: str
    explicit: bool


def _mask_proxy_for_log(proxy_url: str) -> str:
    """
    功能目的：
        避免把代理账号密码输出到日志（例如 http://user:pass@host:port）。
    """

    raw = str(proxy_url or "").strip()
    if not raw:
        return ""
    try:
        parsed = urllib.parse.urlparse(raw)
        scheme = str(parsed.scheme or "").strip() or "http"
        host = str(parsed.hostname or "").strip()
        port = int(parsed.port) if parsed.port else None
        if (parsed.username is not None) or (parsed.password is not None):
            if host and port:
                return f"{scheme}://<redacted>@{host}:{port}"
            if host:
                return f"{scheme}://<redacted>@{host}"
            return f"{scheme}://<redacted>"
        # 无 userinfo：原样返回
        return raw
    except Exception:
        return raw[:200]


def _resolve_proxy_decision(url: str) -> ProxyDecision:
    # 1) 显式覆盖：AIO_API_PROXY（即使为空也算覆盖系统代理）
    if "AIO_API_PROXY" in os.environ:
        return ProxyDecision(
            proxy_url=_normalize_proxy_url(str(os.getenv("AIO_API_PROXY") or "")),
            source="env",
            explicit=True,
        )

    # 2) 系统/环境代理：urllib.request.getproxies()
    parsed = urllib.parse.urlparse(str(url or "").strip())
    scheme = str(parsed.scheme or "").strip().lower()
    try:
        proxies = urllib.request.getproxies() or {}
    except Exception:
        proxies = {}

    proxy = ""
    if scheme == "https":
        proxy = str(proxies.get("https") or proxies.get("http") or "")
    elif scheme == "http":
        proxy = str(proxies.get("http") or "")
    normalized = _normalize_proxy_url(proxy)
    if normalized:
        return ProxyDecision(proxy_url=normalized, source="system", explicit=False)

    default_proxy = _resolve_windows_dev_local_http_proxy_url()
    if default_proxy:
        return ProxyDecision(proxy_url=default_proxy, source="windows_dev_default", explicit=False)
    return ProxyDecision(proxy_url="", source="", explicit=False)


def resolve_proxy_for_url(url: str) -> str:
    """
    功能目的：
        为指定 URL 选择代理（若存在）。

    优先级：
        1) 显式覆盖：AIO_API_PROXY（可设为 direct/none/off 以禁用）
        2) 系统/环境代理：urllib.request.getproxies()
    """

    return _resolve_proxy_decision(url).proxy_url


def _available_curl_cffi_impersonates() -> set[str]:
    browser_type = getattr(curl_cffi_requests, "BrowserType", None)
    if browser_type is None:
        return set()

    available: set[str] = set()
    for name in dir(browser_type):
        if name.startswith("_"):
            continue
        value = getattr(browser_type, name, None)
        text = str(value or "").strip()
        if text:
            available.add(text)
    return available


def _resolve_chatgpt_curl_impersonate() -> str:
    if curl_cffi_requests is None:
        return ""

    preferred = str(os.getenv("AIO_CHATGPT_API_CURL_IMPERSONATE") or "").strip()
    if preferred:
        return preferred

    for candidate in _CHATGPT_CURL_IMPERSONATE_CANDIDATES:
        value = str(candidate or "").strip()
        if not value:
            continue
        return value
    return ""


def _resolve_chatgpt_http_browser_identity_for_impersonate(impersonate: str = "") -> dict[str, str]:
    normalized = str(impersonate or "").strip().lower()
    matched = re.search(r"chrome(\d+)", normalized)
    if not matched:
        return {
            "user-agent": _CHATGPT_HTTP_BROWSER_USER_AGENT,
            "sec-ch-ua": _CHATGPT_HTTP_BROWSER_SEC_CH_UA,
            "sec-ch-ua-mobile": _CHATGPT_HTTP_BROWSER_SEC_CH_UA_MOBILE,
            "sec-ch-ua-platform": _CHATGPT_HTTP_BROWSER_SEC_CH_UA_PLATFORM,
        }

    major = str(matched.group(1) or "").strip()
    if not major:
        return {
            "user-agent": _CHATGPT_HTTP_BROWSER_USER_AGENT,
            "sec-ch-ua": _CHATGPT_HTTP_BROWSER_SEC_CH_UA,
            "sec-ch-ua-mobile": _CHATGPT_HTTP_BROWSER_SEC_CH_UA_MOBILE,
            "sec-ch-ua-platform": _CHATGPT_HTTP_BROWSER_SEC_CH_UA_PLATFORM,
        }
    return {
        "user-agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{major}.0.0.0 Safari/537.36"
        ),
        "sec-ch-ua": f'"Chromium";v="{major}", "Not-A.Brand";v="24", "Google Chrome";v="{major}"',
        "sec-ch-ua-mobile": _CHATGPT_HTTP_BROWSER_SEC_CH_UA_MOBILE,
        "sec-ch-ua-platform": _CHATGPT_HTTP_BROWSER_SEC_CH_UA_PLATFORM,
    }


def _build_chatgpt_http_browser_identity_headers(
    *,
    include_accept_language: bool = False,
    include_accept_encoding: bool = False,
    impersonate: str = "",
) -> dict[str, str]:
    headers = get_http_stage_browser_headers(impersonate=impersonate) or _resolve_chatgpt_http_browser_identity_for_impersonate(impersonate)
    if include_accept_language:
        headers["accept-language"] = _CHATGPT_HTTP_BROWSER_ACCEPT_LANGUAGE
    if include_accept_encoding:
        headers["accept-encoding"] = _CHATGPT_HTTP_BROWSER_ACCEPT_ENCODING
    return headers


def _load_storage_state_payload(*, storage_state_path: str) -> dict[str, Any]:
    p = Path(str(storage_state_path or "").strip()).expanduser()
    if not str(p) or (not p.exists()):
        return {}

    try:
        payload = json.loads(p.read_text(encoding="utf-8") or "{}")
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _extract_storage_state_cookies(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    cookies = payload.get("cookies")
    if not isinstance(cookies, list):
        return []
    return [dict(item) for item in cookies if isinstance(item, dict)]


def _create_curl_cffi_session_from_storage_state(
    *,
    storage_state_path: str,
    proxy_url: str = "",
    impersonate: str = "",
) -> Any:
    if curl_cffi_requests is None:
        raise RuntimeError("curl_cffi_unavailable")

    storage_state = _load_storage_state_payload(storage_state_path=storage_state_path) if str(storage_state_path or "").strip() else {}
    if str(storage_state_path or "").strip() and (not storage_state):
        raise ChatGptApiHealthError("storage_state 不存在或格式无效，无法执行纯 API 检测", status=400, code="invalid_storage_state")

    session_kwargs: dict[str, Any] = {"default_headers": False}
    impersonate_value = str(impersonate or "").strip()
    if impersonate_value:
        session_kwargs["impersonate"] = impersonate_value

    proxy_value = _normalize_proxy_url(proxy_url)
    if proxy_value:
        session_kwargs["proxy"] = proxy_value

    session = curl_cffi_requests.Session(**session_kwargs)
    cookies = storage_state.get("cookies")
    if not isinstance(cookies, list):
        return session

    now_ts = time.time()
    for cookie in cookies:
        if not isinstance(cookie, dict):
            continue
        name = str(cookie.get("name") or "").strip()
        if not name:
            continue

        expires = cookie.get("expires")
        try:
            expires_num = float(expires)
        except Exception:
            expires_num = 0.0
        if expires_num > 0 and now_ts >= expires_num:
            continue

        set_kwargs: dict[str, Any] = {}
        domain = str(cookie.get("domain") or "").strip()
        if domain:
            set_kwargs["domain"] = domain
        path = str(cookie.get("path") or "/").strip() or "/"
        if path:
            set_kwargs["path"] = path
        secure = cookie.get("secure")
        if isinstance(secure, bool):
            set_kwargs["secure"] = secure
        if expires_num > 0:
            set_kwargs["expires"] = int(expires_num)

        try:
            session.cookies.set(name, str(cookie.get("value") or ""), **set_kwargs)
        except Exception:
            continue
    return session


def _sync_https_request_via_proxy(
    *,
    url: str,
    method: str,
    headers: dict[str, str],
    data: bytes | None,
    timeout_sec: float,
    proxy_url: str,
) -> tuple[int, dict[str, str], bytes]:
    parsed = urllib.parse.urlparse(str(url or "").strip())
    if parsed.scheme.lower() != "https":
        raise ValueError("仅支持 https URL")
    proxy = _normalize_proxy_url(proxy_url)
    if not proxy:
        raise ValueError("proxy_url 为空")

    proxy_parsed = urllib.parse.urlparse(proxy)
    proxy_scheme = str(proxy_parsed.scheme or "").strip().lower()
    if proxy_scheme.startswith("socks"):
        raise OSError("暂不支持 socks 代理：请使用 http/https 代理（例如 Clash 的 HTTP 端口）")

    ctx = ssl.create_default_context()
    handler_list: list[urllib.request.BaseHandler] = [
        urllib.request.ProxyHandler({"http": proxy, "https": proxy}),
        urllib.request.HTTPSHandler(context=ctx),
    ]

    # 代理认证（尽力支持 basic auth）
    try:
        username = urllib.parse.unquote(str(proxy_parsed.username or ""))
        password = urllib.parse.unquote(str(proxy_parsed.password or ""))
        if username or password:
            host = str(proxy_parsed.hostname or "").strip()
            port = proxy_parsed.port
            base = proxy
            if host and port:
                base = f"{proxy_scheme}://{host}:{int(port)}"
            mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
            mgr.add_password(None, base, username, password)
            handler_list.append(urllib.request.ProxyBasicAuthHandler(mgr))
    except Exception:
        pass

    opener = urllib.request.build_opener(*handler_list)
    req = urllib.request.Request(url=str(url), data=data, method=str(method or "GET").upper())
    for k, v in (headers or {}).items():
        key = str(k or "").strip()
        if not key:
            continue
        req.add_header(key, str(v))

    try:
        with opener.open(req, timeout=float(max(1.0, timeout_sec))) as resp:
            status = int(resp.getcode() or 0)
            resp_headers = {str(k).lower(): str(v) for k, v in (resp.headers.items() or [])}
            body = resp.read() or b""
            return status, resp_headers, body
    except urllib.error.HTTPError as error:
        status = int(getattr(error, "code", 0) or 0)
        try:
            hdr_items = error.headers.items() if getattr(error, "headers", None) is not None else []
        except Exception:
            hdr_items = []
        resp_headers = {str(k).lower(): str(v) for k, v in (hdr_items or [])}
        try:
            body = error.read() or b""
        except Exception:
            body = b""
        return status, resp_headers, body


def _sync_https_request_auto(
    *,
    url: str,
    method: str,
    headers: dict[str, str],
    data: bytes | None,
    timeout_sec: float,
) -> tuple[int, dict[str, str], bytes]:
    """
    功能目的：
        自动选择“代理请求 or IPv4 直连请求”。若检测到代理配置，优先走代理。
    """

    decision = _resolve_proxy_decision(url)
    proxy = str(decision.proxy_url or "").strip()
    if proxy:
        try:
            return _sync_https_request_via_proxy(
                url=url,
                method=method,
                headers=headers,
                data=data,
                timeout_sec=timeout_sec,
                proxy_url=proxy,
            )
        except Exception as proxy_error:
            # 显式设置了 AIO_API_PROXY：不做直连回退，避免“绕过用户明确配置”造成误判
            if bool(decision.explicit):
                masked = _mask_proxy_for_log(proxy)
                raise OSError(f"代理请求失败（AIO_API_PROXY={masked or '<empty>'}）：{proxy_error}") from proxy_error

            # 系统代理：若代理不可用，自动回退直连一次（常见：系统代理残留死端口/不可用）
            try:
                return _sync_https_request_ipv4(url=url, method=method, headers=headers, data=data, timeout_sec=timeout_sec)
            except Exception as direct_error:
                masked = _mask_proxy_for_log(proxy)
                # 提示尽量简短且可操作：明确建议用户显式配置 HTTP 代理
                raise OSError(
                    "系统代理请求失败，且直连也失败："
                    f"proxy={masked or '<empty>'}；proxy_error={proxy_error}；direct_error={direct_error}。"
                    "建议：在设置里填写并应用 AIO_API_PROXY（例如 Windows 开发机常见的 http://127.0.0.1:10808），"
                    "或检查系统代理/网络是否可用。"
                ) from direct_error

    # 未发现可用代理：走 IPv4 直连
    try:
        return _sync_https_request_ipv4(url=url, method=method, headers=headers, data=data, timeout_sec=timeout_sec)
    except Exception as direct_error:
        msg = str(direct_error or "").strip()
        code = _infer_network_code_from_message(msg)
        if code in {"timeout", "dns", "unreachable", "conn_reset", "conn_refused", "network"}:
            raise OSError(
                f"直连请求失败：{msg or type(direct_error).__name__}。"
                "未检测到可用 HTTP 代理；若你依赖代理/PAC/TUN，请在设置里配置并应用 AIO_API_PROXY"
                "（例如 Windows 开发机常见的 127.0.0.1:10808）。"
            ) from direct_error
        raise


async def _https_request_text_ipv4(
    *,
    url: str,
    method: str,
    headers: dict[str, str],
    data: bytes | None,
    timeout_ms: int,
    err_prefix: str,
) -> tuple[int, dict[str, str], str]:
    timeout_sec = float(max(1, int(timeout_ms)) / 1000.0)
    try:
        status, resp_headers, body = await asyncio.to_thread(
            _sync_https_request_auto,
            url=url,
            method=method,
            headers=headers,
            data=data,
            timeout_sec=timeout_sec,
        )
    except Exception as error:
        msg = str(error or "").strip()
        code = _infer_network_code_from_message(msg)
        raise ChatGptApiHealthError(
            f"{str(err_prefix or '请求失败').strip()}：{msg or type(error).__name__}",
            status=0,
            code=code,
        ) from None

    try:
        text = body.decode("utf-8", errors="replace")
    except Exception:
        text = ""
    return status, resp_headers, text


def _domain_match_cookie(cookie_domain: str, target_host: str) -> bool:
    cd = str(cookie_domain or "").strip().lstrip(".").lower()
    th = str(target_host or "").strip().lower()
    if not cd or not th:
        return False
    if cd == th:
        return True
    return th.endswith("." + cd)


def _cookie_identity_key(cookie: Any) -> tuple[str, str, str]:
    if not isinstance(cookie, dict):
        return "", "", ""
    return (
        str(cookie.get("name") or "").strip().lower(),
        str(cookie.get("domain") or "").strip().lower(),
        str(cookie.get("path") or "/").strip() or "/",
    )


def _build_cookie_header_from_cookies(*, cookies: list[dict[str, Any]], target_host: str) -> str:
    pairs: list[str] = []
    for cookie in cookies:
        if not isinstance(cookie, dict):
            continue
        if not _domain_match_cookie(str(cookie.get("domain") or ""), target_host):
            continue
        name = str(cookie.get("name") or "").strip()
        if not name:
            continue
        value = str(cookie.get("value") or "").strip()
        pairs.append(f"{name}={value}")
    return "; ".join(pairs)


def _is_session_cookie_name(name: Any) -> bool:
    normalized = str(name or "").strip().lower()
    if not normalized:
        return False
    return (
        "session-token" in normalized
        or normalized in {"__secure-next-auth.session-token", "__secure-authjs.session-token", "next-auth.session-token"}
    )


def normalize_storage_state_cookies(
    *,
    storage_state_path: str = "",
    target_host: str = "chatgpt.com",
    cookies: Optional[list[dict[str, Any]]] = None,
) -> list[dict[str, Any]]:
    if isinstance(cookies, list):
        source_cookies = [dict(item) for item in cookies if isinstance(item, dict)]
    else:
        source_cookies = _extract_storage_state_cookies(
            _load_storage_state_payload(storage_state_path=storage_state_path)
        )
    normalized: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str, str]] = set()
    for cookie in source_cookies:
        identity = _cookie_identity_key(cookie)
        if not _domain_match_cookie(str(cookie.get("domain") or ""), target_host):
            normalized.append(dict(cookie))
            continue
        if identity in seen_keys:
            continue
        seen_keys.add(identity)
        normalized.append(dict(cookie))
    return normalized


def build_normalized_cookie_header(
    storage_state_path: str,
    *,
    target_host: str = "chatgpt.com",
) -> tuple[str, list[dict[str, Any]]]:
    normalized = normalize_storage_state_cookies(
        storage_state_path=storage_state_path,
        target_host=target_host,
    )
    return _build_cookie_header_from_cookies(cookies=normalized, target_host=target_host), normalized


def build_storage_state_cookie_summary(
    *,
    storage_state_path: str,
    target_host: str = "chatgpt.com",
    cookies: Optional[list[dict[str, Any]]] = None,
) -> dict[str, Any]:
    source_cookies = (
        [dict(item) for item in cookies if isinstance(item, dict)]
        if isinstance(cookies, list)
        else _extract_storage_state_cookies(_load_storage_state_payload(storage_state_path=storage_state_path))
    )
    chatgpt_cookies = [
        dict(cookie)
        for cookie in source_cookies
        if _domain_match_cookie(str(cookie.get("domain") or ""), target_host)
    ]
    cookie_names = [
        str(cookie.get("name") or "").strip().lower()
        for cookie in chatgpt_cookies
        if str(cookie.get("name") or "").strip()
    ]
    duplicate_counts = Counter(cookie_names)
    duplicate_names = sorted([name for name, count in duplicate_counts.items() if int(count or 0) >= 2])
    duplicate_large_names = sorted(
        [
            name
            for name in duplicate_names
            if sum(
                len(str(cookie.get("name") or "")) + len(str(cookie.get("value") or ""))
                for cookie in chatgpt_cookies
                if str(cookie.get("name") or "").strip().lower() == name
            ) >= 1024
        ]
    )
    session_cookie_names = [
        str(cookie.get("name") or "").strip().lower()
        for cookie in chatgpt_cookies
        if _is_session_cookie_name(cookie.get("name"))
    ]
    cookie_header = _build_cookie_header_from_cookies(cookies=chatgpt_cookies, target_host=target_host)
    cookie_header_length = int(len(cookie_header))
    session_cookie_count = int(len(session_cookie_names))
    duplicate_session_cookie = any(
        int(duplicate_counts.get(name, 0) or 0) >= 2
        for name in session_cookie_names
    )
    suspect_header_too_large = cookie_header_length >= 8000
    suspect_cookie_corrupted = bool(
        suspect_header_too_large
        or duplicate_session_cookie
        or duplicate_large_names
    )
    return {
        "targetHost": str(target_host or "").strip().lower(),
        "chatgptCookieCount": int(len(chatgpt_cookies)),
        "cookieHeaderLength": cookie_header_length,
        "hasSessionCookie": bool(session_cookie_count > 0),
        "sessionCookieCount": session_cookie_count,
        "duplicateCookieNames": duplicate_names,
        "duplicateLargeCookieNames": duplicate_large_names,
        "suspectHeaderTooLarge": bool(suspect_header_too_large),
        "suspectCookieCorrupted": bool(suspect_cookie_corrupted),
    }


def load_cookie_header_from_storage_state(*, storage_state_path: str, target_host: str) -> str:
    """
    功能目的：
        从 Playwright storage_state JSON 中提取指定域名的 cookies，拼接为 Cookie header。
    """

    cookies = _extract_storage_state_cookies(
        _load_storage_state_payload(storage_state_path=storage_state_path)
    )
    return _build_cookie_header_from_cookies(cookies=cookies, target_host=target_host)


def try_read_oai_did_from_storage_state(storage_state_path: str) -> str:
    """
    功能目的：
        从 storage_state 中尝试读取 `oai-did` cookie，用作 backend-api header 的 oai-device-id。
    """

    p = Path(str(storage_state_path or "").strip()).expanduser()
    if not str(p) or (not p.exists()):
        return ""
    try:
        obj = json.loads(p.read_text(encoding="utf-8") or "{}")
    except Exception:
        return ""
    cookies = obj.get("cookies") if isinstance(obj, dict) else None
    if not isinstance(cookies, list):
        return ""
    for c in cookies:
        if not isinstance(c, dict):
            continue
        name = str(c.get("name") or "").strip()
        if name != "oai-did":
            continue
        domain = str(c.get("domain") or "").strip()
        if not _domain_match_cookie(domain, "chatgpt.com"):
            continue
        return str(c.get("value") or "").strip()
    return ""


def _base64url_decode(segment: str) -> bytes:
    raw = str(segment or "").strip()
    if not raw:
        return b""
    pad = "=" * ((4 - (len(raw) % 4)) % 4)
    return base64.urlsafe_b64decode((raw + pad).encode("utf-8"))


def parse_jwt_payload_no_verify(token: str) -> dict[str, Any]:
    """
    功能目的：
        仅解析 JWT payload（不校验签名），用于提取 chatgpt_account_id 等信息。
    """

    raw = str(token or "").strip()
    parts = raw.split(".")
    if len(parts) < 2:
        return {}
    try:
        payload = _base64url_decode(parts[1]).decode("utf-8", errors="replace")
        obj = json.loads(payload or "{}")
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def extract_chatgpt_account_id_from_jwt(token: str) -> str:
    payload = parse_jwt_payload_no_verify(token)
    auth = payload.get("https://api.openai.com/auth")
    if isinstance(auth, dict):
        account_id = str(auth.get("chatgpt_account_id") or "").strip()
        if account_id:
            return account_id
    return ""


def _extract_error_code_from_body(text: str) -> str:
    """
    功能目的：
        尽力从上游 JSON 错误体中提取 code（例如 account_deactivated）。
    """

    raw = str(text or "").strip()
    if not raw:
        return ""
    try:
        obj = json.loads(raw)
    except Exception:
        return ""
    if not isinstance(obj, dict):
        return ""
    code = obj.get("code")
    if isinstance(code, str) and code.strip():
        return code.strip()
    err = obj.get("error")
    if isinstance(err, dict):
        c = err.get("code")
        if isinstance(c, str) and c.strip():
            return c.strip()
    return ""


def _sanitize_json_payload(payload: Any) -> dict[str, Any]:
    return payload if isinstance(payload, dict) else {}


def _first_non_empty_text(*values: Any) -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _is_personal_workspace_text(text: str) -> bool:
    raw = str(text or "").strip()
    if not raw:
        return False
    lower = raw.lower()
    return (
        ("personal account" in lower)
        or (lower == "personal")
        or ("个人账户" in raw)
        or ("个人账号" in raw)
        or (raw == "个人")
        or (raw.endswith("个人"))
    )


def _extract_workspace_item_text(item: Any) -> str:
    if not isinstance(item, dict):
        return ""
    return _first_non_empty_text(
        item.get("name"),
        item.get("title"),
        item.get("label"),
        item.get("display_name"),
        item.get("displayName"),
        item.get("workspace_name"),
        item.get("workspaceName"),
        item.get("organization_name"),
        item.get("organizationName"),
        item.get("slug"),
        item.get("id"),
    )


def _extract_workspace_item_id(item: Any) -> str:
    if not isinstance(item, dict):
        return ""
    return _first_non_empty_text(
        item.get("id"),
        item.get("workspace_id"),
        item.get("workspaceId"),
        item.get("account_id"),
        item.get("accountId"),
    )


def _is_non_personal_workspace_item(item: Any) -> bool:
    if not isinstance(item, dict):
        return False
    structure = str(item.get("structure") or item.get("type") or item.get("kind") or "").strip().lower()
    if structure and (structure != "personal"):
        return True
    label = _extract_workspace_item_text(item)
    return bool(label) and (not _is_personal_workspace_text(label))


def _pick_selected_workspace(payload: dict[str, Any], account: dict[str, Any]) -> dict[str, Any]:
    candidates = [
        payload.get("workspace"),
        payload.get("selectedWorkspace"),
        payload.get("selected_workspace"),
        payload.get("currentWorkspace"),
        payload.get("current_workspace"),
        account.get("workspace") if isinstance(account, dict) else None,
        account.get("selectedWorkspace") if isinstance(account, dict) else None,
        account.get("selected_workspace") if isinstance(account, dict) else None,
    ]
    for candidate in candidates:
        if isinstance(candidate, dict):
            return candidate
    return {}


def _extract_session_plan_type(payload: dict[str, Any], token: str) -> str:
    account = payload.get("account") if isinstance(payload.get("account"), dict) else {}
    direct = _first_non_empty_text(
        account.get("planType"),
        account.get("plan_type"),
        payload.get("planType"),
        payload.get("plan_type"),
    ).lower()
    if direct:
        return direct

    jwt_payload = parse_jwt_payload_no_verify(token)
    auth = jwt_payload.get("https://api.openai.com/auth")
    if isinstance(auth, dict):
        candidate = _first_non_empty_text(auth.get("chatgpt_plan_type"), auth.get("plan_type")).lower()
        if candidate:
            return candidate
    return _first_non_empty_text(jwt_payload.get("chatgpt_plan_type"), jwt_payload.get("plan_type")).lower()


def _extract_session_account_id(payload: dict[str, Any], token: str) -> str:
    account = payload.get("account") if isinstance(payload.get("account"), dict) else {}
    return _first_non_empty_text(
        extract_chatgpt_account_id_from_jwt(token),
        account.get("id"),
        account.get("accountId"),
        account.get("account_id"),
        payload.get("accountId"),
        payload.get("account_id"),
    )


def extract_session_summary_from_payload(
    payload: Any,
    *,
    status: int = 0,
    error_text: str = "",
    updated_at: str = "",
) -> dict[str, Any]:
    """
    功能目的：
        从 `auth/session` 原始 JSON 提取订阅判定所需的非敏感摘要。
    """

    data = _sanitize_json_payload(payload)
    token = _extract_access_token_from_session_payload(data)
    account = data.get("account") if isinstance(data.get("account"), dict) else {}
    workspaces = data.get("workspaces") if isinstance(data.get("workspaces"), list) else []
    accounts = data.get("accounts") if isinstance(data.get("accounts"), list) else []
    user = data.get("user") if isinstance(data.get("user"), dict) else {}
    selected_workspace = _pick_selected_workspace(data, account)
    top_level_keys = [str(key).strip() for key in data.keys() if str(key).strip()]
    top_level_key_count = int(len(top_level_keys))
    has_auth_provider = bool(_first_non_empty_text(data.get("authProvider"), data.get("auth_provider")))
    has_expires = bool(
        _first_non_empty_text(
            data.get("expires"),
            data.get("sessionExpires"),
            data.get("session_expires"),
            data.get("exp"),
        )
    )
    has_session_token_field = bool(
        token
        or has_auth_provider
        or has_expires
        or _first_non_empty_text(
            data.get("sessionToken"),
            data.get("session_token"),
            data.get("accessToken"),
            data.get("access_token"),
        )
    )

    account_structure = _first_non_empty_text(
        account.get("structure"),
        data.get("structure"),
        selected_workspace.get("structure") if isinstance(selected_workspace, dict) else "",
    ).strip().lower()
    selected_workspace_name = _extract_workspace_item_text(selected_workspace)
    selected_workspace_id = _extract_workspace_item_id(selected_workspace)
    non_personal_workspace_count = sum(1 for item in workspaces if _is_non_personal_workspace_item(item))
    non_personal_account_count = sum(1 for item in accounts if _is_non_personal_workspace_item(item))
    selected_workspace_non_personal = _is_non_personal_workspace_item(selected_workspace)
    non_personal_seen = bool(
        selected_workspace_non_personal
        or (non_personal_workspace_count > 0)
        or (non_personal_account_count > 0)
        or (account_structure and account_structure != "personal")
    )

    updated_at_value = str(updated_at or "").strip() or datetime.datetime.now(datetime.timezone.utc).isoformat()
    account_id = _extract_session_account_id(data, token)
    warning_banner_only = bool(
        top_level_key_count <= 2
        and set(top_level_keys).issubset({"warningBanner", "warning_banner", "error", "message"})
        and _first_non_empty_text(data.get("warningBanner"), data.get("warning_banner"))
    )
    return {
        "updatedAt": updated_at_value,
        "httpStatus": int(status or 0),
        "error": str(error_text or "").strip(),
        "topLevelKeys": top_level_keys,
        "topLevelKeyCount": top_level_key_count,
        "accessTokenPresent": bool(token),
        "accessTokenLength": int(len(token)),
        "accountPlanType": _extract_session_plan_type(data, token),
        "accountStructure": account_structure,
        "accountId": account_id,
        "accountIdPresent": bool(account_id),
        "hasUser": bool(user or account),
        "hasAccount": bool(account),
        "hasWorkspaces": bool(workspaces),
        "workspaceCount": int(len(workspaces)),
        "hasAccounts": bool(accounts),
        "accountsCount": int(len(accounts)),
        "hasSessionTokenField": bool(has_session_token_field),
        "hasAuthProvider": bool(has_auth_provider),
        "hasExpires": bool(has_expires),
        "warningBannerOnly": bool(warning_banner_only),
        "selectedWorkspaceId": selected_workspace_id,
        "selectedWorkspaceName": selected_workspace_name,
        "selectedWorkspaceNonPersonal": bool(selected_workspace_non_personal),
        "nonPersonalWorkspaceCount": int(non_personal_workspace_count),
        "nonPersonalAccountCount": int(non_personal_account_count),
        "nonPersonalSeen": bool(non_personal_seen),
    }


def _normalize_access_token_text(value: Any) -> str:
    token = str(value or "").strip()
    if not token:
        return ""
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    return token


def _is_compact_token_charset(value: str) -> bool:
    raw = str(value or "").strip()
    if not raw:
        return False
    if not re.fullmatch(r"[A-Za-z0-9._~+/=-]+", raw):
        return False
    alnum_count = sum(1 for ch in raw if ch.isalnum())
    return alnum_count >= max(16, int(len(raw) * 0.55))


def _looks_like_access_token(*, token: str, key: str, path: str) -> bool:
    raw = _normalize_access_token_text(token)
    if not raw:
        return False
    if len(raw) < 24 or len(raw) > 8192:
        return False
    if any(ch in raw for ch in ("\r", "\n", "\t", " ")):
        return False
    if not _is_compact_token_charset(raw):
        return False

    key_low = str(key or "").strip().lower()
    path_low = str(path or "").strip().lower()
    if re.fullmatch(r"[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]{10,}){2,4}", raw) and len(raw) >= 48:
        return True
    if raw.startswith("eyJ") and len(raw) >= 48:
        return True
    if key_low in {"accesstoken", "access_token", "session_access_token", "sessionaccesstoken", "bearertoken"}:
        return True
    if key_low in {"id_token", "idtoken"}:
        return True
    if key_low == "token":
        return ("session" in path_low) or ("auth" in path_low) or ("access" in path_low)
    return ("session" in path_low and "token" in path_low) or ("access_token" in path_low)


def _extract_access_token_from_session_payload(payload: Any) -> str:
    candidates: list[dict[str, Any]] = []
    max_depth = 9
    max_nodes = 4000
    node_count = 0

    def _push(token_value: Any, *, key: str, path: str, bonus: int = 0) -> None:
        token_text = _normalize_access_token_text(token_value)
        if not _looks_like_access_token(token=token_text, key=key, path=path):
            return
        key_low = str(key or "").strip().lower()
        score = int(bonus)
        if key_low == "accesstoken":
            score += 130
        elif key_low == "access_token":
            score += 128
        elif key_low in {"session_access_token", "sessionaccesstoken"}:
            score += 124
        elif key_low == "bearertoken":
            score += 110
        elif key_low in {"id_token", "idtoken"}:
            score += 86
        elif key_low == "token":
            score += 42
        if token_text.count(".") >= 2:
            score += 40
        if token_text.startswith("eyJ"):
            score += 24
        if len(token_text) >= 256:
            score += 16
        elif len(token_text) >= 128:
            score += 10
        elif len(token_text) >= 64:
            score += 6
        path_low = str(path or "").strip().lower()
        if "session" in path_low:
            score += 12
        if "access" in path_low:
            score += 12
        if "auth" in path_low:
            score += 10
        candidates.append({"token": token_text, "score": int(score), "len": len(token_text)})

    def _walk(node: Any, *, path: str, depth: int) -> None:
        nonlocal node_count
        if depth > max_depth:
            return
        if node_count >= max_nodes:
            return
        node_count += 1

        if isinstance(node, dict):
            for key, value in list(node.items())[:300]:
                key_text = str(key or "").strip()
                key_low = key_text.lower()
                child_path = f"{path}.{key_text}" if path else key_text
                if isinstance(value, str):
                    _push(value, key=key_low, path=child_path)
                    if value and (value[0] in "{[") and (len(value) <= 200_000):
                        try:
                            nested = json.loads(value)
                        except Exception:
                            nested = None
                        if isinstance(nested, (dict, list)):
                            _walk(nested, path=f"{child_path}.$json", depth=depth + 1)
                elif isinstance(value, (dict, list)):
                    _walk(value, path=child_path, depth=depth + 1)
        elif isinstance(node, list):
            for idx, value in enumerate(node[:200]):
                child_path = f"{path}[{idx}]"
                if isinstance(value, str):
                    _push(value, key="", path=child_path)
                elif isinstance(value, (dict, list)):
                    _walk(value, path=child_path, depth=depth + 1)

    if isinstance(payload, (dict, list)):
        _walk(payload, path="", depth=0)
        try:
            raw_text = json.dumps(payload, ensure_ascii=False)
        except Exception:
            raw_text = ""
    else:
        raw_text = str(payload or "")

    if raw_text:
        for key in ("accessToken", "access_token", "session_access_token", "id_token", "bearerToken"):
            pattern = rf'"{re.escape(key)}"\s*:\s*"([^"]+)"'
            for match in re.finditer(pattern, raw_text):
                _push(match.group(1), key=key.lower(), path=f"text.{key}", bonus=20)

    if not candidates:
        return ""
    candidates.sort(key=lambda item: (int(item.get("score") or 0), int(item.get("len") or 0)), reverse=True)
    return str(candidates[0].get("token") or "").strip()


def extract_access_token_from_session_payload(payload: Any) -> str:
    """
    功能目的：
        对外暴露 `auth/session` 中 accessToken 的稳妥提取逻辑。
    """

    return _extract_access_token_from_session_payload(payload)


def load_codex_oauth_tokens(path: str) -> Optional[CodexOAuthTokens]:
    """
    功能目的：
        读取 codex-邮箱.json 并提取 (account_id, refresh_token)。

    兼容策略：
        - 优先读取 refresh_token_enc（DPAPI base64 密文）。
        - 否则读取 refresh_token（明文，历史兼容）。
    """

    p = Path(str(path or "").strip()).expanduser()
    if not str(p):
        return None
    if not p.exists():
        return None
    try:
        raw = p.read_text(encoding="utf-8")
        payload = json.loads(raw or "{}")
        payload = _sanitize_json_payload(payload)
    except Exception:
        return None

    account_id = str(payload.get("account_id") or payload.get("chatgpt_account_id") or "").strip()
    refresh_token_enc = str(payload.get("refresh_token_enc") or "").strip()
    refresh_token_plain = str(payload.get("refresh_token") or "").strip()

    refresh_token = ""
    if refresh_token_enc:
        try:
            refresh_token = str(decrypt_text(refresh_token_enc) or "").strip()
        except Exception:
            refresh_token = ""
    if not refresh_token:
        refresh_token = refresh_token_plain

    if not account_id or not refresh_token:
        return None
    return CodexOAuthTokens(account_id=account_id, refresh_token=refresh_token, raw_payload=payload)


def _parse_iso_datetime_best_effort(raw: Any) -> datetime.datetime | None:
    text = str(raw or "").strip()
    if not text:
        return None
    try:
        normalized = text.replace("Z", "+00:00")
        dt = datetime.datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=datetime.timezone.utc)
        return dt.astimezone(datetime.timezone.utc)
    except Exception:
        return None


def _get_valid_cached_access_token_from_codex_payload(payload: dict[str, Any], *, min_valid_seconds: int = 60) -> str:
    """
    功能目的：
        从 codex oauth 文件中提取“当前仍可直接使用”的 access_token。

    说明：
        - 优先使用显式 `expired` / `expires_at` 字段判断；
        - 若缺少显式过期时间，则回退解析 JWT `exp`；
        - 仅在距离过期仍超过 `min_valid_seconds` 时返回，避免把临近过期的 token 再带入 API 调用。
    """

    if not isinstance(payload, dict):
        return ""

    access_token = _normalize_access_token_text(payload.get("access_token") or payload.get("accessToken") or "")
    if not access_token:
        return ""

    now_dt = datetime.datetime.now(datetime.timezone.utc)
    expires_dt = None
    for key in ("expired", "expires_at", "expiresAt", "access_token_expires_at", "accessTokenExpiresAt"):
        expires_dt = _parse_iso_datetime_best_effort(payload.get(key))
        if expires_dt is not None:
            break

    if expires_dt is None:
        try:
            jwt_payload = parse_jwt_payload_no_verify(access_token)
            exp_raw = int(jwt_payload.get("exp") or 0)
            if exp_raw > 0:
                expires_dt = datetime.datetime.fromtimestamp(exp_raw, tz=datetime.timezone.utc)
        except Exception:
            expires_dt = None

    if expires_dt is None:
        return ""

    remaining_seconds = (expires_dt - now_dt).total_seconds()
    if remaining_seconds <= float(max(1, int(min_valid_seconds or 1))):
        return ""
    return access_token


async def _resolve_access_token_from_codex_oauth(
    request_ctx: "APIRequestContext",
    *,
    codex_oauth_path: str,
    timeout_ms: int = 60_000,
    log: Optional[Callable[[str], None]] = None,
) -> tuple[CodexOAuthTokens, str]:
    """
    功能目的：
        解析 Codex OAuth 认证文件并拿到可直接用于 backend-api 的 access_token。

    说明：
        - 主路径：refresh_token 刷新；
        - 兜底：若刷新失败，但本地文件内仍缓存了未过期 access_token，则直接复用，
          避免因 refresh_token 被上游标记 `reused` 而把本来仍可用的账号误判为失效。
    """

    _safe_log(log, "步骤：读取 Codex OAuth 认证文件")
    tokens = load_codex_oauth_tokens(codex_oauth_path)
    if tokens is None:
        raise ChatGptApiHealthError(
            "无可用 Codex OAuth 认证文件（缺少 account_id/refresh_token）",
            status=400,
            stage="codex_oauth_file",
        )

    cached_access_token = _get_valid_cached_access_token_from_codex_payload(tokens.raw_payload)

    try:
        _safe_log(log, "步骤：刷新 access_token（OAuth refresh_token）")
        refreshed = await refresh_access_token(request_ctx, refresh_token=tokens.refresh_token, timeout_ms=timeout_ms)
        access_token = str(refreshed.get("access_token") or "").strip()
        new_refresh_token = str(refreshed.get("refresh_token") or "").strip()
        if new_refresh_token:
            persist_refresh_token_enc(path=codex_oauth_path, payload=tokens.raw_payload, refresh_token=new_refresh_token)
        else:
            if not str(tokens.raw_payload.get("refresh_token_enc") or "").strip():
                persist_refresh_token_enc(path=codex_oauth_path, payload=tokens.raw_payload, refresh_token=tokens.refresh_token)
        return tokens, access_token
    except Exception as error:
        if cached_access_token:
            if isinstance(error, ChatGptApiHealthError):
                _safe_log(
                    log,
                    f"步骤：refresh 失败（HTTP {int(error.status or 0)} {str(error.code or '').strip() or '-'}），回退使用文件内仍有效的 access_token",
                )
            else:
                _safe_log(log, "步骤：refresh 失败，回退使用文件内仍有效的 access_token")
            return tokens, cached_access_token
        raise


def persist_refresh_token_enc(*, path: str, payload: dict[str, Any], refresh_token: str) -> None:
    """
    功能目的：
        将 refresh_token 写入 refresh_token_enc（DPAPI 密文）字段，供本机后续自动刷新使用。

    说明：
        - 默认不会删除 refresh_token 明文字段（兼容外部工具）；如需清理，设置：
            AIO_CODEX_OAUTH_CLEAR_REFRESH_TOKEN_PLAINTEXT=1
    """

    p = Path(str(path or "").strip()).expanduser()
    if not str(p):
        return
    if not isinstance(payload, dict):
        return
    token_plain = str(refresh_token or "").strip()
    if not token_plain:
        return

    try:
        payload["refresh_token_enc"] = encrypt_text(token_plain)
    except Exception:
        # DPAPI 失败时，不阻断流程（仍保留原 refresh_token）
        return

    clear_plain = str(os.getenv("AIO_CODEX_OAUTH_CLEAR_REFRESH_TOKEN_PLAINTEXT", "") or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    if clear_plain:
        payload["refresh_token"] = ""

    # 尽量保持原文件可读（utf-8 + indent）
    try:
        write_codex_auth_text(
            path=p,
            text=json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except Exception:
        return


def _build_chatgpt_backend_headers(*, access_token: str, account_id: str, oai_device_id: str, referer: str) -> dict[str, str]:
    oai_client_version = str(os.getenv("AIO_OAI_CLIENT_VERSION", "") or "").strip() or DEFAULT_OAI_CLIENT_VERSION
    device_id = str(oai_device_id or "").strip() or get_http_stage_device_id()
    identity_headers = _build_chatgpt_http_browser_identity_headers()
    return {
        "accept": "*/*",
        "accept-language": "zh-CN,zh;q=0.9",
        "authorization": f"Bearer {access_token}",
        "chatgpt-account-id": account_id,
        "oai-client-version": oai_client_version,
        "oai-device-id": device_id,
        "oai-language": "zh-CN",
        "origin": "https://chatgpt.com",
        "referer": referer,
        # 说明：尽量贴近真实浏览器 UA，降低被上游拒绝的概率；无需精确版本。
        "user-agent": identity_headers.get("user-agent", ""),
    }


def _request_json_with_curl_cffi_session(
    session: Any,
    *,
    method: str,
    url: str,
    headers: dict[str, str],
    timeout_sec: float,
    request_error_prefix: str,
    http_error_prefix: str,
) -> tuple[dict[str, Any], int]:
    try:
        response = session.request(
            str(method or "GET").strip().upper() or "GET",
            str(url or "").strip(),
            headers=dict(headers),
            timeout=max(5.0, float(timeout_sec or 0.0)),
            allow_redirects=False,
        )
    except Exception as error:
        msg = str(error or "").strip()
        raise ChatGptApiHealthError(
            f"{request_error_prefix}：{msg or type(error).__name__}",
            status=0,
            code=_infer_network_code_from_message(msg),
        ) from None

    status = int(getattr(response, "status_code", 0) or 0)
    text = str(getattr(response, "text", "") or "")
    if status < 200 or status >= 300:
        code = _extract_error_code_from_body(text)
        raise ChatGptApiHealthError(f"{http_error_prefix}：HTTP {status}", status=status, code=code)

    try:
        payload = response.json()
    except Exception:
        try:
            payload = json.loads(text or "{}")
        except Exception as error:
            raise ChatGptApiHealthError(
                f"{http_error_prefix}：响应格式异常（{type(error).__name__}）",
                status=status,
            ) from None
    return _sanitize_json_payload(payload), status


class _CurlCffiApiResponseAdapter:
    def __init__(self, response: Any, *, fallback_url: str) -> None:
        self._response = response
        self.url = str(getattr(response, "url", "") or fallback_url).strip()
        self.status = int(getattr(response, "status_code", 0) or 0)
        self.ok = bool(200 <= self.status < 300)
        self.headers = dict(getattr(response, "headers", {}) or {})
        try:
            self._text = str(getattr(response, "text", "") or "")
        except Exception:
            self._text = ""

    async def text(self) -> str:
        return self._text

    async def json(self) -> Any:
        try:
            return json.loads(self._text or "{}")
        except Exception:
            return {}


class _CurlCffiApiRequestContext:
    def __init__(
        self,
        *,
        storage_state_path: str = "",
        proxy_url: str = "",
        impersonate: str = "",
    ) -> None:
        self.proxy_url = str(proxy_url or "").strip()
        self.impersonate = str(impersonate or "").strip()
        self._session = _create_curl_cffi_session_from_storage_state(
            storage_state_path=storage_state_path,
            proxy_url=self.proxy_url,
            impersonate=self.impersonate,
        )

    def _request_sync(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[dict[str, str]] = None,
        data: str | bytes | None = None,
        timeout_ms: int = 60_000,
    ) -> _CurlCffiApiResponseAdapter:
        request_kwargs: dict[str, Any] = {
            "headers": dict(headers or {}),
            "timeout": max(5.0, float(max(1, int(timeout_ms or 0)) / 1000.0)),
            "allow_redirects": False,
        }
        if data is not None:
            request_kwargs["data"] = data
        response = self._session.request(str(method or "GET").strip().upper() or "GET", str(url or "").strip(), **request_kwargs)
        return _CurlCffiApiResponseAdapter(response, fallback_url=str(url or "").strip())

    async def get(self, url: str, *, headers: Optional[dict[str, str]] = None, timeout: int = 60_000) -> _CurlCffiApiResponseAdapter:
        return await asyncio.to_thread(
            self._request_sync,
            "GET",
            url,
            headers=headers,
            data=None,
            timeout_ms=int(timeout or 60_000),
        )

    async def post(
        self,
        url: str,
        *,
        headers: Optional[dict[str, str]] = None,
        data: str | bytes | None = None,
        timeout: int = 60_000,
    ) -> _CurlCffiApiResponseAdapter:
        return await asyncio.to_thread(
            self._request_sync,
            "POST",
            url,
            headers=headers,
            data=data,
            timeout_ms=int(timeout or 60_000),
        )

    async def dispose(self) -> None:
        try:
            close = getattr(self._session, "close", None)
            if callable(close):
                close()
        except Exception:
            pass


def _sync_fetch_chatgpt_counts_with_curl_cffi_session(
    session: Any,
    *,
    access_token: str,
    account_id: str,
    oai_device_id: str,
    storage_state_path: str,
    impersonate: str,
    timeout_ms: int,
) -> ChatGptApiCounts:
    effective_oai_device_id = str(oai_device_id or "").strip() or try_read_oai_did_from_storage_state(storage_state_path)
    backend_timeout_sec = float(max(1, _read_timeout_ms("AIO_TEAM_HEALTHCHECK_BACKEND_TIMEOUT_MS", timeout_ms)) / 1000.0)

    users_url = f"https://chatgpt.com/backend-api/accounts/{account_id}/users?offset=0&limit=1&query="
    users_headers = _build_chatgpt_backend_headers(
        access_token=access_token,
        account_id=account_id,
        oai_device_id=effective_oai_device_id,
        referer="https://chatgpt.com/admin/members?tab=members",
    )
    users_headers.update(
        _build_chatgpt_http_browser_identity_headers(
            include_accept_encoding=True,
            impersonate=impersonate,
        )
    )
    users_payload, users_status = _request_json_with_curl_cffi_session(
        session,
        method="GET",
        url=users_url,
        headers=users_headers,
        timeout_sec=backend_timeout_sec,
        request_error_prefix="读取成员数请求失败",
        http_error_prefix="读取成员数失败",
    )
    user_total = users_payload.get("total")
    if not isinstance(user_total, (int, float)):
        raise ChatGptApiHealthError("成员响应格式异常：缺少 total 字段", status=users_status)

    invite_total: Optional[int]
    try:
        invites_url = f"https://chatgpt.com/backend-api/accounts/{account_id}/invites?offset=0&limit=1&query="
        invites_headers = _build_chatgpt_backend_headers(
            access_token=access_token,
            account_id=account_id,
            oai_device_id=effective_oai_device_id,
            referer="https://chatgpt.com/admin/members?tab=invites",
        )
        invites_headers.update(
            _build_chatgpt_http_browser_identity_headers(
                include_accept_encoding=True,
                impersonate=impersonate,
            )
        )
        invites_payload, invites_status = _request_json_with_curl_cffi_session(
            session,
            method="GET",
            url=invites_url,
            headers=invites_headers,
            timeout_sec=backend_timeout_sec,
            request_error_prefix="读取邀请数请求失败",
            http_error_prefix="读取邀请数失败",
        )
        invite_total_raw = invites_payload.get("total")
        if not isinstance(invite_total_raw, (int, float)):
            raise ChatGptApiHealthError("邀请响应格式异常：缺少 total 字段", status=invites_status)
        invite_total = int(invite_total_raw)
    except Exception:
        invite_total = None

    return ChatGptApiCounts(user_total=int(user_total), invite_total=invite_total)


def _sync_check_via_storage_state_session_curl_cffi(
    *,
    storage_state_path: str,
    oai_device_id: str,
    timeout_ms: int = 60_000,
) -> ChatGptApiCounts:
    if curl_cffi_requests is None:
        raise ChatGptApiHealthError("当前环境未安装 curl_cffi，无法执行纯 API 浏览器仿真检测", status=0, code="curl_cffi_unavailable")

    cookie_header = load_cookie_header_from_storage_state(storage_state_path=storage_state_path, target_host="chatgpt.com")
    if not cookie_header:
        raise ChatGptApiHealthError("storage_state 缺少 chatgpt.com Cookie，无法执行纯 API 席位检测", status=400, code="no_cookie")

    proxy_url = resolve_proxy_for_url(SESSION_URL)
    impersonate = _resolve_chatgpt_curl_impersonate()
    session = _create_curl_cffi_session_from_storage_state(
        storage_state_path=storage_state_path,
        proxy_url=proxy_url,
        impersonate=impersonate,
    )

    session_timeout_sec = float(max(1, _read_timeout_ms("AIO_TEAM_HEALTHCHECK_SESSION_TIMEOUT_MS", timeout_ms)) / 1000.0)
    session_headers = {
        "accept": "application/json",
        "cookie": cookie_header,
    }
    session_headers.update(
        _build_chatgpt_http_browser_identity_headers(
            include_accept_language=True,
            include_accept_encoding=True,
            impersonate=impersonate,
        )
    )
    session_payload, session_status = _request_json_with_curl_cffi_session(
        session,
        method="GET",
        url=SESSION_URL,
        headers=session_headers,
        timeout_sec=session_timeout_sec,
        request_error_prefix="session 请求失败",
        http_error_prefix="session 获取失败",
    )
    access_token = extract_access_token_from_session_payload(session_payload)
    if not access_token:
        raise ChatGptApiHealthError("session 响应缺少 accessToken（可能未登录）", status=session_status)

    account_id = extract_chatgpt_account_id_from_jwt(access_token)
    if not account_id:
        raise ChatGptApiHealthError("session accessToken 无法解析 chatgpt_account_id（JWT payload 缺失）", status=500)
    return _sync_fetch_chatgpt_counts_with_curl_cffi_session(
        session,
        access_token=access_token,
        account_id=account_id,
        oai_device_id=oai_device_id,
        storage_state_path=storage_state_path,
        impersonate=impersonate,
        timeout_ms=timeout_ms,
    )


async def check_via_storage_state_session_curl_cffi(
    *,
    storage_state_path: str,
    oai_device_id: str,
    timeout_ms: int = 60_000,
    log: Optional[Callable[[str], None]] = None,
) -> ChatGptApiCounts:
    """
    功能目的：
        使用 curl_cffi 模拟真实浏览器请求栈，通过 storage_state 调用 session/backend-api 获取席位信息。

    说明：
        - 这是纯 API 方案，不依赖 Playwright `APIRequestContext`。
        - 适合作为 Windows 环境下 `request.new_context()` 不可用时的优先回退。
    """

    _safe_log(log, "步骤：使用 curl_cffi 浏览器仿真链路执行纯 API 席位检测")
    return await asyncio.to_thread(
        _sync_check_via_storage_state_session_curl_cffi,
        storage_state_path=storage_state_path,
        oai_device_id=oai_device_id,
        timeout_ms=timeout_ms,
    )


async def fetch_access_token_from_storage_state_curl_cffi(
    *,
    storage_state_path: str,
    timeout_ms: int = 60_000,
) -> str:
    """
    功能目的：
        使用 curl_cffi 浏览器仿真链路，通过 storage_state 的 Cookie 调用 session API 获取 accessToken。
    """

    cookie_header = load_cookie_header_from_storage_state(storage_state_path=storage_state_path, target_host="chatgpt.com")
    if not cookie_header:
        raise ChatGptApiHealthError("storage_state 缺少 chatgpt.com Cookie，无法 session 检活", status=400, code="no_cookie")

    proxy_url = resolve_proxy_for_url(SESSION_URL)
    impersonate = _resolve_chatgpt_curl_impersonate()
    session = _create_curl_cffi_session_from_storage_state(
        storage_state_path=storage_state_path,
        proxy_url=proxy_url,
        impersonate=impersonate,
    )
    timeout_sec = float(max(1, _read_timeout_ms("AIO_TEAM_HEALTHCHECK_SESSION_TIMEOUT_MS", timeout_ms)) / 1000.0)
    headers = {
        "accept": "application/json",
        "cookie": cookie_header,
    }
    headers.update(
        _build_chatgpt_http_browser_identity_headers(
            include_accept_language=True,
            include_accept_encoding=True,
            impersonate=impersonate,
        )
    )
    payload, status = await asyncio.to_thread(
        _request_json_with_curl_cffi_session,
        session,
        method="GET",
        url=SESSION_URL,
        headers=headers,
        timeout_sec=timeout_sec,
        request_error_prefix="session 请求失败",
        http_error_prefix="session 获取失败",
    )
    token = extract_access_token_from_session_payload(payload)
    if not token:
        raise ChatGptApiHealthError("session 响应缺少 accessToken（可能未登录）", status=status)
    return token


def _is_access_token_auth_error(error: Exception) -> bool:
    if not isinstance(error, ChatGptApiHealthError):
        return False
    code = str(getattr(error, "code", "") or "").strip().lower()
    message = str(error or "").strip().lower()
    status = int(getattr(error, "status", 0) or 0)
    if status in {401, 403}:
        return True
    return any(
        marker in code or marker in message
        for marker in (
            "token_expired",
            "expired",
            "token_invalidated",
            "invalid_api_key",
            "invalid_token",
            "unauthorized",
        )
    )


async def fetch_access_token_from_session(request_ctx: "APIRequestContext", *, timeout_ms: int = 60_000) -> str:
    """
    功能目的：
        从 chatgpt.com session API 获取 accessToken（需已有登录 Cookie）。
    """

    # 允许对 session 请求单独调参：部分网络环境下 session 接口更容易超时
    timeout_ms = _read_timeout_ms("AIO_TEAM_HEALTHCHECK_SESSION_TIMEOUT_MS", timeout_ms)

    try:
        resp = await request_ctx.get(SESSION_URL, timeout=int(max(1000, timeout_ms)))
    except Exception as error:
        msg = _strip_playwright_call_log(str(error))
        raise ChatGptApiHealthError(
            f"session 请求失败：{msg or type(error).__name__}",
            status=0,
            code=_infer_network_code_from_message(msg),
        ) from None
    if not bool(resp.ok):
        text = ""
        try:
            text = await resp.text()
        except Exception:
            text = ""
        code = _extract_error_code_from_body(text)
        raise ChatGptApiHealthError(f"session 获取失败：HTTP {resp.status}", status=int(resp.status or 0), code=code)
    data = _sanitize_json_payload(await resp.json())
    token = _extract_access_token_from_session_payload(data)
    if not token:
        raise ChatGptApiHealthError("session 响应缺少 accessToken（可能未登录）", status=int(resp.status or 0))
    return token


async def fetch_access_token_from_storage_state_ipv4(
    *,
    storage_state_path: str,
    timeout_ms: int = 60_000,
) -> str:
    """
    功能目的：
        不启动浏览器，仅通过 storage_state 中的 Cookie 调用 session API，获取 accessToken。
    """

    cookie_header = load_cookie_header_from_storage_state(storage_state_path=storage_state_path, target_host="chatgpt.com")
    if not cookie_header:
        raise ChatGptApiHealthError("storage_state 缺少 chatgpt.com Cookie，无法 session 检活", status=400, code="no_cookie")

    timeout_ms = _read_timeout_ms("AIO_TEAM_HEALTHCHECK_SESSION_TIMEOUT_MS", timeout_ms)

    status, _hdrs, text = await _https_request_text_ipv4(
        url=SESSION_URL,
        method="GET",
        headers={
            "accept": "application/json",
            "accept-language": "zh-CN,zh;q=0.9",
            "accept-encoding": "identity",
            "cookie": cookie_header,
            "user-agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/142.0.0.0 Safari/537.36"
            ),
        },
        data=None,
        timeout_ms=timeout_ms,
        err_prefix="session 请求失败",
    )
    if int(status) < 200 or int(status) >= 300:
        code = _extract_error_code_from_body(text)
        raise ChatGptApiHealthError(f"session 获取失败：HTTP {int(status)}", status=int(status), code=code)
    data = _sanitize_json_payload(json.loads(text or "{}"))
    token = _extract_access_token_from_session_payload(data)
    if not token:
        raise ChatGptApiHealthError("session 响应缺少 accessToken（可能未登录）", status=int(status))
    return token


async def fetch_session_payload_from_storage_state(
    request_ctx: "APIRequestContext",
    *,
    storage_state_path: str,
    timeout_ms: int = 60_000,
    cookie_header_override: str = "",
) -> dict[str, Any]:
    """
    功能目的：
        不启动浏览器，仅通过 storage_state 中的 Cookie 调用 session API，获取原始 JSON。

    说明：
        - 依赖 Playwright 的 Node 请求栈，更贴近浏览器/axios 的 TLS 指纹。
        - request_ctx 可复用（批量检测时建议复用同一个 request_ctx）。
    """

    cookie_header = str(cookie_header_override or "").strip() or load_cookie_header_from_storage_state(
        storage_state_path=storage_state_path,
        target_host="chatgpt.com",
    )
    if not cookie_header:
        raise ChatGptApiHealthError("storage_state 缺少 chatgpt.com Cookie，无法 session 检活", status=400, code="no_cookie")

    timeout_ms = _read_timeout_ms("AIO_TEAM_HEALTHCHECK_SESSION_TIMEOUT_MS", timeout_ms)

    try:
        resp = await request_ctx.get(
            SESSION_URL,
            headers={
                "accept": "application/json",
                "accept-language": "zh-CN,zh;q=0.9",
                "cookie": cookie_header,
                "user-agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/142.0.0.0 Safari/537.36"
                ),
            },
            timeout=int(max(1000, timeout_ms)),
        )
    except Exception as error:
        msg = _strip_playwright_call_log(str(error))
        raise ChatGptApiHealthError(
            f"session 请求失败：{msg or type(error).__name__}",
            status=0,
            code=_infer_network_code_from_message(msg),
        ) from None

    if not bool(resp.ok):
        text = ""
        try:
            text = await resp.text()
        except Exception:
            text = ""
        code = _extract_error_code_from_body(text)
        raise ChatGptApiHealthError(f"session 获取失败：HTTP {resp.status}", status=int(resp.status or 0), code=code)

    return _sanitize_json_payload(await resp.json())


async def fetch_session_summary_from_storage_state(
    request_ctx: "APIRequestContext",
    *,
    storage_state_path: str,
    timeout_ms: int = 60_000,
    cookie_header_override: str = "",
) -> dict[str, Any]:
    """
    功能目的：
        通过 storage_state 请求 `auth/session`，并返回非敏感摘要。
    """

    payload = await fetch_session_payload_from_storage_state(
        request_ctx,
        storage_state_path=storage_state_path,
        timeout_ms=timeout_ms,
        cookie_header_override=cookie_header_override,
    )
    return {
        "sessionSummary": extract_session_summary_from_payload(
            payload,
            status=200,
            error_text="",
            updated_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        ),
        "cookieSummary": build_storage_state_cookie_summary(storage_state_path=storage_state_path),
    }


async def fetch_access_token_from_storage_state(
    request_ctx: "APIRequestContext",
    *,
    storage_state_path: str,
    timeout_ms: int = 60_000,
) -> str:
    """
    功能目的：
        不启动浏览器，仅通过 storage_state 中的 Cookie 调用 session API，获取 accessToken（使用 Playwright 请求栈）。
    """

    data = await fetch_session_payload_from_storage_state(
        request_ctx,
        storage_state_path=storage_state_path,
        timeout_ms=timeout_ms,
    )
    token = extract_access_token_from_session_payload(data)
    if not token:
        raise ChatGptApiHealthError("session 响应缺少 accessToken（可能未登录）", status=200)
    return token


async def refresh_access_token(
    request_ctx: "APIRequestContext",
    *,
    refresh_token: str,
    client_id: str = "",
    timeout_ms: int = 60_000,
) -> dict[str, Any]:
    """
    功能目的：
        使用 refresh_token 刷新 access_token（OAuth）。
    """

    # 允许对 token 刷新单独调参：该步骤通常是最容易被网络/代理影响的一步
    timeout_ms = _read_timeout_ms("AIO_TEAM_HEALTHCHECK_TOKEN_TIMEOUT_MS", timeout_ms)

    cid = str(client_id or "").strip() or str(os.getenv("OPENAI_CLIENT_ID") or "").strip() or DEFAULT_OPENAI_CLIENT_ID
    rt = str(refresh_token or "").strip()
    if not cid or not rt:
        raise ChatGptApiHealthError("刷新 token 失败：缺少 client_id 或 refresh_token", status=400)

    form = urllib.parse.urlencode(
        {
            "grant_type": "refresh_token",
            "client_id": cid,
            "refresh_token": rt,
            "scope": "openid profile email",
        }
    )
    try:
        resp = await request_ctx.post(
            TOKEN_URL,
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
            data=form,
            timeout=int(max(1000, timeout_ms)),
        )
    except Exception as error:
        msg = _strip_playwright_call_log(str(error))
        raise ChatGptApiHealthError(
            f"刷新 token 请求失败：{msg or type(error).__name__}",
            status=0,
            code=_infer_network_code_from_message(msg),
        ) from None

    text = ""
    try:
        text = await resp.text()
    except Exception:
        text = ""

    if not bool(resp.ok):
        code = _extract_error_code_from_body(text)
        raise ChatGptApiHealthError(f"刷新 token 失败：HTTP {resp.status}", status=int(resp.status or 0), code=code)

    try:
        payload = json.loads(text or "{}")
    except Exception:
        payload = {}
    payload = _sanitize_json_payload(payload)
    access_token = str(payload.get("access_token") or "").strip()
    if not access_token:
        raise ChatGptApiHealthError("刷新 token 失败：响应缺少 access_token", status=int(resp.status or 0))
    return payload


async def refresh_access_token_ipv4(
    *,
    refresh_token: str,
    client_id: str = "",
    timeout_ms: int = 60_000,
) -> dict[str, Any]:
    """
    功能目的：
        使用 refresh_token 刷新 access_token（IPv4 直连，规避 Node/IPv6 超时问题）。
    """

    timeout_ms = _read_timeout_ms("AIO_TEAM_HEALTHCHECK_TOKEN_TIMEOUT_MS", timeout_ms)

    cid = str(client_id or "").strip() or str(os.getenv("OPENAI_CLIENT_ID") or "").strip() or DEFAULT_OPENAI_CLIENT_ID
    rt = str(refresh_token or "").strip()
    if not cid or not rt:
        raise ChatGptApiHealthError("刷新 token 失败：缺少 client_id 或 refresh_token", status=400)

    form = urllib.parse.urlencode(
        {
            "grant_type": "refresh_token",
            "client_id": cid,
            "refresh_token": rt,
            "scope": "openid profile email",
        }
    ).encode("utf-8")

    status, _hdrs, text = await _https_request_text_ipv4(
        url=TOKEN_URL,
        method="POST",
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "accept": "application/json",
            "accept-encoding": "identity",
        },
        data=form,
        timeout_ms=timeout_ms,
        err_prefix="刷新 token 请求失败",
    )
    if int(status) < 200 or int(status) >= 300:
        code = _extract_error_code_from_body(text)
        raise ChatGptApiHealthError(f"刷新 token 失败：HTTP {int(status)}", status=int(status), code=code)

    try:
        payload = json.loads(text or "{}")
    except Exception:
        payload = {}
    payload = _sanitize_json_payload(payload)
    access_token = str(payload.get("access_token") or "").strip()
    if not access_token:
        raise ChatGptApiHealthError("刷新 token 失败：响应缺少 access_token", status=int(status))
    return payload


async def _resolve_access_token_from_codex_oauth_for_curl_cffi(
    *,
    codex_oauth_path: str,
    timeout_ms: int = 60_000,
    log: Optional[Callable[[str], None]] = None,
) -> tuple[CodexOAuthTokens, str]:
    _safe_log(log, "步骤：读取 Codex OAuth 认证文件")
    tokens = load_codex_oauth_tokens(codex_oauth_path)
    if tokens is None:
        raise ChatGptApiHealthError(
            "无可用 Codex OAuth 认证文件（缺少 account_id/refresh_token）",
            status=400,
            stage="codex_oauth_file",
        )

    cached_access_token = _get_valid_cached_access_token_from_codex_payload(tokens.raw_payload)
    if cached_access_token:
        _safe_log(log, "步骤：复用文件中仍有效的 Codex access_token")
        return tokens, cached_access_token

    _safe_log(log, "步骤：本地未缓存有效 Codex access_token，尝试 refresh_token 刷新")
    refreshed = await refresh_access_token_ipv4(refresh_token=tokens.refresh_token, timeout_ms=timeout_ms)
    access_token = str(refreshed.get("access_token") or "").strip()
    new_refresh_token = str(refreshed.get("refresh_token") or "").strip()
    if new_refresh_token:
        persist_refresh_token_enc(path=codex_oauth_path, payload=tokens.raw_payload, refresh_token=new_refresh_token)
    else:
        if not str(tokens.raw_payload.get("refresh_token_enc") or "").strip():
            persist_refresh_token_enc(path=codex_oauth_path, payload=tokens.raw_payload, refresh_token=tokens.refresh_token)
    return tokens, access_token


async def check_via_codex_oauth_curl_cffi(
    *,
    codex_oauth_path: str,
    storage_state_path: str = "",
    oai_device_id: str,
    timeout_ms: int = 60_000,
    log: Optional[Callable[[str], None]] = None,
) -> ChatGptApiCounts:
    """
    功能目的：
        使用 Codex OAuth 中仍有效的 access_token（或刷新后的 token），通过 curl_cffi 纯 API 链路获取席位信息。

    说明：
        - 优先复用本地仍有效的 access_token，避免 refresh_token 被上游风控拒绝时误判账号失效。
        - 若同时提供 storage_state，则会把 Cookie 一并注入 curl_cffi session，尽量贴近真实浏览器环境。
    """

    tokens, access_token = await _resolve_access_token_from_codex_oauth_for_curl_cffi(
        codex_oauth_path=codex_oauth_path,
        timeout_ms=timeout_ms,
        log=log,
    )
    proxy_url = resolve_proxy_for_url(SESSION_URL)
    impersonate = _resolve_chatgpt_curl_impersonate()
    session = _create_curl_cffi_session_from_storage_state(
        storage_state_path=storage_state_path,
        proxy_url=proxy_url,
        impersonate=impersonate,
    )
    _safe_log(log, "步骤：使用 Codex access_token 执行 curl_cffi 纯 API 席位检测")
    return await asyncio.to_thread(
        _sync_fetch_chatgpt_counts_with_curl_cffi_session,
        session,
        access_token=access_token,
        account_id=tokens.account_id,
        oai_device_id=oai_device_id,
        storage_state_path=storage_state_path,
        impersonate=impersonate,
        timeout_ms=timeout_ms,
    )


async def fetch_users_total(
    request_ctx: "APIRequestContext",
    *,
    access_token: str,
    account_id: str,
    oai_device_id: str,
    timeout_ms: int = 60_000,
) -> int:
    """
    功能目的：
        调用 backend-api/users 获取 total，用于检活与同步 member_count。
    """

    timeout_ms = _read_timeout_ms("AIO_TEAM_HEALTHCHECK_BACKEND_TIMEOUT_MS", timeout_ms)

    url = f"https://chatgpt.com/backend-api/accounts/{account_id}/users?offset=0&limit=1&query="
    headers = _build_chatgpt_backend_headers(
        access_token=access_token,
        account_id=account_id,
        oai_device_id=oai_device_id,
        referer="https://chatgpt.com/admin/members?tab=members",
    )
    try:
        resp = await request_ctx.get(url, headers=headers, timeout=int(max(1000, timeout_ms)))
    except Exception as error:
        msg = _strip_playwright_call_log(str(error))
        raise ChatGptApiHealthError(
            f"读取成员数请求失败：{msg or type(error).__name__}",
            status=0,
            code=_infer_network_code_from_message(msg),
        ) from None
    if not bool(resp.ok):
        text = ""
        try:
            text = await resp.text()
        except Exception:
            text = ""
        code = _extract_error_code_from_body(text)
        raise ChatGptApiHealthError(f"读取成员数失败：HTTP {resp.status}", status=int(resp.status or 0), code=code)
    data = _sanitize_json_payload(await resp.json())
    total = data.get("total")
    if not isinstance(total, (int, float)):
        raise ChatGptApiHealthError("成员响应格式异常：缺少 total 字段", status=int(resp.status or 0))
    return int(total)



def _looks_like_email(value: str) -> bool:
    """
    功能目的：
        轻量判断字符串是否像邮箱地址。
    """

    text = str(value or "").strip()
    if not text:
        return False
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", text))


def _extract_email_deep(payload: Any, *, max_depth: int = 5) -> str:
    """
    功能目的：
        从未知结构的成员项中尽力提取邮箱。
    """

    def _walk(node: Any, depth: int) -> str:
        if depth > max_depth:
            return ""
        if isinstance(node, dict):
            # 优先匹配“键名包含 email/mail 且值像邮箱”的字段
            for key, raw in node.items():
                if not isinstance(raw, str):
                    continue
                value = str(raw or "").strip().lower()
                if not value:
                    continue
                low_key = str(key or "").strip().lower()
                if ("email" in low_key or "mail" in low_key) and _looks_like_email(value):
                    return value
            # 其次递归子结构
            for raw in node.values():
                found = _walk(raw, depth + 1)
                if found:
                    return found
            return ""

        if isinstance(node, list):
            for item in node[:20]:
                found = _walk(item, depth + 1)
                if found:
                    return found
            return ""

        if isinstance(node, str):
            value = str(node or "").strip().lower()
            if _looks_like_email(value):
                return value
        return ""

    return _walk(payload, 0)


def _extract_user_items(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """
    功能目的：
        从 users 接口响应中提取成员项数组（兼容不同字段名）。
    """

    for key in ("items", "users", "results", "members"):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]

    data = payload.get("data")
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        for key in ("items", "users", "results", "members"):
            value = data.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []


def _pick_str(*values: Any) -> str:
    for raw in values:
        text = str(raw or "").strip()
        if text:
            return text
    return ""


def _normalize_member_item(item: dict[str, Any]) -> Optional[dict[str, str]]:
    """
    功能目的：
        将 users 接口单条成员项标准化为统一结构。
    """

    user = item.get("user") if isinstance(item.get("user"), dict) else {}
    profile = item.get("profile") if isinstance(item.get("profile"), dict) else {}

    email = _pick_str(
        item.get("email"),
        item.get("primary_email"),
        item.get("login_email"),
        user.get("email"),
        user.get("primary_email"),
        profile.get("email"),
    ).lower()
    if not _looks_like_email(email):
        email = _extract_email_deep(item)

    if not _looks_like_email(email):
        return None

    member_id = _pick_str(item.get("id"), item.get("user_id"), item.get("userId"), user.get("id"), user.get("user_id"))
    name = _pick_str(item.get("name"), item.get("full_name"), item.get("display_name"), user.get("name"), profile.get("name"))
    role = _pick_str(item.get("role"), item.get("member_role"), item.get("membership_role"), user.get("role"))
    status = _pick_str(item.get("status"), item.get("state"), user.get("status"), user.get("state"))

    return {
        "email": email,
        "id": member_id,
        "name": name,
        "role": role,
        "status": status,
    }


def _normalize_invite_emails(emails: list[str]) -> list[str]:
    """
    功能目的：
        规范化邀请邮箱列表（去空、去重、转小写）。
    """

    normalized: list[str] = []
    seen: set[str] = set()
    for item in list(emails or []):
        email = str(item or "").strip().lower()
        if (not email) or ("@" not in email):
            continue
        if email in seen:
            continue
        seen.add(email)
        normalized.append(email)
    return normalized


async def fetch_users_page(
    request_ctx: "APIRequestContext",
    *,
    access_token: str,
    account_id: str,
    oai_device_id: str,
    offset: int,
    limit: int,
    query: str = "",
    timeout_ms: int = 60_000,
) -> dict[str, Any]:
    """
    功能目的：
        调用 backend-api/users 拉取一页成员数据。
    """

    timeout_ms = _read_timeout_ms("AIO_TEAM_HEALTHCHECK_BACKEND_TIMEOUT_MS", timeout_ms)
    safe_offset = max(0, int(offset or 0))
    safe_limit = max(1, min(200, int(limit or 1)))
    query_value = str(query or "").strip()

    url = (
        f"https://chatgpt.com/backend-api/accounts/{account_id}/users"
        f"?offset={safe_offset}&limit={safe_limit}&query={urllib.parse.quote(query_value)}"
    )
    headers = _build_chatgpt_backend_headers(
        access_token=access_token,
        account_id=account_id,
        oai_device_id=oai_device_id,
        referer="https://chatgpt.com/admin/members?tab=members",
    )
    try:
        resp = await request_ctx.get(url, headers=headers, timeout=int(max(1000, timeout_ms)))
    except Exception as error:
        msg = _strip_playwright_call_log(str(error))
        raise ChatGptApiHealthError(
            f"读取成员列表请求失败：{msg or type(error).__name__}",
            status=0,
            code=_infer_network_code_from_message(msg),
        ) from None

    if not bool(resp.ok):
        text = ""
        try:
            text = await resp.text()
        except Exception:
            text = ""
        code = _extract_error_code_from_body(text)
        raise ChatGptApiHealthError(f"读取成员列表失败：HTTP {resp.status}", status=int(resp.status or 0), code=code)

    payload = _sanitize_json_payload(await resp.json())
    raw_items = _extract_user_items(payload)
    total_raw = payload.get("total")
    total = int(total_raw) if isinstance(total_raw, (int, float)) else len(raw_items)
    return {
        "total": int(max(0, total)),
        "items": raw_items,
    }


async def fetch_users_members(
    request_ctx: "APIRequestContext",
    *,
    access_token: str,
    account_id: str,
    oai_device_id: str,
    query: str = "",
    page_limit: int = 100,
    max_items: int = 300,
    timeout_ms: int = 60_000,
) -> tuple[list[dict[str, str]], int]:
    """
    功能目的：
        分页拉取成员并提取邮箱，返回去重后的成员列表与 total。
    """

    safe_page_limit = max(1, min(200, int(page_limit or 1)))
    safe_max_items = max(1, min(2000, int(max_items or 1)))

    members: list[dict[str, str]] = []
    seen_emails: set[str] = set()
    offset = 0
    total_hint = 0

    while len(members) < safe_max_items:
        page = await fetch_users_page(
            request_ctx,
            access_token=access_token,
            account_id=account_id,
            oai_device_id=oai_device_id,
            offset=offset,
            limit=safe_page_limit,
            query=query,
            timeout_ms=timeout_ms,
        )

        raw_items = page.get("items") if isinstance(page.get("items"), list) else []
        try:
            total_hint = max(int(total_hint), int(page.get("total") or 0))
        except Exception:
            total_hint = max(int(total_hint), 0)

        if not raw_items:
            break

        for raw in raw_items:
            if not isinstance(raw, dict):
                continue
            normalized = _normalize_member_item(raw)
            if normalized is None:
                continue
            email_key = str(normalized.get("email") or "").strip().lower()
            if not email_key or email_key in seen_emails:
                continue
            seen_emails.add(email_key)
            members.append(normalized)
            if len(members) >= safe_max_items:
                break

        fetched = len(raw_items)
        offset += fetched

        if fetched < safe_page_limit:
            break
        if total_hint > 0 and offset >= total_hint:
            break

    if total_hint <= 0:
        total_hint = len(members)
    return members, int(total_hint)


def _extract_invite_items(payload: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    for key in ("items", "results", "invites", "data"):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []


def _extract_email_from_invite_item(item: dict[str, Any]) -> str:
    if not isinstance(item, dict):
        return ""
    invitee = item.get("invitee") if isinstance(item.get("invitee"), dict) else {}
    user = item.get("user") if isinstance(item.get("user"), dict) else {}
    email = _pick_str(
        item.get("email"),
        item.get("invitee_email"),
        item.get("invited_email"),
        invitee.get("email"),
        user.get("email"),
    ).lower()
    if _looks_like_email(email):
        return email
    return _extract_email_deep(item)


def _normalize_invite_item(item: dict[str, Any]) -> Optional[dict[str, str]]:
    """
    功能目的：
        将 invites 接口单条邀请项标准化为统一结构。
    """

    if not isinstance(item, dict):
        return None

    invitee = item.get("invitee") if isinstance(item.get("invitee"), dict) else {}
    user = item.get("user") if isinstance(item.get("user"), dict) else {}
    email = _extract_email_from_invite_item(item)
    if not _looks_like_email(email):
        return None

    invite_id = _extract_invite_id_from_item(item)
    name = _pick_str(
        item.get("name"),
        item.get("full_name"),
        item.get("display_name"),
        invitee.get("name"),
        user.get("name"),
    )
    role = _pick_str(
        item.get("role"),
        item.get("member_role"),
        item.get("membership_role"),
        user.get("role"),
        "member",
    )
    status = _pick_str(
        item.get("status"),
        item.get("state"),
        item.get("invite_status"),
        item.get("inviteState"),
        "invited",
    )
    invited_at = _pick_str(
        item.get("invited_at"),
        item.get("invitedAt"),
        item.get("created_at"),
        item.get("createdAt"),
        item.get("updated_at"),
        item.get("updatedAt"),
    )
    return {
        "email": email,
        "id": invite_id,
        "name": name,
        "role": role,
        "status": status or "invited",
        "invited_at": invited_at,
    }


async def fetch_invites_page(
    request_ctx: "APIRequestContext",
    *,
    access_token: str,
    account_id: str,
    oai_device_id: str,
    offset: int,
    limit: int,
    query: str = "",
    timeout_ms: int = 60_000,
) -> dict[str, Any]:
    """
    功能目的：
        调用 backend-api/invites 拉取一页待接受邀请。
    """

    timeout_ms = _read_timeout_ms("AIO_TEAM_HEALTHCHECK_BACKEND_TIMEOUT_MS", timeout_ms)
    safe_offset = max(0, int(offset or 0))
    safe_limit = max(1, min(200, int(limit or 1)))
    query_value = str(query or "").strip()

    url = (
        f"https://chatgpt.com/backend-api/accounts/{account_id}/invites"
        f"?offset={safe_offset}&limit={safe_limit}&query={urllib.parse.quote(query_value)}"
    )
    headers = _build_chatgpt_backend_headers(
        access_token=access_token,
        account_id=account_id,
        oai_device_id=oai_device_id,
        referer="https://chatgpt.com/admin/members?tab=invites",
    )
    headers["accept"] = "application/json, text/plain, */*"
    try:
        resp = await request_ctx.get(url, headers=headers, timeout=int(max(1000, timeout_ms)))
    except Exception as error:
        msg = _strip_playwright_call_log(str(error))
        raise ChatGptApiHealthError(
            f"读取待接受邀请失败：{msg or type(error).__name__}",
            status=0,
            code=_infer_network_code_from_message(msg),
        ) from None

    if not bool(resp.ok):
        text = ""
        try:
            text = await resp.text()
        except Exception:
            text = ""
        code = _extract_error_code_from_body(text)
        raise ChatGptApiHealthError(
            f"读取待接受邀请失败：HTTP {resp.status}",
            status=int(resp.status or 0),
            code=code,
        )

    payload = _sanitize_json_payload(await resp.json())
    raw_items = _extract_invite_items(payload)
    total_raw = payload.get("total")
    total = int(total_raw) if isinstance(total_raw, (int, float)) else len(raw_items)
    return {
        "total": int(max(0, total)),
        "items": raw_items,
    }


async def fetch_invite_members(
    request_ctx: "APIRequestContext",
    *,
    access_token: str,
    account_id: str,
    oai_device_id: str,
    query: str = "",
    page_limit: int = 100,
    max_items: int = 300,
    timeout_ms: int = 60_000,
) -> tuple[list[dict[str, str]], int]:
    """
    功能目的：
        分页拉取待接受邀请并提取邮箱，返回去重后的邀请列表与 total。
    """

    safe_page_limit = max(1, min(200, int(page_limit or 1)))
    safe_max_items = max(1, min(2000, int(max_items or 1)))

    invites: list[dict[str, str]] = []
    seen_emails: set[str] = set()
    offset = 0
    total_hint = 0

    while len(invites) < safe_max_items:
        page = await fetch_invites_page(
            request_ctx,
            access_token=access_token,
            account_id=account_id,
            oai_device_id=oai_device_id,
            offset=offset,
            limit=safe_page_limit,
            query=query,
            timeout_ms=timeout_ms,
        )

        raw_items = page.get("items") if isinstance(page.get("items"), list) else []
        try:
            total_hint = max(int(total_hint), int(page.get("total") or 0))
        except Exception:
            total_hint = max(int(total_hint), 0)

        if not raw_items:
            break

        for raw in raw_items:
            if not isinstance(raw, dict):
                continue
            normalized = _normalize_invite_item(raw)
            if normalized is None:
                continue
            email_key = str(normalized.get("email") or "").strip().lower()
            if not email_key or email_key in seen_emails:
                continue
            seen_emails.add(email_key)
            invites.append(normalized)
            if len(invites) >= safe_max_items:
                break

        fetched = len(raw_items)
        offset += fetched

        if fetched < safe_page_limit:
            break
        if total_hint > 0 and offset >= total_hint:
            break

    if total_hint <= 0:
        total_hint = len(invites)
    return invites, int(total_hint)


def _merge_member_rows(*groups: list[dict[str, str]]) -> list[dict[str, str]]:
    """
    功能目的：
        合并已加入成员与待接受邀请，按邮箱去重并优先保留已加入成员。
    """

    merged: list[dict[str, str]] = []
    seen_emails: set[str] = set()
    for group in groups:
        for item in group:
            row = dict(item or {})
            email = str(row.get("email") or "").strip().lower()
            if not email or email in seen_emails:
                continue
            row["email"] = email
            seen_emails.add(email)
            merged.append(row)
    return merged


async def _deprecated_check_invite_exists_by_email(
    request_ctx: "APIRequestContext",
    *,
    access_token: str,
    account_id: str,
    oai_device_id: str,
    email: str,
    timeout_ms: int = 60_000,
) -> bool:
    query_email = str(email or "").strip().lower()
    if not _looks_like_email(query_email):
        return False

    url = (
        f"https://chatgpt.com/backend-api/accounts/{account_id}/invites"
        f"?offset=0&limit=20&query={urllib.parse.quote(query_email)}"
    )
    headers = _build_chatgpt_backend_headers(
        access_token=access_token,
        account_id=account_id,
        oai_device_id=oai_device_id,
        referer="https://chatgpt.com/admin/members?tab=invites",
    )
    headers["accept"] = "application/json, text/plain, */*"
    try:
        resp = await request_ctx.get(url, headers=headers, timeout=int(max(1000, timeout_ms)))
    except Exception as error:
        msg = _strip_playwright_call_log(str(error))
        raise ChatGptApiHealthError(
            f"校验邀请结果失败：{msg or type(error).__name__}",
            status=0,
            code=_infer_network_code_from_message(msg),
        ) from None

    if not bool(resp.ok):
        text = ""
        try:
            text = await resp.text()
        except Exception:
            text = ""
        code = _extract_error_code_from_body(text)
        raise ChatGptApiHealthError(
            f"校验邀请结果失败：HTTP {int(resp.status or 0)}",
            status=int(resp.status or 0),
            code=code,
        )

    payload = _sanitize_json_payload(await resp.json())
    items = _extract_invite_items(payload)
    for item in items:
        found = _extract_email_from_invite_item(item)
        if str(found or "").strip().lower() == query_email:
            return True

    total_raw = payload.get("total")
    if isinstance(total_raw, (int, float)) and int(total_raw) > 0:
        # query 已按邮箱过滤，total>0 也可视为存在
        return True
    return False


async def check_invite_emails_via_access_token(
    request_ctx: "APIRequestContext",
    *,
    access_token: str,
    account_id: str,
    oai_device_id: str,
    emails: list[str],
    timeout_ms: int = 60_000,
) -> dict[str, bool]:
    normalized = _normalize_invite_emails(emails)
    result: dict[str, bool] = {}
    for email in normalized:
        result[email] = bool(
            await _check_invite_exists_by_email(
                request_ctx,
                access_token=access_token,
                account_id=account_id,
                oai_device_id=oai_device_id,
                email=email,
                timeout_ms=timeout_ms,
            )
        )
    return result


async def check_invite_emails_via_codex_oauth_refresh(
    request_ctx: "APIRequestContext",
    *,
    codex_oauth_path: str,
    oai_device_id: str,
    emails: list[str],
    timeout_ms: int = 60_000,
    log: Optional[Callable[[str], None]] = None,
) -> dict[str, bool]:
    tokens, access_token = await _resolve_access_token_from_codex_oauth(
        request_ctx,
        codex_oauth_path=codex_oauth_path,
        timeout_ms=timeout_ms,
        log=log,
    )
    return await check_invite_emails_via_access_token(
        request_ctx,
        access_token=access_token,
        account_id=tokens.account_id,
        oai_device_id=oai_device_id,
        emails=emails,
        timeout_ms=timeout_ms,
    )


async def check_invite_emails_via_storage_state_session(
    request_ctx: "APIRequestContext",
    *,
    storage_state_path: str,
    oai_device_id: str,
    emails: list[str],
    timeout_ms: int = 60_000,
    log: Optional[Callable[[str], None]] = None,
) -> dict[str, bool]:
    _safe_log(log, "步骤：从 storage_state 读取 Cookie 并请求 session accessToken")
    access_token = await fetch_access_token_from_storage_state(
        request_ctx,
        storage_state_path=storage_state_path,
        timeout_ms=timeout_ms,
    )
    account_id = extract_chatgpt_account_id_from_jwt(access_token)
    if not account_id:
        raise ChatGptApiHealthError("session accessToken 无法解析 chatgpt_account_id（JWT payload 缺失）", status=500)
    return await check_invite_emails_via_access_token(
        request_ctx,
        access_token=access_token,
        account_id=account_id,
        oai_device_id=oai_device_id,
        emails=emails,
        timeout_ms=timeout_ms,
    )


async def _deprecated_verify_invites_created(
    request_ctx: "APIRequestContext",
    *,
    access_token: str,
    account_id: str,
    oai_device_id: str,
    emails: list[str],
    timeout_ms: int = 60_000,
    verify_timeout_sec: float = 12.0,
    poll_interval_sec: float = 1.5,
) -> list[str]:
    expected = _normalize_invite_emails(emails)
    if not expected:
        return []

    timeout_sec = max(1.0, float(verify_timeout_sec or 1.0))
    interval_sec = max(0.2, float(poll_interval_sec or 0.2))
    deadline = asyncio.get_event_loop().time() + timeout_sec
    missing = list(expected)

    while True:
        next_missing: list[str] = []
        for email in missing:
            ok = await _check_invite_exists_by_email(
                request_ctx,
                access_token=access_token,
                account_id=account_id,
                oai_device_id=oai_device_id,
                email=email,
                timeout_ms=timeout_ms,
            )
            if not ok:
                next_missing.append(email)

        if not next_missing:
            return []
        if asyncio.get_event_loop().time() >= deadline:
            return next_missing
        missing = next_missing
        await asyncio.sleep(interval_sec)


async def _check_invite_exists_by_email(
    request_ctx: "APIRequestContext",
    *,
    access_token: str,
    account_id: str,
    oai_device_id: str,
    email: str,
    timeout_ms: int = 60_000,
) -> bool:
    query_email = str(email or "").strip().lower()
    if not _looks_like_email(query_email):
        return False

    url = (
        f"https://chatgpt.com/backend-api/accounts/{account_id}/invites"
        f"?offset=0&limit=20&query={urllib.parse.quote(query_email)}"
    )
    headers = _build_chatgpt_backend_headers(
        access_token=access_token,
        account_id=account_id,
        oai_device_id=oai_device_id,
        referer="https://chatgpt.com/admin/members?tab=invites",
    )
    headers["accept"] = "application/json, text/plain, */*"
    try:
        resp = await request_ctx.get(url, headers=headers, timeout=int(max(1000, timeout_ms)))
    except Exception as error:
        msg = _strip_playwright_call_log(str(error))
        raise ChatGptApiHealthError(
            f"鏍￠獙閭€璇风粨鏋滃け璐ワ細{msg or type(error).__name__}",
            status=0,
            code=_infer_network_code_from_message(msg),
        ) from None

    if not bool(resp.ok):
        text = ""
        try:
            text = await resp.text()
        except Exception:
            text = ""
        code = _extract_error_code_from_body(text)
        raise ChatGptApiHealthError(
            f"鏍￠獙閭€璇风粨鏋滃け璐ワ細HTTP {int(resp.status or 0)}",
            status=int(resp.status or 0),
            code=code,
        )

    payload = _sanitize_json_payload(await resp.json())
    items = _extract_invite_items(payload)
    for item in items:
        found = _extract_email_from_invite_item(item)
        if str(found or "").strip().lower() == query_email:
            return True
    return False


async def _check_invite_or_member_exists_by_email(
    request_ctx: "APIRequestContext",
    *,
    access_token: str,
    account_id: str,
    oai_device_id: str,
    email: str,
    timeout_ms: int = 60_000,
) -> bool:
    query_email = str(email or "").strip().lower()
    if not _looks_like_email(query_email):
        return False
    if await _check_invite_exists_by_email(
        request_ctx,
        access_token=access_token,
        account_id=account_id,
        oai_device_id=oai_device_id,
        email=query_email,
        timeout_ms=timeout_ms,
    ):
        return True
    member_item = await _find_member_item_by_email(
        request_ctx,
        access_token=access_token,
        account_id=account_id,
        oai_device_id=oai_device_id,
        email=query_email,
        allow_full_scan_fallback=False,
        timeout_ms=timeout_ms,
    )
    return member_item is not None


async def _verify_invites_created(
    request_ctx: "APIRequestContext",
    *,
    access_token: str,
    account_id: str,
    oai_device_id: str,
    emails: list[str],
    timeout_ms: int = 60_000,
    verify_timeout_sec: float = 12.0,
    poll_interval_sec: float = 1.5,
) -> list[str]:
    expected = _normalize_invite_emails(emails)
    if not expected:
        return []

    timeout_sec = max(1.0, float(verify_timeout_sec or 1.0))
    interval_sec = max(0.2, float(poll_interval_sec or 0.2))
    deadline = asyncio.get_event_loop().time() + timeout_sec
    missing = list(expected)

    while True:
        next_missing: list[str] = []
        for email in missing:
            ok = await _check_invite_or_member_exists_by_email(
                request_ctx,
                access_token=access_token,
                account_id=account_id,
                oai_device_id=oai_device_id,
                email=email,
                timeout_ms=timeout_ms,
            )
            if not ok:
                next_missing.append(email)

        if not next_missing:
            return []
        if asyncio.get_event_loop().time() >= deadline:
            return next_missing
        missing = next_missing
        await asyncio.sleep(interval_sec)


async def invite_members_via_access_token(
    request_ctx: "APIRequestContext",
    *,
    access_token: str,
    account_id: str,
    oai_device_id: str,
    emails: list[str],
    send_invite_email: bool = True,
    verify_invite_result: bool = False,
    verify_timeout_sec: float = 12.0,
    timeout_ms: int = 60_000,
) -> ChatGptApiInviteResult:
    """
    功能目的：
        使用已就绪的 access_token 调用 Team 邀请接口。

    说明：
        - 主路径：/api/organizations/{orgId}/invites
        - 兼容回退：/backend-api/accounts/{accountId}/invites
    """

    timeout_ms = _read_timeout_ms("AIO_TEAM_INVITE_API_TIMEOUT_MS", timeout_ms)
    safe_emails = _normalize_invite_emails(emails)
    if not safe_emails:
        raise ChatGptApiHealthError("邀请失败：未提供有效邮箱。", status=400, code="invalid_email")

    backend_payload = {
        "email_addresses": safe_emails,
        "role": "standard-user",
        "send_invite_email": bool(send_invite_email),
    }
    org_payload = {
        "emails": safe_emails,
        "role": "member",
        "send_invite_email": bool(send_invite_email),
    }
    headers = _build_chatgpt_backend_headers(
        access_token=access_token,
        account_id=account_id,
        oai_device_id=oai_device_id,
        referer="https://chatgpt.com/admin/members?tab=invites",
    )
    headers["content-type"] = "application/json"
    headers["accept"] = "application/json, text/plain, */*"

    endpoints = [
        ("backend_invites", f"https://chatgpt.com/backend-api/accounts/{account_id}/invites", backend_payload),
        ("org_invites", f"https://chatgpt.com/api/organizations/{account_id}/invites", org_payload),
    ]
    last_error: ChatGptApiHealthError | None = None

    for stage, url, payload in endpoints:
        body = json.dumps(payload, ensure_ascii=False)
        try:
            resp = await request_ctx.post(
                url,
                headers=headers,
                data=body,
                timeout=int(max(1000, timeout_ms)),
            )
        except Exception as error:
            msg = _strip_playwright_call_log(str(error))
            last_error = ChatGptApiHealthError(
                f"发送邀请请求失败：{msg or type(error).__name__}（{stage}）",
                status=0,
                code=_infer_network_code_from_message(msg),
            )
            continue

        text = ""
        try:
            text = await resp.text()
        except Exception:
            text = ""

        if bool(resp.ok):
            content_type = str(getattr(resp, "headers", {}).get("content-type") or "").strip().lower()
            stripped = str(text or "").lstrip()
            if stripped.startswith("<!DOCTYPE html") or stripped.startswith("<html"):
                last_error = ChatGptApiHealthError(
                    f"发送邀请失败：接口返回 HTML 页面内容（{stage}）",
                    status=int(resp.status or 0),
                    code="invite_non_json_response",
                )
                continue

            raw: dict[str, Any]
            try:
                raw_obj = json.loads(text or "{}")
                raw = _sanitize_json_payload(raw_obj if isinstance(raw_obj, dict) else {})
            except Exception:
                if stripped and ("json" not in content_type):
                    last_error = ChatGptApiHealthError(
                        f"发送邀请失败：接口返回非 JSON 内容（{stage}）",
                        status=int(resp.status or 0),
                        code="invite_non_json_response",
                    )
                    continue
                raw = {}

            if bool(verify_invite_result):
                missing = await _verify_invites_created(
                    request_ctx,
                    access_token=access_token,
                    account_id=account_id,
                    oai_device_id=oai_device_id,
                    emails=safe_emails,
                    timeout_ms=timeout_ms,
                    verify_timeout_sec=verify_timeout_sec,
                )
                if missing:
                    missing_preview = ", ".join(missing[:3])
                    if len(missing) > 3:
                        missing_preview = f"{missing_preview} ..."
                    error = ChatGptApiHealthError(
                        f"邀请接口响应成功，但未在待接受成员/成员列表中精确命中邮箱：{missing_preview}",
                        status=409,
                        code="invite_not_confirmed",
                    )
                    # backend-api 为当前稳定接口；若已确认失败，直接返回错误。
                    if stage == "backend_invites":
                        raise error
                    last_error = error
                    continue
            return ChatGptApiInviteResult(
                account_id=account_id,
                requested_count=len(safe_emails),
                endpoint=stage,
                raw=raw,
            )

        code = _extract_error_code_from_body(text)
        last_error = ChatGptApiHealthError(
            f"发送邀请失败：HTTP {int(resp.status or 0)}（{stage}）",
            status=int(resp.status or 0),
            code=code,
        )

    if last_error is not None:
        raise last_error
    raise ChatGptApiHealthError("发送邀请失败：未知错误。", status=0)


async def invite_members_via_access_token_curl_cffi(
    *,
    access_token: str,
    account_id: str,
    oai_device_id: str,
    emails: list[str],
    storage_state_path: str = "",
    send_invite_email: bool = True,
    verify_invite_result: bool = False,
    verify_timeout_sec: float = 12.0,
    timeout_ms: int = 60_000,
    log: Optional[Callable[[str], None]] = None,
) -> ChatGptApiInviteResult:
    """
    功能目的：
        不依赖 Playwright，直接使用 curl_cffi 请求上下文携带 access_token 调用邀请接口。
    """

    proxy_url = resolve_proxy_for_url(SESSION_URL)
    impersonate = _resolve_chatgpt_curl_impersonate()
    request_ctx = _CurlCffiApiRequestContext(
        storage_state_path=storage_state_path,
        proxy_url=proxy_url,
        impersonate=impersonate,
    )
    try:
        _safe_log(log, "步骤：使用 curl_cffi 请求上下文调用邀请接口")
        return await invite_members_via_access_token(
            request_ctx,
            access_token=access_token,
            account_id=account_id,
            oai_device_id=oai_device_id,
            emails=emails,
            send_invite_email=send_invite_email,
            verify_invite_result=verify_invite_result,
            verify_timeout_sec=verify_timeout_sec,
            timeout_ms=timeout_ms,
        )
    finally:
        await request_ctx.dispose()


def _build_codex_quota_window(item: Any) -> dict[str, Any]:
    payload = item if isinstance(item, dict) else {}
    usage_limit = payload.get("usage_limit") if isinstance(payload.get("usage_limit"), dict) else {}
    total = payload.get("total_usage") if isinstance(payload.get("total_usage"), dict) else {}
    window_name = _first_non_empty_text(
        payload.get("name"),
        payload.get("label"),
        payload.get("window"),
        usage_limit.get("window"),
    )
    used = int(total.get("input_tokens") or total.get("requests") or payload.get("used") or 0)
    limit = int(usage_limit.get("input_tokens") or usage_limit.get("requests") or payload.get("limit") or 0)
    remaining = max(0, limit - used) if limit > 0 else 0
    reset_at = _first_non_empty_text(
        usage_limit.get("resets_at"),
        usage_limit.get("reset_at"),
        payload.get("resets_at"),
        payload.get("reset_at"),
    )
    is_exhausted = bool(limit > 0 and remaining <= 0)
    return {
        "name": window_name,
        "used": used,
        "limit": limit,
        "remaining": remaining,
        "reset_at": reset_at,
        "is_exhausted": is_exhausted,
        "raw": payload,
    }


def _build_chatgpt_mfa_headers(*, access_token: str, cookie_header: str, oai_device_id: str, referer: str) -> dict[str, str]:
    identity_headers = _build_chatgpt_http_browser_identity_headers()
    headers = {
        "accept": "application/json, text/plain, */*",
        "accept-language": "zh-CN,zh;q=0.9",
        "authorization": f"Bearer {str(access_token or '').strip()}",
        "cookie": str(cookie_header or "").strip(),
        "oai-language": "zh-CN",
        "origin": "https://chatgpt.com",
        "referer": str(referer or "https://chatgpt.com/#settings/Security").strip() or "https://chatgpt.com/#settings/Security",
        "user-agent": identity_headers.get("user-agent", ""),
    }
    device_id = str(oai_device_id or "").strip() or get_http_stage_device_id()
    if device_id:
        headers["oai-device-id"] = device_id
    return headers


def _extract_totp_factors(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    factors = payload.get("factors")
    if not isinstance(factors, dict):
        return []
    raw_totp = factors.get("totp")
    if not isinstance(raw_totp, list):
        return []
    return [item for item in raw_totp if isinstance(item, dict)]


def _extract_mfa_state(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {
            "mfa_enabled": False,
            "factor_type": "totp",
            "factor_id": "",
            "factors": [],
        }
    factors = _extract_totp_factors(payload)
    factor_id = ""
    if factors:
        factor_id = str((factors[0] or {}).get("id") or "").strip()
    return {
        "mfa_enabled": bool(payload.get("mfa_enabled")),
        "factor_type": "totp" if factors else str(payload.get("factor_type") or "totp").strip() or "totp",
        "factor_id": factor_id,
        "factors": factors,
    }


def _generate_totp_code_from_secret(secret: str, *, for_time: int | None = None) -> str:
    normalized = re.sub(r"\s+", "", str(secret or "").strip()).upper()
    if not normalized:
        raise ValueError("TOTP secret 为空。")

    try:
        import pyotp  # noqa: WPS433

        totp = pyotp.TOTP(normalized)
        if for_time is None:
            return str(totp.now()).zfill(6)
        return str(totp.at(int(for_time))).zfill(6)
    except Exception:
        try:
            key = base64.b32decode(normalized, casefold=True)
        except Exception as error:
            raise ValueError("TOTP secret 不是有效的 Base32 字符串。") from error

        timestamp = int(time.time()) if for_time is None else int(for_time)
        counter = int(timestamp // 30)
        digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
        return str(code % 1_000_000).zfill(6)


async def _request_chatgpt_mfa_json(
    *,
    method: str,
    url: str,
    headers: dict[str, str],
    payload: Optional[dict[str, Any]] = None,
    timeout_ms: int = 60_000,
    stage: str,
) -> dict[str, Any]:
    req_headers = dict(headers or {})
    body_bytes: bytes | None = None
    if payload is not None:
        req_headers["content-type"] = "application/json"
        body_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")

    status, _resp_headers, text = await _https_request_text_ipv4(
        url=url,
        method=str(method or "GET").upper(),
        headers=req_headers,
        data=body_bytes,
        timeout_ms=int(max(1000, timeout_ms)),
        err_prefix=f"MFA {stage}",
    )
    stripped = str(text or "").strip()
    data: dict[str, Any] = {}
    if stripped:
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, dict):
                data = _sanitize_json_payload(parsed)
            else:
                data = {"data": parsed}
        except Exception:
            data = {"text": stripped[:2000]}
    if int(status or 0) not in {200, 201, 202, 204}:
        code = _extract_error_code_from_body(stripped)
        raise ChatGptApiHealthError(
            f"MFA 请求失败：HTTP {int(status or 0)}（{stage}）。",
            status=int(status or 0),
            code=str(code or "").strip(),
        )
    return data


async def enable_totp_mfa_via_storage_state(
    *,
    storage_state_path: str,
    access_token: str = "",
    timeout_ms: int = 60_000,
    log: Optional[Callable[[str], None]] = None,
) -> dict[str, Any]:
    """
    功能目的：
        基于现有 storage_state + access_token 为 ChatGPT 账号开通 TOTP 2FA。

    说明：
        - 必须携带完整 chatgpt.com cookies；
        - 必须发送 `OAI-Language: zh-CN`；
        - 若账号已启用 2FA，则返回幂等成功，不重复 enroll。
    """

    safe_state_path = str(storage_state_path or "").strip()
    if not safe_state_path:
        raise ChatGptApiHealthError("开通 2FA 失败：storage_state 路径为空。", status=400, code="storage_state_missing")

    token_value = str(access_token or "").strip() or _read_access_token_from_storage_state(storage_state_path=safe_state_path)
    if not token_value:
        raise ChatGptApiHealthError("开通 2FA 失败：缺少 access_token。", status=401, code="missing_access_token")

    cookie_header = load_cookie_header_from_storage_state(storage_state_path=safe_state_path, target_host="chatgpt.com")
    if not cookie_header:
        raise ChatGptApiHealthError("开通 2FA 失败：缺少 chatgpt.com cookies。", status=400, code="no_cookie")

    oai_device_id = try_read_oai_did_from_storage_state(safe_state_path)
    headers = _build_chatgpt_mfa_headers(
        access_token=token_value,
        cookie_header=cookie_header,
        oai_device_id=oai_device_id,
        referer="https://chatgpt.com/#settings/Security",
    )

    _safe_log(log, "步骤：读取当前 MFA 状态")
    info_before = await _request_chatgpt_mfa_json(
        method="GET",
        url=MFA_INFO_URL,
        headers=headers,
        timeout_ms=timeout_ms,
        stage="mfa_info_before",
    )
    before_state = _extract_mfa_state(info_before)
    if bool(before_state.get("mfa_enabled")):
        return {
            "success": True,
            "alreadyEnabled": True,
            "mfaEnabled": True,
            "factorType": str(before_state.get("factor_type") or "totp"),
            "factorId": str(before_state.get("factor_id") or ""),
            "secret": "",
            "secretMasked": "",
            "sessionId": "",
            "updatedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "mfaInfo": info_before,
        }

    _safe_log(log, "步骤：创建 TOTP enroll 会话")
    enroll_payload = await _request_chatgpt_mfa_json(
        method="POST",
        url=MFA_ENROLL_URL,
        headers=headers,
        payload={"factor_type": "totp"},
        timeout_ms=timeout_ms,
        stage="mfa_enroll",
    )
    secret = re.sub(r"\s+", "", str(enroll_payload.get("secret") or "").strip()).upper()
    session_id = str(enroll_payload.get("session_id") or "").strip()
    enroll_factor = enroll_payload.get("factor") if isinstance(enroll_payload.get("factor"), dict) else {}
    factor_id = str((enroll_factor or {}).get("id") or "").strip()
    if (not secret) or (not session_id):
        raise ChatGptApiHealthError("开通 2FA 失败：enroll 响应缺少 secret 或 session_id。", status=500, code="invalid_enroll_payload")

    _safe_log(log, "步骤：生成 TOTP 验证码并激活")
    code = _generate_totp_code_from_secret(secret)
    activate_payload = await _request_chatgpt_mfa_json(
        method="POST",
        url=MFA_ACTIVATE_URL,
        headers=headers,
        payload={"code": code, "factor_type": "totp", "session_id": session_id},
        timeout_ms=timeout_ms,
        stage="mfa_activate",
    )
    if (activate_payload.get("success") is False):
        raise ChatGptApiHealthError("开通 2FA 失败：activate 响应未成功。", status=500, code="activate_failed")

    _safe_log(log, "步骤：确认 MFA 已生效")
    info_after = await _request_chatgpt_mfa_json(
        method="GET",
        url=MFA_INFO_URL,
        headers=headers,
        timeout_ms=timeout_ms,
        stage="mfa_info_after",
    )
    after_state = _extract_mfa_state(info_after)
    enabled = bool(after_state.get("mfa_enabled"))
    final_factor_id = str(after_state.get("factor_id") or factor_id or "").strip()
    if not enabled:
        raise ChatGptApiHealthError("开通 2FA 失败：激活后状态仍未生效。", status=500, code="mfa_not_enabled")

    return {
        "success": True,
        "alreadyEnabled": False,
        "mfaEnabled": True,
        "factorType": "totp",
        "factorId": final_factor_id,
        "secret": secret,
        "secretMasked": _mask_totp_secret(secret),
        "sessionId": session_id,
        "updatedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "mfaInfo": info_after,
    }


async def fetch_codex_quota_via_access_token(
    request_ctx: "APIRequestContext",
    *,
    access_token: str,
    account_id: str,
    oai_device_id: str,
    plan_type: str = "",
    timeout_ms: int = 60_000,
) -> ChatGptCodexQuotaSnapshot:
    url = "https://chatgpt.com/backend-api/codex/usage"
    headers = _build_chatgpt_backend_headers(
        access_token=access_token,
        account_id=account_id,
        oai_device_id=oai_device_id,
        referer="https://chatgpt.com/codex/settings/usage",
    )
    headers["accept"] = "application/json, text/plain, */*"
    try:
        resp = await request_ctx.get(url, headers=headers, timeout=int(max(1000, timeout_ms)))
    except Exception as error:
        msg = _strip_playwright_call_log(str(error))
        raise ChatGptApiHealthError(
            f"读取 Codex 配额失败：{msg or type(error).__name__}",
            status=0,
            code=_infer_network_code_from_message(msg),
        ) from None
    text = ""
    try:
        text = await resp.text()
    except Exception:
        text = ""
    if not bool(resp.ok):
        code = _extract_error_code_from_body(text)
        raise ChatGptApiHealthError(
            f"读取 Codex 配额失败：HTTP {int(resp.status or 0)}",
            status=int(resp.status or 0),
            code=code,
        )
    try:
        payload = _sanitize_json_payload(json.loads(text or "{}"))
    except Exception as error:
        raise ChatGptApiHealthError(f"读取 Codex 配额失败：返回内容不是合法 JSON：{error}", status=int(resp.status or 0), code="invalid_json")
    windows_raw = payload.get("rate_limits") if isinstance(payload.get("rate_limits"), list) else []
    windows = [_build_codex_quota_window(item) for item in windows_raw]
    exhausted = any(bool(item.get("is_exhausted")) for item in windows)
    return ChatGptCodexQuotaSnapshot(
        account_id=account_id,
        plan_type=str(plan_type or "").strip().lower(),
        windows=windows,
        exhausted=exhausted,
        raw=payload,
    )


async def fetch_codex_quota_via_codex_oauth_refresh(
    request_ctx: "APIRequestContext",
    *,
    codex_oauth_path: str,
    oai_device_id: str,
    timeout_ms: int = 60_000,
    log: Optional[Callable[[str], None]] = None,
) -> ChatGptCodexQuotaSnapshot:
    tokens, access_token = await _resolve_access_token_from_codex_oauth(
        request_ctx,
        codex_oauth_path=codex_oauth_path,
        timeout_ms=timeout_ms,
        log=log,
    )
    plan_type = _first_non_empty_text(
        tokens.raw_payload.get("chatgpt_plan_type"),
        tokens.raw_payload.get("plan_type"),
        tokens.raw_payload.get("planType"),
    )
    return await fetch_codex_quota_via_access_token(
        request_ctx,
        access_token=access_token,
        account_id=tokens.account_id,
        oai_device_id=oai_device_id,
        plan_type=plan_type,
        timeout_ms=timeout_ms,
    )


async def _fetch_codex_wham_usage_via_access_token_curl_cffi(
    *,
    access_token: str,
    account_id: str,
    oai_device_id: str,
    storage_state_path: str = "",
    timeout_ms: int = 60_000,
) -> tuple[dict[str, Any], int]:
    url = "https://chatgpt.com/backend-api/wham/usage"
    timeout_ms = _read_timeout_ms("AIO_CODEX_USAGE_TIMEOUT_MS", timeout_ms, min_ms=3_000, max_ms=180_000)
    proxy_url = resolve_proxy_for_url(url)
    impersonate = _resolve_chatgpt_curl_impersonate()
    session = _create_curl_cffi_session_from_storage_state(
        storage_state_path=storage_state_path,
        proxy_url=proxy_url,
        impersonate=impersonate,
    )
    headers = _build_chatgpt_backend_headers(
        access_token=access_token,
        account_id=account_id,
        oai_device_id=oai_device_id,
        referer="https://chatgpt.com/codex/settings/usage",
    )
    headers["accept"] = "application/json, text/plain, */*"
    try:
        return await asyncio.to_thread(
            _request_json_with_curl_cffi_session,
            session,
            method="GET",
            url=url,
            headers=headers,
            timeout_sec=max(5.0, float(timeout_ms) / 1000.0),
            request_error_prefix="读取 Codex 配额失败",
            http_error_prefix="读取 Codex 配额失败",
        )
    finally:
        try:
            close = getattr(session, "close", None)
            if callable(close):
                close()
        except Exception:
            pass


async def fetch_codex_wham_quota_via_codex_oauth_preferred(
    *,
    codex_oauth_path: str,
    storage_state_path: str = "",
    oai_device_id: str,
    timeout_ms: int = 60_000,
    log: Optional[Callable[[str], None]] = None,
) -> tuple[dict[str, Any], int, str]:
    """
    功能目的：
        使用纯 API 链路读取 Codex `wham/usage` 配额，并优先复用本地仍有效的 Codex access_token。

    说明：
        - 优先级：cached Codex access_token -> refresh_token 刷新 access_token
        - 不依赖 Playwright `APIRequestContext`
        - 返回值：(`wham/usage` 原始 payload, http_status, plan_type)
    """

    tokens = load_codex_oauth_tokens(codex_oauth_path)
    last_error: Exception | None = None
    plan_type = ""

    if tokens is None:
        last_error = ChatGptApiHealthError(
            "无可用 Codex OAuth 认证文件（缺少 account_id/refresh_token）",
            status=400,
            code="codex_oauth_missing",
            stage="codex_oauth_file",
        )
        if not storage_state_path:
            raise last_error
        _safe_log(log, "步骤：缺少 Codex OAuth 认证文件，准备尝试 curl session accessToken 兜底")
    else:
        plan_type = _first_non_empty_text(
            tokens.raw_payload.get("chatgpt_plan_type"),
            tokens.raw_payload.get("plan_type"),
            tokens.raw_payload.get("planType"),
        ).strip().lower()

        cached_access_token = _get_valid_cached_access_token_from_codex_payload(tokens.raw_payload)
        if cached_access_token:
            try:
                _safe_log(log, "步骤：优先使用本地仍有效的 Codex access_token 读取配额")
                payload, status = await _fetch_codex_wham_usage_via_access_token_curl_cffi(
                    access_token=cached_access_token,
                    account_id=tokens.account_id,
                    oai_device_id=oai_device_id,
                    storage_state_path=storage_state_path,
                    timeout_ms=timeout_ms,
                )
                return payload, int(status or 0), plan_type
            except Exception as error:
                last_error = _wrap_api_health_error(
                    error,
                    stage="codex_cached_quota",
                    prefix="Codex cached access_token 读取配额失败",
                )
                if _is_access_token_auth_error(error):
                    _safe_log(log, "步骤：Codex cached access_token 已失效，准备 refresh_token 刷新后重试配额读取")
                else:
                    _safe_log(log, f"步骤：Codex cached access_token 读取配额失败，继续尝试 refresh/session 兜底：{last_error}")

        try:
            _safe_log(log, "步骤：尝试使用 refresh_token 刷新 Codex access_token 后读取配额")
            refreshed = await refresh_access_token_ipv4(refresh_token=tokens.refresh_token, timeout_ms=timeout_ms)
            refreshed_access_token = str(refreshed.get("access_token") or "").strip()
            new_refresh_token = str(refreshed.get("refresh_token") or "").strip()
            if new_refresh_token:
                persist_refresh_token_enc(path=codex_oauth_path, payload=tokens.raw_payload, refresh_token=new_refresh_token)
            else:
                if not str(tokens.raw_payload.get("refresh_token_enc") or "").strip():
                    persist_refresh_token_enc(path=codex_oauth_path, payload=tokens.raw_payload, refresh_token=tokens.refresh_token)

            try:
                payload, status = await _fetch_codex_wham_usage_via_access_token_curl_cffi(
                    access_token=refreshed_access_token,
                    account_id=tokens.account_id,
                    oai_device_id=oai_device_id,
                    storage_state_path=storage_state_path,
                    timeout_ms=timeout_ms,
                )
                return payload, int(status or 0), plan_type
            except Exception as error:
                last_error = _wrap_api_health_error(
                    error,
                    stage="codex_refresh_quota",
                    prefix="Codex refresh_token 已换出新 access_token，但读取配额仍失败",
                )
                _safe_log(log, f"步骤：Codex refresh 后读取配额失败，准备尝试 curl session accessToken 兜底：{last_error}")
        except Exception as error:
            last_error = _wrap_api_health_error(
                error,
                stage="codex_refresh_token",
                prefix="Codex refresh_token 刷新失败",
            )
            _safe_log(log, f"步骤：Codex refresh_token 刷新失败，准备尝试 curl session accessToken 兜底：{last_error}")

    if storage_state_path:
        try:
            _safe_log(log, "步骤：通过 curl_cffi session 获取 accessToken 后再次读取 Codex 配额")
            session_access_token = await fetch_access_token_from_storage_state_curl_cffi(
                storage_state_path=storage_state_path,
                timeout_ms=timeout_ms,
            )
            account_id = extract_chatgpt_account_id_from_jwt(session_access_token)
            if not account_id:
                raise ChatGptApiHealthError(
                    "session accessToken 无法解析 chatgpt_account_id（JWT payload 缺失）",
                    status=500,
                    code="account_id_missing",
                )
            resolved_plan_type = plan_type or _extract_session_plan_type({}, session_access_token)
            try:
                payload, status = await _fetch_codex_wham_usage_via_access_token_curl_cffi(
                    access_token=session_access_token,
                    account_id=account_id,
                    oai_device_id=oai_device_id,
                    storage_state_path=storage_state_path,
                    timeout_ms=timeout_ms,
                )
                return payload, int(status or 0), resolved_plan_type
            except Exception as error:
                last_error = _wrap_api_health_error(
                    error,
                    stage="session_quota",
                    prefix="session accessToken 已获取，但读取 Codex 配额仍失败",
                )
        except Exception as error:
            if isinstance(error, ChatGptApiHealthError) and str(getattr(error, "stage", "") or "").strip() == "session_quota":
                last_error = error
            else:
                last_error = _wrap_api_health_error(
                    error,
                    stage="session_access_token",
                    prefix="通过 storage_state 获取 session accessToken 失败",
                )

    if last_error is not None:
        raise last_error
    raise ChatGptApiHealthError("读取 Codex 配额失败", status=500, code="quota_unknown", stage="quota")


async def invite_members_via_codex_oauth_preferred(
    *,
    codex_oauth_path: str,
    storage_state_path: str = "",
    oai_device_id: str,
    emails: list[str],
    send_invite_email: bool = True,
    verify_invite_result: bool = False,
    verify_timeout_sec: float = 12.0,
    timeout_ms: int = 60_000,
    log: Optional[Callable[[str], None]] = None,
) -> ChatGptApiInviteResult:
    """
    功能目的：
        使用“cached Codex access_token -> refresh_token 刷新 -> curl session accessToken”优先级执行 API 邀请。

    说明：
        - 这是纯 API 优先实现，不依赖 Playwright `APIRequestContext`。
        - 如果本地缓存的 Codex access_token 仍有效，优先直接邀请。
        - 若 cached token 不可用或邀请接口返回认证错误，再尝试 refresh_token 刷新后重试。
        - 若 Codex 路径仍失败且提供了 storage_state，则回退到 curl_cffi session accessToken。
    """

    tokens = load_codex_oauth_tokens(codex_oauth_path)
    if tokens is None:
        raise ChatGptApiHealthError("无可用 Codex OAuth 认证文件（缺少 account_id/refresh_token）", status=400)

    last_error: Exception | None = None
    cached_access_token = _get_valid_cached_access_token_from_codex_payload(tokens.raw_payload)
    if cached_access_token:
        try:
            _safe_log(log, "步骤：优先使用本地仍有效的 Codex access_token 执行邀请")
            return await invite_members_via_access_token_curl_cffi(
                access_token=cached_access_token,
                account_id=tokens.account_id,
                oai_device_id=oai_device_id,
                emails=emails,
                storage_state_path=storage_state_path,
                send_invite_email=send_invite_email,
                verify_invite_result=verify_invite_result,
                verify_timeout_sec=verify_timeout_sec,
                timeout_ms=timeout_ms,
                log=log,
            )
        except Exception as error:
            last_error = _wrap_api_health_error(
                error,
                stage="codex_cached_invite",
                prefix="Codex cached access_token 邀请失败",
            )
            if _is_access_token_auth_error(error):
                _safe_log(log, "步骤：Codex cached access_token 已失效，准备 refresh_token 刷新后重试")
            else:
                _safe_log(log, f"步骤：Codex cached access_token 邀请失败，继续尝试 refresh/session 兜底：{last_error}")

    try:
        _safe_log(log, "步骤：尝试使用 refresh_token 刷新 Codex access_token")
        refreshed = await refresh_access_token_ipv4(refresh_token=tokens.refresh_token, timeout_ms=timeout_ms)
        refreshed_access_token = str(refreshed.get("access_token") or "").strip()
        new_refresh_token = str(refreshed.get("refresh_token") or "").strip()
        if new_refresh_token:
            persist_refresh_token_enc(path=codex_oauth_path, payload=tokens.raw_payload, refresh_token=new_refresh_token)
        else:
            if not str(tokens.raw_payload.get("refresh_token_enc") or "").strip():
                persist_refresh_token_enc(path=codex_oauth_path, payload=tokens.raw_payload, refresh_token=tokens.refresh_token)

        try:
            return await invite_members_via_access_token_curl_cffi(
                access_token=refreshed_access_token,
                account_id=tokens.account_id,
                oai_device_id=oai_device_id,
                emails=emails,
                storage_state_path=storage_state_path,
                send_invite_email=send_invite_email,
                verify_invite_result=verify_invite_result,
                verify_timeout_sec=verify_timeout_sec,
                timeout_ms=timeout_ms,
                log=log,
            )
        except Exception as error:
            last_error = _wrap_api_health_error(
                error,
                stage="codex_refresh_invite",
                prefix="Codex refresh_token 已换出新 access_token，但邀请接口仍失败",
            )
            _safe_log(log, f"步骤：Codex refresh 后邀请失败，准备尝试 curl session accessToken 兜底：{last_error}")
    except Exception as error:
        last_error = _wrap_api_health_error(
            error,
            stage="codex_refresh_token",
            prefix="Codex refresh_token 刷新失败",
        )
        _safe_log(log, f"步骤：Codex refresh_token 刷新失败，准备尝试 curl session accessToken 兜底：{last_error}")

    if storage_state_path:
        try:
            _safe_log(log, "步骤：通过 curl_cffi session 获取 accessToken 后再次执行邀请")
            session_access_token = await fetch_access_token_from_storage_state_curl_cffi(
                storage_state_path=storage_state_path,
                timeout_ms=timeout_ms,
            )
            account_id = extract_chatgpt_account_id_from_jwt(session_access_token)
            if not account_id:
                raise ChatGptApiHealthError(
                    "session accessToken 无法解析 chatgpt_account_id（JWT payload 缺失）",
                    status=500,
                    code="account_id_missing",
                )
            try:
                return await invite_members_via_access_token_curl_cffi(
                    access_token=session_access_token,
                    account_id=account_id,
                    oai_device_id=oai_device_id,
                    emails=emails,
                    storage_state_path=storage_state_path,
                    send_invite_email=send_invite_email,
                    verify_invite_result=verify_invite_result,
                    verify_timeout_sec=verify_timeout_sec,
                    timeout_ms=timeout_ms,
                    log=log,
                )
            except Exception as error:
                last_error = _wrap_api_health_error(
                    error,
                    stage="session_invite",
                    prefix="session accessToken 已获取，但邀请接口仍失败",
                )
        except Exception as error:
            if isinstance(error, ChatGptApiHealthError) and str(getattr(error, "stage", "") or "").strip() == "session_invite":
                last_error = error
            else:
                last_error = _wrap_api_health_error(
                    error,
                    stage="session_access_token",
                    prefix="session accessToken 获取失败",
                )

    if last_error is not None:
        raise last_error
    raise ChatGptApiHealthError("Codex OAuth 邀请失败：无法获取可用 access_token。", status=0, stage="codex_unknown")


async def invite_members_via_codex_oauth_refresh(
    request_ctx: "APIRequestContext",
    *,
    codex_oauth_path: str,
    oai_device_id: str,
    emails: list[str],
    send_invite_email: bool = True,
    verify_invite_result: bool = False,
    verify_timeout_sec: float = 12.0,
    timeout_ms: int = 60_000,
    log: Optional[Callable[[str], None]] = None,
) -> ChatGptApiInviteResult:
    """
    功能目的：
        使用 Codex OAuth 刷新 access_token 后，通过 API 发送成员邀请。
    """

    tokens, access_token = await _resolve_access_token_from_codex_oauth(
        request_ctx,
        codex_oauth_path=codex_oauth_path,
        timeout_ms=timeout_ms,
        log=log,
    )
    _safe_log(log, "步骤：调用邀请接口（API）")
    return await invite_members_via_access_token(
        request_ctx,
        access_token=access_token,
        account_id=tokens.account_id,
        oai_device_id=oai_device_id,
        emails=emails,
        send_invite_email=send_invite_email,
        verify_invite_result=verify_invite_result,
        verify_timeout_sec=verify_timeout_sec,
        timeout_ms=timeout_ms,
    )


@dataclasses.dataclass(frozen=True)
class TokenCtxAccessContext:
    """最小化的 token_ctx 访问上下文。"""

    access_token: str
    account_id: str
    stage: str
    metadata: dict[str, Any] = dataclasses.field(default_factory=dict)


def _resolve_token_ctx_access_context(
    token_ctx: Any,
    *,
    stage: str = "token_ctx",
) -> TokenCtxAccessContext:
    if not isinstance(token_ctx, dict):
        raise ChatGptApiHealthError(f"缺少 {stage} 输入。", status=400, code="token_ctx_invalid")
    token = str(token_ctx.get("token") or "").strip()
    if not token:
        raise ChatGptApiHealthError(f"{stage} 未返回 accessToken。", status=400, code="token_missing")
    account_id = str(token_ctx.get("accountId") or "").strip()
    if not account_id:
        account_id = extract_chatgpt_account_id_from_jwt(token)
    if not account_id:
        raise ChatGptApiHealthError(f"{stage} accessToken 缺少 chatgpt_account_id。", status=500, code="account_id_missing")
    metadata: dict[str, Any] = {"stage": stage}
    if isinstance(token_ctx.get("source"), str):
        metadata["source"] = token_ctx["source"].strip()
    return TokenCtxAccessContext(access_token=token, account_id=account_id, stage=stage, metadata=metadata)


async def invite_members_via_storage_state_session(
    request_ctx: "APIRequestContext",
    *,
    storage_state_path: str,
    oai_device_id: str,
    emails: list[str],
    send_invite_email: bool = True,
    verify_invite_result: bool = False,
    verify_timeout_sec: float = 12.0,
    timeout_ms: int = 60_000,
    log: Optional[Callable[[str], None]] = None,
) -> ChatGptApiInviteResult:
    """
    功能目的：
        使用 storage_state -> session accessToken，通过 API 发送成员邀请。
    """

    _safe_log(log, "步骤：从 storage_state 读取 Cookie 并请求 session accessToken")
    access_token = await fetch_access_token_from_storage_state(
        request_ctx,
        storage_state_path=storage_state_path,
        timeout_ms=timeout_ms,
    )
    account_id = extract_chatgpt_account_id_from_jwt(access_token)
    if not account_id:
        raise ChatGptApiHealthError("session accessToken 无法解析 chatgpt_account_id（JWT payload 缺失）", status=500)

    _safe_log(log, "步骤：调用邀请接口（API）")
    return await invite_members_via_access_token(
        request_ctx,
        access_token=access_token,
        account_id=account_id,
        oai_device_id=oai_device_id,
        emails=emails,
        send_invite_email=send_invite_email,
        verify_invite_result=verify_invite_result,
        verify_timeout_sec=verify_timeout_sec,
        timeout_ms=timeout_ms,
    )


async def invite_members_via_token_ctx(
    request_ctx: "APIRequestContext",
    *,
    token_ctx: dict[str, Any],
    oai_device_id: str,
    emails: list[str],
    send_invite_email: bool = True,
    verify_invite_result: bool = False,
    verify_timeout_sec: float = 12.0,
    timeout_ms: int = 60_000,
    log: Optional[Callable[[str], None]] = None,
) -> ChatGptApiInviteResult:
    context = _resolve_token_ctx_access_context(token_ctx, stage="token_ctx")
    return await invite_members_via_access_token(
        request_ctx,
        access_token=context.access_token,
        account_id=context.account_id,
        oai_device_id=oai_device_id,
        emails=emails,
        send_invite_email=send_invite_email,
        verify_invite_result=verify_invite_result,
        verify_timeout_sec=verify_timeout_sec,
        timeout_ms=timeout_ms,
        log=log,
    )


def _extract_invite_id_from_item(item: dict[str, Any]) -> str:
    if not isinstance(item, dict):
        return ""
    invitee = item.get("invitee") if isinstance(item.get("invitee"), dict) else {}
    user = item.get("user") if isinstance(item.get("user"), dict) else {}
    return _pick_str(
        item.get("id"),
        item.get("invite_id"),
        item.get("inviteId"),
        invitee.get("id"),
        user.get("id"),
    )


async def _find_invite_item_by_email(
    request_ctx: "APIRequestContext",
    *,
    access_token: str,
    account_id: str,
    oai_device_id: str,
    email: str,
    timeout_ms: int = 60_000,
) -> Optional[dict[str, Any]]:
    query_email = str(email or "").strip().lower()
    if not _looks_like_email(query_email):
        return None

    url = (
        f"https://chatgpt.com/backend-api/accounts/{account_id}/invites"
        f"?offset=0&limit=20&query={urllib.parse.quote(query_email)}"
    )
    headers = _build_chatgpt_backend_headers(
        access_token=access_token,
        account_id=account_id,
        oai_device_id=oai_device_id,
        referer="https://chatgpt.com/admin/members?tab=invites",
    )
    headers["accept"] = "application/json, text/plain, */*"
    try:
        resp = await request_ctx.get(url, headers=headers, timeout=int(max(1000, timeout_ms)))
    except Exception as error:
        msg = _strip_playwright_call_log(str(error))
        raise ChatGptApiHealthError(
            f"???????????{msg or type(error).__name__}",
            status=0,
            code=_infer_network_code_from_message(msg),
        ) from None

    if not bool(resp.ok):
        text = ""
        try:
            text = await resp.text()
        except Exception:
            text = ""
        code = _extract_error_code_from_body(text)
        raise ChatGptApiHealthError(
            f"?????????HTTP {int(resp.status or 0)}",
            status=int(resp.status or 0),
            code=code,
        )

    payload = _sanitize_json_payload(await resp.json())
    items = _extract_invite_items(payload)
    for item in items:
        found = _extract_email_from_invite_item(item)
        if str(found or "").strip().lower() == query_email:
            return item
    return None


async def _find_member_item_by_email(
    request_ctx: "APIRequestContext",
    *,
    access_token: str,
    account_id: str,
    oai_device_id: str,
    email: str,
    member_id: str = "",
    allow_full_scan_fallback: bool = False,
    timeout_ms: int = 60_000,
) -> Optional[dict[str, str]]:
    query_email = str(email or "").strip().lower()
    target_member_id = str(member_id or "").strip()
    if (not _looks_like_email(query_email)) and not target_member_id:
        return None

    members, _total = await fetch_users_members(
        request_ctx,
        access_token=access_token,
        account_id=account_id,
        oai_device_id=oai_device_id,
        query=query_email,
        page_limit=20,
        max_items=50,
        timeout_ms=timeout_ms,
    )
    for item in members:
        item_email = str((item or {}).get("email") or "").strip().lower()
        item_member_id = _pick_str((item or {}).get("id"), (item or {}).get("user_id"), (item or {}).get("userId"), (item or {}).get("member_id"))
        if query_email and item_email == query_email:
            return item
        if target_member_id and item_member_id == target_member_id:
            return item
    if not allow_full_scan_fallback:
        return None
    members, _total = await fetch_users_members(
        request_ctx,
        access_token=access_token,
        account_id=account_id,
        oai_device_id=oai_device_id,
        query="",
        page_limit=100,
        max_items=500,
        timeout_ms=timeout_ms,
    )
    for item in members:
        item_email = str((item or {}).get("email") or "").strip().lower()
        item_member_id = _pick_str((item or {}).get("id"), (item or {}).get("user_id"), (item or {}).get("userId"), (item or {}).get("member_id"))
        if query_email and item_email == query_email:
            return item
        if target_member_id and item_member_id == target_member_id:
            return item
    return None


async def _request_team_mutation(
    request_ctx: "APIRequestContext",
    *,
    method: str,
    url: str,
    headers: dict[str, str],
    stage: str,
    payload: Optional[dict[str, Any]] = None,
    timeout_ms: int = 60_000,
) -> dict[str, Any]:
    request_method = str(method or "").strip().lower()
    sender = getattr(request_ctx, request_method, None)
    if not callable(sender):
        raise ChatGptApiHealthError(f"?????????{request_method}", status=500, code="unsupported_method")

    req_headers = dict(headers or {})
    kwargs: dict[str, Any] = {
        "headers": req_headers,
        "timeout": int(max(1000, timeout_ms)),
    }
    if payload is not None:
        req_headers["content-type"] = "application/json"
        kwargs["data"] = json.dumps(payload, ensure_ascii=False)

    try:
        resp = await sender(url, **kwargs)
    except Exception as error:
        msg = _strip_playwright_call_log(str(error))
        raise ChatGptApiHealthError(
            f"?????{msg or type(error).__name__}?{stage}?",
            status=0,
            code=_infer_network_code_from_message(msg),
        ) from None

    text = ""
    try:
        text = await resp.text()
    except Exception:
        text = ""

    if bool(resp.ok):
        stripped = str(text or "").lstrip()
        if stripped.startswith("<!DOCTYPE html") or stripped.startswith("<html"):
            raise ChatGptApiHealthError(
                f"???? HTML ?????{stage}?",
                status=int(resp.status or 0),
                code="non_json_response",
            )
        if not stripped:
            return {}
        try:
            raw_obj = json.loads(text or "{}")
        except Exception:
            return {"text": text[:2000]}
        return _sanitize_json_payload(raw_obj if isinstance(raw_obj, dict) else {"data": raw_obj})

    code = _extract_error_code_from_body(text)
    raise ChatGptApiHealthError(
        f"?????HTTP {int(resp.status or 0)}?{stage}?",
        status=int(resp.status or 0),
        code=code,
    )


async def remove_member_via_access_token(
    request_ctx: "APIRequestContext",
    *,
    access_token: str,
    account_id: str,
    oai_device_id: str,
    email: str,
    member_id: str = "",
    timeout_ms: int = 60_000,
    log: Optional[Callable[[str], None]] = None,
) -> ChatGptApiMutationResult:
    safe_email = str(email or "").strip().lower()
    safe_member_id = str(member_id or "").strip()
    if not _looks_like_email(safe_email):
        raise ChatGptApiHealthError("成员邮箱格式无效。", status=400, code="invalid_email")

    _safe_log(log, "步骤：定位目标成员")
    member = await _find_member_item_by_email(
        request_ctx,
        access_token=access_token,
        account_id=account_id,
        oai_device_id=oai_device_id,
        email=safe_email,
        member_id=safe_member_id,
        allow_full_scan_fallback=bool(safe_member_id),
        timeout_ms=timeout_ms,
    )
    if member is None:
        raise ChatGptApiHealthError("目标成员不存在或已被移除。", status=404, code="member_not_found")

    member_status = str(member.get("status") or "").strip().lower()
    if member_status in {"invited", "invite", "pending", "queued"}:
        raise ChatGptApiHealthError("目标邮箱当前仍处于邀请中，不能按已加入成员移除。", status=409, code="invite_pending")

    resolved_member_id = _pick_str(member.get("id"), member.get("user_id"), member.get("userId"), member.get("member_id"), safe_member_id)
    if not resolved_member_id:
        raise ChatGptApiHealthError("移除成员失败：缺少 member_id。", status=500, code="member_id_missing")

    headers = _build_chatgpt_backend_headers(
        access_token=access_token,
        account_id=account_id,
        oai_device_id=oai_device_id,
        referer="https://chatgpt.com/admin/members?tab=members",
    )
    headers["accept"] = "application/json, text/plain, */*"
    mutation_payload = {
        "user_id": resolved_member_id,
        "member_id": resolved_member_id,
        "email": safe_email,
    }
    endpoints = [
        ("backend_users_delete", "delete", f"https://chatgpt.com/backend-api/accounts/{account_id}/users/{resolved_member_id}", None),
        ("backend_users_remove_collection", "post", f"https://chatgpt.com/backend-api/accounts/{account_id}/users/remove", mutation_payload),
        ("backend_users_remove_item", "post", f"https://chatgpt.com/backend-api/accounts/{account_id}/users/{resolved_member_id}/remove", mutation_payload),
        ("org_users_delete", "delete", f"https://chatgpt.com/api/organizations/{account_id}/users/{resolved_member_id}", None),
        ("org_members_delete", "delete", f"https://chatgpt.com/api/organizations/{account_id}/members/{resolved_member_id}", None),
        ("org_memberships_delete", "delete", f"https://chatgpt.com/api/organizations/{account_id}/memberships/{resolved_member_id}", None),
        ("org_users_remove_collection", "post", f"https://chatgpt.com/api/organizations/{account_id}/users/remove", mutation_payload),
        ("org_members_remove_collection", "post", f"https://chatgpt.com/api/organizations/{account_id}/members/remove", mutation_payload),
    ]
    last_error: ChatGptApiHealthError | None = None

    for stage, method, url, payload in endpoints:
        try:
            raw = await _request_team_mutation(
                request_ctx,
                method=method,
                url=url,
                headers=headers,
                stage=stage,
                payload=payload,
                timeout_ms=timeout_ms,
            )
        except ChatGptApiHealthError as error:
            last_error = error
            continue

        remaining = await _find_member_item_by_email(
            request_ctx,
            access_token=access_token,
            account_id=account_id,
            oai_device_id=oai_device_id,
            email=safe_email,
            member_id=resolved_member_id,
            allow_full_scan_fallback=True,
            timeout_ms=timeout_ms,
        )
        if remaining is not None:
            last_error = ChatGptApiHealthError(
                f"移除成员后仍能查到目标成员（stage={stage}）。",
                status=409,
                code="member_not_removed",
            )
            continue

        return ChatGptApiMutationResult(
            account_id=account_id,
            target_id=resolved_member_id,
            email=safe_email,
            endpoint=stage,
            raw=raw,
        )

    if last_error is not None:
        raise last_error
    raise ChatGptApiHealthError("移除成员失败：所有候选接口均未成功。", status=0)


async def remove_member_via_codex_oauth_refresh(
    request_ctx: "APIRequestContext",
    *,
    codex_oauth_path: str,
    oai_device_id: str,
    email: str,
    member_id: str = "",
    timeout_ms: int = 60_000,
    log: Optional[Callable[[str], None]] = None,
) -> ChatGptApiMutationResult:
    _safe_log(log, "步骤：读取 Codex OAuth 认证文件")
    tokens, access_token = await _resolve_access_token_from_codex_oauth(
        request_ctx,
        codex_oauth_path=codex_oauth_path,
        timeout_ms=timeout_ms,
        log=log,
    )

    _safe_log(log, "步骤：调用移除成员接口（API）")
    return await remove_member_via_access_token(
        request_ctx,
        access_token=access_token,
        account_id=tokens.account_id,
        oai_device_id=oai_device_id,
        email=email,
        member_id=member_id,
        timeout_ms=timeout_ms,
        log=log,
    )


async def remove_member_via_storage_state_session(
    request_ctx: "APIRequestContext",
    *,
    storage_state_path: str,
    oai_device_id: str,
    email: str,
    member_id: str = "",
    timeout_ms: int = 60_000,
    log: Optional[Callable[[str], None]] = None,
) -> ChatGptApiMutationResult:
    _safe_log(log, "步骤：使用 storage_state 中的 Cookie 获取 session accessToken")
    access_token = await fetch_access_token_from_storage_state(
        request_ctx,
        storage_state_path=storage_state_path,
        timeout_ms=timeout_ms,
    )
    account_id = extract_chatgpt_account_id_from_jwt(access_token)
    if not account_id:
        raise ChatGptApiHealthError("session accessToken 缺少 chatgpt_account_id，无法从 JWT payload 解析。", status=500)

    _safe_log(log, "步骤：调用移除成员接口（API）")
    return await remove_member_via_access_token(
        request_ctx,
        access_token=access_token,
        account_id=account_id,
        oai_device_id=oai_device_id,
        email=email,
        member_id=member_id,
        timeout_ms=timeout_ms,
        log=log,
    )


async def remove_member_via_token_ctx(
    request_ctx: "APIRequestContext",
    *,
    token_ctx: dict[str, Any],
    oai_device_id: str,
    email: str,
    member_id: str = "",
    timeout_ms: int = 60_000,
    log: Optional[Callable[[str], None]] = None,
) -> ChatGptApiMutationResult:
    context = _resolve_token_ctx_access_context(token_ctx, stage="token_ctx")
    return await remove_member_via_access_token(
        request_ctx,
        access_token=context.access_token,
        account_id=context.account_id,
        oai_device_id=oai_device_id,
        email=email,
        member_id=member_id,
        timeout_ms=timeout_ms,
        log=log,
    )


async def revoke_invite_via_access_token(
    request_ctx: "APIRequestContext",
    *,
    access_token: str,
    account_id: str,
    oai_device_id: str,
    email: str,
    timeout_ms: int = 60_000,
    log: Optional[Callable[[str], None]] = None,
) -> ChatGptApiMutationResult:
    safe_email = str(email or "").strip().lower()
    if not _looks_like_email(safe_email):
        raise ChatGptApiHealthError("成员邮箱格式无效。", status=400, code="invalid_email")

    _safe_log(log, "步骤：定位目标邀请")
    invite_item = await _find_invite_item_by_email(
        request_ctx,
        access_token=access_token,
        account_id=account_id,
        oai_device_id=oai_device_id,
        email=safe_email,
        timeout_ms=timeout_ms,
    )
    if invite_item is None:
        raise ChatGptApiHealthError("目标邀请不存在或已撤回。", status=404, code="invite_not_found")

    invite_id = _extract_invite_id_from_item(invite_item)
    headers = _build_chatgpt_backend_headers(
        access_token=access_token,
        account_id=account_id,
        oai_device_id=oai_device_id,
        referer="https://chatgpt.com/admin/members?tab=invites",
    )
    headers["accept"] = "application/json, text/plain, */*"
    # 真实撤回端点：
    #   DELETE /backend-api/accounts/{account_id}/invites
    # 请求体要求使用 email_address。
    # 说明：
    #   - /invites/{invite_id} 虽然会返回 Allow: PATCH，但实测并不会撤回邀请；
    #   - /invites/revoke / /invites/cancel 并不是实际可用的撤回路由。
    mutation_payload = {
        "email_address": safe_email,
    }
    endpoints: list[tuple[str, str, str, Optional[dict[str, Any]]]] = [
        (
            "backend_invites_delete_collection_by_email",
            "delete",
            f"https://chatgpt.com/backend-api/accounts/{account_id}/invites",
            mutation_payload,
        ),
    ]
    last_error: ChatGptApiHealthError | None = None

    for stage, method, url, payload in endpoints:
        try:
            raw = await _request_team_mutation(
                request_ctx,
                method=method,
                url=url,
                headers=headers,
                stage=stage,
                payload=payload,
                timeout_ms=timeout_ms,
            )
        except ChatGptApiHealthError as error:
            last_error = error
            continue

        still_exists = True
        for attempt in range(6):
            still_exists = await _check_invite_exists_by_email(
                request_ctx,
                access_token=access_token,
                account_id=account_id,
                oai_device_id=oai_device_id,
                email=safe_email,
                timeout_ms=timeout_ms,
            )
            if not still_exists:
                break
            if attempt < 5:
                await asyncio.sleep(1)
        if still_exists:
            last_error = ChatGptApiHealthError(
                f"撤回邀请后仍能查到目标邀请（stage={stage}）。",
                status=409,
                code="invite_not_revoked",
            )
            continue

        return ChatGptApiMutationResult(
            account_id=account_id,
            target_id=invite_id or safe_email,
            email=safe_email,
            endpoint=stage,
            raw=raw,
        )

    if last_error is not None:
        raise last_error
    raise ChatGptApiHealthError("撤回邀请失败：所有候选接口均未成功。", status=0)


async def revoke_invite_via_codex_oauth_refresh(
    request_ctx: "APIRequestContext",
    *,
    codex_oauth_path: str,
    oai_device_id: str,
    email: str,
    timeout_ms: int = 60_000,
    log: Optional[Callable[[str], None]] = None,
) -> ChatGptApiMutationResult:
    _safe_log(log, "步骤：读取 Codex OAuth 认证文件")
    tokens, access_token = await _resolve_access_token_from_codex_oauth(
        request_ctx,
        codex_oauth_path=codex_oauth_path,
        timeout_ms=timeout_ms,
        log=log,
    )

    _safe_log(log, "步骤：调用撤回邀请接口（API）")
    return await revoke_invite_via_access_token(
        request_ctx,
        access_token=access_token,
        account_id=tokens.account_id,
        oai_device_id=oai_device_id,
        email=email,
        timeout_ms=timeout_ms,
        log=log,
    )


async def revoke_invite_via_storage_state_session(
    request_ctx: "APIRequestContext",
    *,
    storage_state_path: str,
    oai_device_id: str,
    email: str,
    timeout_ms: int = 60_000,
    log: Optional[Callable[[str], None]] = None,
) -> ChatGptApiMutationResult:
    _safe_log(log, "步骤：使用 storage_state 中的 Cookie 获取 session accessToken")
    access_token = await fetch_access_token_from_storage_state(
        request_ctx,
        storage_state_path=storage_state_path,
        timeout_ms=timeout_ms,
    )
    account_id = extract_chatgpt_account_id_from_jwt(access_token)
    if not account_id:
        raise ChatGptApiHealthError("session accessToken 缺少 chatgpt_account_id，无法从 JWT payload 解析。", status=500)

    _safe_log(log, "步骤：调用撤回邀请接口（API）")
    return await revoke_invite_via_access_token(
        request_ctx,
        access_token=access_token,
        account_id=account_id,
        oai_device_id=oai_device_id,
        email=email,
        timeout_ms=timeout_ms,
        log=log,
    )


async def revoke_invite_via_token_ctx(
    request_ctx: "APIRequestContext",
    *,
    token_ctx: dict[str, Any],
    oai_device_id: str,
    email: str,
    timeout_ms: int = 60_000,
    log: Optional[Callable[[str], None]] = None,
) -> ChatGptApiMutationResult:
    context = _resolve_token_ctx_access_context(token_ctx, stage="token_ctx")
    return await revoke_invite_via_access_token(
        request_ctx,
        access_token=context.access_token,
        account_id=context.account_id,
        oai_device_id=oai_device_id,
        email=email,
        timeout_ms=timeout_ms,
        log=log,
    )


async def list_members_via_codex_oauth_refresh(
    request_ctx: "APIRequestContext",
    *,
    codex_oauth_path: str,
    oai_device_id: str,
    query: str = "",
    page_limit: int = 100,
    max_items: int = 300,
    timeout_ms: int = 60_000,
    log: Optional[Callable[[str], None]] = None,
) -> ChatGptApiMembers:
    """
    功能目的：
        通过 Codex OAuth 刷新 access_token，并拉取成员邮箱列表。
    """

    tokens, access_token = await _resolve_access_token_from_codex_oauth(
        request_ctx,
        codex_oauth_path=codex_oauth_path,
        timeout_ms=timeout_ms,
        log=log,
    )
    _safe_log(log, "步骤：读取成员列表（backend-api/users）")
    joined_members, joined_total = await fetch_users_members(
        request_ctx,
        access_token=access_token,
        account_id=tokens.account_id,
        oai_device_id=oai_device_id,
        query=query,
        page_limit=page_limit,
        max_items=max_items,
        timeout_ms=timeout_ms,
    )
    invite_members: list[dict[str, str]] = []
    invite_total = 0
    try:
        invite_members, invite_total = await fetch_invite_members(
            request_ctx,
            access_token=access_token,
            account_id=tokens.account_id,
            oai_device_id=oai_device_id,
            query=query,
            page_limit=page_limit,
            max_items=max_items,
            timeout_ms=timeout_ms,
        )
    except Exception as error:  # noqa: BLE001
        _safe_log(log, f"步骤：读取待接受邀请失败，已回退为仅显示成员列表：{error}")
    members = _merge_member_rows(joined_members, invite_members)
    total = int(max(0, int(joined_total or 0) + int(invite_total or 0)))
    _safe_log(
        log,
        f"步骤：成员列表读取完成（members={int(joined_total)}，invites={int(invite_total)}，parsed={int(len(members))}）",
    )
    return ChatGptApiMembers(
        account_id=tokens.account_id,
        total=total,
        members=members,
        user_total=int(joined_total),
        invite_total=int(invite_total),
    )


async def list_members_via_storage_state_session(
    request_ctx: "APIRequestContext",
    *,
    storage_state_path: str,
    oai_device_id: str,
    query: str = "",
    page_limit: int = 100,
    max_items: int = 300,
    timeout_ms: int = 60_000,
    log: Optional[Callable[[str], None]] = None,
) -> ChatGptApiMembers:
    """
    功能目的：
        通过 storage_state -> session accessToken 拉取成员邮箱列表。
    """

    _safe_log(log, "步骤：从 storage_state 读取 Cookie 并请求 session accessToken")
    access_token = await fetch_access_token_from_storage_state(
        request_ctx,
        storage_state_path=storage_state_path,
        timeout_ms=timeout_ms,
    )
    account_id = extract_chatgpt_account_id_from_jwt(access_token)
    if not account_id:
        raise ChatGptApiHealthError("session accessToken 无法解析 chatgpt_account_id（JWT payload 缺失）", status=500)

    _safe_log(log, "步骤：读取成员列表（backend-api/users）")
    joined_members, joined_total = await fetch_users_members(
        request_ctx,
        access_token=access_token,
        account_id=account_id,
        oai_device_id=oai_device_id,
        query=query,
        page_limit=page_limit,
        max_items=max_items,
        timeout_ms=timeout_ms,
    )
    invite_members: list[dict[str, str]] = []
    invite_total = 0
    try:
        invite_members, invite_total = await fetch_invite_members(
            request_ctx,
            access_token=access_token,
            account_id=account_id,
            oai_device_id=oai_device_id,
            query=query,
            page_limit=page_limit,
            max_items=max_items,
            timeout_ms=timeout_ms,
        )
    except Exception as error:  # noqa: BLE001
        _safe_log(log, f"步骤：读取待接受邀请失败，已回退为仅显示成员列表：{error}")
    members = _merge_member_rows(joined_members, invite_members)
    total = int(max(0, int(joined_total or 0) + int(invite_total or 0)))
    _safe_log(
        log,
        f"步骤：成员列表读取完成（members={int(joined_total)}，invites={int(invite_total)}，parsed={int(len(members))}）",
    )
    return ChatGptApiMembers(
        account_id=account_id,
        total=total,
        members=members,
        user_total=int(joined_total),
        invite_total=int(invite_total),
    )


async def list_members_via_token_ctx(
    request_ctx: "APIRequestContext",
    *,
    token_ctx: dict[str, Any],
    oai_device_id: str,
    query: str = "",
    page_limit: int = 100,
    max_items: int = 300,
    timeout_ms: int = 60_000,
    log: Optional[Callable[[str], None]] = None,
) -> ChatGptApiMembers:
    context = _resolve_token_ctx_access_context(token_ctx, stage="token_ctx")
    _safe_log(log, "步骤：使用 token_ctx accessToken 读取成员列表（backend-api/users）")
    joined_members, joined_total = await fetch_users_members(
        request_ctx,
        access_token=context.access_token,
        account_id=context.account_id,
        oai_device_id=oai_device_id,
        query=query,
        page_limit=page_limit,
        max_items=max_items,
        timeout_ms=timeout_ms,
    )
    invite_members: list[dict[str, str]] = []
    invite_total = 0
    try:
        invite_members, invite_total = await fetch_invite_members(
            request_ctx,
            access_token=context.access_token,
            account_id=context.account_id,
            oai_device_id=oai_device_id,
            query=query,
            page_limit=page_limit,
            max_items=max_items,
            timeout_ms=timeout_ms,
        )
    except Exception as error:  # noqa: BLE001
        _safe_log(log, f"步骤：读取待接受邀请失败，已回退为仅显示成员列表：{error}")
    members = _merge_member_rows(joined_members, invite_members)
    total = int(max(0, int(joined_total or 0) + int(invite_total or 0)))
    _safe_log(
        log,
        f"步骤：成员列表读取完成（members={int(joined_total)}，invites={int(invite_total)}，parsed={int(len(members))}）",
    )
    return ChatGptApiMembers(
        account_id=context.account_id,
        total=total,
        members=members,
        user_total=int(joined_total),
        invite_total=int(invite_total),
    )


async def fetch_users_total_ipv4(
    *,
    access_token: str,
    account_id: str,
    oai_device_id: str,
    timeout_ms: int = 60_000,
) -> int:
    """
    功能目的：
        调用 backend-api/users 获取 total（IPv4 直连）。
    """

    timeout_ms = _read_timeout_ms("AIO_TEAM_HEALTHCHECK_BACKEND_TIMEOUT_MS", timeout_ms)

    url = f"https://chatgpt.com/backend-api/accounts/{account_id}/users?offset=0&limit=1&query="
    headers = _build_chatgpt_backend_headers(
        access_token=access_token,
        account_id=account_id,
        oai_device_id=oai_device_id,
        referer="https://chatgpt.com/admin/members?tab=members",
    )
    headers["accept-encoding"] = "identity"

    status, _hdrs, text = await _https_request_text_ipv4(
        url=url,
        method="GET",
        headers=headers,
        data=None,
        timeout_ms=timeout_ms,
        err_prefix="读取成员数请求失败",
    )
    if int(status) < 200 or int(status) >= 300:
        code = _extract_error_code_from_body(text)
        raise ChatGptApiHealthError(f"读取成员数失败：HTTP {int(status)}", status=int(status), code=code)
    data = _sanitize_json_payload(json.loads(text or "{}"))
    total = data.get("total")
    if not isinstance(total, (int, float)):
        raise ChatGptApiHealthError("成员响应格式异常：缺少 total 字段", status=int(status))
    return int(total)


async def fetch_invites_total(
    request_ctx: "APIRequestContext",
    *,
    access_token: str,
    account_id: str,
    oai_device_id: str,
    timeout_ms: int = 60_000,
) -> int:
    """
    功能目的：
        调用 backend-api/invites 获取 total，用于同步 invite_count。
    """

    timeout_ms = _read_timeout_ms("AIO_TEAM_HEALTHCHECK_BACKEND_TIMEOUT_MS", timeout_ms)

    url = f"https://chatgpt.com/backend-api/accounts/{account_id}/invites?offset=0&limit=1&query="
    headers = _build_chatgpt_backend_headers(
        access_token=access_token,
        account_id=account_id,
        oai_device_id=oai_device_id,
        referer="https://chatgpt.com/admin/members?tab=invites",
    )
    try:
        resp = await request_ctx.get(url, headers=headers, timeout=int(max(1000, timeout_ms)))
    except Exception as error:
        msg = _strip_playwright_call_log(str(error))
        raise ChatGptApiHealthError(
            f"读取邀请数请求失败：{msg or type(error).__name__}",
            status=0,
            code=_infer_network_code_from_message(msg),
        ) from None
    if not bool(resp.ok):
        text = ""
        try:
            text = await resp.text()
        except Exception:
            text = ""
        code = _extract_error_code_from_body(text)
        raise ChatGptApiHealthError(f"读取邀请数失败：HTTP {resp.status}", status=int(resp.status or 0), code=code)
    data = _sanitize_json_payload(await resp.json())
    total = data.get("total")
    if not isinstance(total, (int, float)):
        raise ChatGptApiHealthError("邀请响应格式异常：缺少 total 字段", status=int(resp.status or 0))
    return int(total)


async def fetch_invites_total_ipv4(
    *,
    access_token: str,
    account_id: str,
    oai_device_id: str,
    timeout_ms: int = 60_000,
) -> int:
    """
    功能目的：
        调用 backend-api/invites 获取 total（IPv4 直连）。
    """

    timeout_ms = _read_timeout_ms("AIO_TEAM_HEALTHCHECK_BACKEND_TIMEOUT_MS", timeout_ms)

    url = f"https://chatgpt.com/backend-api/accounts/{account_id}/invites?offset=0&limit=1&query="
    headers = _build_chatgpt_backend_headers(
        access_token=access_token,
        account_id=account_id,
        oai_device_id=oai_device_id,
        referer="https://chatgpt.com/admin/members?tab=invites",
    )
    headers["accept-encoding"] = "identity"

    status, _hdrs, text = await _https_request_text_ipv4(
        url=url,
        method="GET",
        headers=headers,
        data=None,
        timeout_ms=timeout_ms,
        err_prefix="读取邀请数请求失败",
    )
    if int(status) < 200 or int(status) >= 300:
        code = _extract_error_code_from_body(text)
        raise ChatGptApiHealthError(f"读取邀请数失败：HTTP {int(status)}", status=int(status), code=code)
    data = _sanitize_json_payload(json.loads(text or "{}"))
    total = data.get("total")
    if not isinstance(total, (int, float)):
        raise ChatGptApiHealthError("邀请响应格式异常：缺少 total 字段", status=int(status))
    return int(total)


async def check_via_codex_oauth_refresh(
    request_ctx: "APIRequestContext",
    *,
    codex_oauth_path: str,
    oai_device_id: str,
    timeout_ms: int = 60_000,
    log: Optional[Callable[[str], None]] = None,
) -> ChatGptApiCounts:
    """
    功能目的：
        使用 Codex OAuth refresh_token 刷新后，调用 backend-api 检活并获取人数。
    """

    tokens, access_token = await _resolve_access_token_from_codex_oauth(
        request_ctx,
        codex_oauth_path=codex_oauth_path,
        timeout_ms=timeout_ms,
        log=log,
    )
    _safe_log(log, "步骤：读取成员数（backend-api/users）")
    user_total = await fetch_users_total(
        request_ctx,
        access_token=access_token,
        account_id=tokens.account_id,
        oai_device_id=oai_device_id,
        timeout_ms=timeout_ms,
    )
    _safe_log(log, f"步骤：成员数读取完成（user_total={int(user_total)}）")
    invite_total: Optional[int]
    try:
        _safe_log(log, "步骤：读取邀请数（backend-api/invites）")
        invite_total = await fetch_invites_total(
            request_ctx,
            access_token=access_token,
            account_id=tokens.account_id,
            oai_device_id=oai_device_id,
            timeout_ms=timeout_ms,
        )
        _safe_log(log, f"步骤：邀请数读取完成（invite_total={int(invite_total)}）")
    except Exception:
        _safe_log(log, "步骤：邀请数读取失败（已忽略，不影响成员数检活）")
        invite_total = None
    return ChatGptApiCounts(user_total=user_total, invite_total=invite_total)


async def check_via_codex_oauth_refresh_ipv4(
    *,
    codex_oauth_path: str,
    oai_device_id: str,
    timeout_ms: int = 60_000,
) -> ChatGptApiCounts:
    """
    功能目的：
        使用 Codex OAuth refresh_token 刷新后，调用 backend-api 检活并获取人数（IPv4 直连）。
    """

    tokens = load_codex_oauth_tokens(codex_oauth_path)
    if tokens is None:
        raise ChatGptApiHealthError("无可用 Codex OAuth 认证文件（缺少 account_id/refresh_token）", status=400)

    refreshed = await refresh_access_token_ipv4(refresh_token=tokens.refresh_token, timeout_ms=timeout_ms)
    access_token = str(refreshed.get("access_token") or "").strip()
    new_refresh_token = str(refreshed.get("refresh_token") or "").strip()
    if new_refresh_token:
        persist_refresh_token_enc(path=codex_oauth_path, payload=tokens.raw_payload, refresh_token=new_refresh_token)
    else:
        if not str(tokens.raw_payload.get("refresh_token_enc") or "").strip():
            persist_refresh_token_enc(path=codex_oauth_path, payload=tokens.raw_payload, refresh_token=tokens.refresh_token)

    user_total = await fetch_users_total_ipv4(
        access_token=access_token,
        account_id=tokens.account_id,
        oai_device_id=oai_device_id,
        timeout_ms=timeout_ms,
    )
    invite_total: Optional[int]
    try:
        invite_total = await fetch_invites_total_ipv4(
            access_token=access_token,
            account_id=tokens.account_id,
            oai_device_id=oai_device_id,
            timeout_ms=timeout_ms,
        )
    except Exception:
        invite_total = None
    return ChatGptApiCounts(user_total=user_total, invite_total=invite_total)


async def check_via_session(
    request_ctx: "APIRequestContext",
    *,
    oai_device_id: str,
    timeout_ms: int = 60_000,
) -> ChatGptApiCounts:
    """
    功能目的：
        复用浏览器 session（Cookie）获取 accessToken，并通过 JWT payload 提取 account_id 后检活。
    """

    access_token = await fetch_access_token_from_session(request_ctx, timeout_ms=timeout_ms)
    account_id = extract_chatgpt_account_id_from_jwt(access_token)
    if not account_id:
        raise ChatGptApiHealthError("session accessToken 无法解析 chatgpt_account_id（JWT payload 缺失）", status=500)
    user_total = await fetch_users_total(
        request_ctx, access_token=access_token, account_id=account_id, oai_device_id=oai_device_id, timeout_ms=timeout_ms
    )
    invite_total: Optional[int]
    try:
        invite_total = await fetch_invites_total(
            request_ctx,
            access_token=access_token,
            account_id=account_id,
            oai_device_id=oai_device_id,
            timeout_ms=timeout_ms,
        )
    except Exception:
        invite_total = None
    return ChatGptApiCounts(user_total=user_total, invite_total=invite_total)


async def check_via_storage_state_session(
    request_ctx: "APIRequestContext",
    *,
    storage_state_path: str,
    oai_device_id: str,
    timeout_ms: int = 60_000,
    log: Optional[Callable[[str], None]] = None,
) -> ChatGptApiCounts:
    """
    功能目的：
        复用 storage_state（Cookie）调用 session API 获取 accessToken，再通过 backend-api 检活。

    说明：
        - 与 `check_via_storage_state_session_ipv4()` 类似，但使用 Playwright 请求栈，避免 urllib 指纹导致的 403。
    """

    _safe_log(log, "步骤：从 storage_state 读取 Cookie 并请求 session accessToken")
    access_token = await fetch_access_token_from_storage_state(
        request_ctx,
        storage_state_path=storage_state_path,
        timeout_ms=timeout_ms,
    )
    account_id = extract_chatgpt_account_id_from_jwt(access_token)
    if not account_id:
        raise ChatGptApiHealthError("session accessToken 无法解析 chatgpt_account_id（JWT payload 缺失）", status=500)

    _safe_log(log, "步骤：读取成员数（backend-api/users）")
    user_total = await fetch_users_total(
        request_ctx,
        access_token=access_token,
        account_id=account_id,
        oai_device_id=oai_device_id,
        timeout_ms=timeout_ms,
    )
    _safe_log(log, f"步骤：成员数读取完成（user_total={int(user_total)}）")
    invite_total: Optional[int]
    try:
        _safe_log(log, "步骤：读取邀请数（backend-api/invites）")
        invite_total = await fetch_invites_total(
            request_ctx,
            access_token=access_token,
            account_id=account_id,
            oai_device_id=oai_device_id,
            timeout_ms=timeout_ms,
        )
        _safe_log(log, f"步骤：邀请数读取完成（invite_total={int(invite_total)}）")
    except Exception:
        _safe_log(log, "步骤：邀请数读取失败（已忽略，不影响成员数检活）")
        invite_total = None
    return ChatGptApiCounts(user_total=user_total, invite_total=invite_total)


async def check_via_storage_state_session_ipv4(
    *,
    storage_state_path: str,
    oai_device_id: str,
    timeout_ms: int = 60_000,
) -> ChatGptApiCounts:
    """
    功能目的：
        复用 storage_state（Cookie）调用 session API 获取 accessToken，再通过 backend-api 检活（IPv4 直连）。
    """

    access_token = await fetch_access_token_from_storage_state_ipv4(storage_state_path=storage_state_path, timeout_ms=timeout_ms)
    account_id = extract_chatgpt_account_id_from_jwt(access_token)
    if not account_id:
        raise ChatGptApiHealthError("session accessToken 无法解析 chatgpt_account_id（JWT payload 缺失）", status=500)

    user_total = await fetch_users_total_ipv4(
        access_token=access_token,
        account_id=account_id,
        oai_device_id=oai_device_id,
        timeout_ms=timeout_ms,
    )
    invite_total: Optional[int]
    try:
        invite_total = await fetch_invites_total_ipv4(
            access_token=access_token,
            account_id=account_id,
            oai_device_id=oai_device_id,
            timeout_ms=timeout_ms,
        )
    except Exception:
        invite_total = None
    return ChatGptApiCounts(user_total=user_total, invite_total=invite_total)
