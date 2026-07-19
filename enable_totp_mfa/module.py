from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import hmac
import json
import re
import struct
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

MFA_INFO_URL = "https://chatgpt.com/backend-api/accounts/mfa_info"
MFA_ENROLL_URL = "https://chatgpt.com/backend-api/accounts/mfa/enroll"
MFA_ACTIVATE_URL = "https://chatgpt.com/backend-api/accounts/mfa/user/activate_enrollment"
AUTH_SESSION_URL = "https://chatgpt.com/api/auth/session"
DEFAULT_CHATGPT_REFERER = "https://chatgpt.com/#settings/Security"
DEFAULT_CHATGPT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/142.0.0.0 Safari/537.36"
)
MFA_ACTIVATE_CONFIRM_RETRIES = 5
MFA_ACTIVATE_CONFIRM_INTERVAL_SECONDS = 2.0
CHATGPT_CLIENT_HEADER_ALLOWLIST = (
    "oai-client-build-number",
    "oai-client-version",
    "oai-session-id",
    "sec-ch-ua",
    "sec-ch-ua-arch",
    "sec-ch-ua-bitness",
    "sec-ch-ua-full-version",
    "sec-ch-ua-full-version-list",
    "sec-ch-ua-mobile",
    "sec-ch-ua-model",
    "sec-ch-ua-platform",
    "sec-ch-ua-platform-version",
)


class ChatGptTotpMfaError(RuntimeError):
    """2FA 开通异常。"""

    def __init__(self, message: str, *, status: int = 0, code: str = "", stage: str = "") -> None:
        super().__init__(message)
        self.status = int(status or 0)
        self.code = str(code or "").strip()
        self.stage = str(stage or "").strip()


def _safe_log(log: Callable[[str], None] | None, message: str) -> None:
    if log is None:
        return
    text = str(message or "").strip()
    if not text:
        return
    try:
        log(text)
    except Exception:
        return


def normalize_totp_secret(secret: str) -> str:
    return re.sub(r"\s+", "", str(secret or "").strip()).upper()


def mask_totp_secret(secret: str) -> str:
    normalized = normalize_totp_secret(secret)
    if not normalized:
        return ""
    if len(normalized) <= 8:
        return normalized[0] + ("*" * max(0, len(normalized) - 2)) + normalized[-1:]
    return f"{normalized[:4]}{'*' * max(4, len(normalized) - 8)}{normalized[-4:]}"


def generate_totp_code(secret: str, *, for_time: int | None = None) -> str:
    normalized = normalize_totp_secret(secret)
    if not normalized:
        raise ValueError("TOTP secret 为空")

    try:
        import pyotp  # type: ignore

        totp = pyotp.TOTP(normalized)
        if for_time is None:
            return str(totp.now()).zfill(6)
        return str(totp.at(int(for_time))).zfill(6)
    except Exception:
        try:
            key = base64.b32decode(normalized, casefold=True)
        except Exception as error:
            raise ValueError("TOTP secret 不是有效的 Base32 字符串") from error

        timestamp = int(time.time()) if for_time is None else int(for_time)
        counter = int(timestamp // 30)
        digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
        return str(code % 1_000_000).zfill(6)


def _load_storage_state_payload(storage_state_path: str) -> dict[str, Any]:
    safe_path = Path(str(storage_state_path or "").strip()).expanduser()
    if not str(safe_path) or (not safe_path.exists()):
        raise ChatGptTotpMfaError(
            f"storage_state 不存在：{safe_path}",
            status=400,
            code="invalid_storage_state",
            stage="load_storage_state",
        )
    try:
        payload = json.loads(safe_path.read_text(encoding="utf-8") or "{}")
    except Exception as error:
        raise ChatGptTotpMfaError(
            f"storage_state 读取失败：{error}",
            status=400,
            code="invalid_storage_state",
            stage="load_storage_state",
        ) from error
    if not isinstance(payload, dict):
        raise ChatGptTotpMfaError(
            "storage_state 根节点不是对象",
            status=400,
            code="invalid_storage_state",
            stage="load_storage_state",
        )
    return payload


def _domain_match_cookie(cookie_domain: str, target_host: str) -> bool:
    cookie_value = str(cookie_domain or "").strip().lstrip(".").lower()
    target_value = str(target_host or "").strip().lower()
    if not cookie_value or not target_value:
        return False
    if cookie_value == target_value:
        return True
    return target_value.endswith("." + cookie_value)


def _extract_storage_state_cookies(payload: dict[str, Any]) -> list[dict[str, Any]]:
    cookies = payload.get("cookies")
    if not isinstance(cookies, list):
        return []
    return [dict(item) for item in cookies if isinstance(item, dict)]


def _build_cookie_header_from_cookies(*, cookies: list[dict[str, Any]], target_host: str) -> str:
    parts: list[str] = []
    for cookie in cookies:
        if not _domain_match_cookie(str(cookie.get("domain") or ""), target_host):
            continue
        name = str(cookie.get("name") or "").strip()
        if not name:
            continue
        parts.append(f"{name}={str(cookie.get('value') or '').strip()}")
    return "; ".join(parts)


def _read_cookie_value(*, cookies: list[dict[str, Any]], cookie_name: str, target_host: str) -> str:
    safe_name = str(cookie_name or "").strip()
    if not safe_name:
        return ""
    for cookie in cookies:
        if str(cookie.get("name") or "").strip() != safe_name:
            continue
        if not _domain_match_cookie(str(cookie.get("domain") or ""), target_host):
            continue
        return str(cookie.get("value") or "").strip()
    return ""


def load_cookie_header_from_storage_state(*, storage_state_path: str, target_host: str) -> str:
    payload = _load_storage_state_payload(storage_state_path)
    cookies = _extract_storage_state_cookies(payload)
    return _build_cookie_header_from_cookies(cookies=cookies, target_host=target_host)


def try_read_oai_did_from_storage_state(storage_state_path: str) -> str:
    payload = _load_storage_state_payload(storage_state_path)
    return _read_cookie_value(
        cookies=_extract_storage_state_cookies(payload),
        cookie_name="oai-did",
        target_host="chatgpt.com",
    )


def read_access_token_from_storage_state(storage_state_path: str) -> str:
    payload = _load_storage_state_payload(storage_state_path)
    return str(payload.get("session_access_token") or payload.get("accessToken") or "").strip()


def _extract_error_code_from_body(text: str) -> str:
    raw = str(text or "").strip()
    if not raw:
        return ""
    try:
        payload = json.loads(raw)
    except Exception:
        return ""
    if not isinstance(payload, dict):
        return ""
    code = payload.get("code")
    if isinstance(code, str) and code.strip():
        return code.strip()
    error_payload = payload.get("error")
    if isinstance(error_payload, dict):
        nested_code = error_payload.get("code")
        if isinstance(nested_code, str) and nested_code.strip():
            return nested_code.strip()
    return ""


def _sanitize_json_payload(payload: Any) -> dict[str, Any]:
    return payload if isinstance(payload, dict) else {}


def _import_requests_for_proxy():
    try:
        import requests as _req  # type: ignore
    except ImportError as error:
        raise ChatGptTotpMfaError(
            "代理模式缺少 requests，请先安装 requirements.txt 中的依赖",
            status=500,
            code="requests_missing",
            stage="proxy_setup",
        ) from error

    try:
        import socks  # noqa: F401
    except ImportError as error:
        raise ChatGptTotpMfaError(
            "代理模式缺少 PySocks，请安装 requests[socks]",
            status=500,
            code="pysocks_missing",
            stage="proxy_setup",
        ) from error

    return _req


def _build_proxy_mapping(proxy: str | None) -> dict[str, str] | None:
    proxy_value = str(proxy or "").strip()
    if not proxy_value:
        return None
    if "://" in proxy_value:
        proxy_url = proxy_value
    else:
        parts = [str(part or "").strip() for part in proxy_value.split(":")]
        if len(parts) >= 4 and parts[0] and parts[1]:
            proxy_url = f"socks5h://{parts[2]}:{parts[3]}@{parts[0]}:{parts[1]}"
        else:
            proxy_url = f"socks5h://{proxy_value}"
    return {"http": proxy_url, "https": proxy_url}


def _normalize_chatgpt_client_headers(headers: dict[str, Any] | None) -> dict[str, str]:
    payload = headers if isinstance(headers, dict) else {}
    normalized: dict[str, str] = {}
    for key in CHATGPT_CLIENT_HEADER_ALLOWLIST:
        value = str(payload.get(key) or "").strip()
        if value:
            normalized[key] = value
    return normalized


def _build_chatgpt_mfa_headers(
    *,
    access_token: str,
    cookie_header: str,
    oai_device_id: str,
    referer: str,
    client_headers: dict[str, Any] | None = None,
) -> dict[str, str]:
    headers = {
        "accept": "application/json, text/plain, */*",
        "accept-language": "zh-CN,zh;q=0.9",
        "authorization": f"Bearer {str(access_token or '').strip()}",
        "cookie": str(cookie_header or "").strip(),
        "oai-language": "zh-CN",
        "origin": "https://chatgpt.com",
        "referer": str(referer or DEFAULT_CHATGPT_REFERER).strip() or DEFAULT_CHATGPT_REFERER,
        "user-agent": DEFAULT_CHATGPT_USER_AGENT,
    }
    headers.update(_normalize_chatgpt_client_headers(client_headers))
    if str(oai_device_id or "").strip():
        headers["oai-device-id"] = str(oai_device_id).strip()
    return headers


def _build_chatgpt_session_headers(
    *,
    cookie_header: str,
    oai_device_id: str,
    referer: str,
) -> dict[str, str]:
    headers = {
        "accept": "application/json, text/plain, */*",
        "accept-language": "zh-CN,zh;q=0.9",
        "cookie": str(cookie_header or "").strip(),
        "oai-language": "zh-CN",
        "origin": "https://chatgpt.com",
        "referer": str(referer or DEFAULT_CHATGPT_REFERER).strip() or DEFAULT_CHATGPT_REFERER,
        "user-agent": DEFAULT_CHATGPT_USER_AGENT,
    }
    if str(oai_device_id or "").strip():
        headers["oai-device-id"] = str(oai_device_id).strip()
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


def _request_chatgpt_mfa_json(
    *,
    method: str,
    url: str,
    headers: dict[str, str],
    payload: dict[str, Any] | None = None,
    timeout_ms: int = 60_000,
    stage: str,
    proxy: str | None = None,
) -> dict[str, Any]:
    request_headers = dict(headers or {})
    safe_url = str(url or "").strip()
    target_match = re.match(r"^https://chatgpt\.com(?P<path>/[^?#]*)", safe_url, flags=re.I)
    if target_match:
        target_path = str(target_match.group("path") or "").strip()
        if target_path:
            request_headers["x-openai-target-path"] = target_path
            request_headers["x-openai-target-route"] = target_path
    body_bytes: bytes | None = None
    if payload is not None:
        request_headers["content-type"] = "application/json"
        body_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")

    timeout_sec = max(1.0, float(int(timeout_ms or 60_000)) / 1000.0)
    text = ""
    if str(proxy or "").strip():
        request_lib = _import_requests_for_proxy()
        try:
            response = request_lib.request(
                method=str(method or "GET").upper(),
                url=safe_url,
                headers=request_headers,
                data=body_bytes,
                timeout=timeout_sec,
                proxies=_build_proxy_mapping(proxy),
            )
            status = int(response.status_code or 0)
            text = str(getattr(response, "text", "") or "").strip()
        except Exception as error:
            raise ChatGptTotpMfaError(
                f"MFA 请求失败（{stage}）：{error}",
                status=0,
                code="network_error",
                stage=stage,
            ) from error
    else:
        request = urllib.request.Request(
            url=safe_url,
            data=body_bytes,
            method=str(method or "GET").upper(),
        )
        for key, value in request_headers.items():
            safe_key = str(key or "").strip()
            if safe_key:
                request.add_header(safe_key, str(value))

        try:
            with urllib.request.urlopen(request, timeout=timeout_sec) as response:
                status = int(response.getcode() or 0)
                body = response.read()
        except urllib.error.HTTPError as error:
            status = int(error.code or 0)
            try:
                body = error.read()
            except Exception:
                body = b""
        except Exception as error:
            raise ChatGptTotpMfaError(
                f"MFA 请求失败（{stage}）：{error}",
                status=0,
                code="network_error",
                stage=stage,
            ) from error

        text = body.decode("utf-8", errors="replace").strip()
    data: dict[str, Any] = {}
    if text:
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                data = _sanitize_json_payload(parsed)
            else:
                data = {"data": parsed}
        except Exception:
            data = {"text": text[:2000]}

    if status not in {200, 201, 202, 204}:
        raise ChatGptTotpMfaError(
            f"MFA 请求失败，HTTP {status}（{stage}）",
            status=status,
            code=_extract_error_code_from_body(text),
            stage=stage,
        )
    return data


def _extract_access_token_from_session_payload(payload: dict[str, Any]) -> str:
    if not isinstance(payload, dict):
        return ""
    token = payload.get("accessToken")
    if isinstance(token, str) and token.strip():
        return token.strip()
    token = payload.get("access_token")
    if isinstance(token, str) and token.strip():
        return token.strip()
    return ""


def read_auth_session_via_cookie_header(
    *,
    cookie_header: str,
    oai_device_id: str = "",
    referer: str = DEFAULT_CHATGPT_REFERER,
    timeout_ms: int = 60_000,
    proxy: str | None = None,
) -> dict[str, Any]:
    safe_cookie = str(cookie_header or "").strip()
    if not safe_cookie:
        return {}
    return _request_chatgpt_mfa_json(
        method="GET",
        url=AUTH_SESSION_URL,
        headers=_build_chatgpt_session_headers(
            cookie_header=safe_cookie,
            oai_device_id=oai_device_id,
            referer=referer,
        ),
        timeout_ms=timeout_ms,
        stage="auth_session",
        proxy=proxy,
    )


def read_access_token_via_cookie_header(
    *,
    cookie_header: str,
    oai_device_id: str = "",
    referer: str = DEFAULT_CHATGPT_REFERER,
    timeout_ms: int = 60_000,
    proxy: str | None = None,
) -> str:
    payload = read_auth_session_via_cookie_header(
        cookie_header=cookie_header,
        oai_device_id=oai_device_id,
        referer=referer,
        timeout_ms=timeout_ms,
        proxy=proxy,
    )
    return _extract_access_token_from_session_payload(payload)


def enable_totp_mfa_with_credentials(
    *,
    access_token: str,
    cookie_header: str,
    oai_device_id: str = "",
    referer: str = DEFAULT_CHATGPT_REFERER,
    client_headers: dict[str, Any] | None = None,
    timeout_ms: int = 60_000,
    log: Callable[[str], None] | None = None,
    proxy: str | None = None,
    before_activate: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    token_value = str(access_token or "").strip()
    if not token_value:
        raise ChatGptTotpMfaError(
            "开通 2FA 失败：缺少 access_token",
            status=401,
            code="missing_access_token",
            stage="validate_input",
        )

    safe_cookie = str(cookie_header or "").strip()
    if not safe_cookie:
        raise ChatGptTotpMfaError(
            "开通 2FA 失败：缺少 chatgpt.com cookies",
            status=400,
            code="no_cookie",
            stage="validate_input",
        )

    headers = _build_chatgpt_mfa_headers(
        access_token=token_value,
        cookie_header=safe_cookie,
        oai_device_id=oai_device_id,
        referer=referer,
        client_headers=client_headers,
    )

    _safe_log(log, "步骤 1/4：读取当前 MFA 状态")
    info_before = _request_chatgpt_mfa_json(
        method="GET",
        url=MFA_INFO_URL,
        headers=headers,
        timeout_ms=timeout_ms,
        stage="mfa_info_before",
        proxy=proxy,
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
            "updatedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
            "mfaInfo": info_before,
        }

    _safe_log(log, "步骤 2/4：创建 TOTP enroll 会话")
    enroll_payload = _request_chatgpt_mfa_json(
        method="POST",
        url=MFA_ENROLL_URL,
        headers=headers,
        payload={"factor_type": "totp"},
        timeout_ms=timeout_ms,
        stage="mfa_enroll",
        proxy=proxy,
    )
    secret = normalize_totp_secret(str(enroll_payload.get("secret") or ""))
    session_id = str(enroll_payload.get("session_id") or "").strip()
    enroll_factor = enroll_payload.get("factor") if isinstance(enroll_payload.get("factor"), dict) else {}
    factor_id = str((enroll_factor or {}).get("id") or "").strip()
    if (not secret) or (not session_id):
        raise ChatGptTotpMfaError(
            "开通 2FA 失败：enroll 响应缺少 secret 或 session_id",
            status=500,
            code="invalid_enroll_payload",
            stage="mfa_enroll",
        )

    if before_activate is not None:
        before_activate(
            {
                "secret": secret,
                "sessionId": session_id,
                "factorId": factor_id,
                "factorType": "totp",
                "createdAt": dt.datetime.now(dt.timezone.utc).isoformat(),
            }
        )

    _safe_log(log, "步骤 3/4：生成 TOTP 验证码并激活")
    seconds_remaining = 30 - (int(time.time()) % 30)
    if seconds_remaining <= 8:
        wait_seconds = float(seconds_remaining + 1)
        _safe_log(log, f"当前 TOTP 窗口即将结束，等待 {wait_seconds:.0f}s 后激活")
        time.sleep(wait_seconds)
    code = generate_totp_code(secret)
    activate_payload = _request_chatgpt_mfa_json(
        method="POST",
        url=MFA_ACTIVATE_URL,
        headers=headers,
        payload={"code": code, "factor_type": "totp", "session_id": session_id},
        timeout_ms=timeout_ms,
        stage="mfa_activate",
        proxy=proxy,
    )
    if activate_payload.get("success") is False:
        raise ChatGptTotpMfaError(
            "开通 2FA 失败：activate 响应未成功",
            status=500,
            code="activate_failed",
            stage="mfa_activate",
        )

    _safe_log(log, "步骤 4/4：回读确认 MFA 已生效")
    info_after: dict[str, Any] = {}
    after_state: dict[str, Any] = {}
    enabled = False
    final_factor_id = str(factor_id or "").strip()
    for confirm_attempt in range(1, MFA_ACTIVATE_CONFIRM_RETRIES + 1):
        info_after = _request_chatgpt_mfa_json(
            method="GET",
            url=MFA_INFO_URL,
            headers=headers,
            timeout_ms=timeout_ms,
            stage="mfa_info_after",
            proxy=proxy,
        )
        after_state = _extract_mfa_state(info_after)
        enabled = bool(after_state.get("mfa_enabled"))
        final_factor_id = str(after_state.get("factor_id") or factor_id or "").strip()
        if enabled:
            if confirm_attempt > 1:
                _safe_log(log, f"步骤 4/4：第 {confirm_attempt} 次回读确认成功，2FA 已生效")
            break
        if confirm_attempt >= MFA_ACTIVATE_CONFIRM_RETRIES:
            break
        _safe_log(
            log,
            f"步骤 4/4：第 {confirm_attempt} 次回读仍未生效，"
            f"{MFA_ACTIVATE_CONFIRM_INTERVAL_SECONDS:.1f}s 后重试",
        )
        time.sleep(MFA_ACTIVATE_CONFIRM_INTERVAL_SECONDS)

    if not enabled:
        raise ChatGptTotpMfaError(
            f"开通 2FA 失败：激活后状态仍未生效，已连续确认 {MFA_ACTIVATE_CONFIRM_RETRIES} 次",
            status=500,
            code="mfa_not_enabled",
            stage="mfa_info_after",
        )

    return {
        "success": True,
        "alreadyEnabled": False,
        "mfaEnabled": True,
        "factorType": "totp",
        "factorId": final_factor_id,
        "secret": secret,
        "secretMasked": mask_totp_secret(secret),
        "sessionId": session_id,
        "updatedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "mfaInfo": info_after,
    }


def _find_chatgpt_page_from_browser(*, browser: Any, page_url: str) -> tuple[Any, Any]:
    filter_value = str(page_url or "").strip()
    candidates: list[tuple[Any, Any]] = []
    for context in list(getattr(browser, "contexts", []) or [])[::-1]:
        for page in list(getattr(context, "pages", []) or [])[::-1]:
            current_url = str(getattr(page, "url", "") or "").strip()
            if "chatgpt.com" not in current_url:
                continue
            if filter_value and filter_value not in current_url:
                continue
            candidates.append((context, page))
    if candidates:
        return candidates[0]
    raise ChatGptTotpMfaError(
        "未找到可用的已登录 ChatGPT 页面，请确认浏览器已打开 chatgpt.com 且启用了远程调试",
        status=400,
        code="chatgpt_page_not_found",
        stage="attach_browser",
    )


def _capture_chatgpt_client_headers_from_browser_page(
    *,
    page: Any,
    access_token: str,
    timeout_ms: int,
) -> dict[str, str]:
    captured: dict[str, str] = {}

    def _on_request(request: Any) -> None:
        try:
            url = str(getattr(request, "url", "") or "")
        except Exception:
            url = ""
        if url != MFA_INFO_URL:
            return
        try:
            headers_attr = getattr(request, "headers", None)
            raw_headers = headers_attr() if callable(headers_attr) else headers_attr
        except Exception:
            raw_headers = {}
        if not isinstance(raw_headers, dict):
            return
        for key, value in raw_headers.items():
            safe_key = str(key or "").strip().lower()
            safe_value = str(value or "").strip()
            if safe_key and safe_value:
                captured[safe_key] = safe_value

    page.on("request", _on_request)
    try:
        page.evaluate(
            """
            async ({ url, token }) => {
              await fetch(url, {
                method: "GET",
                credentials: "include",
                headers: {
                  accept: "application/json, text/plain, */*",
                  authorization: `Bearer ${token}`,
                  "oai-language": "zh-CN",
                },
              }).catch(() => null);
            }
            """,
            {"url": MFA_INFO_URL, "token": str(access_token or "").strip()},
        )
        page.wait_for_timeout(max(500, min(int(timeout_ms or 60_000), 5_000)))
    finally:
        try:
            page.remove_listener("request", _on_request)
        except Exception:
            pass
    return _normalize_chatgpt_client_headers(captured)


def extract_runtime_auth_from_browser_page(
    *,
    cdp_url: str,
    page_url: str = "",
    access_token: str = "",
    timeout_ms: int = 60_000,
    log: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    safe_cdp_url = str(cdp_url or "").strip()
    if not safe_cdp_url:
        raise ChatGptTotpMfaError(
            "读取页面登录态失败：缺少 CDP 地址",
            status=400,
            code="missing_cdp_url",
            stage="attach_browser",
        )

    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except Exception as error:
        raise ChatGptTotpMfaError(
            "读取页面登录态失败：未安装 playwright，请先执行 `pip install playwright`",
            status=500,
            code="playwright_missing",
            stage="attach_browser",
        ) from error

    playwright = sync_playwright().start()
    try:
        browser = playwright.chromium.connect_over_cdp(
            endpoint_url=safe_cdp_url,
            timeout=int(timeout_ms or 60_000),
        )
        context, page = _find_chatgpt_page_from_browser(browser=browser, page_url=page_url)
        current_url = str(getattr(page, "url", "") or "").strip() or DEFAULT_CHATGPT_REFERER
        _safe_log(log, f"已附着到页面：{current_url}")
        cookies = context.cookies([current_url, "https://chatgpt.com/"])
        cookie_items = [dict(item) for item in cookies if isinstance(item, dict)]
        cookie_header = _build_cookie_header_from_cookies(cookies=cookie_items, target_host="chatgpt.com")
        if not cookie_header:
            raise ChatGptTotpMfaError(
                "读取页面登录态失败：当前页面上下文缺少 chatgpt.com cookies",
                status=400,
                code="no_cookie",
                stage="extract_browser_auth",
            )
        oai_device_id = _read_cookie_value(
            cookies=cookie_items,
            cookie_name="oai-did",
            target_host="chatgpt.com",
        )
        token_value = str(access_token or "").strip()
        if not token_value:
            _safe_log(log, "正在通过当前页面会话读取 access_token")
            token_value = read_access_token_via_cookie_header(
                cookie_header=cookie_header,
                oai_device_id=oai_device_id,
                referer=current_url,
                timeout_ms=timeout_ms,
            )
        if not token_value:
            raise ChatGptTotpMfaError(
                "读取页面登录态失败：未能从当前页面会话获取 access_token",
                status=401,
                code="missing_access_token",
                stage="extract_browser_auth",
            )
        client_headers = _capture_chatgpt_client_headers_from_browser_page(
            page=page,
            access_token=token_value,
            timeout_ms=timeout_ms,
        )
        return {
            "accessToken": token_value,
            "cookieHeader": cookie_header,
            "oaiDeviceId": oai_device_id,
            "referer": current_url,
            "pageUrl": current_url,
            "clientHeaders": client_headers,
        }
    except ChatGptTotpMfaError:
        raise
    except Exception as error:
        raise ChatGptTotpMfaError(
            f"读取页面登录态失败：{error}",
            status=0,
            code="browser_attach_failed",
            stage="attach_browser",
        ) from error
    finally:
        try:
            playwright.stop()
        except Exception:
            pass


def enable_totp_mfa_via_storage_state(
    *,
    storage_state_path: str,
    access_token: str = "",
    timeout_ms: int = 60_000,
    log: Callable[[str], None] | None = None,
    proxy: str | None = None,
    before_activate: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    safe_path = str(storage_state_path or "").strip()
    if not safe_path:
        raise ChatGptTotpMfaError(
            "开通 2FA 失败：storage_state 路径为空",
            status=400,
            code="storage_state_missing",
            stage="validate_input",
        )

    token_value = str(access_token or "").strip() or read_access_token_from_storage_state(safe_path)
    cookie_header = load_cookie_header_from_storage_state(
        storage_state_path=safe_path,
        target_host="chatgpt.com",
    )
    return enable_totp_mfa_with_credentials(
        access_token=token_value,
        cookie_header=cookie_header,
        oai_device_id=try_read_oai_did_from_storage_state(safe_path),
        referer=DEFAULT_CHATGPT_REFERER,
        timeout_ms=timeout_ms,
        log=log,
        proxy=proxy,
        before_activate=before_activate,
    )


def enable_totp_mfa_via_browser_page(
    *,
    cdp_url: str,
    page_url: str = "",
    access_token: str = "",
    timeout_ms: int = 60_000,
    log: Callable[[str], None] | None = None,
    proxy: str | None = None,
) -> dict[str, Any]:
    auth_payload = extract_runtime_auth_from_browser_page(
        cdp_url=cdp_url,
        page_url=page_url,
        access_token=access_token,
        timeout_ms=timeout_ms,
        log=log,
    )
    result = enable_totp_mfa_with_credentials(
        access_token=str(auth_payload.get("accessToken") or "").strip(),
        cookie_header=str(auth_payload.get("cookieHeader") or "").strip(),
        oai_device_id=str(auth_payload.get("oaiDeviceId") or "").strip(),
        referer=str(auth_payload.get("referer") or DEFAULT_CHATGPT_REFERER).strip() or DEFAULT_CHATGPT_REFERER,
        client_headers=auth_payload.get("clientHeaders"),
        timeout_ms=timeout_ms,
        log=log,
        proxy=proxy,
    )
    result["pageUrl"] = str(auth_payload.get("pageUrl") or "").strip()
    result["authMode"] = "browser_page"
    return result


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="enable_totp_mfa",
        description="基于 storage_state 或当前已登录页面为 ChatGPT 账号开通 TOTP 2FA",
    )
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument(
        "--storage-state",
        help="Playwright storage_state JSON 文件路径。",
    )
    source_group.add_argument(
        "--cdp-url",
        default="",
        help="已登录浏览器的 CDP 地址，例如 http://127.0.0.1:9222 。",
    )
    parser.add_argument(
        "--page-url",
        default="",
        help="可选。浏览器模式下用于筛选页面 URL 的关键字。",
    )
    parser.add_argument(
        "--access-token",
        default="",
        help="可选。显式传入 access token；为空时会尝试从 storage_state 或当前页面会话读取。",
    )
    parser.add_argument(
        "--timeout-ms",
        type=int,
        default=60_000,
        help="单次 HTTP 请求超时时间，默认 60000 毫秒。",
    )
    parser.add_argument(
        "--proxy",
        default="",
        help="可选。所有 ChatGPT HTTP 请求使用的代理 URL。",
    )
    parser.add_argument(
        "--print-secret",
        action="store_true",
        help="成功时额外输出未脱敏 TOTP secret。",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="静默模式，不打印进度日志。",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    logger = None if args.quiet else print
    try:
        if args.storage_state:
            result = enable_totp_mfa_via_storage_state(
                storage_state_path=args.storage_state,
                access_token=args.access_token,
                timeout_ms=args.timeout_ms,
                log=logger,
                proxy=args.proxy or None,
            )
        else:
            result = enable_totp_mfa_via_browser_page(
                cdp_url=args.cdp_url,
                page_url=args.page_url,
                access_token=args.access_token,
                timeout_ms=args.timeout_ms,
                log=logger,
                proxy=args.proxy or None,
            )
    except ChatGptTotpMfaError as error:
        payload = {
            "success": False,
            "message": str(error),
            "status": int(error.status or 0),
            "code": str(error.code or ""),
            "stage": str(error.stage or ""),
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 1

    output = dict(result)
    if not args.print_secret and output.get("secret"):
        output["secret"] = ""
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0
