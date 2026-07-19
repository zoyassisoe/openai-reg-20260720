from __future__ import annotations

import argparse
import base64
import contextlib
import copy
import dataclasses
import datetime as _dt
import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from chatgpt_api_health import (
    _build_chatgpt_backend_headers,
    _build_chatgpt_http_browser_identity_headers,
    _create_curl_cffi_session_from_storage_state,
    _resolve_chatgpt_curl_impersonate,
    fetch_access_token_from_storage_state_curl_cffi,
    fetch_access_token_from_storage_state_ipv4,
    try_read_oai_did_from_storage_state,
)
from chatgpt_login_http import (
    ChatGptHttpLoginConfig,
    ChatGptHttpLoginProfile,
    run_chatgpt_http_login,
)
from chatgpt_register_http import (
    ChatGptHttpRegisterConfig,
    ChatGptHttpRegisterProfile,
    run_chatgpt_http_register,
    set_chatgpt_password_via_reset_flow,
)
from codex_oauth import run_codex_oauth_flow


def _resolve_base_dir() -> Path:
    isolated = str(os.environ.get("X9_ISOLATED_ROOT") or "").strip()
    if isolated:
        return Path(isolated).expanduser().resolve()
    here = Path(__file__).resolve().parent
    return here.parent if here.name in {"_toolcore", "_credential_toolcore"} else here


BASE_DIR = _resolve_base_dir()
SUCCESS_DIR = BASE_DIR / "成功凭证"
FAIL_DIR = BASE_DIR / "失败记录"
STATE_DIR = BASE_DIR / "登录态"
AT_DIR = BASE_DIR / "AT文本"
CODEX_TOKEN_DIR = BASE_DIR / "访问令牌"
TRACE_DIR = BASE_DIR / "trace"
WHAM_AUTH_CREDENTIALS_URL = "https://chatgpt.com/backend-api/wham/auth-credentials"
WHAM_CODEX_SCOPE = "model.request"


@dataclass(slots=True)
class CommandResult:
    success: bool
    mode: str
    email: str
    message: str
    storage_state_path: str = ""
    at_txt_path: str = ""
    trace_path: str = ""
    success_credential_path: str = ""
    session_snapshot_path: str = ""
    codex_token_json_path: str = ""
    codex_token_txt_path: str = ""
    bound_phone: str = ""
    stage: str = ""
    error_code: str = ""
    remote_password_set: bool = False
    remote_password_mode: str = ""


class ConsoleLogSink:
    def _emit(self, level: str, message: str) -> None:
        text = str(message or "").strip()
        if not text:
            return
        print(f"[{str(level or 'INFO').upper()}] {text}")

    def info(self, message: str) -> None:
        self._emit("INFO", message)

    def warn(self, message: str) -> None:
        self._emit("WARN", message)

    def error(self, message: str) -> None:
        self._emit("ERROR", message)

    def success(self, message: str) -> None:
        self._emit("SUCCESS", message)


def ensure_runtime_dirs() -> None:
    for path in (SUCCESS_DIR, FAIL_DIR, STATE_DIR, AT_DIR, CODEX_TOKEN_DIR, TRACE_DIR):
        path.mkdir(parents=True, exist_ok=True)


def now_utc_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _safe_name(text: str, *, fallback: str = "unknown") -> str:
    value = str(text or "").strip()
    if not value:
        return fallback
    safe = re.sub(r'[<>:"/\\|?*]+', "_", value)
    safe = safe.strip(" .")
    return safe or fallback


def _trace_path(mode: str, email_hint: str) -> str:
    stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    return str((TRACE_DIR / f"{_safe_name(mode)}_{_safe_name(email_hint)}_{stamp}.jsonl").resolve())


def state_path_for(email_hint: str) -> str:
    return str((STATE_DIR / f"{_safe_name(email_hint)}.json").resolve())


def at_path_for(email_hint: str) -> str:
    return str((AT_DIR / f"{_safe_name(email_hint)}.txt").resolve())


def codex_token_json_path_for(email_hint: str) -> str:
    return str((CODEX_TOKEN_DIR / f"{_safe_name(email_hint)}.json").resolve())


def codex_token_txt_path_for(email_hint: str) -> str:
    return str((CODEX_TOKEN_DIR / f"{_safe_name(email_hint)}.txt").resolve())


def success_path_for(email_hint: str) -> str:
    return str((SUCCESS_DIR / f"{_safe_name(email_hint)}.json").resolve())


def fail_path_for(email_hint: str) -> str:
    return str((FAIL_DIR / f"{_safe_name(email_hint)}.json").resolve())


def load_json(path: str | Path) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"JSON 根节点不是对象：{path}")
    return payload


def write_json(path: str | Path, payload: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_suffix(target.suffix + ".tmp")
    temp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(target)


def write_text(path: str | Path, text: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_suffix(target.suffix + ".tmp")
    temp.write_text(str(text or ""), encoding="utf-8")
    temp.replace(target)


def derive_email_from_state(storage_state_path: str) -> str:
    try:
        payload = load_json(storage_state_path)
    except Exception:
        payload = {}
    for key in ("email", "oauth_email", "outlook_email"):
        value = str(payload.get(key) or "").strip()
        if "@" in value:
            return value
    session_summary = payload.get("session_summary")
    if isinstance(session_summary, dict):
        for key in ("email", "userEmail"):
            value = str(session_summary.get(key) or "").strip()
            if "@" in value:
                return value
    return Path(storage_state_path).stem


def parse_access_token_exp(token: str) -> tuple[int, str]:
    raw = str(token or "").strip()
    if raw.count(".") < 2:
        return 0, ""
    try:
        payload_part = raw.split(".", 2)[1]
        padding = "=" * ((4 - len(payload_part) % 4) % 4)
        payload = json.loads(base64.urlsafe_b64decode((payload_part + padding).encode("ascii")).decode("utf-8"))
    except Exception:
        return 0, ""
    try:
        exp = int(payload.get("exp") or 0)
    except Exception:
        exp = 0
    if exp <= 0:
        return 0, ""
    try:
        exp_iso = _dt.datetime.fromtimestamp(exp, tz=_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    except Exception:
        exp_iso = ""
    return exp, exp_iso


def _decode_jwt_payload(token: str) -> dict[str, Any]:
    raw = str(token or "").strip()
    if raw.count(".") < 2:
        return {}
    try:
        payload_part = raw.split(".", 2)[1]
        padding = "=" * ((4 - len(payload_part) % 4) % 4)
        payload = json.loads(base64.urlsafe_b64decode((payload_part + padding).encode("ascii")).decode("utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _compact_success_credential_payload(*, source: dict[str, Any], email: str, password: str) -> dict[str, Any]:
    src = source if isinstance(source, dict) else {}
    token_exchange = src.get("token_exchange")
    if not isinstance(token_exchange, dict):
        token_exchange = {}
    access_token = str(src.get("access_token") or token_exchange.get("access_token") or "").strip()
    refresh_token = str(src.get("refresh_token") or token_exchange.get("refresh_token") or "").strip()
    id_token = str(src.get("id_token") or token_exchange.get("id_token") or "").strip()
    email_text = str(email or src.get("email") or src.get("oauth_email") or src.get("outlook_email") or "").strip().lower()
    at_claims = _decode_jwt_payload(access_token)
    auth_claims = at_claims.get("https://api.openai.com/auth") if isinstance(at_claims, dict) else {}
    auth_claims = auth_claims if isinstance(auth_claims, dict) else {}
    account_id = str(
        src.get("account_id")
        or auth_claims.get("chatgpt_account_id")
        or ""
    ).strip()
    _exp, expired_iso = parse_access_token_exp(access_token)
    expired = str(src.get("expired") or expired_iso or "").strip()
    last_refresh = str(src.get("last_refresh") or "").strip() or now_utc_iso()
    status = str(src.get("status") or "success").strip() or "success"
    if status != "success":
        status = "success"
    return {
        "access_token": access_token,
        "account_id": account_id,
        "disabled": bool(src.get("disabled", False)),
        "email": email_text,
        "expired": expired,
        "id_token": id_token,
        "last_refresh": last_refresh,
        "oai_password": str(password or src.get("oai_password") or ""),
        "outlook_email": str(src.get("outlook_email") or email_text or "").strip().lower(),
        "refresh_token": refresh_token,
        "status": status,
        "type": "codex",
    }


def read_access_token_from_storage_state(storage_state_path: str) -> str:
    try:
        payload = load_json(storage_state_path)
    except Exception:
        return ""
    for key in ("session_access_token", "accessToken"):
        value = str(payload.get(key) or "").strip()
        if value:
            return value
    return ""


def _first_non_empty(*values: Any) -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _account_id_from_storage_state_payload(payload: dict[str, Any], token: str) -> str:
    payload = payload if isinstance(payload, dict) else {}
    summary = payload.get("session_summary")
    summary = summary if isinstance(summary, dict) else {}
    account = payload.get("account")
    account = account if isinstance(account, dict) else {}
    claims = _decode_jwt_payload(token)
    auth_claims = claims.get("https://api.openai.com/auth") if isinstance(claims, dict) else {}
    auth_claims = auth_claims if isinstance(auth_claims, dict) else {}
    return _first_non_empty(
        summary.get("selectedWorkspaceId"),
        summary.get("accountId"),
        summary.get("selectedAccountId"),
        account.get("id"),
        account.get("account_id"),
        account.get("workspace_id"),
        account.get("workspaceId"),
        payload.get("selectedWorkspaceId"),
        payload.get("selectedAccountId"),
        payload.get("accountId"),
        payload.get("workspaceId"),
        auth_claims.get("chatgpt_account_id"),
        claims.get("chatgpt_account_id") if isinstance(claims, dict) else "",
        claims.get("account_id") if isinstance(claims, dict) else "",
    )


def _cookie_header_from_storage_state_payload(payload: dict[str, Any]) -> str:
    payload = payload if isinstance(payload, dict) else {}
    cookies = payload.get("cookies")
    if not isinstance(cookies, list):
        return ""
    pairs: list[str] = []
    seen: set[str] = set()
    for item in cookies:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        value = str(item.get("value") or "")
        domain = str(item.get("domain") or "").strip().lower()
        if not name or name in seen:
            continue
        if "chatgpt.com" not in domain and "openai.com" not in domain:
            continue
        pairs.append(f"{name}={value}")
        seen.add(name)
    return "; ".join(pairs)


def _compact_response_text(text: str, *, limit: int = 800) -> str:
    clean = re.sub(r"\s+", " ", str(text or "")).strip()
    if len(clean) <= limit:
        return clean
    return clean[:limit] + "...[truncated]"


def _parse_json_response(text: str) -> dict[str, Any]:
    try:
        payload = json.loads(str(text or ""))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _write_codex_wham_token_record(
    *,
    email_hint: str,
    status: int,
    account_id: str,
    response_payload: dict[str, Any],
    response_text: str,
    error: str,
) -> tuple[str, str, bool]:
    json_path = codex_token_json_path_for(email_hint)
    txt_path = codex_token_txt_path_for(email_hint)
    credential_payload = response_payload if isinstance(response_payload, dict) else {}
    codex_token = str(credential_payload.get("access_token") or "").strip()
    ok = bool(200 <= int(status or 0) < 300 and codex_token)
    record = {
        "type": "chatgpt_wham_auth_credential",
        "source": WHAM_AUTH_CREDENTIALS_URL,
        "name": "codex",
        "scopes": [WHAM_CODEX_SCOPE],
        "ttl": 7776000,
        "status": int(status or 0),
        "ok": ok,
        "error": str(error or "").strip(),
        "account_id": str(account_id or "").strip(),
        "updated_at": now_utc_iso(),
        "accessTokenPresent": bool(codex_token),
        "accessTokenLen": len(codex_token),
        "credential": credential_payload,
    }
    if not credential_payload and response_text:
        record["responseTextSnippet"] = _compact_response_text(response_text, limit=800)
    write_json(json_path, record)
    if codex_token:
        write_text(txt_path, f"{codex_token}\n")
    return json_path, txt_path if codex_token else "", ok


def create_codex_wham_token_from_storage_state(
    *,
    storage_state_path: str,
    email_hint: str,
    proxy_url: str = "",
    timeout_seconds: float = 60.0,
) -> tuple[str, str, bool]:
    email_text = str(email_hint or "").strip() or derive_email_from_state(storage_state_path)
    try:
        payload = load_json(storage_state_path)
    except Exception as error:  # noqa: BLE001
        return _write_codex_wham_token_record(
            email_hint=email_text,
            status=0,
            account_id="",
            response_payload={},
            response_text="",
            error=f"load_storage_state_failed: {error}",
        )
    session_token = read_access_token_from_storage_state(storage_state_path)
    account_id = _account_id_from_storage_state_payload(payload, session_token)
    if not session_token or not account_id:
        return _write_codex_wham_token_record(
            email_hint=email_text,
            status=0,
            account_id=account_id,
            response_payload={},
            response_text="",
            error="missing_access_token" if not session_token else "missing_account_id",
        )
    body = {
        "name": "codex",
        "scopes": [WHAM_CODEX_SCOPE],
        "ttl": 7776000,
    }
    headers = {
        "accept": "application/json",
        "authorization": f"Bearer {session_token}",
        "chatgpt-account-id": account_id,
        "content-type": "application/json",
        "origin": "https://chatgpt.com",
        "referer": "https://chatgpt.com/",
    }
    cookie_header = _cookie_header_from_storage_state_payload(payload)
    if cookie_header:
        headers["cookie"] = cookie_header
    timeout = max(8.0, min(60.0, float(timeout_seconds or 60.0) / 3.0))
    status = 0
    response_text = ""
    response_payload: dict[str, Any] = {}
    error_text = ""
    proxy = str(proxy_url or "").strip()
    try:
        try:
            from curl_cffi import requests as curl_requests  # type: ignore
        except Exception:
            curl_requests = None
        if curl_requests is not None:
            impersonate = _resolve_chatgpt_curl_impersonate()
            session = _create_curl_cffi_session_from_storage_state(
                storage_state_path=storage_state_path,
                proxy_url=proxy,
                impersonate=impersonate,
            )
            backend_headers = _build_chatgpt_backend_headers(
                access_token=session_token,
                account_id=account_id,
                oai_device_id=try_read_oai_did_from_storage_state(storage_state_path),
                referer="https://chatgpt.com/",
            )
            backend_headers.update(
                _build_chatgpt_http_browser_identity_headers(
                    include_accept_language=True,
                    include_accept_encoding=True,
                    impersonate=impersonate,
                )
            )
            backend_headers.update(headers)
            resp = session.post(
                WHAM_AUTH_CREDENTIALS_URL,
                headers=backend_headers,
                json=body,
                timeout=timeout,
                allow_redirects=False,
            )
            status = int(getattr(resp, "status_code", 0) or 0)
            response_text = str(getattr(resp, "text", "") or "")
            try:
                maybe_payload = resp.json()
                response_payload = maybe_payload if isinstance(maybe_payload, dict) else {}
            except Exception:
                response_payload = _parse_json_response(response_text)
        else:
            data = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            request = urllib.request.Request(
                WHAM_AUTH_CREDENTIALS_URL,
                data=data,
                headers=headers,
                method="POST",
            )
            handlers = [urllib.request.ProxyHandler({"http": proxy, "https": proxy})] if proxy else []
            opener = urllib.request.build_opener(*handlers)
            try:
                with opener.open(request, timeout=timeout) as resp:
                    status = int(getattr(resp, "status", 0) or resp.getcode() or 0)
                    response_text = resp.read().decode("utf-8", "replace")
            except urllib.error.HTTPError as http_error:
                status = int(http_error.code or 0)
                response_text = http_error.read().decode("utf-8", "replace")
            response_payload = _parse_json_response(response_text)
    except Exception as error:  # noqa: BLE001
        error_text = str(error or "").strip()
    return _write_codex_wham_token_record(
        email_hint=email_text,
        status=status,
        account_id=account_id,
        response_payload=response_payload,
        response_text=response_text,
        error=error_text,
    )


def update_storage_state_token_fields(
    storage_state_path: str,
    *,
    token: str,
    status: int = 200,
    error_text: str = "",
    email: str = "",
) -> None:
    payload = load_json(storage_state_path)
    exp, exp_iso = parse_access_token_exp(token)
    payload["session_access_token"] = str(token or "").strip()
    payload["session_access_token_status"] = int(status or 0)
    payload["session_access_token_error"] = str(error_text or "")
    payload["session_access_token_updated_at"] = now_utc_iso()
    payload["session_access_token_exp"] = int(exp or 0)
    payload["session_access_token_expires_at"] = str(exp_iso or "")
    payload["accessToken"] = str(token or "").strip()
    if str(email or "").strip():
        payload.setdefault("email", str(email or "").strip())
    write_json(storage_state_path, payload)


def save_at_txt(email_hint: str, token: str, *, at_txt_path: str = "") -> str:
    target = str(at_txt_path or "").strip() or at_path_for(email_hint)
    write_text(target, str(token or "").strip())
    return target


async def extract_at_from_storage_state(
    *,
    storage_state_path: str,
    email_hint: str = "",
    at_txt_path: str = "",
) -> tuple[str, str]:
    existing_token = read_access_token_from_storage_state(storage_state_path)
    if existing_token:
        update_storage_state_token_fields(
            storage_state_path,
            token=existing_token,
            status=200,
            error_text="",
            email=email_hint,
        )
        return existing_token, save_at_txt(
            email_hint or derive_email_from_state(storage_state_path),
            existing_token,
            at_txt_path=at_txt_path,
        )
    last_error: Exception | None = None
    token = ""
    for runner in (fetch_access_token_from_storage_state_curl_cffi, fetch_access_token_from_storage_state_ipv4):
        try:
            token = await runner(storage_state_path=storage_state_path, timeout_ms=60_000)
            if token:
                break
        except Exception as error:  # noqa: BLE001
            last_error = error
    if not token:
        raise RuntimeError(str(last_error or "未能从 storage_state 提取到可用 accessToken。"))
    update_storage_state_token_fields(
        storage_state_path,
        token=token,
        status=200,
        error_text="",
        email=email_hint,
    )
    return token, save_at_txt(email_hint or derive_email_from_state(storage_state_path), token, at_txt_path=at_txt_path)


def parse_error_stage_code(message: str, *, default_stage: str = "exception", default_code: str = "runtime_error") -> tuple[str, str]:
    text = str(message or "").strip()
    if ":" in text:
        prefix = str(text.split(":", 1)[0] or "").strip()
        if prefix:
            return prefix, prefix
    return default_stage, default_code


def persist_failure_record(
    *,
    mode: str,
    email_hint: str,
    stage: str,
    error_code: str,
    message: str,
    storage_state_path: str = "",
    trace_path: str = "",
) -> str:
    email_text = str(email_hint or "").strip() or "unknown"
    path = fail_path_for(email_text)
    payload = {
        "email": email_text,
        "mode": str(mode or "").strip(),
        "stage": str(stage or "").strip(),
        "errorCode": str(error_code or "").strip(),
        "message": str(message or "").strip(),
        "storage_state_path": str(storage_state_path or "").strip(),
        "trace_path": str(trace_path or "").strip(),
        "updated_at": now_utc_iso(),
        "status": "failed",
    }
    write_json(path, payload)
    return path


def enrich_success_credential(
    *,
    success_path: str,
    email: str,
    password: str,
    storage_state_path: str,
    at_txt_path: str,
    trace_path: str,
) -> None:
    payload = load_json(success_path)
    compact_payload = _compact_success_credential_payload(source=payload, email=email, password=password)
    write_json(success_path, compact_payload)


@contextlib.contextmanager
def temporary_proxy_env(proxy_url: str) -> Iterator[None]:
    proxy = str(proxy_url or "").strip()
    if not proxy:
        yield
        return
    previous = os.environ.get("AIO_API_PROXY")
    os.environ["AIO_API_PROXY"] = proxy
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("AIO_API_PROXY", None)
        else:
            os.environ["AIO_API_PROXY"] = previous


def temporary_http_env() -> dict[str, str | None]:
    previous = {
        "AIO_CODEX_OAUTH_ENABLE_HTTP_PROVIDER": os.environ.get("AIO_CODEX_OAUTH_ENABLE_HTTP_PROVIDER"),
    }
    os.environ["AIO_CODEX_OAUTH_ENABLE_HTTP_PROVIDER"] = "1"
    return previous


def restore_env(previous: dict[str, str | None]) -> None:
    for key, value in previous.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


def add_shared_network_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--proxy-url", default="", help="可选 HTTP 代理 URL")
    parser.add_argument("--trace", action="store_true", help="启用并落库 trace 文件")
    parser.add_argument("--timeout-seconds", type=float, default=360.0, help="主流程超时，默认 360 秒")
    parser.add_argument("--otp-timeout-seconds", type=float, default=180.0, help="OTP 总超时，默认 180 秒")
    parser.add_argument("--otp-interval-seconds", type=float, default=1.0, help="OTP 轮询间隔，默认 1 秒")


def add_managed_mail_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--managed-mail-provider", default="", help="托管邮箱 provider")
    parser.add_argument("--managed-mail-jwt", default="", help="托管邮箱 JWT")
    parser.add_argument("--managed-mail-api-base", default="", help="托管邮箱 API Base URL")
    parser.add_argument("--managed-mail-frontend-base", default="", help="托管邮箱前端 Base URL")
    parser.add_argument("--managed-mail-latest-n", type=int, default=20, help="托管邮箱最近邮件条数")
    parser.add_argument("--otp-api-url", default="", help="直接接码 URL；返回文本/HTML/JSON 中提取 6 位验证码")
    parser.add_argument("--disable-managed-mail-otp", action="store_true", help="关闭 managed mail OTP")


def add_domain_mail_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--domain-mail-api-base", default="", help="域名邮箱 API Base URL")
    parser.add_argument("--domain-mail-domain", default="", help="域名邮箱域名")
    parser.add_argument("--domain-mail-token", default="", help="域名邮箱 API Token")
    parser.add_argument("--domain-mail-latest-n", type=int, default=0, help="域名邮箱最近邮件条数")
    parser.add_argument("--disable-domain-mail-otp", action="store_true", help="关闭域名邮箱 OTP")


def add_imap_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--use-imap-otp", action="store_true", help="启用 IMAP OTP")
    parser.add_argument("--imap-host", default="imap.2925.com", help="IMAP host")
    parser.add_argument("--imap-port", type=int, default=993, help="IMAP port")
    parser.add_argument("--imap-user", default="", help="IMAP 用户名")
    parser.add_argument("--imap-pass", default="", help="IMAP 密码")
    parser.add_argument("--imap-folder", default="Inbox", help="IMAP 文件夹")
    parser.add_argument("--imap-latest-n", type=int, default=80, help="IMAP 扫描最近邮件数")
    parser.add_argument("--imap-auth-type", default="password", help="IMAP 认证方式：password 或 oauth2")
    parser.add_argument("--imap-oauth-client-id", default="", help="IMAP OAuth2 client_id")
    parser.add_argument("--imap-oauth-refresh-token", default="", help="IMAP OAuth2 refresh_token")
    parser.add_argument("--imap-password-fallback", action="store_true", help="OAuth2 IMAP 失败后回退密码 IMAP")
    parser.add_argument("--imap-pop3-fallback", action="store_true", help="IMAP 失败后回退 POP3 OAuth2")
    parser.add_argument("--imap-profiles-file", default="", help="多 IMAP 主邮箱配置 JSON 文件")
    parser.add_argument("--imap-profiles-json", default="", help="多 IMAP 主邮箱配置 JSON 文本")


def _load_imap_profiles_json(args: argparse.Namespace) -> str:
    raw = str(getattr(args, "imap_profiles_json", "") or "").strip()
    if raw:
        return raw
    path = str(getattr(args, "imap_profiles_file", "") or "").strip()
    if not path:
        return ""
    try:
        return Path(path).expanduser().read_text(encoding="utf-8")
    except Exception:
        return ""


def _load_pipeline_config() -> dict[str, Any]:
    path = BASE_DIR / "data" / "pipeline_config.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _first_non_empty(*values: Any) -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _resolve_domain_mail_args(args: argparse.Namespace) -> dict[str, Any]:
    cfg = _load_pipeline_config()
    latest_raw = (
        getattr(args, "domain_mail_latest_n", 0)
        or os.getenv("X9_DOMAIN_MAIL_LATEST_N")
        or cfg.get("domain_mail_latest_n")
        or 20
    )
    try:
        latest_n = int(latest_raw or 20)
    except Exception:
        latest_n = 20
    return {
        "use": not bool(getattr(args, "disable_domain_mail_otp", False)),
        "api_base": _first_non_empty(
            getattr(args, "domain_mail_api_base", ""),
            os.getenv("X9_DOMAIN_MAIL_API_BASE"),
            cfg.get("domain_mail_api_base"),
        ),
        "domain": _first_non_empty(
            getattr(args, "domain_mail_domain", ""),
            os.getenv("X9_DOMAIN_MAIL_DOMAIN"),
            cfg.get("domain_mail_domain"),
        ),
        "token": _first_non_empty(
            getattr(args, "domain_mail_token", ""),
            os.getenv("X9_DOMAIN_MAIL_TOKEN"),
            cfg.get("domain_mail_token"),
        ),
        "latest_n": max(1, latest_n),
    }


def add_headless_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--headless", action="store_true", help="启用无头模式")


def add_login_identity_args(parser: argparse.ArgumentParser, *, require_password: bool = True) -> None:
    parser.add_argument("--email", required=True, help="账号邮箱")
    parser.add_argument("--password", required=require_password, help="账号密码")


def add_register_identity_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--email", required=True, help="账号邮箱")
    parser.add_argument("--password", required=True, help="账号密码")
    parser.add_argument("--full-name", default="", help="注册姓名；留空则按邮箱自动生成随机真人姓名")
    parser.add_argument("--birth-date", default="", help="生日 YYYY-MM-DD；留空则按邮箱自动生成随机生日")


def add_mfa_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--mfa-totp-secret", default="", help="可选 TOTP 密钥")


def summarize_success(result: CommandResult) -> None:
    print(result.message)
    if result.storage_state_path:
        print(f"登录态: {result.storage_state_path}")
    if result.session_snapshot_path:
        print(f"Session快照: {result.session_snapshot_path}")
    if result.codex_token_txt_path:
        print(f"Codex令牌: {result.codex_token_txt_path}")
    if result.codex_token_json_path:
        print(f"Codex令牌详情: {result.codex_token_json_path}")
    if result.at_txt_path:
        print(f"AT文本: {result.at_txt_path}")
    if result.success_credential_path:
        print(f"成功凭证: {result.success_credential_path}")
    if result.trace_path:
        print(f"Trace: {result.trace_path}")


def summarize_failure(result: CommandResult, *, failure_record_path: str) -> None:
    print(result.message)
    if result.storage_state_path:
        print(f"登录态: {result.storage_state_path}")
    if result.trace_path:
        print(f"Trace: {result.trace_path}")
    print(f"失败记录: {failure_record_path}")


async def run_register_flow(args: argparse.Namespace) -> CommandResult:
    ensure_runtime_dirs()
    email = str(args.email or "").strip().lower()
    state_path = state_path_for(email)
    trace_path = _trace_path("register", email) if bool(args.trace) else ""
    log = ConsoleLogSink()
    register_profile = ChatGptHttpRegisterProfile(
        email=email,
        password=str(args.password or ""),
        fullName=str(args.full_name or "").strip(),
        birthDate=str(args.birth_date or "").strip(),
    )
    register_config = ChatGptHttpRegisterConfig(
        timeoutSeconds=float(args.timeout_seconds or 360.0),
        traceEnabled=bool(args.trace),
        tracePath=trace_path,
        storageStatePath=state_path,
        proxyUrl=str(args.proxy_url or "").strip(),
        useManagedMailOtp=not bool(args.disable_managed_mail_otp),
        managedMailProvider=str(args.managed_mail_provider or "").strip(),
        managedMailJwt=str(args.managed_mail_jwt or "").strip(),
        managedMailApiBase=str(args.managed_mail_api_base or "").strip(),
        managedMailFrontendBase=str(args.managed_mail_frontend_base or "").strip(),
        managedMailLatestN=int(args.managed_mail_latest_n or 20),
        otpApiUrl=str(args.otp_api_url or "").strip(),
        useImapOtp=bool(args.use_imap_otp),
        otpTimeoutSeconds=float(args.otp_timeout_seconds or 180.0),
        otpIntervalSeconds=float(args.otp_interval_seconds or 1.0),
        imapHost=str(args.imap_host or "imap.2925.com").strip() or "imap.2925.com",
        imapPort=int(args.imap_port or 993),
        imapUser=str(args.imap_user or "").strip(),
        imapPass=str(args.imap_pass or ""),
        imapFolder=str(args.imap_folder or "Inbox").strip() or "Inbox",
        imapLatestN=int(args.imap_latest_n or 80),
        imapAuthType=str(args.imap_auth_type or "password").strip() or "password",
        imapOauthClientId=str(args.imap_oauth_client_id or "").strip(),
        imapOauthRefreshToken=str(args.imap_oauth_refresh_token or "").strip(),
        imapPasswordFallback=bool(args.imap_password_fallback),
        imapPop3Fallback=bool(args.imap_pop3_fallback),
    )
    with temporary_proxy_env(str(args.proxy_url or "")):
        result = await run_chatgpt_http_register(
            profile=register_profile,
            config=register_config,
            logInfo=log.info,
            logWarn=log.warn,
            logError=log.error,
        )
    details = dict(getattr(result, "details", {}) or {})
    final_state_path = str(details.get("storageStatePath") or state_path).strip()
    final_trace_path = str(details.get("tracePath") or trace_path).strip()
    session_snapshot_path = str(details.get("sessionSnapshotPath") or "").strip()
    codex_token_json_path = str(details.get("codexTokenJsonPath") or "").strip()
    codex_token_txt_path = str(details.get("codexTokenTxtPath") or "").strip()
    remote_password_set = bool(details.get("remotePasswordSet"))
    remote_password_mode = str(details.get("remotePasswordMode") or "not_attempted").strip()
    if not bool(getattr(result, "success", False)):
        return CommandResult(
            success=False,
            mode="register",
            email=email,
            message=str(getattr(result, "message", "") or "HTTP 注册失败"),
            storage_state_path=final_state_path,
            trace_path=final_trace_path,
            session_snapshot_path=session_snapshot_path,
            codex_token_json_path=codex_token_json_path,
            codex_token_txt_path=codex_token_txt_path,
            stage=str(getattr(result, "stage", "") or "register_failed"),
            error_code=str(getattr(result, "errorCode", "") or "register_failed"),
            remote_password_set=remote_password_set,
            remote_password_mode=remote_password_mode,
        )
    if not remote_password_set:
        log.info("注册完成，开始在启用 2FA 前补设远端密码。")
        with temporary_proxy_env(str(args.proxy_url or "")):
            password_reset_result = await set_chatgpt_password_via_reset_flow(
                profile=register_profile,
                config=dataclasses.replace(register_config, storageStatePath=final_state_path),
                logInfo=log.info,
                logWarn=log.warn,
                logError=log.error,
            )
        if not bool(password_reset_result.get("ok")):
            return CommandResult(
                success=False,
                mode="register",
                email=email,
                message=str(password_reset_result.get("errorMessage") or "注册完成，但补设远端密码失败"),
                storage_state_path=final_state_path,
                trace_path=final_trace_path,
                session_snapshot_path=session_snapshot_path,
                codex_token_json_path=codex_token_json_path,
                codex_token_txt_path=codex_token_txt_path,
                stage="set_password",
                error_code=str(password_reset_result.get("errorCode") or "password_reset_failed"),
                remote_password_set=False,
                remote_password_mode="post_registration_password_reset",
            )
        remote_password_set = True
        remote_password_mode = "post_registration_password_reset"
        final_state_path = str(password_reset_result.get("storageStatePath") or final_state_path)
        log.info("远端密码补设完成，准备继续启用 2FA。")
    try:
        with temporary_proxy_env(str(args.proxy_url or "")):
            _token, at_txt_path = await extract_at_from_storage_state(
                storage_state_path=final_state_path,
                email_hint=email,
            )
    except Exception as error:  # noqa: BLE001
        log.warn(f"HTTP 注册已推进，但登录 Session 尚未补全：{error}")
        return CommandResult(
            success=False,
            mode="register",
            email=email,
            message=f"邮箱注册流程已完成，但登录 Session 尚未建立：{error}",
            storage_state_path=final_state_path,
            trace_path=final_trace_path,
            session_snapshot_path=session_snapshot_path,
            codex_token_json_path=codex_token_json_path,
            codex_token_txt_path=codex_token_txt_path,
            stage="registration_session_pending",
            error_code="session_missing",
            remote_password_set=remote_password_set,
            remote_password_mode=remote_password_mode,
        )
    return CommandResult(
        success=True,
        mode="register",
        email=email,
        message="HTTP 注册成功，AT 已落库",
        storage_state_path=final_state_path,
        at_txt_path=at_txt_path,
        trace_path=final_trace_path,
        session_snapshot_path=session_snapshot_path,
        codex_token_json_path=codex_token_json_path,
        codex_token_txt_path=codex_token_txt_path,
        remote_password_set=remote_password_set,
        remote_password_mode=remote_password_mode,
    )


async def run_set_password_flow(args: argparse.Namespace) -> CommandResult:
    ensure_runtime_dirs()
    email = str(args.email or "").strip().lower()
    state_path = str(args.storage_state or "").strip() or state_path_for(email)
    trace_path = _trace_path("set_password", email) if bool(args.trace) else ""
    log = ConsoleLogSink()
    profile = ChatGptHttpRegisterProfile(
        email=email,
        password=str(args.password or ""),
        fullName=str(args.full_name or "").strip(),
        birthDate=str(args.birth_date or "").strip(),
    )
    config = ChatGptHttpRegisterConfig(
        timeoutSeconds=float(args.timeout_seconds or 360.0),
        traceEnabled=bool(args.trace),
        tracePath=trace_path,
        storageStatePath=state_path,
        proxyUrl=str(args.proxy_url or "").strip(),
        useManagedMailOtp=not bool(args.disable_managed_mail_otp),
        managedMailProvider=str(args.managed_mail_provider or "").strip(),
        managedMailJwt=str(args.managed_mail_jwt or "").strip(),
        managedMailApiBase=str(args.managed_mail_api_base or "").strip(),
        managedMailFrontendBase=str(args.managed_mail_frontend_base or "").strip(),
        managedMailLatestN=int(args.managed_mail_latest_n or 20),
        otpApiUrl=str(args.otp_api_url or "").strip(),
        useImapOtp=bool(args.use_imap_otp),
        otpTimeoutSeconds=float(args.otp_timeout_seconds or 180.0),
        otpIntervalSeconds=float(args.otp_interval_seconds or 1.0),
        imapHost=str(args.imap_host or "imap.2925.com").strip() or "imap.2925.com",
        imapPort=int(args.imap_port or 993),
        imapUser=str(args.imap_user or "").strip(),
        imapPass=str(args.imap_pass or ""),
        imapFolder=str(args.imap_folder or "Inbox").strip() or "Inbox",
        imapLatestN=int(args.imap_latest_n or 80),
        imapAuthType=str(args.imap_auth_type or "password").strip() or "password",
        imapOauthClientId=str(args.imap_oauth_client_id or "").strip(),
        imapOauthRefreshToken=str(args.imap_oauth_refresh_token or "").strip(),
        imapPasswordFallback=bool(args.imap_password_fallback),
        imapPop3Fallback=bool(args.imap_pop3_fallback),
    )
    with temporary_proxy_env(str(args.proxy_url or "")):
        result = await set_chatgpt_password_via_reset_flow(
            profile=profile,
            config=config,
            logInfo=log.info,
            logWarn=log.warn,
            logError=log.error,
        )
    if not bool(result.get("ok")):
        return CommandResult(
            success=False,
            mode="set_password",
            email=email,
            message=str(result.get("errorMessage") or "补设远端密码失败"),
            storage_state_path=str(result.get("storageStatePath") or state_path),
            trace_path=trace_path,
            stage="set_password",
            error_code=str(result.get("errorCode") or "password_reset_failed"),
            remote_password_set=False,
            remote_password_mode="post_registration_password_reset",
        )
    return CommandResult(
        success=True,
        mode="set_password",
        email=email,
        message="远端密码补设成功",
        storage_state_path=str(result.get("storageStatePath") or state_path),
        trace_path=trace_path,
        stage="password_set",
        remote_password_set=True,
        remote_password_mode="post_registration_password_reset",
    )


async def run_login_flow(args: argparse.Namespace) -> CommandResult:
    ensure_runtime_dirs()
    email = str(args.email or "").strip().lower()
    state_path = state_path_for(email)
    trace_path = _trace_path("login", email) if bool(args.trace) else ""
    log = ConsoleLogSink()
    domain_mail = _resolve_domain_mail_args(args)
    with temporary_proxy_env(str(args.proxy_url or "")):
        result = await run_chatgpt_http_login(
            profile=ChatGptHttpLoginProfile(
                email=email,
                password=str(args.password or ""),
                mfaTotpSecret=str(args.mfa_totp_secret or "").strip(),
            ),
            config=ChatGptHttpLoginConfig(
                timeoutSeconds=float(args.timeout_seconds or 240.0),
                traceEnabled=bool(args.trace),
                tracePath=trace_path,
                storageStatePath=state_path,
                proxyUrl=str(args.proxy_url or "").strip(),
                useManagedMailOtp=not bool(args.disable_managed_mail_otp),
                managedMailProvider=str(args.managed_mail_provider or "").strip(),
                managedMailJwt=str(args.managed_mail_jwt or "").strip(),
                managedMailApiBase=str(args.managed_mail_api_base or "").strip(),
                managedMailFrontendBase=str(args.managed_mail_frontend_base or "").strip(),
                managedMailLatestN=int(args.managed_mail_latest_n or 20),
                otpApiUrl=str(args.otp_api_url or "").strip(),
                useDomainMailOtp=bool(domain_mail["use"]),
                domainMailApiBase=str(domain_mail["api_base"]),
                domainMailDomain=str(domain_mail["domain"]),
                domainMailToken=str(domain_mail["token"]),
                domainMailLatestN=int(domain_mail["latest_n"]),
                useImapOtp=bool(args.use_imap_otp),
                otpTimeoutSeconds=float(args.otp_timeout_seconds or 180.0),
                otpIntervalSeconds=float(args.otp_interval_seconds or 1.0),
                imapHost=str(args.imap_host or "imap.2925.com").strip() or "imap.2925.com",
                imapPort=int(args.imap_port or 993),
                imapUser=str(args.imap_user or "").strip(),
                imapPass=str(args.imap_pass or ""),
                imapFolder=str(args.imap_folder or "Inbox").strip() or "Inbox",
                imapLatestN=int(args.imap_latest_n or 80),
                imapAuthType=str(args.imap_auth_type or "password").strip() or "password",
                imapOauthClientId=str(args.imap_oauth_client_id or "").strip(),
                imapOauthRefreshToken=str(args.imap_oauth_refresh_token or "").strip(),
                imapPasswordFallback=bool(args.imap_password_fallback),
                imapPop3Fallback=bool(args.imap_pop3_fallback),
                imapProfilesJson=_load_imap_profiles_json(args),
            ),
            logInfo=log.info,
            logWarn=log.warn,
            logError=log.error,
        )
    details = dict(getattr(result, "details", {}) or {})
    final_state_path = str(details.get("storageStatePath") or state_path).strip()
    final_trace_path = str(details.get("tracePath") or trace_path).strip()
    codex_token_json_path = str(details.get("codexTokenJsonPath") or "").strip()
    codex_token_txt_path = str(details.get("codexTokenTxtPath") or "").strip()
    if not bool(getattr(result, "success", False)):
        return CommandResult(
            success=False,
            mode="login",
            email=email,
            message=str(getattr(result, "message", "") or "HTTP 登录失败"),
            storage_state_path=final_state_path,
            trace_path=final_trace_path,
            stage=str(getattr(result, "stage", "") or "login_failed"),
            error_code=str(getattr(result, "errorCode", "") or "login_failed"),
        )
    try:
        with temporary_proxy_env(str(args.proxy_url or "")):
            _token, at_txt_path = await extract_at_from_storage_state(
                storage_state_path=final_state_path,
                email_hint=email,
            )
    except Exception as error:  # noqa: BLE001
        log.warn(f"邮箱登录流程已完成，但 Session 尚未返回 accessToken：{error}")
        return CommandResult(
            success=False,
            mode="login",
            email=email,
            message=f"邮箱登录流程已完成，但登录 Session 尚未建立：{error}",
            storage_state_path=final_state_path,
            trace_path=final_trace_path,
            stage="login_session_missing",
            error_code="session_missing",
        )
    if not codex_token_json_path:
        codex_token_json_path, codex_token_txt_path, _codex_token_ok = create_codex_wham_token_from_storage_state(
            storage_state_path=final_state_path,
            email_hint=email,
            proxy_url=str(args.proxy_url or "").strip(),
            timeout_seconds=float(args.timeout_seconds or 240.0),
        )
    return CommandResult(
        success=True,
        mode="login",
        email=email,
        message="HTTP 登录成功，AT 已落库",
        storage_state_path=final_state_path,
        at_txt_path=at_txt_path,
        trace_path=final_trace_path,
        codex_token_json_path=codex_token_json_path,
        codex_token_txt_path=codex_token_txt_path,
    )


async def run_bind_phone_flow(args: argparse.Namespace) -> CommandResult:
    """Bind a phone after registration by reusing an existing authenticated state."""

    ensure_runtime_dirs()
    storage_state_path = str(getattr(args, "storage_state", "") or "").strip()
    email = str(getattr(args, "email", "") or "").strip().lower()
    if not storage_state_path or not Path(storage_state_path).is_file():
        return CommandResult(
            success=False,
            mode="bind_phone",
            email=email or "unknown",
            message="绑定手机号失败：缺少可用 storage_state。",
            storage_state_path=storage_state_path,
            stage="validate_args",
            error_code="missing_storage_state",
        )
    if not email:
        email = derive_email_from_state(storage_state_path)
    if not email or "@" not in email:
        return CommandResult(
            success=False,
            mode="bind_phone",
            email=email or "unknown",
            message="绑定手机号失败：无法从 storage_state 确认账号邮箱。",
            storage_state_path=storage_state_path,
            stage="validate_args",
            error_code="missing_email",
        )

    phone_config = dict(getattr(args, "phone_verification", {}) or {})
    manual_phone_enabled = bool(
        str(
            phone_config.get("manual_phone_control_path")
            or phone_config.get("manual_phone_ipc_dir")
            or ""
        ).strip()
    )
    if (not manual_phone_enabled) and (
        not str(phone_config.get("sms_provider") or "").strip()
        or not str(phone_config.get("sms_api_key") or "").strip()
    ):
        return CommandResult(
            success=False,
            mode="bind_phone",
            email=email,
            message="绑定手机号失败：接码服务未配置。",
            storage_state_path=storage_state_path,
            stage="validate_args",
            error_code="sms_provider_not_configured",
        )

    log = ConsoleLogSink()
    domain_mail = _resolve_domain_mail_args(args)
    env_snapshot = temporary_http_env()
    try:
        with temporary_proxy_env(str(getattr(args, "proxy_url", "") or "")):
            oauth_result = await run_codex_oauth_flow(
                email=email,
                password=str(getattr(args, "password", "") or ""),
                storage_state_path=storage_state_path,
                output_path=success_path_for(email),
                headless=True,
                log=log,
                otp_timeout_sec=float(getattr(args, "otp_timeout_seconds", 180.0) or 180.0),
                otp_interval_sec=float(getattr(args, "otp_interval_seconds", 1.0) or 1.0),
                otp_api_url=str(getattr(args, "otp_api_url", "") or "").strip(),
                mfa_totp_secret=str(getattr(args, "mfa_totp_secret", "") or "").strip(),
                use_imap_otp=bool(getattr(args, "use_imap_otp", False)),
                use_managed_mail_otp=not bool(getattr(args, "disable_managed_mail_otp", True)),
                managed_mail_provider=str(getattr(args, "managed_mail_provider", "") or "").strip(),
                managed_mail_jwt=str(getattr(args, "managed_mail_jwt", "") or "").strip(),
                managed_mail_api_base=str(getattr(args, "managed_mail_api_base", "") or "").strip(),
                managed_mail_frontend_base=str(getattr(args, "managed_mail_frontend_base", "") or "").strip(),
                managed_mail_latest_n=int(getattr(args, "managed_mail_latest_n", 20) or 20),
                use_domain_mail_otp=bool(domain_mail["use"]),
                domain_mail_api_base=str(domain_mail["api_base"]),
                domain_mail_domain=str(domain_mail["domain"]),
                domain_mail_token=str(domain_mail["token"]),
                domain_mail_latest_n=int(domain_mail["latest_n"]),
                imap_host=str(getattr(args, "imap_host", "imap.2925.com") or "imap.2925.com").strip(),
                imap_port=int(getattr(args, "imap_port", 993) or 993),
                imap_user=str(getattr(args, "imap_user", "") or "").strip(),
                imap_pass=str(getattr(args, "imap_pass", "") or ""),
                imap_folder=str(getattr(args, "imap_folder", "Inbox") or "Inbox").strip(),
                imap_latest_n=int(getattr(args, "imap_latest_n", 80) or 80),
                imap_auth_type=str(getattr(args, "imap_auth_type", "password") or "password").strip(),
                imap_oauth_client_id=str(getattr(args, "imap_oauth_client_id", "") or "").strip(),
                imap_oauth_refresh_token=str(getattr(args, "imap_oauth_refresh_token", "") or "").strip(),
                imap_password_fallback=bool(getattr(args, "imap_password_fallback", False)),
                imap_pop3_fallback=bool(getattr(args, "imap_pop3_fallback", False)),
                imap_profiles_json=_load_imap_profiles_json(args),
                timeout_sec=float(getattr(args, "timeout_seconds", 360.0) or 360.0),
                provider="http",
                expected_workspace_id=str(getattr(args, "expected_workspace_id", "") or "").strip(),
                phone_verification=phone_config,
                require_phone_bind=True,
            )
    except Exception as error:  # noqa: BLE001
        stage, error_code = parse_error_stage_code(
            str(error),
            default_stage="phone_bind_failed",
            default_code="phone_bind_failed",
        )
        return CommandResult(
            success=False,
            mode="bind_phone",
            email=email,
            message=f"绑定手机号失败：{error}",
            storage_state_path=storage_state_path,
            stage=stage,
            error_code=error_code,
        )
    finally:
        restore_env(env_snapshot)

    bound_phone = str(oauth_result.get("bound_phone") or "").strip()
    if not bound_phone:
        return CommandResult(
            success=False,
            mode="bind_phone",
            email=email,
            message="绑定手机号失败：认证事务未提供 add-phone 步骤。",
            storage_state_path=storage_state_path,
            trace_path=str(oauth_result.get("trace_path") or "").strip(),
            stage="phone_bind_not_offered",
            error_code="phone_bind_not_offered",
        )

    updated_state = oauth_result.get("storage_state")
    if isinstance(updated_state, dict):
        try:
            original_state = load_json(storage_state_path)
            refreshed_cookies = updated_state.get("cookies")
            if isinstance(refreshed_cookies, list) and refreshed_cookies:
                original_state["cookies"] = refreshed_cookies
            refreshed_origins = updated_state.get("origins")
            if isinstance(refreshed_origins, list):
                original_state["origins"] = refreshed_origins
            write_json(storage_state_path, original_state)
        except Exception:
            log.warn("手机号已绑定，但更新后的 storage_state 未能写回。")

    success_credential_path = ""
    rt_message = ""
    try:
        auth_args = copy.deepcopy(args)
        auth_args.email = email
        auth_args.storage_state = storage_state_path
        auth_args.headless = True
        auth_result = await run_auth_flow(auth_args)
        if auth_result.success and str(auth_result.success_credential_path or "").strip():
            success_credential_path = str(auth_result.success_credential_path or "").strip()
            rt_message = "，RT 已落库"
            if auth_result.trace_path:
                oauth_result = {
                    **(oauth_result if isinstance(oauth_result, dict) else {}),
                    "trace_path": auth_result.trace_path,
                }
        else:
            rt_message = f"，RT 导出失败：{auth_result.message or auth_result.error_code or 'unknown'}"
            log.warn(f"手机号已绑定，但 RT 导出失败：{auth_result.message or auth_result.error_code or 'unknown'}")
    except Exception as error:  # noqa: BLE001
        rt_message = f"，RT 导出异常：{error}"
        log.warn(f"手机号已绑定，但 RT 导出异常：{error}")

    return CommandResult(
        success=True,
        mode="bind_phone",
        email=email,
        message=f"手机号绑定验证已完成{rt_message}。",
        storage_state_path=storage_state_path,
        trace_path=str(oauth_result.get("trace_path") or "").strip(),
        success_credential_path=success_credential_path,
        bound_phone=bound_phone,
        stage="phone_bound",
    )


async def run_extract_at_flow(args: argparse.Namespace) -> CommandResult:
    ensure_runtime_dirs()
    storage_state_path = str(args.storage_state or "").strip()
    if not storage_state_path:
        return CommandResult(
            success=False,
            mode="extract_at",
            email="unknown",
            message="提取 AT 失败：缺少 storage_state 路径。",
            stage="validate_args",
            error_code="missing_storage_state",
        )
    email_hint = str(args.email or "").strip() or derive_email_from_state(storage_state_path)
    at_target = str(args.at_file or "").strip()
    try:
        _token, at_txt_path = await extract_at_from_storage_state(
            storage_state_path=storage_state_path,
            email_hint=email_hint,
            at_txt_path=at_target,
        )
    except Exception as error:  # noqa: BLE001
        stage, error_code = parse_error_stage_code(str(error), default_stage="extract_at_failed", default_code="extract_at_failed")
        return CommandResult(
            success=False,
            mode="extract_at",
            email=email_hint,
            message=f"提取 AT 失败：{error}",
            storage_state_path=storage_state_path,
            stage=stage,
            error_code=error_code,
        )
    return CommandResult(
        success=True,
        mode="extract_at",
        email=email_hint,
        message="AT 已落库",
        storage_state_path=storage_state_path,
        at_txt_path=at_txt_path,
    )


async def run_auth_flow(args: argparse.Namespace) -> CommandResult:
    ensure_runtime_dirs()
    requested_state_path = str(args.storage_state or "").strip()
    email = str(args.email or "").strip().lower()
    password = str(args.password or "")
    trace_path = _trace_path("auth", email or requested_state_path or "state") if bool(args.trace) else ""
    domain_mail = _resolve_domain_mail_args(args)

    state_path = requested_state_path
    at_txt_path = ""
    if state_path:
        if not email:
            email = derive_email_from_state(state_path)
        try:
            _token, at_txt_path = await extract_at_from_storage_state(storage_state_path=state_path, email_hint=email)
        except Exception as error:  # noqa: BLE001
            stage, error_code = parse_error_stage_code(str(error), default_stage="extract_at_failed", default_code="extract_at_failed")
            return CommandResult(
                success=False,
                mode="auth",
                email=email or "unknown",
                message=f"认证前提取 AT 失败：{error}",
                storage_state_path=state_path,
                stage=stage,
                error_code=error_code,
            )
    else:
        if not email or "@" not in email:
            return CommandResult(
                success=False,
                mode="auth",
                email=email or "unknown",
                message="认证失败：未提供有效邮箱，也没有可复用 storage_state。",
                stage="validate_args",
                error_code="missing_email",
            )
        if not password:
            return CommandResult(
                success=False,
                mode="auth",
                email=email,
                message="认证失败：未提供密码，且没有可复用 storage_state。",
                stage="validate_args",
                error_code="missing_password",
            )
        login_result = await run_login_flow(copy.deepcopy(args))
        if not login_result.success:
            return CommandResult(
                success=False,
                mode="auth",
                email=email,
                message=f"认证失败：前置 HTTP 登录未完成。{login_result.message}",
                storage_state_path=login_result.storage_state_path,
                trace_path=login_result.trace_path,
                stage=login_result.stage or "login_failed",
                error_code=login_result.error_code or "login_failed",
            )
        state_path = login_result.storage_state_path
        at_txt_path = login_result.at_txt_path

    success_path = success_path_for(email or derive_email_from_state(state_path))
    log = ConsoleLogSink()
    env_snapshot = temporary_http_env()
    try:
        with temporary_proxy_env(str(args.proxy_url or "")):
            oauth_result = await run_codex_oauth_flow(
                email=email,
                password=password,
                storage_state_path=state_path,
                output_path=success_path,
                headless=bool(args.headless),
                log=log,
                otp_timeout_sec=float(args.otp_timeout_seconds or 180.0),
                otp_interval_sec=float(args.otp_interval_seconds or 1.0),
                otp_api_url=str(args.otp_api_url or "").strip(),
                mfa_totp_secret=str(args.mfa_totp_secret or "").strip(),
                use_imap_otp=bool(args.use_imap_otp),
                use_managed_mail_otp=not bool(args.disable_managed_mail_otp),
                managed_mail_provider=str(args.managed_mail_provider or "").strip(),
                managed_mail_jwt=str(args.managed_mail_jwt or "").strip(),
                managed_mail_api_base=str(args.managed_mail_api_base or "").strip(),
                managed_mail_frontend_base=str(args.managed_mail_frontend_base or "").strip(),
                managed_mail_latest_n=int(args.managed_mail_latest_n or 20),
                use_domain_mail_otp=bool(domain_mail["use"]),
                domain_mail_api_base=str(domain_mail["api_base"]),
                domain_mail_domain=str(domain_mail["domain"]),
                domain_mail_token=str(domain_mail["token"]),
                domain_mail_latest_n=int(domain_mail["latest_n"]),
                imap_host=str(args.imap_host or "imap.2925.com").strip() or "imap.2925.com",
                imap_port=int(args.imap_port or 993),
                imap_user=str(args.imap_user or "").strip(),
                imap_pass=str(args.imap_pass or ""),
                imap_folder=str(args.imap_folder or "Inbox").strip() or "Inbox",
                imap_latest_n=int(args.imap_latest_n or 80),
                imap_auth_type=str(args.imap_auth_type or "password").strip() or "password",
                imap_oauth_client_id=str(args.imap_oauth_client_id or "").strip(),
                imap_oauth_refresh_token=str(args.imap_oauth_refresh_token or "").strip(),
                imap_password_fallback=bool(args.imap_password_fallback),
                imap_pop3_fallback=bool(args.imap_pop3_fallback),
                imap_profiles_json=_load_imap_profiles_json(args),
                timeout_sec=float(args.timeout_seconds or 360.0),
                provider="http",
                expected_workspace_id=str(args.expected_workspace_id or "").strip(),
            )
    except Exception as error:  # noqa: BLE001
        restore_env(env_snapshot)
        stage, error_code = parse_error_stage_code(str(error), default_stage="auth_failed", default_code="auth_failed")
        return CommandResult(
            success=False,
            mode="auth",
            email=email or "unknown",
            message=f"HTTP 认证失败：{error}",
            storage_state_path=state_path,
            trace_path=trace_path,
            stage=stage,
            error_code=error_code,
        )
    restore_env(env_snapshot)
    final_trace_path = str(oauth_result.get("trace_path") or trace_path).strip()
    if not at_txt_path:
        _token, at_txt_path = await extract_at_from_storage_state(storage_state_path=state_path, email_hint=email)
    enrich_success_credential(
        success_path=success_path,
        email=email,
        password=password,
        storage_state_path=state_path,
        at_txt_path=at_txt_path,
        trace_path=final_trace_path,
    )
    return CommandResult(
        success=True,
        mode="auth",
        email=email,
        message="HTTP 认证成功，AT 已落库",
        storage_state_path=state_path,
        at_txt_path=at_txt_path,
        trace_path=final_trace_path,
        success_credential_path=success_path,
    )
