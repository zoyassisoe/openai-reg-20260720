from __future__ import annotations

import asyncio
import base64
import dataclasses
import datetime
import inspect
import json
import os
import re
import secrets
import threading
import time
import urllib.request
import uuid
import zlib
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from chatgpt_api_health import (
    extract_access_token_from_session_payload,
    extract_chatgpt_account_id_from_jwt,
    extract_session_summary_from_payload,
    resolve_proxy_for_url,
)
from managed_mail_otp import poll_managed_mail_verification_code_sync
from domain_mail_otp import poll_domain_mail_verification_code_sync
from code_utils import defaultCodeKeywords, extractVerificationCode, extractVerificationTimestamp
from codex_oauth import (
    _BLOCK_PAGE_MARKERS,
    _ERROR_TEXT_MARKERS,
    _HTTP_AUTHORIZE_CONTINUE_SENTINEL_FLOW,
    _HTTP_PASSWORD_VERIFY_SENTINEL_FLOW,
    _OTP_IMAP_NOT_BEFORE_GRACE_SEC,
    _OTP_IMAP_POST_SEND_GRACE_SEC,
    _OTP_INVALID_MARKERS,
    _build_empty_storage_state_payload,
    _build_http_auth_fetch_headers,
    _build_http_datadog_trace_headers,
    _build_http_html_headers,
    _build_playwright_proxy_option,
    _build_http_provider_request_context,
    _choose_http_otp_send_request,
    _choose_http_provider_workspace_context_from_storage_state,
    _collect_http_provider_workspaces,
    _collect_auth_step_hints,
    _collect_http_sentinel_header_candidates_for_flows,
    _compress_debug_text,
    _callback_from_url,
    _decode_base64_json_cookie_value,
    _extract_continue_url,
    _extract_error,
    _follow_http_authorize_chain,
    _is_email_otp_verification_step,
    _is_invalid_authorization_step,
    _mask_proxy_url_for_log,
    _mask_email,
    _pick_http_provider_workspace,
    _poll_imap_code_multi_sync,
    _read_request_context_storage_state,
    _read_storage_state_cookie_value,
    _response_looks_like_cloudflare_challenge,
    _request_auth_api_with_context,
    _request_json_with_context,
    _request_with_context,
    _resolve_http_provider_curl_impersonate,
    _resolve_request_ctx_impersonate,
    _sanitize_url_for_log,
    _normalize_imap_profiles_payload,
    _should_try_http_passwordless_login_fallback,
)
from totp_utils import generate_totp_code, normalize_totp_secret, totp_seconds_remaining
from imap_2925 import Imap2925Config, scan_imap_recent_uids
from http_stage_features import (
    activate_http_stage_feature_session,
    get_http_stage_browser_headers,
    get_http_stage_device_id,
    get_http_stage_feature_summary,
)


LogFn = Callable[[str], None]
StageReporter = Callable[[dict[str, Any]], Any]

_DEFAULT_ACCOUNT_RESIDENCY_REGION = "no_constraint"
_DEFAULT_CHATGPT_HOME_HINT = "WHAT_ARE_YOU_WORKING_ON%20%7C%20GOOD_TO_SEE_YOU"
_DEFAULT_SEARCH_ATTRIBUTIONS_SETTINGS = {
    "state": {
        "debugMode": False,
        "viewModelPredictedFallback": False,
        "disableSegmentReplacement": False,
        "useSigmoid": True,
        "influenceTemperature": 0.2,
        "probThreshold": 0.45,
        "probBaseline": 0.02,
    },
    "version": 8,
}
_HTTP_LOGIN_RUNTIME_COOKIE_NAMES: tuple[str, ...] = (
    "__Secure-next-auth.session-token",
    "next-auth.session-token",
    "__Secure-authjs.session-token",
    "authjs.session-token",
    "_account",
    "_account_residency_region",
    "_account_is_fedramp",
    "oai-hlib",
    "oai-hm",
    "oai-did",
    "oai-client-auth-session",
    "auth-session-minimized",
    "oai-client-auth-info",
    "__cf_bm",
    "__cflb",
    "_cfuvid",
)
_HTTP_LOGIN_RUNTIME_COOKIE_NAME_PREFIXES: tuple[str, ...] = (
    "__Secure-next-auth.session-token.",
    "next-auth.session-token.",
    "__Secure-authjs.session-token.",
    "authjs.session-token.",
)
_HTTP_LOGIN_RUNTIME_OPTIONAL_COOKIE_DROP_ORDER: tuple[str, ...] = (
    "oai-client-auth-info",
    "auth-session-minimized",
    "_cfuvid",
    "__cflb",
    "__cf_bm",
)
_HTTP_LOGIN_RUNTIME_CHATGPT_LOCAL_STORAGE_EXACT_KEYS = frozenset(
    {
        "_account",
        "_account_residency_region",
        "client-correlated-secret",
        "oai-did",
    }
)
_HTTP_LOGIN_RUNTIME_CHATGPT_LOCAL_STORAGE_PREFIXES: tuple[str, ...] = (
    "statsig.session_id.",
    "statsig.stable_id.",
)
_HTTP_LOGIN_RUNTIME_AUTH_LOCAL_STORAGE_PREFIXES: tuple[str, ...] = (
    "statsig.session_id.",
    "statsig.stable_id.",
)
_HTTP_LOGIN_RUNTIME_COOKIE_HEADER_MAX_LENGTH = 7_000
_WHAM_AUTH_CREDENTIALS_URL = "https://chatgpt.com/backend-api/wham/auth-credentials"
_WHAM_CODEX_SCOPE = "chatgpt.workspace.feature.allow-codex-local-access.access"


def _http_login_direct_token_exchange_enabled() -> bool:
    raw = str(os.getenv("OAI_HTTP_LOGIN_DIRECT_TOKEN_EXCHANGE") or "").strip().lower()
    return raw in {"1", "true", "yes", "y", "on"}


@dataclasses.dataclass(frozen=True, slots=True)
class ChatGptHttpLoginProfile:
    email: str
    password: str
    mfaTotpSecret: str = ""


@dataclasses.dataclass(frozen=True, slots=True)
class ChatGptHttpLoginConfig:
    timeoutSeconds: float = 240.0
    traceEnabled: bool = False
    tracePath: str = ""
    storageStatePath: str = ""
    proxyUrl: str = ""
    useManagedMailOtp: bool = True
    managedMailProvider: str = ""
    managedMailJwt: str = ""
    managedMailApiBase: str = ""
    managedMailFrontendBase: str = ""
    managedMailLatestN: int = 20
    otpApiUrl: str = ""
    useDomainMailOtp: bool = True
    domainMailApiBase: str = ""
    domainMailDomain: str = ""
    domainMailToken: str = ""
    domainMailLatestN: int = 20
    useImapOtp: bool = False
    otpTimeoutSeconds: float = 120.0
    otpIntervalSeconds: float = 3.0
    imapHost: str = "imap.2925.com"
    imapPort: int = 993
    imapUser: str = ""
    imapPass: str = ""
    imapFolder: str = "Inbox"
    imapLatestN: int = 80
    imapAuthType: str = "password"
    imapOauthClientId: str = ""
    imapOauthRefreshToken: str = ""
    imapPasswordFallback: bool = False
    imapPop3Fallback: bool = False
    imapProfilesJson: str = ""


@dataclasses.dataclass(frozen=True, slots=True)
class ChatGptHttpLoginResult:
    success: bool
    stage: str
    errorCode: str
    message: str
    details: dict[str, Any] = dataclasses.field(default_factory=dict)


class _TraceWriter:
    def __init__(self, *, email: str, path: str = "", enabled: bool = False) -> None:
        self._enabled = bool(enabled or str(path or "").strip())
        self._lock = threading.Lock()
        self._email = str(email or "").strip()
        if str(path or "").strip():
            trace_path = Path(str(path).strip()).expanduser().resolve()
            trace_path.parent.mkdir(parents=True, exist_ok=True)
            self.path = str(trace_path)
            return

        debug_dir = (Path(__file__).resolve().parent / "tmp" / "chatgpt_http_login_debug").resolve()
        debug_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        suffix = _safe_filename_slug(email or "unknown")[:80] or "unknown"
        self.path = str((debug_dir / f"chatgpt_http_login_{ts}_{suffix}_{uuid.uuid4().hex[:8]}.jsonl").resolve())

    def write(self, payload: dict[str, Any]) -> None:
        if not self._enabled:
            return
        try:
            raw = json.dumps(_sanitize_trace_payload(dict(payload or {}), email=self._email), ensure_ascii=False, default=str)
        except Exception:
            return
        with self._lock:
            with Path(self.path).open("a", encoding="utf-8") as handle:
                handle.write(raw + "\n")


class _LogSink:
    def __init__(self, *, logInfo: Optional[LogFn], logWarn: Optional[LogFn], logError: Optional[LogFn]) -> None:
        self._log_info = logInfo
        self._log_warn = logWarn
        self._log_error = logError

    def info(self, message: str) -> None:
        _safe_log(self._log_info, message)

    def warn(self, message: str) -> None:
        _safe_log(self._log_warn or self._log_info, message)

    def error(self, message: str) -> None:
        _safe_log(self._log_error or self._log_warn or self._log_info, message)

    def success(self, message: str) -> None:
        _safe_log(self._log_info, message)


def _noop_log(_: str) -> None:
    return None


def _safe_log(fn: Optional[LogFn], message: str) -> None:
    if not callable(fn):
        return
    try:
        fn(str(message or "").strip())
    except Exception:
        return


async def _report_http_stage(
    reporter: Optional[StageReporter],
    *,
    stage: str,
    step_name: str,
    current_url: str = "",
    detail: str = "",
    error_message: str = "",
) -> None:
    if not callable(reporter):
        return
    payload = {
        "stage": str(stage or "").strip(),
        "stepName": str(step_name or "").strip(),
        "currentUrl": _sanitize_url_for_log(current_url),
        "detail": str(detail or "").strip(),
        "errorMessage": str(error_message or "").strip(),
    }
    try:
        maybe = reporter(payload)
        if inspect.isawaitable(maybe):
            await maybe
    except Exception:
        return


def _iso_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _safe_filename_slug(text: str) -> str:
    safe = re.sub(r"[^0-9A-Za-z._@-]+", "_", str(text or "").strip())
    safe = safe.replace(":", "_").replace("\\", "_").replace("/", "_")
    return safe.strip("._-") or "unknown"


def _is_trace_secret_key(key: str) -> bool:
    normalized = str(key or "").strip().lower()
    if not normalized:
        return False
    if normalized in {
        "authorization",
        "cookie",
        "set-cookie",
        "password",
        "access_token",
        "accesstoken",
        "session_access_token",
        "refresh_token",
        "id_token",
        "secret",
        "mfatotpsecret",
    }:
        return True
    if "cookie" in normalized:
        return True
    if normalized.endswith("_token") or normalized.endswith("-token") or normalized.endswith("token"):
        return normalized not in {"tokenlength", "tokenpresent"}
    if normalized.endswith("_secret") or normalized.endswith("-secret") or normalized.endswith("secret"):
        return True
    return False


def _sanitize_trace_string(text: str, *, email: str, key_hint: str = "") -> str:
    value = str(text or "")
    if not value:
        return value

    masked_email = _mask_email(email) if str(email or "").strip() else ""
    if email:
        value = value.replace(str(email), masked_email)

    normalized_key = str(key_hint or "").strip().lower()
    if normalized_key == "authorization":
        return "Bearer ***"
    if normalized_key == "code" and value.isdigit() and 4 <= len(value) <= 8:
        return "***"
    if "email" in normalized_key and "@" in value:
        return masked_email or value
    if _is_trace_secret_key(normalized_key):
        return "***"

    stripped = value.strip()
    if stripped[:1] in {"{", "["}:
        try:
            parsed = json.loads(stripped)
        except Exception:
            parsed = None
        if parsed is not None:
            return json.dumps(_sanitize_trace_payload(parsed, email=email), ensure_ascii=False)

    value = re.sub(
        r'(?i)("(?:password|authorization|cookie|set-cookie|secret|mfaTotpSecret|accessToken|session_access_token|refresh_token|id_token|openai-sentinel-token|client-correlated-secret)"\s*:\s*")[^"]*(")',
        r'\1***\2',
        value,
    )
    value = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._-]+\b", "Bearer ***", value)
    value = re.sub(
        r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])",
        "***",
        value,
    )
    return value


def _sanitize_trace_payload(value: Any, *, email: str, key_hint: str = "") -> Any:
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            key_text = str(raw_key or "")
            sanitized[key_text] = _sanitize_trace_payload(raw_value, email=email, key_hint=key_text)
        return sanitized
    if isinstance(value, list):
        return [_sanitize_trace_payload(item, email=email, key_hint=key_hint) for item in value]
    if isinstance(value, tuple):
        return [_sanitize_trace_payload(item, email=email, key_hint=key_hint) for item in value]
    if isinstance(value, str):
        return _sanitize_trace_string(value, email=email, key_hint=key_hint)
    return value


def _build_result(
    *,
    success: bool,
    stage: str,
    error_code: str,
    message: str,
    trace_path: str,
    extra: Optional[dict[str, Any]] = None,
) -> ChatGptHttpLoginResult:
    payload: dict[str, Any] = {}
    if trace_path:
        payload["tracePath"] = str(trace_path)
    if isinstance(extra, dict):
        payload.update(extra)
    return ChatGptHttpLoginResult(
        success=bool(success),
        stage=str(stage or ""),
        errorCode=str(error_code or ""),
        message=str(message or ""),
        details=payload,
    )


def _codex_token_paths_for_storage_state(output_path: str) -> tuple[str, str]:
    storage_path = Path(str(output_path or "")).expanduser()
    if not storage_path.name:
        return "", ""
    try:
        resolved = storage_path.resolve()
    except Exception:
        resolved = storage_path
    root = resolved.parent.parent if resolved.parent.name else resolved.parent
    target_dir = root / "访问令牌"
    json_name = resolved.name if resolved.suffix else f"{resolved.name}.json"
    txt_name = f"{resolved.stem or resolved.name}.txt"
    return str(target_dir / json_name), str(target_dir / txt_name)


def _success_credential_path_for_storage_state(output_path: str, email_hint: str = "") -> str:
    storage_path = Path(str(output_path or "")).expanduser()
    if not storage_path.name:
        return ""
    try:
        resolved = storage_path.resolve()
    except Exception:
        resolved = storage_path
    root = resolved.parent.parent if resolved.parent.name else resolved.parent
    target_dir = root / "成功凭证"
    raw_name = str(email_hint or resolved.stem or resolved.name or "credential").strip()
    safe_name = re.sub(r'[<>:"/\\|?*]+', "_", raw_name).strip(" .") or "credential"
    return str(target_dir / f"{safe_name[:180]}.json")


def _write_text_file(path: str, text: str) -> None:
    target = Path(str(path or "")).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    _write_text_with_windows_fallback(target, str(text or ""))


def _first_non_empty_string(*values: Any) -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _iso_local_now() -> str:
    return datetime.datetime.now().astimezone().replace(microsecond=0).isoformat()


def _iso_local_from_timestamp(value: Any, *, fallback: str = "") -> str:
    try:
        ts = int(float(str(value).strip()))
    except Exception:
        return fallback
    return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).astimezone().replace(microsecond=0).isoformat()


def _iso_local_from_any(value: Any, *, fallback_now: bool = False) -> str:
    text = str(value or "").strip()
    if text:
        try:
            parsed = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=datetime.timezone.utc)
            return parsed.astimezone().replace(microsecond=0).isoformat()
        except Exception:
            return text
    return _iso_local_now() if fallback_now else ""


def _extract_email_from_session_payload(session_payload: dict[str, Any], output_path: str) -> str:
    user = session_payload.get("user") if isinstance(session_payload.get("user"), dict) else {}
    return _first_non_empty_string(
        user.get("email"),
        session_payload.get("email"),
        Path(str(output_path or "")).stem,
    ).lower()


def _write_success_codex_credential(
    *,
    output_path: str,
    session_payload: dict[str, Any],
    account_id: str,
    credential_payload: dict[str, Any],
) -> tuple[str, str]:
    session_payload = session_payload if isinstance(session_payload, dict) else {}
    credential_payload = credential_payload if isinstance(credential_payload, dict) else {}
    session_token = str(extract_access_token_from_session_payload(session_payload) or "").strip()
    codex_token = str(credential_payload.get("access_token") or "").strip()
    if not session_token:
        return "", "missing_login_access_token"
    if not codex_token:
        return "", "missing_cpa_header_token"
    email = _extract_email_from_session_payload(session_payload, output_path)
    if not email:
        return "", "missing_email"
    expired = _iso_local_from_timestamp(
        credential_payload.get("expires_at"),
        fallback=_first_non_empty_string(
            _iso_local_from_any(session_payload.get("session_access_token_expires_at")),
            "2026-12-31T10:00:00+08:00",
        ),
    )
    payload = {
        "access_token": session_token,
        "account_id": str(account_id or credential_payload.get("workspace_id") or "").strip(),
        "disabled": False,
        "email": email,
        "expired": expired,
        "headers": {
            "authorization": f"Bearer {codex_token}",
        },
        "id_token": None,
        "last_refresh": _iso_local_from_any(session_payload.get("session_access_token_updated_at"), fallback_now=True),
        "refresh_token": None,
        "type": "codex",
        "websockets": True,
    }
    success_path = _success_credential_path_for_storage_state(output_path, email)
    if not success_path:
        return "", "missing_success_path"
    _write_json_file(success_path, payload)
    return success_path, ""


def _extract_wham_account_id(session_payload: dict[str, Any], summary: dict[str, Any]) -> str:
    account = session_payload.get("account") if isinstance(session_payload, dict) else {}
    if isinstance(account, dict):
        direct = _first_non_empty_string(
            account.get("id"),
            account.get("account_id"),
            account.get("workspace_id"),
            account.get("workspaceId"),
        )
        if direct:
            return direct
    direct = _first_non_empty_string(
        summary.get("selectedWorkspaceId") if isinstance(summary, dict) else "",
        summary.get("accountId") if isinstance(summary, dict) else "",
        summary.get("selectedAccountId") if isinstance(summary, dict) else "",
        session_payload.get("selectedWorkspaceId") if isinstance(session_payload, dict) else "",
        session_payload.get("selectedAccountId") if isinstance(session_payload, dict) else "",
        session_payload.get("accountId") if isinstance(session_payload, dict) else "",
        session_payload.get("workspaceId") if isinstance(session_payload, dict) else "",
    )
    if direct:
        return direct
    accounts = session_payload.get("accounts") if isinstance(session_payload, dict) else None
    if isinstance(accounts, list):
        selected_accounts = [item for item in accounts if isinstance(item, dict) and bool(item.get("is_selected"))]
        for item in selected_accounts + [item for item in accounts if isinstance(item, dict)]:
            candidate = _first_non_empty_string(
                item.get("id"),
                item.get("account_id"),
                item.get("workspace_id"),
                item.get("workspaceId"),
            )
            if candidate:
                return candidate
    return ""


def _write_codex_token_result(
    *,
    output_path: str,
    status: int,
    account_id: str,
    response_payload: dict[str, Any],
    response_text: str,
    error: str,
    session_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    json_path, txt_path = _codex_token_paths_for_storage_state(output_path)
    if not json_path:
        return {"ok": False, "error": "missing_output_path", "jsonPath": "", "txtPath": ""}
    credential_payload = response_payload if isinstance(response_payload, dict) else {}
    codex_token = str(credential_payload.get("access_token") or "").strip()
    record = {
        "type": "chatgpt_wham_auth_credential",
        "source": _WHAM_AUTH_CREDENTIALS_URL,
        "name": "codex",
        "scopes": [_WHAM_CODEX_SCOPE],
        "ttl": 7776000,
        "status": int(status or 0),
        "ok": bool(200 <= int(status or 0) < 300 and codex_token),
        "error": str(error or "").strip(),
        "account_id": str(account_id or "").strip(),
        "updated_at": _iso_now(),
        "accessTokenPresent": bool(codex_token),
        "accessTokenLen": len(codex_token),
        "credential": dict(credential_payload),
    }
    if not credential_payload and response_text:
        record["responseTextSnippet"] = _compress_debug_text(response_text, limit=800)
    _write_json_file(json_path, record)
    if codex_token:
        _write_text_file(txt_path, f"{codex_token}\n")
    success_credential_path = ""
    success_credential_error = ""
    if bool(200 <= int(status or 0) < 300 and codex_token):
        success_credential_path, success_credential_error = _write_success_codex_credential(
            output_path=output_path,
            session_payload=session_payload or {},
            account_id=account_id,
            credential_payload=credential_payload,
        )
    return {
        "ok": bool(codex_token and 200 <= int(status or 0) < 300),
        "error": str(error or "").strip(),
        "status": int(status or 0),
        "jsonPath": json_path,
        "txtPath": txt_path if codex_token else "",
        "successCredentialPath": success_credential_path,
        "successCredentialError": success_credential_error,
        "accessTokenPresent": bool(codex_token),
        "accessTokenLen": len(codex_token),
    }


async def _create_codex_wham_auth_credential(
    *,
    request_ctx: Any,
    trace: _TraceWriter,
    output_path: str,
    session_payload: dict[str, Any],
    session_status: int,
    session_error: str,
    timeout_sec: float,
) -> dict[str, Any]:
    session_payload = session_payload if isinstance(session_payload, dict) else {}
    session_token = str(extract_access_token_from_session_payload(session_payload) or "").strip()
    summary = extract_session_summary_from_payload(
        session_payload,
        status=int(session_status or 0),
        error_text=str(session_error or "").strip(),
        updated_at=_iso_now(),
    )
    account_id = _extract_wham_account_id(session_payload, dict(summary))
    if not session_token or not account_id:
        result = await asyncio.to_thread(
            _write_codex_token_result,
            output_path=output_path,
            status=0,
            account_id=account_id,
            response_payload={},
            response_text="",
            error="missing_access_token" if not session_token else "missing_account_id",
            session_payload=session_payload,
        )
        trace.write(
            {
                "ts": _iso_now(),
                "stage": "http_login_codex_token_skipped",
                "reason": result.get("error") or "",
                "accountIdPresent": bool(account_id),
                "sessionAccessTokenPresent": bool(session_token),
                "jsonPath": result.get("jsonPath") or "",
            }
        )
        return dict(result)
    body = json.dumps(
        {
            "name": "codex",
            "scopes": [_WHAM_CODEX_SCOPE],
            "ttl": 7776000,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )
    headers = {
        "accept": "application/json",
        "authorization": f"Bearer {session_token}",
        "chatgpt-account-id": account_id,
        "content-type": "application/json",
        "origin": "https://chatgpt.com",
        "referer": "https://chatgpt.com/",
    }
    try:
        payload, status, text, response_url, response_headers = await _request_with_context(
            request_ctx,
            method="POST",
            url=_WHAM_AUTH_CREDENTIALS_URL,
            headers=headers,
            body_text=body,
            timeout_ms=int(max(15_000, float(timeout_sec or 0.0) * 1000.0 / 3.0)),
            max_redirects=0,
        )
        error = ""
    except Exception as exc:
        payload, status, text, response_url, response_headers = {}, 0, "", _WHAM_AUTH_CREDENTIALS_URL, {}
        error = str(exc or "").strip()
    result = await asyncio.to_thread(
        _write_codex_token_result,
        output_path=output_path,
        status=int(status or 0),
        account_id=account_id,
        response_payload=payload if isinstance(payload, dict) else {},
        response_text=text,
        error=error,
        session_payload=session_payload,
    )
    trace.write(
        {
            "ts": _iso_now(),
            "stage": "http_login_codex_token_create",
            "status": int(status or 0),
            "ok": bool(result.get("ok")),
            "accountId": account_id,
            "credentialId": str((payload or {}).get("credential_id") or "").strip() if isinstance(payload, dict) else "",
            "accessTokenLen": int(result.get("accessTokenLen") or 0),
            "jsonPath": str(result.get("jsonPath") or ""),
            "txtPath": str(result.get("txtPath") or ""),
            "successCredentialPath": str(result.get("successCredentialPath") or ""),
            "successCredentialError": _compress_debug_text(str(result.get("successCredentialError") or ""), limit=240),
            "responseUrl": _sanitize_url_for_log(response_url),
            "error": _compress_debug_text(error, limit=240),
            "responseTextLen": len(str(text or "")),
            "responseAccessTokenPresent": bool((payload or {}).get("access_token")) if isinstance(payload, dict) else False,
            "headerKeys": sorted(list((response_headers or {}).keys()))[:20],
        }
    )
    return dict(result)


def _build_imap_profiles_json_with_uid_baseline(
    *,
    config: ChatGptHttpLoginConfig,
    safe_email: str,
    log: _LogSink,
) -> str:
    if not bool(config.useImapOtp):
        return ""
    profiles = _normalize_imap_profiles_payload(
        str(config.imapProfilesJson or ""),
        fallback_host=str(config.imapHost or "imap.2925.com").strip() or "imap.2925.com",
        fallback_port=int(config.imapPort or 993),
        fallback_user=str(config.imapUser or "").strip(),
        fallback_pass=str(config.imapPass or ""),
        fallback_folder=str(config.imapFolder or "Inbox").strip() or "Inbox",
        fallback_latest_n=int(config.imapLatestN or 10),
        fallback_auth_type=str(config.imapAuthType or "password").strip() or "password",
        fallback_oauth_client_id=str(config.imapOauthClientId or "").strip(),
        fallback_oauth_refresh_token=str(config.imapOauthRefreshToken or "").strip(),
        fallback_password_fallback=bool(config.imapPasswordFallback),
        fallback_pop3_fallback=bool(config.imapPop3Fallback),
    )
    if not profiles:
        return ""
    prepared: list[dict[str, Any]] = []
    for index, profile in enumerate(profiles, start=1):
        item = dict(profile)
        latest_n = max(1, int(item.get("latest_n") or config.imapLatestN or 10))
        try:
            cfg = Imap2925Config(
                host=str(item.get("host") or "imap.2925.com").strip() or "imap.2925.com",
                port=int(item.get("port") or 993),
                username=str(item.get("user") or "").strip(),
                password=str(item.get("password") or ""),
                auth_type=str(item.get("auth_type") or "password").strip() or "password",
                oauth_client_id=str(item.get("oauth_client_id") or "").strip(),
                oauth_refresh_token=str(item.get("oauth_refresh_token") or "").strip(),
                password_fallback_enabled=bool(item.get("password_fallback")),
                pop3_fallback_enabled=bool(item.get("pop3_fallback")),
                folder=str(item.get("folder") or "Inbox").strip() or "Inbox",
                latest_n=latest_n,
                scan_newest_first=True,
                stop_on_not_before_boundary=True,
            )
            baseline_uids = scan_imap_recent_uids(cfg)
            item["baseline_uids"] = list(baseline_uids)
            log.info(
                "【ChatGPT HTTP 登录】IMAP 取码基线已预扫"
                f"（profile={index}/{len(profiles)}, target={_mask_email(safe_email)}, latest_n={latest_n}, baseline_uids={len(baseline_uids)}）。"
            )
        except Exception as error:  # noqa: BLE001
            item["baseline_uids"] = []
            log.warn(
                "【ChatGPT HTTP 登录】IMAP 取码基线预扫失败，将继续仅按时间窗过滤"
                f"（profile={index}/{len(profiles)}, {type(error).__name__}: {_compress_debug_text(str(error), limit=160)}）。"
            )
        prepared.append(item)
    return json.dumps({"profiles": prepared}, ensure_ascii=False)


def _build_workspace_signal_from_session_summary(
    session_summary: dict[str, Any],
    *,
    source: str = "session",
) -> dict[str, Any]:
    if not isinstance(session_summary, dict):
        return {}
    non_personal_seen = bool(session_summary.get("nonPersonalSeen"))
    selected_workspace_name = str(session_summary.get("selectedWorkspaceName") or "").strip()
    selected_workspace_id = str(session_summary.get("selectedWorkspaceId") or "").strip()
    if (not non_personal_seen) and (not selected_workspace_name) and (not selected_workspace_id):
        return {}
    return {
        "nonPersonalSeen": bool(non_personal_seen),
        "stableNonPersonalSeen": bool(non_personal_seen),
        "selectedWorkspaceName": selected_workspace_name,
        "selectedWorkspaceId": selected_workspace_id,
        "source": str(source or "session").strip() or "session",
        "updatedAt": str(session_summary.get("updatedAt") or "").strip(),
        "selectionKind": "session",
        "signalConfidence": "high" if non_personal_seen else "",
    }


def _extract_auth_page_type(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ""
    page_payload = payload.get("page")
    if not isinstance(page_payload, dict):
        return ""
    return str(page_payload.get("type") or "").strip().lower()


def _login_phone_step(payload: Any, continue_url: str) -> str:
    page_type = _extract_auth_page_type(payload)
    if page_type in {"phone_otp_select_channel", "phone_otp_channel_selection"}:
        return "select_channel"
    if page_type in {"add_phone", "phone_number_verification"}:
        return "add_phone"
    merged = " ".join(
        (
            str(continue_url or "").strip().lower(),
            json.dumps(payload, ensure_ascii=False).lower() if isinstance(payload, dict) else "",
        )
    )
    if "/phone-otp/select-channel" in merged:
        return "select_channel"
    if "/add-phone" in merged or "/phone-verification" in merged:
        return "add_phone"
    return ""


def _is_workspace_completion_continue_url(continue_url: str) -> bool:
    normalized = str(continue_url or "").strip().lower()
    if not normalized:
        return False
    if normalized.startswith("https://chatgpt.com/"):
        return True
    return "/workspace" in normalized


def _is_auth_workspace_continue_url(continue_url: str) -> bool:
    normalized = str(continue_url or "").strip().lower()
    if not normalized:
        return False
    try:
        parsed = urlsplit(normalized)
    except Exception:
        return normalized.startswith("https://auth.openai.com/") and "/workspace" in normalized
    host = str(parsed.hostname or "").strip().lower()
    return host == "auth.openai.com" and "/workspace" in str(parsed.path or "").strip().lower()


def _build_http_otp_follow_up(
    *,
    handled: bool,
    payload: Any,
    continue_url: str = "",
    submitted_codes: set[str] | None = None,
) -> dict[str, Any]:
    resolved_continue_url = str(continue_url or _extract_continue_url(payload) or "").strip()
    page_type = _extract_auth_page_type(payload)
    login_completed = page_type in {"workspace", "done"} or _is_workspace_completion_continue_url(
        resolved_continue_url
    )
    return {
        "handled": bool(handled),
        "payload": payload,
        "continue_url": resolved_continue_url,
        "page_type": page_type,
        "login_completed": bool(login_completed),
        # Internal-only hand-off used to avoid submitting the first-factor
        # email code again when an MFA email recovery challenge immediately
        # follows it.
        "submitted_codes": list(submitted_codes or set()),
    }


def poll_otp_api_url_verification_code_sync(
    *,
    email: str,
    otp_api_url: str,
    otp_timeout_sec: float,
    otp_interval_sec: float,
    blocked_codes: set[str] | None = None,
    not_before_ts: float = 0.0,
    log_info: Optional[LogFn] = None,
    log_warn: Optional[LogFn] = None,
) -> str:
    url = str(otp_api_url or "").strip()
    if not url:
        return ""
    deadline = time.time() + max(3.0, float(otp_timeout_sec or 120.0))
    poll_interval = max(1.0, float(otp_interval_sec or 3.0))
    blocked = blocked_codes or set()
    last_error = ""
    if log_info:
        log_info(f"【ChatGPT HTTP 登录】开始通过接码 URL 自动取码（target={_mask_email(email)}）。")
    while time.time() <= deadline:
        try:
            request = urllib.request.Request(
                url,
                headers={
                    "accept": "text/html,application/json,text/plain,*/*",
                    "user-agent": "Mozilla/5.0",
                },
            )
            with urllib.request.urlopen(request, timeout=min(20.0, max(5.0, poll_interval + 5.0))) as response:
                raw = response.read(2_000_000)
            text = raw.decode("utf-8", errors="ignore")
            message_ts = extractVerificationTimestamp(text)
            if float(not_before_ts or 0.0) > 0 and message_ts > 0 and message_ts < float(not_before_ts):
                time.sleep(poll_interval)
                continue
            code_value = extractVerificationCode(
                text,
                keywords=defaultCodeKeywords,
                blockedCodes=blocked,
            )
            if code_value:
                if log_info:
                    log_info("【ChatGPT HTTP 登录】接码 URL 收到验证码。")
                return str(code_value)
        except Exception as exc:
            last_error = str(exc or "")
            if log_warn:
                log_warn(f"【ChatGPT HTTP 登录】接码 URL 取码异常（将重试）：{last_error}")
        time.sleep(poll_interval)
    if log_warn:
        suffix = f" last_error={last_error}" if last_error else ""
        log_warn(f"【ChatGPT HTTP 登录】接码 URL 超时未获取到验证码。{suffix}")
    return ""


def _normalize_state_output_path(raw_path: str, email: str) -> str:
    value = str(raw_path or "").strip()
    if value:
        path_obj = Path(value).expanduser().resolve()
        path_obj.parent.mkdir(parents=True, exist_ok=True)
        return str(path_obj)
    out_dir = (Path(__file__).resolve().parent / "tmp" / "chatgpt_http_login_state").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    filename = f"{_safe_filename_slug(email)}_{uuid.uuid4().hex}.json"
    return str((out_dir / filename).resolve())


def _is_blocked_response(*, response_url: str, text: str) -> bool:
    merged = "\n".join([str(response_url or ""), str(text or "")]).lower()
    return any(marker in merged for marker in _BLOCK_PAGE_MARKERS)


def _is_error_response(*, response_url: str, text: str) -> bool:
    merged = "\n".join([str(response_url or ""), str(text or "")]).lower()
    return any(marker in merged for marker in _ERROR_TEXT_MARKERS)


def _json_compact(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _first_non_empty_text(*values: Any) -> str:
    for item in values:
        text = str(item or "").strip()
        if text:
            return text
    return ""


def _coerce_bool(value: Any, *, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    if text in {"1", "true", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "no", "n", "off"}:
        return False
    return bool(default)


def _parse_json_string_value(raw_value: Any) -> Any:
    text = str(raw_value or "").strip()
    if not text:
        return ""
    try:
        return json.loads(text)
    except Exception:
        return text


def _clone_storage_state_payload(storage_state: dict[str, Any] | None) -> dict[str, Any]:
    payload = dict(storage_state or {})
    cookies: list[dict[str, Any]] = []
    for row in payload.get("cookies") or []:
        if isinstance(row, dict):
            cookies.append(dict(row))
    origins: list[dict[str, Any]] = []
    for row in payload.get("origins") or []:
        if not isinstance(row, dict):
            continue
        cloned_row = dict(row)
        local_storage: list[dict[str, Any]] = []
        for item in row.get("localStorage") or []:
            if isinstance(item, dict):
                local_storage.append({"name": str(item.get("name") or ""), "value": str(item.get("value") or "")})
        cloned_row["localStorage"] = local_storage
        origins.append(cloned_row)
    payload["cookies"] = cookies
    payload["origins"] = origins
    return payload


def _build_request_context_storage_state(payload: dict[str, Any]) -> dict[str, Any]:
    cloned = _clone_storage_state_payload(payload)
    return {
        "cookies": list(cloned.get("cookies") or []),
        "origins": list(cloned.get("origins") or []),
    }


def _cookie_identity(cookie: dict[str, Any]) -> tuple[str, str, str]:
    name = str(cookie.get("name") or "").strip().lower()
    scope = _first_non_empty_text(cookie.get("domain"), cookie.get("url")).lower()
    path = str(cookie.get("path") or "/").strip() or "/"
    return (name, scope, path)


def _merge_cookie_rows(
    existing_rows: list[dict[str, Any]],
    desired_rows: list[dict[str, Any]],
    *,
    override_identities: Optional[set[tuple[str, str, str]]] = None,
) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = [dict(row) for row in existing_rows if isinstance(row, dict)]
    index_by_identity = {_cookie_identity(row): idx for idx, row in enumerate(merged)}
    override_identities = set(override_identities or set())
    for row in desired_rows:
        if not isinstance(row, dict):
            continue
        normalized = dict(row)
        identity = _cookie_identity(normalized)
        if not identity[0]:
            continue
        existing_index = index_by_identity.get(identity)
        if existing_index is None:
            index_by_identity[identity] = len(merged)
            merged.append(normalized)
            continue
        if identity in override_identities or not str(merged[existing_index].get("value") or "").strip():
            updated = dict(merged[existing_index])
            updated.update(normalized)
            merged[existing_index] = updated
    return merged


def _find_origin_index(payload: dict[str, Any], *, origin: str) -> int:
    target = str(origin or "").strip().lower()
    for index, row in enumerate(payload.get("origins") or []):
        if not isinstance(row, dict):
            continue
        current = str(row.get("origin") or "").strip().lower()
        if current == target:
            return index
    return -1


def _get_origin_local_storage_rows(payload: dict[str, Any], *, origin: str) -> list[dict[str, Any]]:
    index = _find_origin_index(payload, origin=origin)
    if index < 0:
        return []
    row = payload.get("origins")[index]
    out: list[dict[str, Any]] = []
    for item in row.get("localStorage") or []:
        if isinstance(item, dict):
            out.append({"name": str(item.get("name") or ""), "value": str(item.get("value") or "")})
    return out


def _merge_local_storage_rows(
    existing_rows: list[dict[str, Any]],
    desired_rows: list[dict[str, Any]],
    *,
    override_keys: Optional[set[str]] = None,
) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    index_by_name: dict[str, int] = {}
    for row in existing_rows:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or "").strip()
        if not name:
            continue
        index_by_name[name] = len(merged)
        merged.append({"name": name, "value": str(row.get("value") or "")})
    override_keys = set(override_keys or set())
    for row in desired_rows:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or "").strip()
        if not name:
            continue
        value = str(row.get("value") or "")
        existing_index = index_by_name.get(name)
        if existing_index is None:
            index_by_name[name] = len(merged)
            merged.append({"name": name, "value": value})
            continue
        if (name in override_keys) or (not str(merged[existing_index].get("value") or "").strip()):
            merged[existing_index]["value"] = value
    return merged


def _upsert_origin_local_storage(
    payload: dict[str, Any],
    *,
    origin: str,
    local_storage: list[dict[str, Any]],
) -> None:
    normalized_origin = str(origin or "").strip()
    if not normalized_origin:
        return
    origin_row = {"origin": normalized_origin, "localStorage": list(local_storage or [])}
    index = _find_origin_index(payload, origin=normalized_origin)
    if index < 0:
        payload.setdefault("origins", []).append(origin_row)
        return
    current_row = payload["origins"][index]
    updated_row = dict(current_row) if isinstance(current_row, dict) else {}
    updated_row["origin"] = normalized_origin
    updated_row["localStorage"] = list(local_storage or [])
    payload["origins"][index] = updated_row


def _make_cookie_row(
    *,
    name: str,
    value: str,
    domain: str,
    path: str = "/",
    expires: float = -1,
    http_only: bool = False,
    secure: bool = False,
    same_site: str = "Lax",
) -> dict[str, Any]:
    return {
        "name": str(name or "").strip(),
        "value": str(value or ""),
        "domain": str(domain or "").strip(),
        "path": str(path or "/").strip() or "/",
        "expires": float(expires),
        "httpOnly": bool(http_only),
        "secure": bool(secure),
        "sameSite": str(same_site or "Lax").strip() or "Lax",
    }


def _extract_origin_statsig_namespace(local_storage: list[dict[str, Any]]) -> str:
    prefixes = (
        "statsig.session_id.",
        "statsig.stable_id.",
        "statsig.cached.evaluations.",
    )
    for row in local_storage:
        if not isinstance(row, dict):
            continue
        key = str(row.get("name") or "").strip()
        for prefix in prefixes:
            if key.startswith(prefix):
                suffix = str(key[len(prefix) :]).strip()
                if suffix:
                    return suffix
    return ""


def _derive_statsig_namespace(*, origin: str, device_id: str) -> str:
    seed = f"{str(origin or '').strip().lower()}|{str(device_id or '').strip()}".encode("utf-8", errors="ignore")
    return str(zlib.crc32(seed) & 0xFFFFFFFF)


def _generate_client_correlated_secret() -> str:
    secret = base64.urlsafe_b64encode(secrets.token_bytes(64)).decode("ascii").rstrip("=")
    return _json_compact(
        {
            "alg": "HS512",
            "ext": True,
            "k": secret,
            "key_ops": ["sign", "verify"],
            "kty": "oct",
        }
    )


def _resolve_http_login_device_id(storage_state: dict[str, Any]) -> str:
    cookie_value = str(_read_storage_state_cookie_value(storage_state, cookie_name="oai-did") or "").strip()
    if cookie_value:
        return cookie_value
    for origin in ("https://chatgpt.com", "https://auth.openai.com"):
        for row in _get_origin_local_storage_rows(storage_state, origin=origin):
            if str(row.get("name") or "").strip() != "oai-did":
                continue
            parsed = _parse_json_string_value(row.get("value"))
            value = parsed if isinstance(parsed, str) else str(parsed or "")
            value = str(value or "").strip()
            if value:
                return value
    stage_device_id = get_http_stage_device_id()
    if stage_device_id:
        return stage_device_id
    return str(uuid.uuid4())


def _resolve_http_login_workspace_context(
    *,
    storage_state: dict[str, Any],
    session_payload: dict[str, Any],
) -> dict[str, Any]:
    safe_session_payload = session_payload if isinstance(session_payload, dict) else {}
    account_payload = safe_session_payload.get("account")
    safe_account_payload = account_payload if isinstance(account_payload, dict) else {}
    access_token = str(extract_access_token_from_session_payload(safe_session_payload) or "").strip()
    session_workspaces = _collect_http_provider_workspaces(safe_session_payload)
    selected_session_workspace = _pick_http_provider_workspace(session_workspaces)
    cookie_workspace_ctx = _choose_http_provider_workspace_context_from_storage_state(storage_state)
    selected_cookie_workspace = (
        dict(cookie_workspace_ctx.get("selected_workspace") or {})
        if isinstance(cookie_workspace_ctx, dict)
        else {}
    )
    account_id = _first_non_empty_text(
        extract_chatgpt_account_id_from_jwt(access_token),
        selected_session_workspace.get("workspace_id"),
        safe_account_payload.get("id"),
        safe_account_payload.get("account_id"),
        selected_cookie_workspace.get("workspace_id"),
        _read_storage_state_cookie_value(storage_state, cookie_name="_account"),
    )
    preferred_workspace = selected_session_workspace or selected_cookie_workspace
    residency_region = _first_non_empty_text(
        _read_storage_state_cookie_value(storage_state, cookie_name="_account_residency_region"),
        safe_account_payload.get("residency_region"),
        safe_account_payload.get("residencyRegion"),
        safe_session_payload.get("account_residency_region"),
        safe_session_payload.get("accountResidencyRegion"),
    )
    if not residency_region:
        residency_region = _DEFAULT_ACCOUNT_RESIDENCY_REGION
    fedramp_raw = _first_non_empty_text(
        _read_storage_state_cookie_value(storage_state, cookie_name="_account_is_fedramp"),
        safe_account_payload.get("is_fedramp"),
        safe_account_payload.get("isFedramp"),
        safe_account_payload.get("account_is_fedramp"),
        safe_session_payload.get("is_fedramp"),
        safe_session_payload.get("isFedramp"),
    )
    auth_session_payload = _decode_base64_json_cookie_value(
        _read_storage_state_cookie_value(storage_state, cookie_name="oai-client-auth-session")
    )
    return {
        "account_id": account_id,
        "account_id_source": (
            "session.jwt"
            if extract_chatgpt_account_id_from_jwt(access_token)
            else (
                "session.workspace"
                if str(selected_session_workspace.get("workspace_id") or "").strip()
                else (
                    "session.account"
                    if _first_non_empty_text(safe_account_payload.get("id"), safe_account_payload.get("account_id"))
                    else (
                        "auth_session_cookie.workspace"
                        if str(selected_cookie_workspace.get("workspace_id") or "").strip()
                        else "storage_state.cookie._account"
                    )
                )
            )
            if account_id
            else ""
        ),
        "workspace_kind": _first_non_empty_text(
            preferred_workspace.get("kind"),
            safe_account_payload.get("structure"),
        ).lower(),
        "workspace_label": _first_non_empty_text(
            preferred_workspace.get("display_name"),
            preferred_workspace.get("label"),
            safe_account_payload.get("name"),
        ),
        "residency_region": residency_region,
        "is_fedramp": _coerce_bool(fedramp_raw, default=False),
        "device_id": _resolve_http_login_device_id(storage_state),
        "auth_session_payload": auth_session_payload,
    }


def _build_chatgpt_bootstrap_cookie_rows(context: dict[str, Any]) -> list[dict[str, Any]]:
    device_id = str(context.get("device_id") or "").strip()
    account_id = str(context.get("account_id") or "").strip()
    residency_region = str(context.get("residency_region") or _DEFAULT_ACCOUNT_RESIDENCY_REGION).strip()
    is_fedramp = bool(context.get("is_fedramp"))
    expire_ts = time.time() + (180.0 * 24.0 * 3600.0)
    rows: list[dict[str, Any]] = [
        _make_cookie_row(
            name="oai-did",
            value=device_id,
            domain=".chatgpt.com",
            expires=expire_ts,
        ),
        _make_cookie_row(
            name="oai-did",
            value=device_id,
            domain=".openai.com",
            expires=expire_ts,
        ),
        _make_cookie_row(
            name="oai-hlib",
            value="true",
            domain="chatgpt.com",
            expires=expire_ts,
        ),
        _make_cookie_row(
            name="oai-hm",
            value=_DEFAULT_CHATGPT_HOME_HINT,
            domain="chatgpt.com",
            expires=-1,
        ),
        _make_cookie_row(
            name="_account_residency_region",
            value=residency_region,
            domain="chatgpt.com",
            expires=expire_ts,
        ),
        _make_cookie_row(
            name="_account_is_fedramp",
            value="true" if is_fedramp else "false",
            domain="chatgpt.com",
            expires=expire_ts,
        ),
    ]
    if account_id:
        rows.append(
            _make_cookie_row(
                name="_account",
                value=account_id,
                domain="chatgpt.com",
                expires=expire_ts,
            )
        )
    return rows


def _build_chatgpt_bootstrap_local_storage(
    *,
    existing_rows: list[dict[str, Any]],
    context: dict[str, Any],
) -> list[dict[str, Any]]:
    device_id = str(context.get("device_id") or "").strip()
    account_id = str(context.get("account_id") or "").strip()
    residency_region = str(context.get("residency_region") or _DEFAULT_ACCOUNT_RESIDENCY_REGION).strip()
    now_ms = int(time.time() * 1000.0)
    namespace = _first_non_empty_text(
        _extract_origin_statsig_namespace(existing_rows),
        _derive_statsig_namespace(origin="https://chatgpt.com", device_id=device_id),
    )
    desired_rows: list[dict[str, Any]] = [
        {"name": "oai-did", "value": _json_compact(device_id)},
        {
            "name": f"statsig.session_id.{namespace}",
            "value": _json_compact(
                {
                    "sessionID": str(uuid.uuid4()),
                    "startTime": now_ms,
                    "lastUpdate": now_ms,
                }
            ),
        },
        {
            "name": f"statsig.stable_id.{namespace}",
            "value": _json_compact(device_id),
        },
        {
            "name": "client-correlated-secret",
            "value": _generate_client_correlated_secret(),
        },
        {"name": "oai/apps/subscriptionFailedBanner", "value": "null"},
        {"name": "search.attributions-settings", "value": _json_compact(_DEFAULT_SEARCH_ATTRIBUTIONS_SETTINGS)},
        {"name": "oai/apps/capExpiresAt", "value": _json_compact({"state": {"isoDate": ""}, "version": 0})},
        {"name": "oai/apps/hasSeenNoAuthImagegenNux", "value": "false"},
        {"name": "oai/apps/hasDismissedOnboardingSidebarEntry", "value": "false"},
        {"name": "oai/apps/connectorInContextUpsellBannerV1", "value": "null"},
        {"name": "oai/apps/tatertotInContextUpsellBannerV2", "value": "null"},
        {"name": "oai/apps/lastPageLoadDate", "value": _json_compact(_iso_now().replace("+00:00", "Z"))},
    ]
    override_keys: set[str] = set()
    if account_id:
        desired_rows.append({"name": "_account", "value": _json_compact(account_id)})
        override_keys.add("_account")
    if residency_region:
        desired_rows.append({"name": "_account_residency_region", "value": _json_compact(residency_region)})
        override_keys.add("_account_residency_region")
    return _merge_local_storage_rows(existing_rows, desired_rows, override_keys=override_keys)


def _build_auth_bootstrap_local_storage(
    *,
    existing_rows: list[dict[str, Any]],
    context: dict[str, Any],
) -> list[dict[str, Any]]:
    device_id = str(context.get("device_id") or "").strip()
    now_ms = int(time.time() * 1000.0)
    namespace = _first_non_empty_text(
        _extract_origin_statsig_namespace(existing_rows),
        _derive_statsig_namespace(origin="https://auth.openai.com", device_id=device_id),
    )
    desired_rows: list[dict[str, Any]] = [
        {
            "name": f"statsig.session_id.{namespace}",
            "value": _json_compact(
                {
                    "sessionID": str(uuid.uuid4()),
                    "startTime": now_ms,
                    "lastUpdate": now_ms,
                }
            ),
        },
        {
            "name": f"statsig.stable_id.{namespace}",
            "value": _json_compact(device_id),
        },
    ]
    return _merge_local_storage_rows(existing_rows, desired_rows)


def _build_http_login_bootstrap_storage_state(
    *,
    storage_state: dict[str, Any],
    session_payload: dict[str, Any],
) -> dict[str, Any]:
    payload = _clone_storage_state_payload(storage_state)
    payload.setdefault("cookies", [])
    payload.setdefault("origins", [])
    context = _resolve_http_login_workspace_context(
        storage_state=payload,
        session_payload=session_payload,
    )
    desired_cookies = _build_chatgpt_bootstrap_cookie_rows(context)
    override_identities = {_cookie_identity(row) for row in desired_cookies}
    payload["cookies"] = _merge_cookie_rows(
        list(payload.get("cookies") or []),
        desired_cookies,
        override_identities=override_identities,
    )
    chatgpt_rows = _build_chatgpt_bootstrap_local_storage(
        existing_rows=_get_origin_local_storage_rows(payload, origin="https://chatgpt.com"),
        context=context,
    )
    _upsert_origin_local_storage(payload, origin="https://chatgpt.com", local_storage=chatgpt_rows)
    auth_rows = _build_auth_bootstrap_local_storage(
        existing_rows=_get_origin_local_storage_rows(payload, origin="https://auth.openai.com"),
        context=context,
    )
    _upsert_origin_local_storage(payload, origin="https://auth.openai.com", local_storage=auth_rows)
    return payload


def _normalize_http_login_cookie_host(cookie: dict[str, Any]) -> str:
    raw_url = str(cookie.get("url") or "").strip()
    if raw_url:
        try:
            return str(urlsplit(raw_url).hostname or "").strip().lower().lstrip(".")
        except Exception:
            return ""
    return str(cookie.get("domain") or "").strip().lower().lstrip(".")


def _build_http_login_cookie_header_length(cookie_rows: list[dict[str, Any]]) -> int:
    pairs: list[str] = []
    for row in cookie_rows:
        if not isinstance(row, dict):
            continue
        if _normalize_http_login_cookie_host(row) != "chatgpt.com":
            continue
        name = str(row.get("name") or "").strip()
        if not name:
            continue
        pairs.append(f"{name}={str(row.get('value') or '')}")
    return len("; ".join(pairs))


def _http_login_runtime_cookie_candidate_rank(cookie: dict[str, Any]) -> tuple[int, int, int]:
    host = _normalize_http_login_cookie_host(cookie)
    raw_domain = str(cookie.get("domain") or "").strip().lower()
    path = str(cookie.get("path") or "/").strip() or "/"
    if host == "chatgpt.com":
        if raw_domain == "chatgpt.com":
            scope_rank = 0
        elif raw_domain == ".chatgpt.com":
            scope_rank = 1
        else:
            scope_rank = 2
    else:
        scope_rank = 9
    return (
        scope_rank,
        0 if path == "/" else 1,
        0 if str(cookie.get("value") or "").strip() else 1,
    )


def _select_http_login_runtime_cookie_rows(existing_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected_by_name: dict[str, dict[str, Any]] = {}
    selected_prefixed: dict[str, dict[str, Any]] = {}
    for row in existing_rows:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or "").strip()
        is_exact_runtime_cookie = name in _HTTP_LOGIN_RUNTIME_COOKIE_NAMES
        is_prefixed_runtime_cookie = any(name.startswith(prefix) for prefix in _HTTP_LOGIN_RUNTIME_COOKIE_NAME_PREFIXES)
        if not is_exact_runtime_cookie and not is_prefixed_runtime_cookie:
            continue
        if _normalize_http_login_cookie_host(row) != "chatgpt.com":
            continue
        if is_prefixed_runtime_cookie:
            current_prefixed = selected_prefixed.get(name)
            if (
                current_prefixed is None
                or _http_login_runtime_cookie_candidate_rank(row)
                < _http_login_runtime_cookie_candidate_rank(current_prefixed)
            ):
                selected_prefixed[name] = dict(row)
            continue
        current = selected_by_name.get(name)
        if current is None or _http_login_runtime_cookie_candidate_rank(row) < _http_login_runtime_cookie_candidate_rank(current):
            selected_by_name[name] = dict(row)
    ordered = [dict(selected_by_name[name]) for name in _HTTP_LOGIN_RUNTIME_COOKIE_NAMES if name in selected_by_name]
    ordered.extend(
        dict(row)
        for _name, row in sorted(
            selected_prefixed.items(),
            key=lambda item: (
                _http_login_runtime_cookie_candidate_rank(item[1]),
                str(item[0]),
            ),
        )
    )
    if _build_http_login_cookie_header_length(ordered) <= _HTTP_LOGIN_RUNTIME_COOKIE_HEADER_MAX_LENGTH:
        return ordered
    trimmed = list(ordered)
    for drop_name in _HTTP_LOGIN_RUNTIME_OPTIONAL_COOKIE_DROP_ORDER:
        if _build_http_login_cookie_header_length(trimmed) <= _HTTP_LOGIN_RUNTIME_COOKIE_HEADER_MAX_LENGTH:
            break
        trimmed = [row for row in trimmed if str(row.get("name") or "").strip() != drop_name]
    return trimmed


def _should_keep_http_login_runtime_local_storage_key(*, origin: str, key: str) -> bool:
    normalized_origin = str(origin or "").strip().lower()
    normalized_key = str(key or "").strip()
    if not normalized_key:
        return False
    if normalized_origin == "https://chatgpt.com":
        return (
            normalized_key in _HTTP_LOGIN_RUNTIME_CHATGPT_LOCAL_STORAGE_EXACT_KEYS
            or any(normalized_key.startswith(prefix) for prefix in _HTTP_LOGIN_RUNTIME_CHATGPT_LOCAL_STORAGE_PREFIXES)
        )
    if normalized_origin == "https://auth.openai.com":
        return any(normalized_key.startswith(prefix) for prefix in _HTTP_LOGIN_RUNTIME_AUTH_LOCAL_STORAGE_PREFIXES)
    return False


def _filter_http_login_runtime_local_storage_rows(
    *,
    origin: str,
    rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    filtered: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or "").strip()
        if (not name) or (name in seen):
            continue
        if not _should_keep_http_login_runtime_local_storage_key(origin=origin, key=name):
            continue
        seen.add(name)
        filtered.append({"name": name, "value": str(row.get("value") or "")})
    return filtered


def _sanitize_http_login_storage_state_for_runtime(storage_state: dict[str, Any]) -> dict[str, Any]:
    payload = _clone_storage_state_payload(storage_state)
    payload["cookies"] = _select_http_login_runtime_cookie_rows(list(payload.get("cookies") or []))
    runtime_origins: list[dict[str, Any]] = []
    for origin in ("https://chatgpt.com", "https://auth.openai.com"):
        local_rows = _filter_http_login_runtime_local_storage_rows(
            origin=origin,
            rows=_get_origin_local_storage_rows(payload, origin=origin),
        )
        if local_rows:
            runtime_origins.append({"origin": origin, "localStorage": local_rows})
    payload["origins"] = runtime_origins
    return payload


def _build_sanitized_http_login_bootstrap_storage_state(
    *,
    storage_state: dict[str, Any],
    session_payload: dict[str, Any],
) -> dict[str, Any]:
    return _sanitize_http_login_storage_state_for_runtime(
        _build_http_login_bootstrap_storage_state(
            storage_state=storage_state,
            session_payload=session_payload,
        )
    )


def _augment_storage_state_payload(
    *,
    storage_state: dict[str, Any],
    session_payload: dict[str, Any],
    session_status: int,
    session_error: str,
) -> dict[str, Any]:
    payload = _build_sanitized_http_login_bootstrap_storage_state(
        storage_state=storage_state,
        session_payload=session_payload,
    )
    token = str(extract_access_token_from_session_payload(session_payload) or "").strip()
    summary = extract_session_summary_from_payload(
        session_payload,
        status=int(session_status or 0),
        error_text=str(session_error or "").strip(),
        updated_at=_iso_now(),
    )
    payload["accessToken"] = token
    payload["session_access_token"] = token
    payload["session_access_token_status"] = int(session_status or 0)
    payload["session_access_token_error"] = str(session_error or "").strip()
    payload["session_access_token_updated_at"] = _iso_now()
    payload["session_summary"] = dict(summary)
    workspace_signal = _build_workspace_signal_from_session_summary(summary, source="session")
    if workspace_signal:
        payload["workspace_signal"] = dict(workspace_signal)
    return payload


def _build_chatgpt_json_fetch_headers(*, referer_url: str, content_type: str = "application/json") -> dict[str, str]:
    referer = str(referer_url or "").strip()
    if not referer.lower().startswith("https://chatgpt.com/"):
        referer = "https://chatgpt.com/auth/login_with"
    # accept-language 优先用 profile 的英语值（与时区/指纹一致），兜底英语，避免发 zh-CN 与英语区指纹矛盾
    accept_language = str((get_http_stage_browser_headers() or {}).get("accept-language") or "").strip() or "en-US,en;q=0.9"
    return {
        "accept": "application/json",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": accept_language,
        "origin": "https://chatgpt.com",
        "priority": "u=1, i",
        "referer": referer,
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "content-type": str(content_type or "application/json").strip() or "application/json",
    }


def _extract_chatgpt_csrf_token(*, storage_state: dict[str, Any], payload: Any) -> str:
    if isinstance(payload, dict):
        token = str(payload.get("csrfToken") or payload.get("csrf_token") or "").strip()
        if token:
            return token
    csrf_cookie = _read_storage_state_cookie_value(storage_state, cookie_name="__Host-next-auth.csrf-token")
    if csrf_cookie:
        return str(str(csrf_cookie).split("|", 1)[0] or "").strip()
    return ""


def _write_text_with_windows_fallback(path: str | Path, text: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = str(text or "")
    try:
        if target.exists() and target.read_text(encoding="utf-8") == payload:
            return
    except Exception:
        pass

    temp = target.with_suffix(target.suffix + f".tmp.{os.getpid()}.{uuid.uuid4().hex[:8]}")
    temp.write_text(payload, encoding="utf-8")
    last_error: Exception | None = None
    for _ in range(8):
        try:
            temp.replace(target)
            return
        except PermissionError as exc:
            last_error = exc
            time.sleep(0.15)
        except Exception:
            raise

    for _ in range(8):
        try:
            target.write_text(payload, encoding="utf-8")
            try:
                temp.unlink(missing_ok=True)
            except Exception:
                pass
            return
        except PermissionError as exc:
            last_error = exc
            time.sleep(0.15)
        except Exception:
            raise

    try:
        temp.unlink(missing_ok=True)
    except Exception:
        pass
    if last_error is not None:
        raise last_error


def _write_json_file(path: str, payload: dict[str, Any]) -> None:
    target = Path(str(path or "").strip()).expanduser().resolve()
    _write_text_with_windows_fallback(target, json.dumps(payload, ensure_ascii=False, indent=2))


async def _rebuild_request_context_with_storage_state(
    *,
    request_ctx: Any,
    storage_state: dict[str, Any],
    proxy_url: str,
    impersonate: str,
) -> Any:
    new_request_ctx = await asyncio.to_thread(
        _build_http_provider_request_context,
        storage_state=_build_request_context_storage_state(storage_state),
        proxy_url=str(proxy_url or "").strip(),
        impersonate=str(impersonate or "").strip(),
    )
    if request_ctx is not None:
        try:
            await request_ctx.dispose()
        except Exception:
            pass
    return new_request_ctx


async def _open_continue_url(
    *,
    request_ctx: Any,
    continue_url: str,
    trace: _TraceWriter,
    timeout_ms: int,
    stage_name: str,
) -> tuple[str, str]:
    target_url = str(continue_url or "").strip()
    if not target_url:
        return "", ""
    current_url = target_url
    visited_urls: set[str] = set()
    last_response_url = ""
    last_text = ""
    max_redirect_hops = 8
    for hop in range(1, max_redirect_hops + 1):
        normalized_url = str(current_url or "").strip()
        if (not normalized_url) or (normalized_url in visited_urls):
            break
        visited_urls.add(normalized_url)
        _payload, status, text, response_url, response_headers = await _request_with_context(
            request_ctx,
            method="GET",
            url=normalized_url,
            headers=_build_http_html_headers(impersonate=_resolve_request_ctx_impersonate(request_ctx)),
            timeout_ms=timeout_ms,
            max_redirects=0,
        )
        location_raw = str(response_headers.get("location") or "").strip()
        next_url = ""
        if location_raw:
            try:
                next_url = str(urljoin(str(response_url or normalized_url), location_raw) or "").strip()
            except Exception:
                next_url = location_raw
        trace.write(
            {
                "ts": _iso_now(),
                "stage": stage_name,
                "hop": int(hop),
                "status": int(status),
                "url": _sanitize_url_for_log(normalized_url),
                "responseUrl": _sanitize_url_for_log(response_url),
                "location": _sanitize_url_for_log(next_url or location_raw),
                "bodySnippet": _compress_debug_text(text, limit=320),
            }
        )
        if _is_blocked_response(response_url=response_url, text=text):
            raise RuntimeError("http_auth_challenge_blocked: 登录继续链路命中 Cloudflare challenge，纯 HTTP 无法继续。")
        if _is_error_response(response_url=response_url, text=text):
            raise RuntimeError("http_auth_login_failed: 登录继续页面返回错误。")
        last_response_url = str(response_url or normalized_url or "").strip()
        last_text = str(text or "")
        if int(status) in {301, 302, 303, 307, 308} and next_url:
            current_url = next_url
            continue
        break
    return last_response_url, last_text


def _extract_http_login_authorize_callback_context(authorize_url: str) -> tuple[str, str]:
    oauth_ctx = _extract_http_login_authorize_oauth_context(authorize_url)
    return (
        str(oauth_ctx.get("redirect_uri") or "").strip(),
        str(oauth_ctx.get("state") or "").strip(),
    )


def _extract_http_login_authorize_oauth_context(authorize_url: str) -> dict[str, str]:
    normalized_url = str(authorize_url or "").strip()
    if not normalized_url:
        return {}
    try:
        query_pairs = dict(parse_qsl(urlsplit(normalized_url).query, keep_blank_values=True))
    except Exception:
        return {}
    return {
        "client_id": str(query_pairs.get("client_id") or "").strip(),
        "redirect_uri": str(query_pairs.get("redirect_uri") or "").strip(),
        "state": str(query_pairs.get("state") or "").strip(),
        "scope": str(query_pairs.get("scope") or "").strip(),
    }


def _build_http_login_authorize_callback_url(
    *,
    redirect_uri: str,
    code: str,
    state: str,
    error: str = "",
    error_description: str = "",
) -> str:
    normalized_redirect_uri = str(redirect_uri or "").strip()
    if not normalized_redirect_uri:
        return ""
    query_pairs: list[tuple[str, str]] = []
    try:
        parsed = urlsplit(normalized_redirect_uri)
        query_pairs.extend(
            (key, value)
            for key, value in parse_qsl(parsed.query, keep_blank_values=True)
            if key not in {"code", "state", "error", "error_description"}
        )
        base_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", parsed.fragment))
    except Exception:
        base_url = normalized_redirect_uri.split("?", 1)[0]
    if code:
        query_pairs.append(("code", str(code).strip()))
    if state:
        query_pairs.append(("state", str(state).strip()))
    if error:
        query_pairs.append(("error", str(error).strip()))
    if error_description:
        query_pairs.append(("error_description", str(error_description).strip()))
    if not query_pairs:
        return ""
    return f"{base_url}?{urlencode(query_pairs)}"


def _parse_http_login_jwt_payload(token: str) -> dict[str, Any]:
    raw_token = str(token or "").strip()
    parts = raw_token.split(".")
    if len(parts) != 3:
        return {}
    payload_part = str(parts[1] or "").strip()
    if not payload_part:
        return {}
    padding = "=" * ((4 - (len(payload_part) % 4)) % 4)
    try:
        raw_bytes = base64.urlsafe_b64decode((payload_part + padding).encode("utf-8"))
        payload = json.loads(raw_bytes.decode("utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _extract_http_login_access_token_claims(access_token: str) -> dict[str, str]:
    payload = _parse_http_login_jwt_payload(access_token)
    auth_claim = payload.get("https://api.openai.com/auth")
    if not isinstance(auth_claim, dict):
        auth_claim = {}
    return {
        "account_id": str(
            auth_claim.get("chatgpt_account_id")
            or auth_claim.get("chatgpt_account")
            or payload.get("account_id")
            or ""
        ).strip(),
        "plan_type": str(
            auth_claim.get("chatgpt_plan_type")
            or auth_claim.get("plan_type")
            or payload.get("plan_type")
            or ""
        ).strip(),
        "user_id": str(
            auth_claim.get("chatgpt_user_id")
            or auth_claim.get("user_id")
            or payload.get("sub")
            or ""
        ).strip(),
        "jti": str(payload.get("jti") or "").strip(),
    }


def _build_http_login_direct_token_session_payload(
    *,
    access_token: str,
    workspace_id: str,
    workspace_name: str,
    workspace_kind: str,
) -> dict[str, Any]:
    normalized_token = str(access_token or "").strip()
    if not normalized_token:
        return {}
    claims = _extract_http_login_access_token_claims(normalized_token)
    normalized_workspace_id = str(workspace_id or "").strip()
    normalized_workspace_name = str(workspace_name or "").strip()
    normalized_workspace_kind = str(workspace_kind or "").strip().lower()
    structure = "personal" if normalized_workspace_kind == "personal" else ("organization" if normalized_workspace_id else "")

    payload: dict[str, Any] = {
        "accessToken": normalized_token,
    }
    account: dict[str, Any] = {}
    account_id = str(claims.get("account_id") or "").strip()
    plan_type = str(claims.get("plan_type") or "").strip()
    user_id = str(claims.get("user_id") or "").strip()
    if account_id:
        account["id"] = account_id
    if plan_type:
        account["plan_type"] = plan_type
    if structure:
        account["structure"] = structure
    if user_id:
        account["user_id"] = user_id
    if account:
        payload["account"] = account
    if user_id:
        payload["user"] = {"id": user_id}

    if normalized_workspace_id:
        workspace_item = {
            "id": normalized_workspace_id,
            "workspace_id": normalized_workspace_id,
            "selected": True,
        }
        if normalized_workspace_name:
            workspace_item["name"] = normalized_workspace_name
        if normalized_workspace_kind:
            workspace_item["kind"] = normalized_workspace_kind
        if structure:
            workspace_item["structure"] = structure
        payload["selectedWorkspace"] = dict(workspace_item)
        payload["workspaces"] = [dict(workspace_item)]
        if structure and structure != "personal":
            payload["accounts"] = [dict(workspace_item)]
    return payload


def _summarize_http_login_oauth_token_response_for_trace(payload: Any, text: str) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    if isinstance(payload, dict):
        summary["payloadKeys"] = sorted(str(key) for key in payload.keys())
        access_token = str(payload.get("access_token") or payload.get("accessToken") or "").strip()
        refresh_token = str(payload.get("refresh_token") or "").strip()
        id_token = str(payload.get("id_token") or "").strip()
        if access_token:
            summary["accessTokenPresent"] = True
            summary["accessTokenLength"] = len(access_token)
        if refresh_token:
            summary["refreshTokenPresent"] = True
            summary["refreshTokenLength"] = len(refresh_token)
        if id_token:
            summary["idTokenPresent"] = True
        expires_in = payload.get("expires_in")
        try:
            if expires_in not in (None, ""):
                summary["expiresIn"] = int(expires_in)
        except Exception:
            pass
        raw_error = payload.get("error")
        if isinstance(raw_error, str):
            if raw_error:
                summary["error"] = raw_error
            raw_error_description = str(payload.get("error_description") or payload.get("errorDescription") or "").strip()
            if raw_error_description:
                summary["errorDescription"] = _compress_debug_text(raw_error_description, limit=240)
        elif isinstance(raw_error, dict):
            error_code = str(raw_error.get("code") or raw_error.get("type") or "").strip()
            error_message = str(raw_error.get("message") or "").strip()
            if error_code:
                summary["errorCode"] = error_code
            if error_message:
                summary["errorMessage"] = _compress_debug_text(error_message, limit=240)
    if not summary and text:
        summary["bodySnippet"] = _compress_debug_text(text, limit=320)
    return summary


def _extract_http_login_oauth_token_error(payload: Any, text: str, status: int) -> str:
    if isinstance(payload, dict):
        raw_error = payload.get("error")
        if isinstance(raw_error, dict):
            error_code = str(raw_error.get("code") or raw_error.get("type") or "").strip()
            error_message = str(raw_error.get("message") or "").strip()
            if error_code and error_message:
                return f"HTTP {int(status or 0)} {error_code} ({error_message})"
            if error_code:
                return f"HTTP {int(status or 0)} {error_code}"
            if error_message:
                return f"HTTP {int(status or 0)} ({error_message})"
        if isinstance(raw_error, str) and raw_error:
            error_description = str(payload.get("error_description") or payload.get("errorDescription") or "").strip()
            if error_description:
                return f"HTTP {int(status or 0)} {raw_error} ({error_description})"
            return f"HTTP {int(status or 0)} {raw_error}"
    snippet = _compress_debug_text(text, limit=180)
    if snippet:
        return f"HTTP {int(status or 0)} ({snippet})"
    return f"HTTP {int(status or 0)}"


async def _exchange_http_login_callback_code_for_access_token(
    *,
    request_ctx: Any,
    authorize_url: str,
    callback: Any,
    workspace_id: str,
    workspace_name: str,
    workspace_kind: str,
    trace: _TraceWriter,
    timeout_ms: int,
) -> dict[str, Any]:
    oauth_ctx = _extract_http_login_authorize_oauth_context(authorize_url)
    client_id = str(oauth_ctx.get("client_id") or "").strip()
    redirect_uri = str(oauth_ctx.get("redirect_uri") or "").strip()
    code = str(getattr(callback, "code", "") or "").strip()
    if not client_id or not redirect_uri or not code:
        return {}

    token_url = "https://auth.openai.com/oauth/token"
    request_headers = {
        "content-type": "application/x-www-form-urlencoded",
        "accept": "application/json",
        "origin": "https://auth.openai.com",
        "referer": "https://auth.openai.com/",
    }
    form_text = urlencode(
        {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": code,
            "redirect_uri": redirect_uri,
        }
    )
    trace.write(
        {
            "ts": _iso_now(),
            "stage": "http_login_workspace_token_exchange",
            "method": "POST",
            "url": token_url,
            "workspaceId": workspace_id,
            "workspaceName": workspace_name,
            "workspaceKind": workspace_kind,
            "requestHeaders": dict(request_headers),
            "requestFormKeys": ["grant_type", "client_id", "code", "redirect_uri"],
        }
    )
    payload, status, text, response_url, response_headers = await _request_with_context(
        request_ctx,
        method="POST",
        url=token_url,
        headers=request_headers,
        body_text=form_text,
        timeout_ms=timeout_ms,
        max_redirects=0,
    )
    trace.write(
        {
            "ts": _iso_now(),
            "stage": "http_login_workspace_token_exchange",
            "status": int(status or 0),
            "workspaceId": workspace_id,
            "workspaceName": workspace_name,
            "workspaceKind": workspace_kind,
            "responseUrl": _sanitize_url_for_log(response_url),
            "responseHeaders": dict(response_headers or {}),
            "responseSummary": _summarize_http_login_oauth_token_response_for_trace(payload, text),
        }
    )
    if not isinstance(payload, dict):
        return {
            "error": "token 响应格式异常",
            "status": int(status or 0),
        }
    access_token = str(payload.get("access_token") or "").strip()
    if int(status or 0) < 200 or int(status or 0) >= 300 or (not access_token):
        detail = _extract_http_login_oauth_token_error(payload, text, int(status or 0))
        if int(status or 0) in {200, 201} and not access_token:
            detail = "HTTP 200，但响应缺少 access_token"
        return {
            "error": detail,
            "status": int(status or 0),
        }
    session_payload = _build_http_login_direct_token_session_payload(
        access_token=access_token,
        workspace_id=workspace_id,
        workspace_name=workspace_name,
        workspace_kind=workspace_kind,
    )
    return {
        "accessToken": access_token,
        "status": int(status or 0),
        "sessionPayload": session_payload,
        "tokenClaims": _extract_http_login_access_token_claims(access_token),
        "expiresIn": int(payload.get("expires_in") or 0),
    }


async def _try_http_login_direct_token_exchange_from_continue_url(
    *,
    request_ctx: Any,
    authorize_url: str,
    continue_url: str,
    trace: _TraceWriter,
    timeout_ms: int,
    workspace_id: str = "",
    workspace_name: str = "",
    workspace_kind: str = "",
) -> dict[str, Any]:
    normalized_authorize_url = str(authorize_url or "").strip()
    normalized_continue_url = str(continue_url or "").strip()
    if not normalized_authorize_url or not normalized_continue_url:
        return {}
    oauth_ctx = _extract_http_login_authorize_oauth_context(normalized_authorize_url)
    callback = _callback_from_url(
        url=normalized_continue_url,
        expected_state=str(oauth_ctx.get("state") or "").strip(),
        redirect_uri=str(oauth_ctx.get("redirect_uri") or "").strip(),
    )
    if callback is None or (not getattr(callback, "code", "")) or getattr(callback, "error", ""):
        return {}
    return await _exchange_http_login_callback_code_for_access_token(
        request_ctx=request_ctx,
        authorize_url=normalized_authorize_url,
        callback=callback,
        workspace_id=workspace_id,
        workspace_name=workspace_name,
        workspace_kind=workspace_kind,
        trace=trace,
        timeout_ms=timeout_ms,
    )


async def _complete_http_login_workspace_authorize_via_http(
    *,
    request_ctx: Any,
    authorize_url: str,
    session_payload: dict[str, Any],
    trace: _TraceWriter,
    timeout_ms: int,
    workspace_continue_url: str = "",
) -> dict[str, Any]:
    result = {
        "attempted": False,
        "completed": False,
        "workspaceId": "",
        "workspaceName": "",
        "workspaceKind": "",
        "resumeAuthorizeUrl": "",
        "callbackUrl": "",
        "error": "",
    }
    normalized_authorize_url = str(authorize_url or "").strip()
    redirect_uri, expected_state = _extract_http_login_authorize_callback_context(normalized_authorize_url)
    if not normalized_authorize_url:
        trace.write(
            {
                "ts": _iso_now(),
                "stage": "http_login_workspace_authorize_skipped",
                "reason": "authorize_url_missing",
            }
        )
        return result
    if not redirect_uri:
        trace.write(
            {
                "ts": _iso_now(),
                "stage": "http_login_workspace_authorize_skipped",
                "reason": "redirect_uri_missing",
                "authorizeUrl": _sanitize_url_for_log(normalized_authorize_url),
            }
        )
        return result

    try:
        storage_state = await _read_request_context_storage_state(request_ctx)
    except Exception:
        storage_state = _build_empty_storage_state_payload()
    cookie_workspace_ctx = _choose_http_provider_workspace_context_from_storage_state(storage_state)
    selected_session_workspace = _pick_http_provider_workspace(_collect_http_provider_workspaces(session_payload))
    selected_cookie_workspace = (
        dict(cookie_workspace_ctx.get("selected_workspace") or {})
        if isinstance(cookie_workspace_ctx, dict)
        else {}
    )
    selected_workspace = selected_session_workspace or selected_cookie_workspace
    workspace_context = _resolve_http_login_workspace_context(
        storage_state=storage_state,
        session_payload=session_payload,
    )
    workspace_id = _first_non_empty_text(
        selected_workspace.get("workspace_id"),
        cookie_workspace_ctx.get("workspace_id") if isinstance(cookie_workspace_ctx, dict) else "",
        workspace_context.get("account_id"),
    )
    if not workspace_id:
        trace.write(
            {
                "ts": _iso_now(),
                "stage": "http_login_workspace_authorize_skipped",
                "reason": "workspace_id_missing",
                "authorizeUrl": _sanitize_url_for_log(normalized_authorize_url),
            }
        )
        return result

    workspace_name = _first_non_empty_text(
        selected_workspace.get("display_name"),
        selected_workspace.get("label"),
        workspace_context.get("workspace_label"),
        workspace_id,
    )
    workspace_kind = _first_non_empty_text(
        selected_workspace.get("kind"),
        workspace_context.get("workspace_kind"),
    ).lower()
    result["attempted"] = True
    result["workspaceId"] = workspace_id
    result["workspaceName"] = workspace_name
    result["workspaceKind"] = workspace_kind

    try:
        select_url = "https://auth.openai.com/api/accounts/workspace/select"
        referer_url = (
            str(workspace_continue_url or "").strip()
            if _is_auth_workspace_continue_url(workspace_continue_url)
            else "https://auth.openai.com/workspace"
        )
        select_headers = _build_http_auth_fetch_headers(
            referer_url=referer_url,
            accept="application/json",
            impersonate=_resolve_request_ctx_impersonate(request_ctx),
        )
        select_headers["content-type"] = "application/json"
        select_headers.update(_build_http_datadog_trace_headers())
        select_payload, select_status, select_text, select_response_url, select_response_headers = await _request_with_context(
            request_ctx,
            method="POST",
            url=select_url,
            headers=select_headers,
            body_text=json.dumps({"workspace_id": workspace_id}, ensure_ascii=False),
            timeout_ms=timeout_ms,
            max_redirects=0,
        )
        challenge_detected = _response_looks_like_cloudflare_challenge(
            status=select_status,
            text=select_text,
            response_url=select_response_url,
            response_headers=select_response_headers,
        )
        trace.write(
            {
                "ts": _iso_now(),
                "stage": "http_login_workspace_select_result",
                "workspaceId": workspace_id,
                "workspaceName": workspace_name,
                "workspaceKind": workspace_kind,
                "status": int(select_status),
                "responseUrl": _sanitize_url_for_log(select_response_url),
                "responseHeaders": dict(select_response_headers or {}),
                "bodySnippet": _compress_debug_text(select_text, limit=800),
                "challengeDetected": bool(challenge_detected),
            }
        )
        if challenge_detected:
            raise RuntimeError("http_auth_challenge_blocked: workspace/select 命中 Cloudflare challenge，纯 HTTP 无法继续。")
        if int(select_status or 0) < 200 or int(select_status or 0) >= 400:
            raise RuntimeError(f"http_auth_workspace_select_failed: workspace/select 返回 HTTP {int(select_status or 0)}")

        resume_authorize_url = str(_extract_continue_url(select_payload) or normalized_authorize_url).strip()
        result["resumeAuthorizeUrl"] = resume_authorize_url
        callback_source = "follow_chain"
        callback = _callback_from_url(
            url=resume_authorize_url,
            expected_state=expected_state,
            redirect_uri=redirect_uri,
        )
        if callback is not None and (callback.code or callback.error or callback.state):
            callback_source = "direct_url"
            callback_url = resume_authorize_url
        else:
            callback = await _follow_http_authorize_chain(
                request_ctx,
                auth_url=resume_authorize_url,
                redirect_uri=redirect_uri,
                expected_state=expected_state,
                timeout_ms=timeout_ms,
                trace=trace,
            )
            callback_url = _build_http_login_authorize_callback_url(
                redirect_uri=redirect_uri,
                code=str(getattr(callback, "code", "") or "").strip(),
                state=str(getattr(callback, "state", "") or "").strip() or expected_state,
                error=str(getattr(callback, "error", "") or "").strip(),
                error_description=str(getattr(callback, "error_description", "") or "").strip(),
            )
        result["callbackUrl"] = callback_url
        trace.write(
            {
                "ts": _iso_now(),
                "stage": "http_login_workspace_authorize_callback_ready",
                "workspaceId": workspace_id,
                "workspaceName": workspace_name,
                "workspaceKind": workspace_kind,
                "resumeAuthorizeUrl": _sanitize_url_for_log(resume_authorize_url),
                "callbackUrl": _sanitize_url_for_log(callback_url),
                "callbackSource": callback_source,
                "hasCode": bool(getattr(callback, "code", "")),
                "hasError": bool(getattr(callback, "error", "")),
            }
        )
        if not callback_url:
            raise RuntimeError("http_auth_code_missing: authorize 已返回 callback 结果，但未能构造 chatgpt callback URL。")
        direct_token_result: dict[str, Any] = {}
        if (
            _http_login_direct_token_exchange_enabled()
            and getattr(callback, "code", "")
            and not getattr(callback, "error", "")
        ):
            direct_token_result = await _exchange_http_login_callback_code_for_access_token(
                request_ctx=request_ctx,
                authorize_url=normalized_authorize_url,
                callback=callback,
                workspace_id=workspace_id,
                workspace_name=workspace_name,
                workspace_kind=workspace_kind,
                trace=trace,
                timeout_ms=timeout_ms,
            )
            direct_access_token = str(direct_token_result.get("accessToken") or "").strip()
            if direct_access_token:
                result["accessToken"] = direct_access_token
                result["sessionPayload"] = direct_token_result.get("sessionPayload") or {}
                result["sessionStatus"] = int(direct_token_result.get("status") or 200)
                result["tokenSource"] = "oauth_token_exchange"
                result["completed"] = True
                trace.write(
                    {
                        "ts": _iso_now(),
                        "stage": "http_login_workspace_token_exchange_ready",
                        "workspaceId": workspace_id,
                        "workspaceName": workspace_name,
                        "workspaceKind": workspace_kind,
                        "status": int(direct_token_result.get("status") or 200),
                        "accessTokenLen": len(direct_access_token),
                        "tokenAccountId": _compress_debug_text(
                            str((direct_token_result.get("tokenClaims") or {}).get("account_id") or "").strip(),
                            limit=120,
                        ),
                        "tokenPlanType": str((direct_token_result.get("tokenClaims") or {}).get("plan_type") or "").strip(),
                    }
                )
                return result
            direct_exchange_error = str(direct_token_result.get("error") or "").strip()
            if direct_exchange_error:
                result["directTokenExchangeError"] = direct_exchange_error
                trace.write(
                    {
                        "ts": _iso_now(),
                        "stage": "http_login_workspace_token_exchange_failed",
                        "workspaceId": workspace_id,
                        "workspaceName": workspace_name,
                        "workspaceKind": workspace_kind,
                        "error": _compress_debug_text(direct_exchange_error, limit=320),
                    }
                )
        await _open_continue_url(
            request_ctx=request_ctx,
            continue_url=callback_url,
            trace=trace,
            timeout_ms=timeout_ms,
            stage_name="http_login_workspace_callback_continue",
        )
        result["completed"] = True
        return result
    except Exception as error:
        detail = str(error or "").strip()
        result["error"] = detail
        trace.write(
            {
                "ts": _iso_now(),
                "stage": "http_login_workspace_authorize_failed",
                "workspaceId": workspace_id,
                "workspaceName": workspace_name,
                "workspaceKind": workspace_kind,
                "resumeAuthorizeUrl": _sanitize_url_for_log(result.get("resumeAuthorizeUrl")),
                "callbackUrl": _sanitize_url_for_log(result.get("callbackUrl")),
                "error": _compress_debug_text(detail, limit=320),
            }
        )
        return result


async def _bootstrap_http_login_session(
    *,
    request_ctx: Any,
    trace: _TraceWriter,
    timeout_ms: int,
    authorization_params: Optional[dict[str, str]] = None,
) -> dict[str, Any]:
    impersonate = _resolve_request_ctx_impersonate(request_ctx)
    login_entry_url = "https://chatgpt.com/auth/login_with"
    authorize_url = ""

    _payload, status, text, response_url, response_headers = await _request_with_context(
        request_ctx,
        method="GET",
        url=login_entry_url,
        headers=_build_http_html_headers(impersonate=impersonate),
        timeout_ms=timeout_ms,
        max_redirects=5,
    )
    trace.write(
        {
            "ts": _iso_now(),
            "stage": "http_login_bootstrap_login_with",
            "status": int(status),
            "url": _sanitize_url_for_log(login_entry_url),
            "responseUrl": _sanitize_url_for_log(response_url),
            "location": _sanitize_url_for_log(str(response_headers.get("location") or "").strip()),
            "bodySnippet": _compress_debug_text(text, limit=320),
        }
    )
    if _is_blocked_response(response_url=response_url, text=text):
        raise RuntimeError("http_auth_challenge_blocked: chatgpt.com 登录入口被 Cloudflare challenge 拦截，纯 HTTP 无法继续。")
    if _is_error_response(response_url=response_url, text=text):
        raise RuntimeError("http_auth_login_failed: chatgpt.com 登录入口返回错误页面。")

    storage_state: dict[str, Any] = {}
    storage_state_error = ""
    try:
        storage_state = await _read_request_context_storage_state(request_ctx)
    except Exception as error:
        storage_state_error = str(error or "").strip()
        trace.write(
            {
                "ts": _iso_now(),
                "stage": "http_login_bootstrap_storage_state_probe_failed",
                "error": _compress_debug_text(storage_state_error, limit=220),
            }
        )

    csrf_payload, csrf_status, csrf_text, csrf_response_url, csrf_response_headers = await _request_with_context(
        request_ctx,
        method="GET",
        url="https://chatgpt.com/api/auth/csrf",
        headers=_build_chatgpt_json_fetch_headers(referer_url=login_entry_url),
        timeout_ms=timeout_ms,
        max_redirects=0,
    )
    trace.write(
        {
            "ts": _iso_now(),
            "stage": "http_login_bootstrap_csrf",
            "status": int(csrf_status),
            "url": "https://chatgpt.com/api/auth/csrf",
            "responseUrl": _sanitize_url_for_log(csrf_response_url),
            "location": _sanitize_url_for_log(str(csrf_response_headers.get("location") or "").strip()),
            "bodySnippet": _compress_debug_text(csrf_text, limit=240),
        }
    )
    if int(csrf_status) not in {200, 201, 202, 204}:
        raise RuntimeError(f"http_auth_login_failed: 获取 chatgpt csrfToken 失败：HTTP {int(csrf_status or 0)}")

    try:
        storage_state = await _read_request_context_storage_state(request_ctx)
    except Exception:
        pass
    csrf_token = _extract_chatgpt_csrf_token(storage_state=storage_state, payload=csrf_payload)
    if not csrf_token:
        raise RuntimeError("http_auth_login_failed: chatgpt csrfToken 缺失，无法初始化登录授权链路。")

    device_id = _read_storage_state_cookie_value(storage_state, cookie_name="oai-did") or str(uuid.uuid4())
    auth_session_logging_id = str(uuid.uuid4())
    sign_in_query_payload = {
        "prompt": "login",
        "screen_hint": "login",
        "ext-oai-did": device_id,
        "auth_session_logging_id": auth_session_logging_id,
    }
    for key, value in dict(authorization_params or {}).items():
        normalized_key = str(key or "").strip()
        normalized_value = str(value or "").strip()
        if normalized_key and normalized_value:
            sign_in_query_payload[normalized_key] = normalized_value
    sign_in_query = urlencode(sign_in_query_payload)
    trace_query_payload = dict(sign_in_query_payload)
    if "login_hint" in trace_query_payload:
        trace_query_payload["login_hint"] = "***"
    trace_sign_in_url = (
        "https://chatgpt.com/api/auth/signin/openai?"
        f"{urlencode(trace_query_payload)}"
    )
    login_hint = str(sign_in_query_payload.get("login_hint") or "").strip()

    def _redact_login_hint(value: Any) -> str:
        text = str(value or "")
        return text.replace(login_hint, "***") if login_hint else text

    sign_in_payload, sign_in_status, sign_in_text, sign_in_response_url, sign_in_response_headers = await _request_with_context(
        request_ctx,
        method="POST",
        url=f"https://chatgpt.com/api/auth/signin/openai?{sign_in_query}",
        headers=_build_chatgpt_json_fetch_headers(
            referer_url=login_entry_url,
            content_type="application/x-www-form-urlencoded",
        ),
        body_text=urlencode(
            {
                "callbackUrl": login_entry_url,
                "csrfToken": csrf_token,
                "json": "true",
            }
        ),
        timeout_ms=timeout_ms,
        max_redirects=0,
    )
    authorize_url = str(sign_in_payload.get("url") or "").strip() if isinstance(sign_in_payload, dict) else ""
    trace.write(
        {
            "ts": _iso_now(),
            "stage": "http_login_bootstrap_signin_openai",
            "status": int(sign_in_status),
            "url": trace_sign_in_url,
            "responseUrl": _sanitize_url_for_log(sign_in_response_url),
            "location": _sanitize_url_for_log(str(sign_in_response_headers.get("location") or "").strip()),
            "authorizeUrl": _sanitize_url_for_log(_redact_login_hint(authorize_url)),
            "bodySnippet": _compress_debug_text(_redact_login_hint(sign_in_text), limit=320),
        }
    )
    if int(sign_in_status) not in {200, 201, 202, 204}:
        raise RuntimeError(f"http_auth_login_failed: chatgpt signin/openai 引导失败：HTTP {int(sign_in_status or 0)}")
    if not authorize_url:
        raise RuntimeError("http_auth_login_failed: chatgpt signin/openai 未返回 authorize URL。")

    _authorize_payload, authorize_status, authorize_text, authorize_response_url, authorize_response_headers = await _request_with_context(
        request_ctx,
        method="GET",
        url=authorize_url,
        headers=_build_http_html_headers(impersonate=impersonate),
        timeout_ms=timeout_ms,
        max_redirects=5,
    )
    trace.write(
        {
            "ts": _iso_now(),
            "stage": "http_login_bootstrap_authorize_redirect",
            "status": int(authorize_status),
            "url": _sanitize_url_for_log(authorize_url),
            "responseUrl": _sanitize_url_for_log(authorize_response_url),
            "location": _sanitize_url_for_log(str(authorize_response_headers.get("location") or "").strip()),
            "bodySnippet": _compress_debug_text(authorize_text, limit=320),
        }
    )
    if _is_blocked_response(response_url=authorize_response_url, text=authorize_text):
        raise RuntimeError("http_auth_challenge_blocked: OpenAI authorize 入口被 Cloudflare challenge 拦截，纯 HTTP 无法继续。")
    if _is_error_response(response_url=authorize_response_url, text=authorize_text):
        raise RuntimeError("http_auth_login_failed: OpenAI authorize 入口返回错误页面。")

    try:
        storage_state = await _read_request_context_storage_state(request_ctx)
    except Exception:
        pass
    auth_session_cookie = _read_storage_state_cookie_value(storage_state, cookie_name="oai-client-auth-session")
    return {
        "loginUrl": str(authorize_response_url or "https://auth.openai.com/log-in").strip() or "https://auth.openai.com/log-in",
        "hasAuthSessionCookie": bool(auth_session_cookie),
        "deviceId": str(device_id or "").strip(),
        "authSessionLoggingId": auth_session_logging_id,
        "authorizeUrl": authorize_url,
        "storageStateProbeError": storage_state_error,
    }


async def _fetch_session_after_login(
    *,
    request_ctx: Any,
    trace: _TraceWriter,
    timeout_ms: int,
) -> dict[str, Any]:
    session_url = "https://chatgpt.com/api/auth/session"
    last_payload: dict[str, Any] = {}
    last_status = 0
    last_text = ""
    last_error = ""
    for attempt in range(1, 4):
        if attempt > 1:
            try:
                await _request_with_context(
                    request_ctx,
                    method="GET",
                    url="https://chatgpt.com/",
                    headers=_build_http_html_headers(impersonate=_resolve_request_ctx_impersonate(request_ctx)),
                    timeout_ms=timeout_ms,
                    max_redirects=3,
                )
            except Exception:
                pass
            await asyncio.sleep(min(2.0, float(attempt)))

        try:
            payload, status, text = await _request_json_with_context(
                request_ctx,
                url=session_url,
                timeout_ms=timeout_ms,
            )
            error_text = ""
        except Exception as error:
            payload, status, text = {}, 0, ""
            error_text = str(error)
        token = str(extract_access_token_from_session_payload(payload) or "").strip()
        summary = extract_session_summary_from_payload(
            payload,
            status=int(status or 0),
            error_text=str(error_text or "").strip(),
            updated_at=_iso_now(),
        )
        trace.write(
            {
                "ts": _iso_now(),
                "stage": "http_login_session_probe",
                "attempt": int(attempt),
                "status": int(status),
                "accessTokenLen": int(len(token)),
                "selectedWorkspaceId": str(summary.get("selectedWorkspaceId") or "").strip(),
                "selectedWorkspaceName": _compress_debug_text(summary.get("selectedWorkspaceName"), limit=120),
                "planType": str(summary.get("accountPlanType") or "").strip(),
                "error": _compress_debug_text(error_text, limit=220),
                "bodySnippet": _compress_debug_text(text, limit=320),
            }
        )
        last_payload = dict(payload or {})
        last_status = int(status or 0)
        last_text = str(text or "")
        last_error = str(error_text or "").strip()
        if last_status == 200 and token:
            return {
                "payload": last_payload,
                "status": last_status,
                "text": last_text,
                "error": last_error,
            }
    return {
        "payload": last_payload,
        "status": last_status,
        "text": last_text,
        "error": last_error or ("session 响应缺少 accessToken" if last_status == 200 else f"HTTP {last_status or 0}"),
    }


def _http_login_workspace_label_is_personal(text: Any) -> bool:
    raw = str(text or "").strip()
    if not raw:
        return False
    low = raw.lower()
    return (
        "personal account" in low
        or low == "personal"
        or raw == "个人"
        or "个人账户" in raw
        or "个人账号" in raw
    )


def _http_login_workspace_is_non_personal(item: Any) -> bool:
    if not isinstance(item, dict):
        return False
    workspace_id = str(item.get("workspace_id") or item.get("id") or "").strip()
    if not workspace_id:
        return False
    kind = str(item.get("kind") or item.get("structure") or item.get("type") or "").strip().lower()
    label = _first_non_empty_text(
        item.get("display_name"),
        item.get("label"),
        item.get("name"),
        item.get("workspace_name"),
        item.get("workspaceName"),
    )
    if bool(item.get("is_personal")) or kind == "personal" or _http_login_workspace_label_is_personal(label):
        return False
    if kind in {"organization", "org", "team", "teams", "business", "enterprise", "workspace"}:
        return True
    if bool(item.get("is_non_personal")):
        return True
    source = str(item.get("source") or "").strip().lower()
    return bool(("accounts[" in source or "workspaces[" in source) and not _http_login_workspace_label_is_personal(label))


def _pick_http_login_selected_workspace(
    *,
    session_payload: dict[str, Any],
    workspaces: list[dict[str, Any]],
) -> dict[str, Any]:
    summary = extract_session_summary_from_payload(session_payload, status=200, error_text="", updated_at=_iso_now())
    selected_ids = [
        str(summary.get("selectedWorkspaceId") or "").strip(),
        str(summary.get("selectedAccountId") or "").strip(),
        str(summary.get("accountId") or "").strip(),
        str(session_payload.get("selectedWorkspaceId") or "").strip(),
        str(session_payload.get("selectedAccountId") or "").strip(),
        str(session_payload.get("accountId") or "").strip(),
        str(session_payload.get("workspaceId") or "").strip(),
    ]
    selected_ids = [item for item in selected_ids if item]
    for selected_id in selected_ids:
        for item in workspaces:
            workspace_id = str(item.get("workspace_id") or "").strip()
            if workspace_id and workspace_id == selected_id:
                return dict(item)
    for item in workspaces:
        if isinstance(item, dict) and bool(item.get("preferred")):
            return dict(item)
    return dict(workspaces[0]) if workspaces else {}


def _pick_http_login_team_workspace_target(
    session_payload: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    workspaces = _collect_http_provider_workspaces(session_payload)
    selected_workspace = _pick_http_login_selected_workspace(
        session_payload=session_payload,
        workspaces=workspaces,
    )
    team_candidates = [item for item in workspaces if _http_login_workspace_is_non_personal(item)]
    if selected_workspace and _http_login_workspace_is_non_personal(selected_workspace):
        return {}, selected_workspace, workspaces
    selected_id = str(selected_workspace.get("workspace_id") or "").strip()
    team_candidates.sort(
        key=lambda item: (
            str(item.get("workspace_id") or "").strip() == selected_id,
            bool(item.get("preferred")),
            str(item.get("display_name") or item.get("label") or item.get("workspace_id") or "").strip().lower(),
        ),
        reverse=True,
    )
    target = dict(team_candidates[0]) if team_candidates else {}
    return target, selected_workspace, workspaces


async def _ensure_http_login_team_workspace_selected(
    *,
    request_ctx: Any,
    session_snapshot: dict[str, Any],
    trace: _TraceWriter,
    timeout_ms: int,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "attempted": False,
        "completed": False,
        "skipped": False,
        "reason": "",
        "workspaceId": "",
        "workspaceName": "",
        "workspaceKind": "",
        "selectedWorkspaceIdBefore": "",
        "selectedWorkspaceNameBefore": "",
        "workspaceCount": 0,
        "teamWorkspaceCount": 0,
        "error": "",
        "sessionSnapshot": session_snapshot,
    }
    if not isinstance(session_snapshot, dict):
        result["skipped"] = True
        result["reason"] = "session_snapshot_missing"
        return result
    session_payload = session_snapshot.get("payload") if isinstance(session_snapshot.get("payload"), dict) else {}
    if not session_payload:
        result["skipped"] = True
        result["reason"] = "session_payload_missing"
        return result

    target_workspace, selected_workspace, workspaces = _pick_http_login_team_workspace_target(session_payload)
    team_count = sum(1 for item in workspaces if _http_login_workspace_is_non_personal(item))
    selected_id = str(selected_workspace.get("workspace_id") or "").strip()
    selected_name = _first_non_empty_text(
        selected_workspace.get("display_name"),
        selected_workspace.get("label"),
        selected_id,
    )
    result.update(
        {
            "workspaceCount": int(len(workspaces)),
            "teamWorkspaceCount": int(team_count),
            "selectedWorkspaceIdBefore": selected_id,
            "selectedWorkspaceNameBefore": selected_name,
        }
    )
    if not target_workspace:
        result["skipped"] = True
        result["reason"] = "already_team_workspace" if selected_workspace and team_count else "team_workspace_missing"
        trace.write(
            {
                "ts": _iso_now(),
                "stage": "http_login_team_workspace_select_skipped",
                "reason": result["reason"],
                "workspaceCount": int(len(workspaces)),
                "teamWorkspaceCount": int(team_count),
                "selectedWorkspaceId": selected_id,
                "selectedWorkspaceName": _compress_debug_text(selected_name, limit=140),
            }
        )
        return result

    workspace_id = str(target_workspace.get("workspace_id") or "").strip()
    workspace_name = _first_non_empty_text(
        target_workspace.get("display_name"),
        target_workspace.get("label"),
        workspace_id,
    )
    workspace_kind = str(target_workspace.get("kind") or "organization").strip().lower() or "organization"
    result.update(
        {
            "attempted": True,
            "workspaceId": workspace_id,
            "workspaceName": workspace_name,
            "workspaceKind": workspace_kind,
        }
    )
    trace.write(
        {
            "ts": _iso_now(),
            "stage": "http_login_team_workspace_select_attempt",
            "workspaceId": workspace_id,
            "workspaceName": _compress_debug_text(workspace_name, limit=140),
            "workspaceKind": workspace_kind,
            "workspaceCount": int(len(workspaces)),
            "teamWorkspaceCount": int(team_count),
            "selectedWorkspaceIdBefore": selected_id,
            "selectedWorkspaceNameBefore": _compress_debug_text(selected_name, limit=140),
        }
    )
    try:
        select_headers = _build_http_auth_fetch_headers(
            referer_url="https://auth.openai.com/workspace",
            accept="application/json",
            impersonate=_resolve_request_ctx_impersonate(request_ctx),
        )
        select_headers["content-type"] = "application/json"
        select_headers.update(_build_http_datadog_trace_headers())
        select_payload, select_status, select_text, select_response_url, select_response_headers = await _request_with_context(
            request_ctx,
            method="POST",
            url="https://auth.openai.com/api/accounts/workspace/select",
            headers=select_headers,
            body_text=json.dumps({"workspace_id": workspace_id}, ensure_ascii=False),
            timeout_ms=timeout_ms,
            max_redirects=0,
        )
        challenge_detected = _response_looks_like_cloudflare_challenge(
            status=select_status,
            text=select_text,
            response_url=select_response_url,
            response_headers=select_response_headers,
        )
        trace.write(
            {
                "ts": _iso_now(),
                "stage": "http_login_team_workspace_select_result",
                "workspaceId": workspace_id,
                "workspaceName": _compress_debug_text(workspace_name, limit=140),
                "status": int(select_status),
                "responseUrl": _sanitize_url_for_log(select_response_url),
                "location": _sanitize_url_for_log(str((select_response_headers or {}).get("location") or "").strip()),
                "bodySnippet": _compress_debug_text(select_text, limit=800),
                "challengeDetected": bool(challenge_detected),
            }
        )
        if challenge_detected:
            result["error"] = "workspace/select 命中 Cloudflare challenge"
            return result
        if int(select_status or 0) < 200 or int(select_status or 0) >= 400:
            result["error"] = f"workspace/select 返回 HTTP {int(select_status or 0)}"
            return result

        continue_url = str(_extract_continue_url(select_payload) or "").strip()
        if continue_url:
            await _open_continue_url(
                request_ctx=request_ctx,
                continue_url=continue_url,
                trace=trace,
                timeout_ms=timeout_ms,
                stage_name="http_login_team_workspace_select_continue",
            )
        else:
            try:
                await _request_with_context(
                    request_ctx,
                    method="GET",
                    url="https://chatgpt.com/",
                    headers=_build_http_html_headers(impersonate=_resolve_request_ctx_impersonate(request_ctx)),
                    timeout_ms=timeout_ms,
                    max_redirects=3,
                )
            except Exception:
                pass

        refreshed_snapshot = await _fetch_session_after_login(
            request_ctx=request_ctx,
            trace=trace,
            timeout_ms=timeout_ms,
        )
        refreshed_payload = (
            refreshed_snapshot.get("payload")
            if isinstance(refreshed_snapshot.get("payload"), dict)
            else {}
        )
        refreshed_summary = extract_session_summary_from_payload(
            refreshed_payload,
            status=int(refreshed_snapshot.get("status") or 0),
            error_text=str(refreshed_snapshot.get("error") or "").strip(),
            updated_at=_iso_now(),
        )
        refreshed_workspaces = _collect_http_provider_workspaces(refreshed_payload)
        refreshed_selected = _pick_http_login_selected_workspace(
            session_payload=refreshed_payload,
            workspaces=refreshed_workspaces,
        )
        refreshed_selected_id = _first_non_empty_text(
            refreshed_summary.get("selectedWorkspaceId"),
            refreshed_selected.get("workspace_id"),
        )
        refreshed_selected_name = _first_non_empty_text(
            refreshed_summary.get("selectedWorkspaceName"),
            refreshed_selected.get("display_name"),
            refreshed_selected.get("label"),
            refreshed_selected_id,
        )
        result["sessionSnapshot"] = refreshed_snapshot
        result["completed"] = bool(
            refreshed_selected_id == workspace_id
            or _http_login_workspace_is_non_personal(refreshed_selected)
        )
        result["selectedWorkspaceIdAfter"] = refreshed_selected_id
        result["selectedWorkspaceNameAfter"] = refreshed_selected_name
        if not bool(result["completed"]):
            result["error"] = "workspace/select 后 session 未确认切到团队空间"
        trace.write(
            {
                "ts": _iso_now(),
                "stage": "http_login_team_workspace_select_verify",
                "workspaceId": workspace_id,
                "completed": bool(result["completed"]),
                "sessionStatus": int(refreshed_snapshot.get("status") or 0),
                "accessTokenPresent": bool(extract_access_token_from_session_payload(refreshed_payload)),
                "selectedWorkspaceIdAfter": refreshed_selected_id,
                "selectedWorkspaceNameAfter": _compress_debug_text(refreshed_selected_name, limit=140),
                "nonPersonalSeen": bool(refreshed_summary.get("nonPersonalSeen")),
                "error": _compress_debug_text(str(result.get("error") or ""), limit=240),
            }
        )
        return result
    except Exception as error:  # noqa: BLE001
        result["error"] = str(error or "").strip()
        trace.write(
            {
                "ts": _iso_now(),
                "stage": "http_login_team_workspace_select_failed",
                "workspaceId": workspace_id,
                "workspaceName": _compress_debug_text(workspace_name, limit=140),
                "error": _compress_debug_text(result["error"], limit=320),
            }
        )
        return result


def _should_attempt_session_access_token_repair(session_snapshot: dict[str, Any]) -> bool:
    if not isinstance(session_snapshot, dict):
        return False
    session_payload = session_snapshot.get("payload") if isinstance(session_snapshot.get("payload"), dict) else {}
    session_status = int(session_snapshot.get("status") or 0)
    token = str(extract_access_token_from_session_payload(session_payload) or "").strip()
    if session_status != 200 or token:
        return False
    summary = extract_session_summary_from_payload(
        session_payload,
        status=session_status,
        error_text=str(session_snapshot.get("error") or "").strip(),
        updated_at=_iso_now(),
    )
    has_bootstrap_clue = any(
        (
            bool(summary.get("hasWorkspaces")),
            bool(summary.get("hasAccounts")),
            bool(summary.get("selectedWorkspaceId")),
            bool(summary.get("accountId")),
            bool(summary.get("accountStructure")),
            bool(summary.get("accountPlanType")),
            isinstance(session_payload.get("account"), dict),
        )
    )
    return bool(has_bootstrap_clue)


async def _repair_session_access_token_after_login(
    *,
    request_ctx: Any,
    session_snapshot: dict[str, Any],
    trace: _TraceWriter,
    timeout_ms: int,
    proxy_url: str,
    impersonate: str,
    authorize_url: str = "",
) -> tuple[Any, dict[str, Any]]:
    current_request_ctx = request_ctx
    current_snapshot = dict(session_snapshot or {})
    workspace_authorize_retry_attempted = False
    for repair_attempt in range(1, 3):
        current_payload = current_snapshot.get("payload") if isinstance(current_snapshot.get("payload"), dict) else {}
        current_status = int(current_snapshot.get("status") or 0)
        current_token = str(extract_access_token_from_session_payload(current_payload) or "").strip()
        if current_status == 200 and current_token:
            break
        if (not workspace_authorize_retry_attempted) and str(authorize_url or "").strip():
            workspace_authorize_retry_attempted = True
            workspace_authorize_result = await _complete_http_login_workspace_authorize_via_http(
                request_ctx=current_request_ctx,
                authorize_url=authorize_url,
                session_payload=current_payload,
                trace=trace,
                timeout_ms=timeout_ms,
            )
            if bool(workspace_authorize_result.get("attempted")):
                current_snapshot = await _fetch_session_after_login(
                    request_ctx=current_request_ctx,
                    trace=trace,
                    timeout_ms=timeout_ms,
                )
                current_payload = current_snapshot.get("payload") if isinstance(current_snapshot.get("payload"), dict) else {}
                current_status = int(current_snapshot.get("status") or 0)
                current_token = str(extract_access_token_from_session_payload(current_payload) or "").strip()
                if current_status == 200 and current_token:
                    break
        if not _should_attempt_session_access_token_repair(current_snapshot):
            break
        try:
            storage_state = await _read_request_context_storage_state(current_request_ctx)
        except Exception:
            storage_state = _build_empty_storage_state_payload()
        current_payload = current_snapshot.get("payload") if isinstance(current_snapshot.get("payload"), dict) else {}
        repaired_storage_state = _build_sanitized_http_login_bootstrap_storage_state(
            storage_state=storage_state,
            session_payload=current_payload,
        )
        session_summary = extract_session_summary_from_payload(
            current_payload,
            status=int(current_snapshot.get("status") or 0),
            error_text=str(current_snapshot.get("error") or "").strip(),
            updated_at=_iso_now(),
        )
        trace.write(
            {
                "ts": _iso_now(),
                "stage": "http_login_session_access_token_repair",
                "repairAttempt": int(repair_attempt),
                "cookieCount": int(len(repaired_storage_state.get("cookies") or [])),
                "originCount": int(len(repaired_storage_state.get("origins") or [])),
                "accountId": _compress_debug_text(
                    str(session_summary.get("accountId") or ""),
                    limit=120,
                ),
                "selectedWorkspaceId": str(session_summary.get("selectedWorkspaceId") or "").strip(),
                "hasWorkspaces": bool(session_summary.get("hasWorkspaces")),
                "hasAccounts": bool(session_summary.get("hasAccounts")),
            }
        )
        try:
            current_request_ctx = await _rebuild_request_context_with_storage_state(
                request_ctx=current_request_ctx,
                storage_state=repaired_storage_state,
                proxy_url=proxy_url,
                impersonate=impersonate,
            )
            await _request_with_context(
                current_request_ctx,
                method="GET",
                url="https://chatgpt.com/",
                headers=_build_http_html_headers(impersonate=_resolve_request_ctx_impersonate(current_request_ctx)),
                timeout_ms=timeout_ms,
                max_redirects=3,
            )
        except Exception as error:
            trace.write(
                {
                    "ts": _iso_now(),
                    "stage": "http_login_session_access_token_repair_context_rebuild_failed",
                    "repairAttempt": int(repair_attempt),
                    "error": _compress_debug_text(str(error or ""), limit=240),
                }
            )
        current_snapshot = await _fetch_session_after_login(
            request_ctx=current_request_ctx,
            trace=trace,
            timeout_ms=timeout_ms,
        )
        current_payload = current_snapshot.get("payload") if isinstance(current_snapshot.get("payload"), dict) else {}
        token = str(extract_access_token_from_session_payload(current_payload) or "").strip()
        if int(current_snapshot.get("status") or 0) == 200 and token:
            break
    return current_request_ctx, current_snapshot


async def _submit_http_otp_if_required(
    *,
    request_ctx: Any,
    payload: Any,
    safe_email: str,
    trace: _TraceWriter,
    log: _LogSink,
    timeout_sec: float,
    otp_timeout_sec: float,
    otp_interval_sec: float,
    normalized_totp_secret: str,
    allow_totp: bool = False,
    use_managed_mail_otp: bool,
    managed_mail_provider: str,
    managed_mail_jwt: str,
    managed_mail_api_base: str,
    managed_mail_frontend_base: str,
    managed_mail_latest_n: int,
    otp_api_url: str = "",
    use_domain_mail_otp: bool,
    domain_mail_api_base: str,
    domain_mail_domain: str,
    domain_mail_token: str,
    domain_mail_latest_n: int,
    use_imap_otp: bool,
    imap_host: str,
    imap_port: int,
    imap_user: str,
    imap_pass: str,
    imap_folder: str,
    imap_latest_n: int,
    imap_auth_type: str = "password",
    imap_oauth_client_id: str = "",
    imap_oauth_refresh_token: str = "",
    imap_password_fallback: bool = False,
    imap_pop3_fallback: bool = False,
    imap_profiles_json: str = "",
    preferred_send_path: str = "",
    authorize_url: str = "",
) -> dict[str, Any]:
    if not _is_email_otp_verification_step(payload):
        return _build_http_otp_follow_up(handled=False, payload=payload)

    blocked_otp_codes: set[str] = set()
    otp_stage_enter_ts = time.time()
    log.info("【ChatGPT HTTP 登录】检测到 OTP/TOTP 验证，准备自动提交验证码。")
    if normalized_totp_secret and allow_totp:
        last_error = ""
        submitted_codes: set[str] = set()
        for attempt in range(1, 3):
            try:
                remaining_seconds = totp_seconds_remaining()
                if remaining_seconds <= 3:
                    await asyncio.sleep(float(remaining_seconds + 1))
                    remaining_seconds = totp_seconds_remaining()
                code_value = generate_totp_code(normalized_totp_secret)
            except Exception as error:
                raise RuntimeError(f"http_auth_otp_failed: 生成 TOTP 验证码失败：{error}") from error
            if code_value in submitted_codes:
                await asyncio.sleep(float(max(1, remaining_seconds + 1)))
                remaining_seconds = totp_seconds_remaining()
                code_value = generate_totp_code(normalized_totp_secret)
            submitted_codes.add(code_value)
            log.info(
                f"【ChatGPT HTTP 登录】使用 TOTP 提交验证码（attempt={attempt}/2, 剩余 {remaining_seconds}s）。"
            )
            submit_res = await _request_auth_api_with_context(
                request_ctx,
                stage=f"http_login_otp_submit_totp_{attempt}",
                path="/email-otp/validate",
                method="POST",
                timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                trace=trace,
                referer_url=_extract_continue_url(payload) or "https://auth.openai.com/email-verification",
                json_body={"code": str(code_value)},
                trace_json_body={"code": "***"},
            )
            submit_status = int(submit_res.get("status") or 0)
            submit_text = str(submit_res.get("text") or "")
            submit_payload = submit_res.get("payload")
            submit_continue_url = _extract_continue_url(submit_payload)
            if _http_login_direct_token_exchange_enabled():
                direct_token_result = await _try_http_login_direct_token_exchange_from_continue_url(
                    request_ctx=request_ctx,
                    authorize_url=authorize_url,
                    continue_url=submit_continue_url,
                    trace=trace,
                    timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                )
                if str(direct_token_result.get("accessToken") or "").strip():
                    return _build_http_otp_follow_up(
                        handled=True,
                        payload=direct_token_result.get("sessionPayload") or {},
                        continue_url=submit_continue_url,
                        submitted_codes=set(submitted_codes),
                    )
            if submit_continue_url:
                await _open_continue_url(
                    request_ctx=request_ctx,
                    continue_url=submit_continue_url,
                    trace=trace,
                    timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                    stage_name=f"http_login_otp_submit_totp_continue_{attempt}",
                )
            if submit_status in {200, 201, 202, 204}:
                return _build_http_otp_follow_up(
                    handled=True,
                    payload=submit_payload,
                    continue_url=submit_continue_url,
                    submitted_codes=set(submitted_codes),
                )
            err_code, err_msg = _extract_error(submit_payload, submit_text)
            last_error = str(err_code or err_msg or f"HTTP {submit_status}")
            low = f"{err_code}\n{err_msg}\n{submit_text}".lower()
            if submit_status == 429 or any(
                marker in low
                for marker in ("max_check_attempts", "too many tries", "too many attempts", "rate limit")
            ):
                raise RuntimeError(
                    "http_auth_totp_cooldown: TOTP 尝试次数已达上限，请等待远端冷却后再试。"
                )
            if (submit_status == 401) or any(marker in low for marker in _OTP_INVALID_MARKERS):
                if attempt >= 2:
                    break
                wait_seconds = float(max(1, remaining_seconds + 1))
                await asyncio.sleep(wait_seconds)
                continue
            break
        raise RuntimeError(f"http_auth_otp_failed: TOTP 提交失败：{last_error or 'unknown'}")

    managed_mail_enabled = bool(use_managed_mail_otp) and bool(str(managed_mail_jwt or "").strip()) and bool(
        str(managed_mail_api_base or "").strip()
    )
    domain_mail_enabled = bool(use_domain_mail_otp) and bool(str(domain_mail_api_base or "").strip()) and bool(
        str(domain_mail_token or "").strip()
    )
    otp_api_url_enabled = bool(str(otp_api_url or "").strip())
    imap_profiles = _normalize_imap_profiles_payload(
        imap_profiles_json,
        fallback_host=str(imap_host or "imap.2925.com").strip() or "imap.2925.com",
        fallback_port=int(imap_port or 993),
        fallback_user=str(imap_user or "").strip(),
        fallback_pass=str(imap_pass or ""),
        fallback_folder=str(imap_folder or "Inbox").strip() or "Inbox",
        fallback_latest_n=int(imap_latest_n or 10),
        fallback_auth_type=str(imap_auth_type or "password").strip() or "password",
        fallback_oauth_client_id=str(imap_oauth_client_id or "").strip(),
        fallback_oauth_refresh_token=str(imap_oauth_refresh_token or "").strip(),
        fallback_password_fallback=bool(imap_password_fallback),
        fallback_pop3_fallback=bool(imap_pop3_fallback),
    )
    imap_enabled = bool(use_imap_otp) and bool(imap_profiles)
    if (not managed_mail_enabled) and (not domain_mail_enabled) and (not otp_api_url_enabled) and (not imap_enabled):
        if bool(use_domain_mail_otp):
            raise RuntimeError("http_auth_otp_required: 当前登录链路要求邮箱验证码，但未提供可用的 domain_mail_api_base / domain_mail_token。")
        if bool(use_managed_mail_otp):
            raise RuntimeError("http_auth_otp_required: 当前登录链路要求邮箱验证码，但未提供可用的 mail_jwt / mail_api_base。")
        if not bool(use_imap_otp):
            raise RuntimeError("http_auth_otp_required: 当前登录链路要求邮箱验证码，但域名邮箱/managed mail/接码 URL/IMAP 取码均不可用。")
        raise RuntimeError("http_auth_otp_required: 当前登录链路要求邮箱验证码，但未提供可用的接码 URL 或 IMAP 凭据。")

    last_error = ""
    otp_source = (
        "managed_mail"
        if managed_mail_enabled
        else ("domain_mail" if domain_mail_enabled else ("otp_api_url" if otp_api_url_enabled else "imap"))
    )
    max_attempts = 3
    otp_send_path, otp_send_method = _choose_http_otp_send_request(
        payload,
        default_path=str(preferred_send_path or "/email-otp/send"),
    )
    otp_referer_url = _extract_continue_url(payload) or "https://auth.openai.com/email-verification"
    for attempt in range(1, max_attempts + 1):
        should_send = attempt > 1
        send_started_ts = 0.0
        if should_send:
            log.info(
                "【ChatGPT HTTP 登录】准备重新发送邮箱验证码"
                f"（attempt={attempt}/{max_attempts}, endpoint={otp_send_method} {otp_send_path}）。"
            )
            send_started_ts = time.time()
            send_res = await _request_auth_api_with_context(
                request_ctx,
                stage=f"http_login_otp_send_{attempt}",
                path=otp_send_path,
                method=otp_send_method,
                timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                trace=trace,
                referer_url=otp_referer_url,
                accept="application/json",
                include_json_content_type=True,
                json_body={},
            )
            send_status = int(send_res.get("status") or 0)
            send_text = str(send_res.get("text") or "")
            send_payload = send_res.get("payload")
            otp_send_path, otp_send_method = _choose_http_otp_send_request(
                send_payload,
                default_path=otp_send_path,
            )
            if otp_send_path == "/email-otp/resend":
                otp_send_method = "POST"
            if send_status not in {200, 201, 202, 204}:
                err_code, err_msg = _extract_error(send_payload, send_text)
                last_error = str(err_code or err_msg or f"HTTP {send_status}")
                continue
            send_continue_url = _extract_continue_url(send_payload)
            if send_continue_url:
                otp_referer_url = send_continue_url
            not_before_ts = max(0.0, (send_started_ts or time.time()) - 3.0)
        else:
            not_before_ts = max(0.0, otp_stage_enter_ts - 3.0)
        code_value = ""
        if managed_mail_enabled:
            log.info(
                f"【ChatGPT HTTP 登录】开始通过托管邮箱 JWT 自动取码（attempt={attempt}/{max_attempts}, 目标={_mask_email(safe_email)}）。"
            )
            code_value = await asyncio.to_thread(
                poll_managed_mail_verification_code_sync,
                email=safe_email,
                mail_provider=str(managed_mail_provider or "").strip(),
                mail_jwt=str(managed_mail_jwt or "").strip(),
                mail_api_base=str(managed_mail_api_base or "").strip(),
                mail_frontend_base=str(managed_mail_frontend_base or "").strip(),
                otp_timeout_sec=float(otp_timeout_sec),
                otp_interval_sec=float(otp_interval_sec),
                blocked_codes=blocked_otp_codes,
                not_before_ts=float(not_before_ts),
                latest_n=int(managed_mail_latest_n or 20),
                log_info=log.info,
                log_warn=log.warn,
            )
        elif domain_mail_enabled:
            log.info(
                f"【ChatGPT HTTP 登录】开始通过域名邮箱自动取码（attempt={attempt}/{max_attempts}, 目标={_mask_email(safe_email)}）。"
            )
            code_value = await asyncio.to_thread(
                poll_domain_mail_verification_code_sync,
                email=safe_email,
                api_base=str(domain_mail_api_base or "").strip(),
                domain=str(domain_mail_domain or "").strip(),
                token=str(domain_mail_token or "").strip(),
                otp_timeout_sec=float(otp_timeout_sec),
                otp_interval_sec=float(otp_interval_sec),
                blocked_codes=blocked_otp_codes,
                not_before_ts=float(not_before_ts),
                latest_n=int(domain_mail_latest_n or 20),
                log_info=log.info,
                log_warn=log.warn,
            )
        elif otp_api_url_enabled:
            code_value = await asyncio.to_thread(
                poll_otp_api_url_verification_code_sync,
                email=safe_email,
                otp_api_url=str(otp_api_url or "").strip(),
                otp_timeout_sec=float(otp_timeout_sec),
                otp_interval_sec=float(otp_interval_sec),
                blocked_codes=blocked_otp_codes,
                not_before_ts=float(not_before_ts),
                log_info=log.info,
                log_warn=log.warn,
            )
        elif imap_enabled:
            log.info(
                f"【ChatGPT HTTP 登录】开始通过 IMAP 自动取码（attempt={attempt}/{max_attempts}, "
                f"profiles={len(imap_profiles)}, 目标={_mask_email(safe_email)}）。"
            )
            code_value = await asyncio.to_thread(
                _poll_imap_code_multi_sync,
                email=safe_email,
                otp_timeout_sec=float(otp_timeout_sec),
                otp_interval_sec=float(otp_interval_sec),
                imap_profiles=imap_profiles,
                blocked_codes=blocked_otp_codes,
                not_before_ts=float(not_before_ts),
                log=log,
                loop=asyncio.get_running_loop(),
            )
        if not code_value:
            last_error = "otp_timeout"
            continue
        submit_res = await _request_auth_api_with_context(
            request_ctx,
            stage=f"http_login_otp_submit_{otp_source}_{attempt}",
            path="/email-otp/validate",
            method="POST",
            timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
            trace=trace,
            referer_url=otp_referer_url,
            json_body={"code": str(code_value)},
            trace_json_body={"code": "***"},
        )
        submit_status = int(submit_res.get("status") or 0)
        submit_text = str(submit_res.get("text") or "")
        submit_payload = submit_res.get("payload")
        submit_continue_url = _extract_continue_url(submit_payload)
        if _http_login_direct_token_exchange_enabled():
            direct_token_result = await _try_http_login_direct_token_exchange_from_continue_url(
                request_ctx=request_ctx,
                authorize_url=authorize_url,
                continue_url=submit_continue_url,
                trace=trace,
                timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
            )
            if str(direct_token_result.get("accessToken") or "").strip():
                return _build_http_otp_follow_up(
                    handled=True,
                    payload=direct_token_result.get("sessionPayload") or {},
                    continue_url=submit_continue_url,
                    submitted_codes={*blocked_otp_codes, str(code_value)},
                )
        if submit_continue_url:
            await _open_continue_url(
                request_ctx=request_ctx,
                continue_url=submit_continue_url,
                trace=trace,
                    timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                    stage_name=f"http_login_otp_submit_{otp_source}_continue_{attempt}",
            )
        if submit_status in {200, 201, 202, 204}:
            return _build_http_otp_follow_up(
                handled=True,
                payload=submit_payload,
                continue_url=submit_continue_url,
                submitted_codes={*blocked_otp_codes, str(code_value)},
            )
        err_code, err_msg = _extract_error(submit_payload, submit_text)
        last_error = str(err_code or err_msg or f"HTTP {submit_status}")
        low = f"{err_code}\n{err_msg}\n{submit_text}".lower()
        if submit_status == 429 or any(
            marker in low
            for marker in ("max_check_attempts", "too many tries", "too many attempts", "rate limit")
        ):
            raise RuntimeError(
                "http_auth_otp_cooldown: 邮箱验证码尝试次数已达上限，请等待远端冷却后再试。"
            )
        if (submit_status == 401) or any(marker in low for marker in _OTP_INVALID_MARKERS):
            blocked_otp_codes.add(str(code_value))
            continue
        break

    if last_error == "otp_timeout":
        raise RuntimeError("http_auth_otp_failed: 未在超时内获取到可用邮箱验证码。")
    raise RuntimeError(f"http_auth_otp_failed: 邮箱验证码提交失败：{last_error or 'unknown'}")


def _mfa_challenge_factors(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict) or _extract_auth_page_type(payload) != "mfa_challenge":
        return []
    page = payload.get("page") if isinstance(payload.get("page"), dict) else {}
    page_payload = page.get("payload") if isinstance(page.get("payload"), dict) else {}
    factors = page_payload.get("factors") if isinstance(page_payload.get("factors"), list) else []
    return [dict(item) for item in factors if isinstance(item, dict)]


async def _submit_http_mfa_challenge_if_required(
    *,
    request_ctx: Any,
    payload: Any,
    continue_url: str,
    safe_email: str,
    trace: _TraceWriter,
    log: _LogSink,
    timeout_sec: float,
    config: ChatGptHttpLoginConfig,
    normalized_totp_secret: str,
    imap_profiles_json: str,
    previously_submitted_codes: set[str] | None = None,
) -> dict[str, Any]:
    factors = _mfa_challenge_factors(payload)
    if not factors:
        return _build_http_otp_follow_up(handled=False, payload=payload, continue_url=continue_url)

    totp_factor = next((item for item in factors if str(item.get("factor_type") or "") == "totp"), None)
    email_factor = next((item for item in factors if str(item.get("factor_type") or "") == "email"), None)
    selected_factor = totp_factor if normalized_totp_secret and totp_factor else email_factor
    if not selected_factor:
        raise RuntimeError(
            "http_auth_mfa_secret_missing: 账号已开启 2FA，但本地没有 TOTP 密钥，且平台未提供邮箱恢复验证。"
        )

    factor_id = str(selected_factor.get("id") or "").strip()
    factor_type = str(selected_factor.get("factor_type") or "").strip()
    if not factor_id or factor_type not in {"totp", "email"}:
        raise RuntimeError("http_auth_mfa_failed: 平台返回的 MFA 因子无效。")

    referer_url = str(continue_url or _extract_continue_url(payload) or "https://auth.openai.com/mfa-challenge").strip()
    blocked_codes = {str(value) for value in (previously_submitted_codes or set()) if str(value)}
    max_attempts = 2

    imap_profiles = _normalize_imap_profiles_payload(
        imap_profiles_json or str(config.imapProfilesJson or ""),
        fallback_host=str(config.imapHost or "imap.2925.com").strip() or "imap.2925.com",
        fallback_port=int(config.imapPort or 993),
        fallback_user=str(config.imapUser or "").strip(),
        fallback_pass=str(config.imapPass or ""),
        fallback_folder=str(config.imapFolder or "Inbox").strip() or "Inbox",
        fallback_latest_n=int(config.imapLatestN or 10),
        fallback_auth_type=str(config.imapAuthType or "password").strip() or "password",
        fallback_oauth_client_id=str(config.imapOauthClientId or "").strip(),
        fallback_oauth_refresh_token=str(config.imapOauthRefreshToken or "").strip(),
        fallback_password_fallback=bool(config.imapPasswordFallback),
        fallback_pop3_fallback=bool(config.imapPop3Fallback),
    )

    async def poll_email_factor_code(*, not_before_ts: float) -> str:
        if bool(config.useManagedMailOtp) and str(config.managedMailJwt or "").strip() and str(
            config.managedMailApiBase or ""
        ).strip():
            return await asyncio.to_thread(
                poll_managed_mail_verification_code_sync,
                email=safe_email,
                mail_provider=str(config.managedMailProvider or "").strip(),
                mail_jwt=str(config.managedMailJwt or "").strip(),
                mail_api_base=str(config.managedMailApiBase or "").strip(),
                mail_frontend_base=str(config.managedMailFrontendBase or "").strip(),
                otp_timeout_sec=float(config.otpTimeoutSeconds or 120.0),
                otp_interval_sec=float(config.otpIntervalSeconds or 3.0),
                blocked_codes=blocked_codes,
                not_before_ts=float(not_before_ts),
                latest_n=int(config.managedMailLatestN or 20),
                log_info=log.info,
                log_warn=log.warn,
            )
        if bool(config.useDomainMailOtp) and str(config.domainMailApiBase or "").strip() and str(
            config.domainMailToken or ""
        ).strip():
            return await asyncio.to_thread(
                poll_domain_mail_verification_code_sync,
                email=safe_email,
                api_base=str(config.domainMailApiBase or "").strip(),
                domain=str(config.domainMailDomain or "").strip(),
                token=str(config.domainMailToken or "").strip(),
                otp_timeout_sec=float(config.otpTimeoutSeconds or 120.0),
                otp_interval_sec=float(config.otpIntervalSeconds or 3.0),
                blocked_codes=blocked_codes,
                not_before_ts=float(not_before_ts),
                latest_n=int(config.domainMailLatestN or 20),
                log_info=log.info,
                log_warn=log.warn,
            )
        if str(config.otpApiUrl or "").strip():
            return await asyncio.to_thread(
                poll_otp_api_url_verification_code_sync,
                email=safe_email,
                otp_api_url=str(config.otpApiUrl or "").strip(),
                otp_timeout_sec=float(config.otpTimeoutSeconds or 120.0),
                otp_interval_sec=float(config.otpIntervalSeconds or 3.0),
                blocked_codes=blocked_codes,
                not_before_ts=float(not_before_ts),
                log_info=log.info,
                log_warn=log.warn,
            )
        if bool(config.useImapOtp) and imap_profiles:
            return await asyncio.to_thread(
                _poll_imap_code_multi_sync,
                email=safe_email,
                otp_timeout_sec=float(config.otpTimeoutSeconds or 120.0),
                otp_interval_sec=float(config.otpIntervalSeconds or 3.0),
                imap_profiles=imap_profiles,
                blocked_codes=blocked_codes,
                not_before_ts=float(not_before_ts),
                log=log,
                loop=asyncio.get_running_loop(),
            )
        raise RuntimeError("http_auth_mfa_otp_required: 账号需要邮箱 MFA 验证，但当前邮箱取码源不可用。")

    last_error = ""
    submitted_totp_codes: set[str] = set()
    for attempt in range(1, max_attempts + 1):
        issue_started_ts = time.time()
        issue_res = await _request_auth_api_with_context(
            request_ctx,
            stage=f"http_login_mfa_issue_{factor_type}_{attempt}",
            path="/mfa/issue_challenge",
            method="POST",
            timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
            trace=trace,
            referer_url=referer_url,
            json_body={
                "id": factor_id,
                "type": factor_type,
                "force_fresh_challenge": bool(attempt > 1),
            },
        )
        issue_status = int(issue_res.get("status") or 0)
        if issue_status not in {200, 201, 202, 204}:
            err_code, err_msg = _extract_error(issue_res.get("payload"), str(issue_res.get("text") or ""))
            raise RuntimeError(
                f"http_auth_mfa_failed: MFA 挑战发送失败：{err_code or err_msg or ('HTTP ' + str(issue_status))}"
            )

        if factor_type == "totp":
            remaining_seconds = totp_seconds_remaining()
            if remaining_seconds <= 3:
                await asyncio.sleep(float(remaining_seconds + 1))
                remaining_seconds = totp_seconds_remaining()
            code_value = generate_totp_code(normalized_totp_secret)
            if code_value in submitted_totp_codes:
                await asyncio.sleep(float(max(1, remaining_seconds + 1)))
                code_value = generate_totp_code(normalized_totp_secret)
            submitted_totp_codes.add(code_value)
            log.info(f"【ChatGPT HTTP 登录】提交密码后的 TOTP 挑战（attempt={attempt}/{max_attempts}）。")
        else:
            log.info(f"【ChatGPT HTTP 登录】本地无 TOTP 密钥，改用平台提供的邮箱 MFA 恢复验证（attempt={attempt}/{max_attempts}）。")
            code_value = await poll_email_factor_code(not_before_ts=max(0.0, issue_started_ts - 3.0))
            if not code_value:
                last_error = "otp_timeout"
                continue

        verify_res = await _request_auth_api_with_context(
            request_ctx,
            stage=f"http_login_mfa_verify_{factor_type}_{attempt}",
            path="/mfa/verify",
            method="POST",
            timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
            trace=trace,
            referer_url=referer_url,
            json_body={"id": factor_id, "type": factor_type, "code": str(code_value)},
            trace_json_body={"id": factor_id, "type": factor_type, "code": "***"},
        )
        verify_status = int(verify_res.get("status") or 0)
        verify_text = str(verify_res.get("text") or "")
        verify_payload = verify_res.get("payload")
        next_url = str(_extract_continue_url(verify_payload) or "").strip()
        if verify_status in {200, 201, 202, 204}:
            if next_url:
                await _open_continue_url(
                    request_ctx=request_ctx,
                    continue_url=next_url,
                    trace=trace,
                    timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                    stage_name=f"http_login_mfa_verify_{factor_type}_continue_{attempt}",
                )
            return _build_http_otp_follow_up(
                handled=True,
                payload=verify_payload if isinstance(verify_payload, dict) else {},
                continue_url=next_url,
                submitted_codes={*blocked_codes, str(code_value)},
            )

        err_code, err_msg = _extract_error(verify_payload, verify_text)
        last_error = str(err_code or err_msg or f"HTTP {verify_status}")
        low = f"{err_code}\n{err_msg}\n{verify_text}".lower()
        if verify_status == 429 or any(
            marker in low for marker in ("max_check_attempts", "too many tries", "too many attempts", "rate limit")
        ):
            raise RuntimeError("http_auth_mfa_cooldown: MFA 尝试次数已达上限，请等待远端冷却后再试。")
        if verify_status == 401 or any(marker in low for marker in _OTP_INVALID_MARKERS):
            blocked_codes.add(str(code_value))
            continue
        break

    raise RuntimeError(f"http_auth_mfa_failed: MFA 验证失败：{last_error or 'unknown'}")


async def run_chatgpt_http_login(
    *,
    profile: ChatGptHttpLoginProfile,
    config: ChatGptHttpLoginConfig,
    logInfo: Optional[LogFn] = None,
    logWarn: Optional[LogFn] = None,
    logError: Optional[LogFn] = None,
    stageReporter: Optional[StageReporter] = None,
) -> ChatGptHttpLoginResult:
    email = str(profile.email or "").strip().lower()
    password = str(profile.password or "")
    activate_http_stage_feature_session(email, "chatgpt_http_login")
    if (not email) or ("@" not in email):
        return _build_result(
            success=False,
            stage="validate_profile",
            error_code="invalid_email",
            message="HTTP 登录失败：邮箱格式不正确。",
            trace_path="",
        )
    if not str(password).strip():
        return _build_result(
            success=False,
            stage="validate_profile",
            error_code="missing_password",
            message="HTTP 登录失败：密码不能为空。",
            trace_path="",
        )

    log = _LogSink(
        logInfo=logInfo or _noop_log,
        logWarn=logWarn or logInfo or _noop_log,
        logError=logError or logWarn or logInfo or _noop_log,
    )
    trace = _TraceWriter(
        email=email,
        path=str(config.tracePath or "").strip(),
        enabled=bool(config.traceEnabled),
    )
    safe_email = _mask_email(email)
    output_path = _normalize_state_output_path(str(config.storageStatePath or "").strip(), email)
    timeout_sec = max(60.0, min(float(config.timeoutSeconds or 240.0), 900.0))
    resolved_proxy_url = str(config.proxyUrl or "").strip() or str(resolve_proxy_for_url("https://auth.openai.com/log-in") or "").strip()
    sentinel_proxy_opt = _build_playwright_proxy_option(resolved_proxy_url)
    resolved_impersonate = _resolve_http_provider_curl_impersonate()
    normalized_totp_secret = normalize_totp_secret(str(profile.mfaTotpSecret or "").strip())
    request_ctx = None
    last_known_url = ""

    try:
        log.info(f"【ChatGPT HTTP 登录】开始纯 HTTP 登录：{safe_email}")
        request_ctx = await asyncio.to_thread(
            _build_http_provider_request_context,
            storage_state=_build_empty_storage_state_payload(),
            proxy_url=resolved_proxy_url,
            impersonate=resolved_impersonate,
        )
        trace.write(
            {
                "ts": _iso_now(),
                "stage": "http_login_context_ready",
                "proxy": _mask_proxy_url_for_log(resolved_proxy_url),
                "impersonate": resolved_impersonate or "",
                "storageStatePath": output_path,
                "stageFeature": get_http_stage_feature_summary(),
            }
        )

        sentinel_header_candidates: dict[str, list[tuple[str, dict[str, str]]]] = {}
        login_hint_payload: Any = {}
        login_continue_url = ""
        bootstrap_authorize_url = ""
        login_imap_profiles_json = ""
        for bootstrap_attempt in range(1, 3):
            boot_info = await _bootstrap_http_login_session(
                request_ctx=request_ctx,
                trace=trace,
                timeout_ms=min(int(timeout_sec * 1000.0), 60_000),
            )
            interactive_url = str(boot_info.get("loginUrl") or "https://auth.openai.com/log-in").strip()
            bootstrap_authorize_url = str(boot_info.get("authorizeUrl") or "").strip()
            last_known_url = interactive_url or last_known_url
            log.info(
                f"【ChatGPT HTTP 登录】初始化登录会话完成（attempt={bootstrap_attempt}/2, "
                f"hasAuthSession={bool(boot_info.get('hasAuthSessionCookie'))}）。"
            )
            await _report_http_stage(
                stageReporter,
                stage="bootstrap_session",
                step_name="初始化登录会话",
                current_url=interactive_url,
                detail=f"attempt={bootstrap_attempt}/2",
            )
            sentinel_header_candidates = await _collect_http_sentinel_header_candidates_for_flows(
                flow_names=(
                    _HTTP_AUTHORIZE_CONTINUE_SENTINEL_FLOW,
                    _HTTP_PASSWORD_VERIFY_SENTINEL_FLOW,
                ),
                playwright=None,
                storage_state_path="",
                proxy_opt=sentinel_proxy_opt,
                trace=trace,
                timeout_ms=int(max(12_000, float(timeout_sec) * 1000.0 / 3.0)),
            )
            authorize_continue_candidates = list(
                sentinel_header_candidates.get(_HTTP_AUTHORIZE_CONTINUE_SENTINEL_FLOW) or []
            )
            login_imap_profiles_json = _build_imap_profiles_json_with_uid_baseline(
                config=config,
                safe_email=email,
                log=log,
            )
            login_hint_status = 0
            login_hint_payload = {}
            login_hint_error_code = ""
            login_hint_error_message = ""
            retry_bootstrap = False
            for candidate_name, candidate_headers in authorize_continue_candidates:
                login_hint_res = await _request_auth_api_with_context(
                    request_ctx,
                    stage=f"http_login_hint_{bootstrap_attempt}_{candidate_name}",
                    path="/authorize/continue",
                    method="POST",
                    timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                    trace=trace,
                    referer_url=interactive_url,
                    json_body={"username": {"kind": "email", "value": email}},
                    extra_headers=candidate_headers,
                )
                login_hint_status = int(login_hint_res.get("status") or 0)
                login_hint_payload = login_hint_res.get("payload")
                login_hint_text = str(login_hint_res.get("text") or "")
                if login_hint_status in {200, 201, 202, 204}:
                    break
                err_code, err_msg = _extract_error(login_hint_payload, login_hint_text)
                login_hint_error_code = str(err_code or "").strip()
                login_hint_error_message = str(err_msg or "").strip()
                if login_hint_error_code in {"invalid_state", "preauth_cookie_invalid"}:
                    retry_bootstrap = True
                    break

            if retry_bootstrap and bootstrap_attempt < 2:
                log.warn("【ChatGPT HTTP 登录】登录 client/session 已失效，准备重建后重试。")
                continue
            if login_hint_status not in {200, 201, 202, 204}:
                return _build_result(
                    success=False,
                    stage="submit_email",
                    error_code=login_hint_error_code or "submit_email_failed",
                    message=(
                        "HTTP 登录失败：邮箱提交失败："
                        f"{login_hint_error_message or f'HTTP {login_hint_status or 0}'}"
                    ),
                    trace_path=trace.path,
                    extra={
                        "status": int(login_hint_status),
                        "storageStatePath": output_path,
                    },
                )

            login_continue_url = _extract_continue_url(login_hint_payload)
            trace.write(
                {
                    "ts": _iso_now(),
                    "stage": "http_login_hint_parsed",
                    "status": int(login_hint_status),
                    "continueUrl": _sanitize_url_for_log(login_continue_url),
                    "hints": _collect_auth_step_hints(login_hint_payload),
                }
            )
            last_known_url = login_continue_url or interactive_url or last_known_url
            await _report_http_stage(
                stageReporter,
                stage="submit_email",
                step_name="提交邮箱",
                current_url=login_continue_url or interactive_url,
            )
            if login_continue_url:
                await _open_continue_url(
                    request_ctx=request_ctx,
                    continue_url=login_continue_url,
                    trace=trace,
                    timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                    stage_name="http_login_continue_page",
                )
            break

        final_payload: Any = {}
        final_continue_url = ""
        final_error = ""
        final_otp_send_path = "/email-otp/send"
        submit_password_error_code = ""
        invalid_password_error_code = ""
        invalid_password_error_message = ""
        login_hint_otp_completed = False
        login_hint_submitted_codes: set[str] = set()

        login_hint_otp_result = await _submit_http_otp_if_required(
            request_ctx=request_ctx,
            payload=login_hint_payload,
            safe_email=email,
            trace=trace,
            log=log,
            timeout_sec=timeout_sec,
            otp_timeout_sec=float(config.otpTimeoutSeconds or 120.0),
            otp_interval_sec=float(config.otpIntervalSeconds or 3.0),
            normalized_totp_secret=normalized_totp_secret,
            allow_totp=False,
            use_managed_mail_otp=bool(config.useManagedMailOtp),
            managed_mail_provider=str(config.managedMailProvider or "").strip(),
            managed_mail_jwt=str(config.managedMailJwt or "").strip(),
            managed_mail_api_base=str(config.managedMailApiBase or "").strip(),
            managed_mail_frontend_base=str(config.managedMailFrontendBase or "").strip(),
            managed_mail_latest_n=int(config.managedMailLatestN or 20),
            otp_api_url=str(config.otpApiUrl or "").strip(),
            use_domain_mail_otp=bool(config.useDomainMailOtp),
            domain_mail_api_base=str(config.domainMailApiBase or "").strip(),
            domain_mail_domain=str(config.domainMailDomain or "").strip(),
            domain_mail_token=str(config.domainMailToken or "").strip(),
            domain_mail_latest_n=int(config.domainMailLatestN or 20),
            use_imap_otp=bool(config.useImapOtp),
            imap_host=str(config.imapHost or "imap.2925.com").strip() or "imap.2925.com",
            imap_port=int(config.imapPort or 993),
            imap_user=str(config.imapUser or "").strip(),
            imap_pass=str(config.imapPass or ""),
            imap_folder=str(config.imapFolder or "Inbox").strip() or "Inbox",
            imap_latest_n=int(config.imapLatestN or 10),
            imap_auth_type=str(config.imapAuthType or "password").strip() or "password",
            imap_oauth_client_id=str(config.imapOauthClientId or "").strip(),
            imap_oauth_refresh_token=str(config.imapOauthRefreshToken or "").strip(),
            imap_password_fallback=bool(config.imapPasswordFallback),
            imap_pop3_fallback=bool(config.imapPop3Fallback),
            imap_profiles_json=login_imap_profiles_json or str(config.imapProfilesJson or ""),
            authorize_url=bootstrap_authorize_url,
        )
        if bool(login_hint_otp_result.get("handled")):
            # A successful OTP validation advances the authorization
            # transaction itself.  Calling /password/verify again against that
            # advanced transaction returns `Invalid authorization step`.
            # Continue with the resulting cookies/session instead.
            login_hint_otp_completed = True
            login_hint_submitted_codes = {
                str(value) for value in (login_hint_otp_result.get("submitted_codes") or []) if str(value)
            }
            resolved_login_hint_payload = login_hint_otp_result.get("payload")
            login_continue_url = str(login_hint_otp_result.get("continue_url") or "").strip()
            if isinstance(resolved_login_hint_payload, dict):
                login_hint_payload = resolved_login_hint_payload
            elif login_continue_url:
                login_hint_payload = {"continue_url": login_continue_url}
            else:
                login_hint_payload = {}
            final_payload = login_hint_payload if isinstance(login_hint_payload, dict) else {}
            final_continue_url = login_continue_url
            trace.write(
                {
                    "ts": _iso_now(),
                    "stage": "http_login_otp_completed_before_password",
                    "continueUrl": _sanitize_url_for_log(final_continue_url),
                    "pageType": str(login_hint_otp_result.get("page_type") or "").strip(),
                    "hints": _collect_auth_step_hints(final_payload),
                }
            )
            last_known_url = final_continue_url or last_known_url
            await _report_http_stage(
                stageReporter,
                stage="email_otp_completed",
                step_name="邮箱 OTP 验证完成",
                current_url=final_continue_url,
            )

        if (not login_hint_otp_completed) and (not final_payload) and (not final_continue_url):
            await _report_http_stage(
                stageReporter,
                stage="submit_password",
                step_name="提交密码",
                current_url=login_continue_url or last_known_url,
            )
            password_verify_header_candidates = list(
                sentinel_header_candidates.get(_HTTP_PASSWORD_VERIFY_SENTINEL_FLOW) or []
            )
            password_attempts = [
                (
                    f"http_login_password_verify_{candidate_name}",
                    "/password/verify",
                    {"password": str(password)},
                    candidate_headers,
                )
                for candidate_name, candidate_headers in password_verify_header_candidates
            ]
            for stage_name, path, body, extra_headers in password_attempts:
                submit_res = await _request_auth_api_with_context(
                    request_ctx,
                    stage=stage_name,
                    path=path,
                    method="POST",
                    timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                    trace=trace,
                    referer_url=login_continue_url or "https://auth.openai.com/log-in",
                    json_body=body,
                    extra_headers=extra_headers,
                )
                submit_status = int(submit_res.get("status") or 0)
                submit_payload = submit_res.get("payload")
                submit_text = str(submit_res.get("text") or "")
                submit_continue_url = _extract_continue_url(submit_payload)
                if submit_continue_url:
                    await _open_continue_url(
                        request_ctx=request_ctx,
                        continue_url=submit_continue_url,
                        trace=trace,
                        timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                        stage_name=f"{stage_name}_continue_page",
                    )
                if submit_status in {200, 201, 202, 204}:
                    final_payload = submit_payload
                    final_continue_url = submit_continue_url
                    last_known_url = final_continue_url or last_known_url
                    await _report_http_stage(
                        stageReporter,
                        stage="password_submitted",
                        step_name="密码验证通过",
                        current_url=final_continue_url,
                    )
                    break
                err_code, err_msg = _extract_error(submit_payload, submit_text)
                err_code_text = str(err_code or "").strip()
                final_error = str(err_msg or err_code or f"HTTP {submit_status}")
                trace.write(
                    {
                        "ts": _iso_now(),
                        "stage": f"{stage_name}_failed",
                        "status": submit_status,
                        "errorCode": err_code_text,
                        "errorMessage": str(err_msg or "").strip(),
                        "hints": _collect_auth_step_hints(submit_payload),
                    }
                )
                if err_code_text:
                    submit_password_error_code = err_code_text
                if err_code_text in {"invalid_username_or_password", "invalid_credentials"} or _is_invalid_authorization_step(
                    err_code=err_code_text,
                    err_msg=err_msg,
                    text=submit_text,
                ):
                    invalid_password_error_code = err_code_text or "invalid_authorization_step"
                    invalid_password_error_message = str(err_msg or submit_text or "").strip()
                if err_code_text == "account_deactivated":
                    break

        if (not login_hint_otp_completed) and (not final_payload) and (not final_continue_url):
            if _should_try_http_passwordless_login_fallback(
                login_payload=login_hint_payload,
                err_code=invalid_password_error_code,
                err_msg=invalid_password_error_message,
                email=email,
                use_imap_otp=bool(config.useImapOtp),
                imap_user=config.imapUser,
                imap_pass=config.imapPass,
                imap_auth_type=str(config.imapAuthType or "password").strip() or "password",
                imap_oauth_client_id=str(config.imapOauthClientId or "").strip(),
                imap_oauth_refresh_token=str(config.imapOauthRefreshToken or "").strip(),
            ):
                log.warn("【ChatGPT HTTP 登录】密码校验失败，尝试切换到一次性验证码登录链路。")
                passwordless_res = await _request_auth_api_with_context(
                    request_ctx,
                    stage="http_login_passwordless_send_otp",
                    path="/passwordless/send-otp",
                    method="POST",
                    timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                    trace=trace,
                    referer_url=login_continue_url or "https://auth.openai.com/log-in",
                )
                passwordless_status = int(passwordless_res.get("status") or 0)
                passwordless_payload = passwordless_res.get("payload")
                passwordless_text = str(passwordless_res.get("text") or "")
                passwordless_continue_url = _extract_continue_url(passwordless_payload)
                if passwordless_continue_url:
                    await _open_continue_url(
                        request_ctx=request_ctx,
                        continue_url=passwordless_continue_url,
                        trace=trace,
                        timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                        stage_name="http_login_passwordless_send_otp_continue_page",
                    )
                if passwordless_status in {200, 201, 202, 204}:
                    final_payload = (
                        passwordless_payload
                        if isinstance(passwordless_payload, dict)
                        else ({"continue_url": passwordless_continue_url} if passwordless_continue_url else {})
                    )
                    final_continue_url = passwordless_continue_url
                    final_otp_send_path = "/passwordless/send-otp"
                else:
                    err_code, err_msg = _extract_error(passwordless_payload, passwordless_text)
                    final_error = str(err_msg or err_code or f"HTTP {passwordless_status}")

        if not isinstance(final_payload, dict):
            final_payload = {}
        final_hints = _collect_auth_step_hints(final_payload)
        if (
            (not login_hint_otp_completed)
            and final_continue_url
            and ("/log-in/password" in str(final_continue_url or "").strip().lower())
            and not final_hints
        ):
            return _build_result(
                success=False,
                stage="submit_password",
                error_code=submit_password_error_code or invalid_password_error_code or "submit_password_failed",
                message="HTTP 登录失败：密码提交后仍停留在登录密码页。",
                trace_path=trace.path,
                extra={"storageStatePath": output_path},
            )
        if (not login_hint_otp_completed) and (not final_payload) and (not final_continue_url):
            return _build_result(
                success=False,
                stage="submit_password",
                error_code=submit_password_error_code or invalid_password_error_code or "submit_password_failed",
                message=f"HTTP 登录失败：密码提交失败：{final_error or 'unknown'}",
                trace_path=trace.path,
                extra={"storageStatePath": output_path},
            )

        final_otp_result = await _submit_http_otp_if_required(
            request_ctx=request_ctx,
            payload=final_payload,
            safe_email=email,
            trace=trace,
            log=log,
            timeout_sec=timeout_sec,
            otp_timeout_sec=float(config.otpTimeoutSeconds or 120.0),
            otp_interval_sec=float(config.otpIntervalSeconds or 3.0),
            normalized_totp_secret=normalized_totp_secret,
            allow_totp=False,
            use_managed_mail_otp=bool(config.useManagedMailOtp),
            managed_mail_provider=str(config.managedMailProvider or "").strip(),
            managed_mail_jwt=str(config.managedMailJwt or "").strip(),
            managed_mail_api_base=str(config.managedMailApiBase or "").strip(),
            managed_mail_frontend_base=str(config.managedMailFrontendBase or "").strip(),
            managed_mail_latest_n=int(config.managedMailLatestN or 20),
            otp_api_url=str(config.otpApiUrl or "").strip(),
            use_domain_mail_otp=bool(config.useDomainMailOtp),
            domain_mail_api_base=str(config.domainMailApiBase or "").strip(),
            domain_mail_domain=str(config.domainMailDomain or "").strip(),
            domain_mail_token=str(config.domainMailToken or "").strip(),
            domain_mail_latest_n=int(config.domainMailLatestN or 20),
            use_imap_otp=bool(config.useImapOtp),
            imap_host=str(config.imapHost or "imap.2925.com").strip() or "imap.2925.com",
            imap_port=int(config.imapPort or 993),
            imap_user=str(config.imapUser or "").strip(),
            imap_pass=str(config.imapPass or ""),
            imap_folder=str(config.imapFolder or "Inbox").strip() or "Inbox",
            imap_latest_n=int(config.imapLatestN or 10),
            imap_auth_type=str(config.imapAuthType or "password").strip() or "password",
            imap_oauth_client_id=str(config.imapOauthClientId or "").strip(),
            imap_oauth_refresh_token=str(config.imapOauthRefreshToken or "").strip(),
            imap_password_fallback=bool(config.imapPasswordFallback),
            imap_pop3_fallback=bool(config.imapPop3Fallback),
            imap_profiles_json=str(config.imapProfilesJson or ""),
            preferred_send_path=final_otp_send_path,
            authorize_url=bootstrap_authorize_url,
        )
        if bool(final_otp_result.get("handled")):
            resolved_final_otp_payload = final_otp_result.get("payload")
            resolved_final_otp_continue_url = str(final_otp_result.get("continue_url") or "").strip()
            if isinstance(resolved_final_otp_payload, dict):
                final_payload = resolved_final_otp_payload
            elif resolved_final_otp_continue_url:
                final_payload = {"continue_url": resolved_final_otp_continue_url}
            if resolved_final_otp_continue_url:
                final_continue_url = resolved_final_otp_continue_url

        final_mfa_result = await _submit_http_mfa_challenge_if_required(
            request_ctx=request_ctx,
            payload=final_payload,
            continue_url=final_continue_url,
            safe_email=email,
            trace=trace,
            log=log,
            timeout_sec=timeout_sec,
            config=config,
            normalized_totp_secret=normalized_totp_secret,
            imap_profiles_json=login_imap_profiles_json or str(config.imapProfilesJson or ""),
            previously_submitted_codes={
                *login_hint_submitted_codes,
                *{
                    str(value)
                    for value in (final_otp_result.get("submitted_codes") or [])
                    if str(value)
                },
            },
        )
        if bool(final_mfa_result.get("handled")):
            resolved_mfa_payload = final_mfa_result.get("payload")
            resolved_mfa_continue_url = str(final_mfa_result.get("continue_url") or "").strip()
            final_payload = resolved_mfa_payload if isinstance(resolved_mfa_payload, dict) else {}
            if resolved_mfa_continue_url:
                final_continue_url = resolved_mfa_continue_url

        direct_session_snapshot: dict[str, Any] | None = None
        direct_access_token_from_payload = str(extract_access_token_from_session_payload(final_payload) or "").strip()
        if direct_access_token_from_payload:
            direct_session_snapshot = {
                "payload": final_payload if isinstance(final_payload, dict) else {"accessToken": direct_access_token_from_payload},
                "status": 200,
                "text": json.dumps(final_payload if isinstance(final_payload, dict) else {"accessToken": direct_access_token_from_payload}, ensure_ascii=False),
                "error": "",
            }
            log.info("【ChatGPT HTTP 登录】OTP 阶段已直接通过 OAuth 授权码换到 accessToken，跳过 chatgpt callback/session。")
        if bootstrap_authorize_url and (
            _extract_auth_page_type(final_payload) == "workspace"
            or _is_auth_workspace_continue_url(final_continue_url)
        ):
            await _report_http_stage(
                stageReporter,
                stage="workspace_authorize",
                step_name="进入 Workspace 认证",
                current_url=final_continue_url or bootstrap_authorize_url,
            )
            workspace_authorize_result = await _complete_http_login_workspace_authorize_via_http(
                request_ctx=request_ctx,
                authorize_url=bootstrap_authorize_url,
                session_payload=final_payload if isinstance(final_payload, dict) else {},
                trace=trace,
                timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                workspace_continue_url=final_continue_url,
            )
            direct_session_payload = (
                workspace_authorize_result.get("sessionPayload")
                if isinstance(workspace_authorize_result.get("sessionPayload"), dict)
                else {}
            )
            direct_access_token = str(extract_access_token_from_session_payload(direct_session_payload) or "").strip()
            if bool(workspace_authorize_result.get("completed")) and direct_access_token:
                direct_session_snapshot = {
                    "payload": direct_session_payload,
                    "status": int(workspace_authorize_result.get("sessionStatus") or 200),
                    "text": json.dumps(direct_session_payload, ensure_ascii=False),
                    "error": "",
                }
                log.info(
                    "【ChatGPT HTTP 登录】已通过 OAuth 授权码直连 token 端点获取 accessToken，"
                    f"workspace={workspace_authorize_result.get('workspaceName') or workspace_authorize_result.get('workspaceId') or 'unknown'}。"
                )
            elif bool(workspace_authorize_result.get("completed")):
                log.info(
                    "��ChatGPT HTTP ��¼����ͨ���� HTTP ��� workspace/select �� chatgpt callback��"
                    f"workspace={workspace_authorize_result.get('workspaceName') or workspace_authorize_result.get('workspaceId') or 'unknown'}��"
                )
            elif bool(workspace_authorize_result.get("attempted")):
                log.warn(
                    "��ChatGPT HTTP ��¼��workspace/select / callback δֱ����ɣ������ session ���̲�����"
                    f"{workspace_authorize_result.get('error') or 'unknown'}"
                )

        if direct_session_snapshot is None:
            try:
                await _request_with_context(
                    request_ctx,
                    method="GET",
                    url="https://chatgpt.com/",
                    headers=_build_http_html_headers(impersonate=_resolve_request_ctx_impersonate(request_ctx)),
                    timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                    max_redirects=3,
                )
            except Exception:
                pass

            try:
                storage_state_before_session = await _read_request_context_storage_state(request_ctx)
            except Exception:
                storage_state_before_session = _build_empty_storage_state_payload()
            bridged_storage_state = _build_sanitized_http_login_bootstrap_storage_state(
                storage_state=storage_state_before_session,
                session_payload={},
            )
            trace.write(
                {
                    "ts": _iso_now(),
                    "stage": "http_login_session_bridge_state_ready",
                    "cookieCount": int(len(bridged_storage_state.get("cookies") or [])),
                    "originCount": int(len(bridged_storage_state.get("origins") or [])),
                    "accountId": _compress_debug_text(
                        _resolve_http_login_workspace_context(
                            storage_state=bridged_storage_state,
                            session_payload={},
                        ).get("account_id"),
                        limit=120,
                    ),
                }
            )
            try:
                request_ctx = await _rebuild_request_context_with_storage_state(
                    request_ctx=request_ctx,
                    storage_state=bridged_storage_state,
                    proxy_url=resolved_proxy_url,
                    impersonate=resolved_impersonate,
                )
                await _request_with_context(
                    request_ctx,
                    method="GET",
                    url="https://chatgpt.com/",
                    headers=_build_http_html_headers(impersonate=_resolve_request_ctx_impersonate(request_ctx)),
                    timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                    max_redirects=3,
                )
            except Exception as error:
                trace.write(
                    {
                        "ts": _iso_now(),
                        "stage": "http_login_session_bridge_context_rebuild_failed",
                        "error": _compress_debug_text(str(error or ""), limit=240),
                    }
                )

            session_snapshot = await _fetch_session_after_login(
                request_ctx=request_ctx,
                trace=trace,
                timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
            )
            request_ctx, session_snapshot = await _repair_session_access_token_after_login(
                request_ctx=request_ctx,
                session_snapshot=session_snapshot,
                trace=trace,
                timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                proxy_url=resolved_proxy_url,
                impersonate=resolved_impersonate,
                authorize_url=bootstrap_authorize_url,
            )
        else:
            session_snapshot = direct_session_snapshot
        team_workspace_select_result = await _ensure_http_login_team_workspace_selected(
            request_ctx=request_ctx,
            session_snapshot=session_snapshot,
            trace=trace,
            timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
        )
        if isinstance(team_workspace_select_result.get("sessionSnapshot"), dict):
            session_snapshot = team_workspace_select_result.get("sessionSnapshot") or session_snapshot
        if bool(team_workspace_select_result.get("completed")):
            log.info(
                "【ChatGPT HTTP 登录】已切换到团队空间后保存登录态："
                f"{team_workspace_select_result.get('workspaceName') or team_workspace_select_result.get('workspaceId') or 'unknown'}。"
            )
        elif bool(team_workspace_select_result.get("attempted")):
            log.warn(
                "【ChatGPT HTTP 登录】尝试切换团队空间但未确认成功："
                f"{team_workspace_select_result.get('error') or 'unknown'}。"
            )
        session_payload = session_snapshot.get("payload") if isinstance(session_snapshot.get("payload"), dict) else {}
        session_status = int(session_snapshot.get("status") or 0)
        session_error = str(session_snapshot.get("error") or "").strip()
        access_token = str(extract_access_token_from_session_payload(session_payload) or "").strip()
        login_phone_step = _login_phone_step(final_payload, final_continue_url or last_known_url)
        storage_state = await _read_request_context_storage_state(request_ctx)
        final_state_payload = _augment_storage_state_payload(
            storage_state=storage_state,
            session_payload=session_payload,
            session_status=session_status,
            session_error=session_error,
        )
        await asyncio.to_thread(_write_json_file, output_path, final_state_payload)
        summary = extract_session_summary_from_payload(
            session_payload,
            status=int(session_status),
            error_text=session_error,
            updated_at=_iso_now(),
        )
        codex_token_result = await _create_codex_wham_auth_credential(
            request_ctx=request_ctx,
            trace=trace,
            output_path=output_path,
            session_payload=session_payload,
            session_status=session_status,
            session_error=session_error,
            timeout_sec=timeout_sec,
        )
        if access_token:
            completion_success = True
            completion_stage = "done"
            completion_error_code = ""
            completion_step_name = "登录完成"
            success_message = f"HTTP 登录成功：已写入完整登录态（{safe_email}）。"
            log.success(f"【ChatGPT HTTP 登录】登录成功，已写入完整登录态：{safe_email}")
        elif login_phone_step:
            completion_success = False
            completion_stage = "login_phone_required"
            completion_error_code = "phone_required"
            completion_step_name = "等待后期绑定手机号"
            success_message = "邮箱登录已完成，但平台要求绑定手机号；未自动调用接码服务。"
            log.warn("【ChatGPT HTTP 登录】当前停在 add-phone；登录流程未调用接码服务。")
        else:
            completion_success = False
            completion_stage = "login_session_missing"
            completion_error_code = "session_missing"
            completion_step_name = "登录态未建立"
            success_message = "邮箱登录流程已完成，但 Session 未返回 accessToken。"
            log.warn("【ChatGPT HTTP 登录】流程已完成，但完整登录 Session 尚未建立。")
        await _report_http_stage(
            stageReporter,
            stage=completion_stage,
            step_name=completion_step_name,
            current_url=final_continue_url or last_known_url,
        )
        return _build_result(
            success=completion_success,
            stage=completion_stage,
            error_code=completion_error_code,
            message=success_message,
            trace_path=trace.path,
            extra={
                "storageStatePath": output_path,
                "sessionStatus": int(session_status),
                "sessionSummary": dict(summary),
                "accessTokenPresent": bool(access_token),
                "phoneRequired": bool(login_phone_step),
                "codexTokenJsonPath": str(codex_token_result.get("jsonPath") or "").strip(),
                "codexTokenTxtPath": str(codex_token_result.get("txtPath") or "").strip(),
                "codexTokenCreated": bool(codex_token_result.get("ok")),
                "teamWorkspaceSelect": {
                    key: value
                    for key, value in dict(team_workspace_select_result or {}).items()
                    if key != "sessionSnapshot"
                },
            },
        )
    except Exception as error:
        error_text = str(error or "").strip()
        await _report_http_stage(
            stageReporter,
            stage="exception",
            step_name="登录失败",
            current_url=last_known_url,
            error_message=error_text,
        )
        trace.write(
            {
                "ts": _iso_now(),
                "stage": "http_login_exception",
                "error": _compress_debug_text(error_text, limit=320),
            }
        )
        log.error(f"【ChatGPT HTTP 登录】失败：{error_text}")
        return _build_result(
            success=False,
            stage="exception",
            error_code="http_login_failed",
            message=f"HTTP 登录失败：{error_text or 'unknown'}",
            trace_path=trace.path,
            extra={"storageStatePath": output_path},
        )
    finally:
        if request_ctx is not None:
            try:
                await request_ctx.dispose()
            except Exception:
                pass
