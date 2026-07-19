from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import re
import tempfile
import time
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urlencode, urljoin

from chatgpt_api_health import (
    extract_access_token_from_session_payload,
    extract_session_summary_from_payload,
    resolve_proxy_for_url,
)
from chatgpt_login_http import (
    _LogSink,
    _report_http_stage,
    _TraceWriter,
    _augment_storage_state_payload,
    _bootstrap_http_login_session,
    _build_sanitized_http_login_bootstrap_storage_state,
    _compress_debug_text,
    _fetch_session_after_login,
    _iso_now,
    _normalize_state_output_path,
    _open_continue_url,
    _normalize_imap_profiles_payload,
    _poll_imap_code_multi_sync,
    poll_otp_api_url_verification_code_sync,
    _rebuild_request_context_with_storage_state,
    _sanitize_url_for_log,
    _submit_http_otp_if_required,
    _try_http_login_direct_token_exchange_from_continue_url,
    _write_json_file,
)
from managed_mail_otp import poll_managed_mail_verification_code_sync
from codex_oauth import (
    _build_empty_storage_state_payload,
    _build_http_html_headers,
    _build_http_provider_request_context,
    _build_playwright_proxy_option,
    _collect_auth_step_hints,
    _collect_http_sentinel_header_candidates_for_flows,
    _http_sentinel_prefers_fallback_first,
    _extract_auth_error_detail,
    _extract_continue_url,
    _extract_error,
    _is_invalid_authorization_step,
    _is_unknown_parameter_error,
    _mask_email,
    _mask_proxy_url_for_log,
    _read_request_context_storage_state,
    _request_auth_api_with_context,
    _request_json_with_context,
    _request_with_context,
    _resolve_http_provider_curl_impersonate,
    _resolve_request_ctx_impersonate,
)
from http_stage_features import (
    activate_http_stage_feature_session,
    current_http_stage_feature_context,
    get_http_stage_feature_summary,
    random_birth_date,
    random_full_name,
)
from http_phone_verification import (
    acquire_http_phone_candidate,
    acquire_pending_http_phone_candidate,
    blacklist_http_phone,
    dispose_http_phone_after_failure,
    mark_http_phone_completed,
    wait_for_http_phone_code,
)


LogFn = Callable[[str], None]

_SUCCESS_STATUS = {200, 201, 202, 204}
_REGISTER_AUTHORIZE_FLOW = "authorize_continue"
_REGISTER_PASSWORD_FLOW = "username_password_create"
_REGISTER_PROFILE_FLOW = "oauth_create_account"
_WHAM_AUTH_CREDENTIALS_URL = "https://chatgpt.com/backend-api/wham/auth-credentials"
_WHAM_CODEX_SCOPE = "chatgpt.workspace.feature.allow-codex-local-access.access"


@dataclasses.dataclass(frozen=True, slots=True)
class ChatGptHttpRegisterProfile:
    email: str
    password: str
    fullName: str = ""
    birthDate: str = ""


@dataclasses.dataclass(frozen=True, slots=True)
class ChatGptHttpRegisterConfig:
    timeoutSeconds: float = 360.0
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
    useImapOtp: bool = False
    otpTimeoutSeconds: float = 300.0
    otpIntervalSeconds: float = 1.0
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
    phoneVerification: dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass(frozen=True, slots=True)
class ChatGptHttpRegisterResult:
    success: bool
    stage: str
    errorCode: str
    message: str
    details: dict[str, Any] = dataclasses.field(default_factory=dict)


def _env_flag(name: str, default: bool) -> bool:
    raw = str(os.getenv(name, "") or "").strip().lower()
    if not raw:
        return bool(default)
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    return bool(default)


def _prefer_direct_create_account() -> bool:
    return _env_flag("AIO_HTTP_REGISTER_DIRECT_CREATE_ACCOUNT", True)


def _prefer_direct_register_token_exchange() -> bool:
    return _env_flag("AIO_HTTP_REGISTER_DIRECT_TOKEN_EXCHANGE", True)


def _defer_workspace_token_creation() -> bool:
    return _env_flag("AIO_DEFER_WORKSPACE_TOKEN", False)


@dataclasses.dataclass(frozen=True, slots=True)
class _HtmlInputField:
    name: str
    value: str
    input_type: str
    checked: bool = False


@dataclasses.dataclass(frozen=True, slots=True)
class _HtmlFormSnapshot:
    action: str
    method: str
    inputs: tuple[_HtmlInputField, ...]
    submitters: tuple[_HtmlInputField, ...] = ()


class _AboutYouHtmlParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._forms: list[dict[str, Any]] = []
        self._current_form: dict[str, Any] | None = None
        self._in_title = False
        self._title_parts: list[str] = []
        self._body_parts: list[str] = []

    @property
    def forms(self) -> list[dict[str, Any]]:
        return list(self._forms)

    @property
    def title(self) -> str:
        return "".join(self._title_parts).strip()

    @property
    def body_text(self) -> str:
        return " ".join(part.strip() for part in self._body_parts if str(part or "").strip()).strip()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {str(key or "").strip().lower(): str(value or "") for key, value in attrs}
        tag_name = str(tag or "").strip().lower()
        if tag_name == "title":
            self._in_title = True
            return
        if tag_name == "form":
            self._current_form = {
                "action": str(attr_map.get("action") or "").strip(),
                "method": str(attr_map.get("method") or "GET").strip().upper() or "GET",
                "inputs": [],
                "submitters": [],
            }
            return
        if self._current_form is None or tag_name not in {"input", "button"}:
            return
        field_name = str(attr_map.get("name") or "").strip()
        if not field_name:
            return
        input_type = str(
            attr_map.get("type") or ("submit" if tag_name == "button" else "text")
        ).strip().lower() or "text"
        field = _HtmlInputField(
            name=field_name,
            value=str(attr_map.get("value") or ""),
            input_type=input_type,
            checked="checked" in attr_map,
        )
        target = "submitters" if tag_name == "button" and input_type == "submit" else "inputs"
        self._current_form[target].append(field)

    def handle_endtag(self, tag: str) -> None:
        tag_name = str(tag or "").strip().lower()
        if tag_name == "title":
            self._in_title = False
            return
        if tag_name == "form" and self._current_form is not None:
            self._forms.append(dict(self._current_form))
            self._current_form = None

    def handle_data(self, data: str) -> None:
        text = str(data or "")
        if not text.strip():
            return
        if self._in_title:
            self._title_parts.append(text)
            return
        self._body_parts.append(text)


def _noop_log(_: str) -> None:
    return None


def _build_result(
    *,
    success: bool,
    stage: str,
    error_code: str,
    message: str,
    trace_path: str,
    extra: Optional[dict[str, Any]] = None,
) -> ChatGptHttpRegisterResult:
    details: dict[str, Any] = {}
    if trace_path:
        details["tracePath"] = str(trace_path)
    if isinstance(extra, dict):
        details.update(extra)
    return ChatGptHttpRegisterResult(
        success=bool(success),
        stage=str(stage or ""),
        errorCode=str(error_code or ""),
        message=str(message or ""),
        details=details,
    )


def _session_snapshot_path_for_storage_state(output_path: str) -> str:
    storage_path = Path(str(output_path or "")).expanduser()
    if not storage_path.name:
        return ""
    try:
        resolved = storage_path.resolve()
    except Exception:
        resolved = storage_path
    root = resolved.parent.parent if resolved.parent.name else resolved.parent
    return str(root / "登录态session" / resolved.name)


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


def _write_auth_session_snapshot(
    *,
    output_path: str,
    session_payload: dict[str, Any],
    session_status: int,
    session_error: str,
    source: str,
) -> str:
    if not isinstance(session_payload, dict) or not session_payload:
        return ""
    target = _session_snapshot_path_for_storage_state(output_path)
    if not target:
        return ""
    access_token = str(extract_access_token_from_session_payload(session_payload) or "").strip()
    summary = extract_session_summary_from_payload(
        session_payload,
        status=int(session_status or 0),
        error_text=str(session_error or "").strip(),
        updated_at=_iso_now(),
    )
    payload = {
        "type": "chatgpt_auth_session_snapshot",
        "source": str(source or "").strip() or "https://chatgpt.com/api/auth/session",
        "status": int(session_status or 0),
        "error": str(session_error or "").strip(),
        "updated_at": _iso_now(),
        "accessTokenPresent": bool(access_token),
        "accessTokenLen": len(access_token),
        "sessionSummary": dict(summary),
        "session": dict(session_payload),
    }
    _write_json_file(target, payload)
    return target


def _write_text_file(path: str, text: str) -> None:
    target = Path(str(path or "")).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(str(text or ""), encoding="utf-8")


def _first_non_empty_string(*values: Any) -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


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

    def _walk(value: Any) -> str:
        if isinstance(value, dict):
            structure = str(value.get("structure") or "").strip().lower()
            if structure in {"workspace", "team", "org", "organization", "personal"}:
                candidate = _first_non_empty_string(
                    value.get("id"),
                    value.get("account_id"),
                    value.get("workspace_id"),
                    value.get("workspaceId"),
                )
                if candidate:
                    return candidate
            for child in value.values():
                found = _walk(child)
                if found:
                    return found
        elif isinstance(value, list):
            for child in value:
                found = _walk(child)
                if found:
                    return found
        return ""

    return _walk(session_payload)


def _write_codex_token_result(
    *,
    output_path: str,
    status: int,
    account_id: str,
    response_payload: dict[str, Any],
    response_text: str,
    error: str,
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
    return {
        "ok": bool(codex_token and 200 <= int(status or 0) < 300),
        "error": str(error or "").strip(),
        "status": int(status or 0),
        "jsonPath": json_path,
        "txtPath": txt_path if codex_token else "",
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
        )
        trace.write(
            {
                "ts": _iso_now(),
                "stage": "http_register_codex_token_skipped",
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
    )
    trace.write(
        {
            "ts": _iso_now(),
            "stage": "http_register_codex_token_create",
            "status": int(status or 0),
            "ok": bool(result.get("ok")),
            "accountId": account_id,
            "credentialId": str((payload or {}).get("credential_id") or "").strip() if isinstance(payload, dict) else "",
            "accessTokenLen": int(result.get("accessTokenLen") or 0),
            "jsonPath": str(result.get("jsonPath") or ""),
            "txtPath": str(result.get("txtPath") or ""),
            "responseUrl": _sanitize_url_for_log(response_url),
            "error": _compress_debug_text(error, limit=240),
            "responseTextLen": len(str(text or "")),
            "responseAccessTokenPresent": bool((payload or {}).get("access_token")) if isinstance(payload, dict) else False,
            "headerKeys": sorted(list((response_headers or {}).keys()))[:20],
        }
    )
    return dict(result)


def _resolve_profile_name_birthday(profile: ChatGptHttpRegisterProfile) -> tuple[str, str]:
    """名字/生日来源优先级：CLI 显式传入 > 当前邮箱的随机指纹 profile（每邮箱独立、加权自然分布）。

    不再回退到固定的 "Alex Walker"/"2000-06-15"——批量起号若所有号都同名同生日，
    既不真实又是明显的批量特征。CLI 默认值已改为空，未显式指定时一律取随机 profile 名。
    """
    full_name = str(profile.fullName or "").strip()
    birth_date = str(profile.birthDate or "").strip()
    if full_name and birth_date:
        return full_name, birth_date
    # 从激活的 http_stage_feature 会话取随机名/生日（run 流程开头已激活）
    ctx = current_http_stage_feature_context()
    feat = ctx.profile if ctx is not None else {}
    if not full_name:
        full_name = str(feat.get("fullName") or "").strip()
    if not birth_date:
        birth_date = str(feat.get("birthDate") or "").strip()
    # 最终兜底：profile 缺字段（跨版本旧缓存）时也绝不返回空名，生成随机真人名/生日。
    if not full_name:
        full_name = random_full_name()
    if not birth_date:
        birth_date = random_birth_date()
    return full_name, birth_date


def _extract_auth_page_type(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ""
    page_payload = payload.get("page")
    if not isinstance(page_payload, dict):
        return ""
    return str(page_payload.get("type") or "").strip().lower()


def _extract_auth_page_payload(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    page_payload = payload.get("page")
    if not isinstance(page_payload, dict):
        return {}
    nested_payload = page_payload.get("payload")
    return dict(nested_payload) if isinstance(nested_payload, dict) else {}


def _payload_points_to_about_you(payload: Any) -> bool:
    continue_url = str(_extract_continue_url(payload) or "").strip().lower()
    page_type = _extract_auth_page_type(payload)
    return page_type == "about_you" or "/about-you" in continue_url


def _payload_points_to_password_step(payload: Any) -> bool:
    continue_url = str(_extract_continue_url(payload) or "").strip().lower()
    page_type = _extract_auth_page_type(payload)
    page_payload = _extract_auth_page_payload(payload)
    verification_mode = str(page_payload.get("email_verification_mode") or "").strip().lower()
    if page_type == "email_otp_verification" and verification_mode == "passwordless_login":
        return False
    return page_type in {"signup_password", "login_password"} or any(
        marker in continue_url
        for marker in (
            "/create-account/password",
            "/log-in/password",
            "/password",
        )
    )


def _register_password_submission_mode(payload: Any, continue_url: str = "") -> str:
    if _payload_points_to_password_step(payload):
        return "signup_password_step"
    normalized_continue_url = str(continue_url or _extract_continue_url(payload) or "").strip().lower()
    if _payload_points_to_about_you(payload) or "/about-you" in normalized_continue_url:
        return "post_otp_about_you_recovery"
    return ""


def _register_password_response_accepted(response: Any) -> bool:
    if not isinstance(response, dict):
        return False
    return (
        int(response.get("status") or 0) in _SUCCESS_STATUS
        and not str(response.get("errorCode") or "").strip()
        and not str(response.get("errorMessage") or "").strip()
    )


def _build_after_page_payload(*, url: str) -> dict[str, Any]:
    normalized_url = str(url or "").strip()
    lowered_url = normalized_url.lower()
    payload: dict[str, Any] = {}
    if normalized_url and "/about-you" not in lowered_url:
        payload["continue_url"] = normalized_url
    page_type = ""
    if "/log-in/password" in lowered_url:
        page_type = "login_password"
    elif "email-verification" in lowered_url:
        page_type = "email_otp_verification"
    if page_type:
        payload["page"] = {"type": page_type}
    return payload


def _response_looks_blocked(*, status: int, response_url: str, text: str) -> bool:
    merged = "\n".join([str(response_url or ""), str(text or "")]).lower()
    return int(status or 0) >= 429 or any(
        marker in merged
        for marker in (
            "just a moment",
            "attention required",
            "cf_chl",
            "cloudflare",
            "verify you are human",
            "captcha",
        )
    )


def _parse_about_you_html(*, url: str, html_text: str) -> tuple[str, str, _HtmlFormSnapshot | None]:
    parser = _AboutYouHtmlParser()
    try:
        parser.feed(str(html_text or ""))
        parser.close()
    except Exception:
        return "", "", None
    selected_form: _HtmlFormSnapshot | None = None
    for preferred_names in (
        {"new-password", "confirm-password"},
        {"code"},
        {"name", "birthday"},
    ):
        for form in parser.forms:
            inputs = tuple(form.get("inputs") or ())
            input_names = {str(item.name or "").strip().lower() for item in inputs}
            if input_names.intersection(preferred_names):
                selected_form = _HtmlFormSnapshot(
                    action=str(form.get("action") or "").strip(),
                    method=str(form.get("method") or "GET").strip().upper() or "GET",
                    inputs=inputs,
                    submitters=tuple(form.get("submitters") or ()),
                )
                break
        if selected_form is not None:
            break
    if selected_form is None and parser.forms:
        first = parser.forms[0]
        selected_form = _HtmlFormSnapshot(
            action=str(first.get("action") or "").strip(),
            method=str(first.get("method") or "GET").strip().upper() or "GET",
            inputs=tuple(first.get("inputs") or ()),
            submitters=tuple(first.get("submitters") or ()),
        )
    return parser.title, parser.body_text, selected_form


def _looks_like_about_you_page(*, url: str, title: str, body_text: str, form: _HtmlFormSnapshot | None) -> bool:
    normalized_url = str(url or "").strip().lower()
    normalized_title = str(title or "").strip().lower()
    normalized_body = str(body_text or "").strip().lower()
    if "/about-you" in normalized_url:
        return True
    if form is not None:
        field_names = {str(item.name or "").strip().lower() for item in form.inputs}
        if "name" in field_names and ("birthday" in field_names or "finish creating account" in normalized_body):
            return True
    return (
        "finish creating account" in normalized_title
        or "finish creating account" in normalized_body
        or "confirm your age" in normalized_title
        or "confirm your age" in normalized_body
    )


def _build_about_you_form_body(*, form: _HtmlFormSnapshot, full_name: str, birthdate: str) -> str:
    year_text, month_text, day_text = "", "", ""
    parts = str(birthdate or "").strip().split("-")
    if len(parts) == 3:
        year_text, month_text, day_text = parts
    birthdate_slash = str(birthdate or "").replace("-", "/")
    fields: list[tuple[str, str]] = []
    seen_names: set[str] = set()
    for item in form.inputs:
        name = str(item.name or "").strip()
        if not name:
            continue
        lowered_name = name.lower()
        value = str(item.value or "")
        if item.input_type in {"checkbox", "radio"} and not item.checked:
            continue
        if lowered_name == "name":
            value = str(full_name or "")
        elif lowered_name == "birthday":
            value = str(birthdate or "")
        elif ("birth" in lowered_name) and any(part in lowered_name for part in ("year", "yyyy")):
            value = year_text
        elif ("birth" in lowered_name) and "month" in lowered_name:
            value = month_text
        elif ("birth" in lowered_name) and "day" in lowered_name:
            value = day_text
        elif ("birth" in lowered_name) and item.input_type == "date":
            value = str(birthdate or "")
        elif ("birth" in lowered_name) and item.input_type != "hidden":
            value = birthdate_slash
        fields.append((name, value))
        seen_names.add(lowered_name)
    if "name" not in seen_names:
        fields.append(("name", str(full_name or "")))
    if "birthday" not in seen_names:
        fields.append(("birthday", str(birthdate or "")))
    return urlencode(fields, doseq=True)


async def _request_html_page(
    *,
    request_ctx: Any,
    stage: str,
    url: str,
    trace: _TraceWriter,
    timeout_ms: int,
    method: str = "GET",
    referer_url: str = "",
    body_text: str = "",
    trace_body_text: str | None = None,
    max_redirects: int = 5,
    extra_headers: Optional[dict[str, str]] = None,
) -> dict[str, Any]:
    method_text = str(method or "GET").strip().upper() or "GET"
    target_url = str(url or "").strip()
    headers = _build_http_html_headers(impersonate=_resolve_request_ctx_impersonate(request_ctx))
    if referer_url:
        headers["referer"] = str(referer_url or "").strip()
    if method_text == "POST":
        headers["content-type"] = "application/x-www-form-urlencoded"
        headers["origin"] = "https://auth.openai.com"
        headers["cache-control"] = "max-age=0"
        headers["sec-fetch-dest"] = "document"
        headers["sec-fetch-mode"] = "navigate"
        headers["sec-fetch-site"] = "same-origin"
        headers["upgrade-insecure-requests"] = "1"
    if isinstance(extra_headers, dict):
        for key, value in extra_headers.items():
            if value in (None, ""):
                continue
            headers[str(key)] = str(value)
    trace.write(
        {
            "ts": _iso_now(),
            "stage": stage,
            "method": method_text,
            "url": _sanitize_url_for_log(target_url),
            "requestBody": _compress_debug_text(
                body_text if trace_body_text is None else trace_body_text,
                limit=320,
            ),
        }
    )
    payload, status, text, response_url, response_headers = await _request_with_context(
        request_ctx,
        method=method_text,
        url=target_url,
        headers=headers,
        body_text=body_text,
        timeout_ms=timeout_ms,
        max_redirects=max_redirects,
    )
    trace.write(
        {
            "ts": _iso_now(),
            "stage": stage,
            "status": int(status),
            "responseUrl": _sanitize_url_for_log(response_url),
            "location": _sanitize_url_for_log(str(response_headers.get("location") or "").strip()),
            "bodySnippet": _compress_debug_text(text, limit=400),
        }
    )
    return {
        "status": int(status),
        "text": str(text or ""),
        "payload": payload if isinstance(payload, dict) else {},
        "url": str(response_url or target_url).strip(),
        "headers": dict(response_headers or {}),
    }


def _select_html_form_submitter(
    form: _HtmlFormSnapshot,
    *,
    preferred_values: Optional[set[str]] = None,
) -> _HtmlInputField | None:
    submitters = list(form.submitters or ())
    if not submitters:
        return None
    preferred = {
        str(value or "").strip().lower()
        for value in (preferred_values or set())
        if str(value or "").strip()
    }
    if preferred:
        for item in submitters:
            value = str(item.value or "").strip().lower()
            name = str(item.name or "").strip().lower()
            if value in preferred or name in preferred:
                return item
    for item in submitters:
        value = str(item.value or "").strip().lower()
        if value and value != "resend":
            return item
    return submitters[0]


def _build_html_form_body(
    *,
    form: _HtmlFormSnapshot,
    overrides: dict[str, str],
    preferred_submit_values: Optional[set[str]] = None,
) -> str:
    fields: list[tuple[str, str]] = []
    seen: set[str] = set()
    normalized_overrides = {str(key): str(value) for key, value in overrides.items()}
    for item in form.inputs:
        name = str(item.name or "").strip()
        if not name:
            continue
        if item.input_type in {"button", "submit", "reset", "file"}:
            continue
        if item.input_type in {"checkbox", "radio"} and not item.checked:
            continue
        fields.append((name, normalized_overrides.get(name, str(item.value or ""))))
        seen.add(name)
    submitter = _select_html_form_submitter(
        form,
        preferred_values=preferred_submit_values,
    )
    if submitter is not None:
        name = str(submitter.name or "").strip()
        if name and name not in seen:
            fields.append(
                (
                    name,
                    normalized_overrides.get(name, str(submitter.value or "")),
                )
            )
            seen.add(name)
    for name, value in normalized_overrides.items():
        if name not in seen:
            fields.append((name, value))
    return urlencode(fields, doseq=True)


async def _read_password_reset_otp_code(
    *,
    email: str,
    config: ChatGptHttpRegisterConfig,
    log: _LogSink,
    not_before_ts: float,
    blocked_codes: Optional[set[str]] = None,
) -> str:
    blocked_codes = {str(value) for value in (blocked_codes or set()) if str(value)}
    if (
        bool(config.useManagedMailOtp)
        and str(config.managedMailJwt or "").strip()
        and str(config.managedMailApiBase or "").strip()
    ):
        return str(
            await asyncio.to_thread(
                poll_managed_mail_verification_code_sync,
                email=email,
                mail_provider=str(config.managedMailProvider or "").strip(),
                mail_jwt=str(config.managedMailJwt or "").strip(),
                mail_api_base=str(config.managedMailApiBase or "").strip(),
                mail_frontend_base=str(config.managedMailFrontendBase or "").strip(),
                otp_timeout_sec=float(config.otpTimeoutSeconds or 300.0),
                otp_interval_sec=float(config.otpIntervalSeconds or 2.0),
                blocked_codes=blocked_codes,
                not_before_ts=float(not_before_ts),
                latest_n=int(config.managedMailLatestN or 20),
                log_info=log.info,
                log_warn=log.warn,
            )
            or ""
        ).strip()
    if str(config.otpApiUrl or "").strip():
        return str(
            await asyncio.to_thread(
                poll_otp_api_url_verification_code_sync,
                email=email,
                otp_api_url=str(config.otpApiUrl or "").strip(),
                otp_timeout_sec=float(config.otpTimeoutSeconds or 300.0),
                otp_interval_sec=float(config.otpIntervalSeconds or 2.0),
                blocked_codes=blocked_codes,
                not_before_ts=float(not_before_ts),
                log_info=log.info,
                log_warn=log.warn,
            )
            or ""
        ).strip()
    imap_profiles = _normalize_imap_profiles_payload(
        "",
        fallback_host=str(config.imapHost or "imap.2925.com").strip() or "imap.2925.com",
        fallback_port=int(config.imapPort or 993),
        fallback_user=str(config.imapUser or "").strip(),
        fallback_pass=str(config.imapPass or ""),
        fallback_folder=str(config.imapFolder or "Inbox").strip() or "Inbox",
        fallback_latest_n=int(config.imapLatestN or 80),
        fallback_auth_type=str(config.imapAuthType or "password").strip() or "password",
        fallback_oauth_client_id=str(config.imapOauthClientId or "").strip(),
        fallback_oauth_refresh_token=str(config.imapOauthRefreshToken or "").strip(),
        fallback_password_fallback=bool(config.imapPasswordFallback),
        fallback_pop3_fallback=bool(config.imapPop3Fallback),
    )
    if bool(config.useImapOtp) and imap_profiles:
        return str(
            await asyncio.to_thread(
                _poll_imap_code_multi_sync,
                email=email,
                otp_timeout_sec=float(config.otpTimeoutSeconds or 300.0),
                otp_interval_sec=float(config.otpIntervalSeconds or 2.0),
                imap_profiles=imap_profiles,
                blocked_codes=blocked_codes,
                not_before_ts=float(not_before_ts),
                log=log,
                loop=asyncio.get_running_loop(),
            )
            or ""
        ).strip()
    raise RuntimeError("password_reset_otp_unavailable: 没有可用的邮箱验证码读取方式")


async def set_chatgpt_password_via_reset_flow(
    *,
    profile: ChatGptHttpRegisterProfile,
    config: ChatGptHttpRegisterConfig,
    logInfo: Optional[LogFn] = None,
    logWarn: Optional[LogFn] = None,
    logError: Optional[LogFn] = None,
) -> dict[str, Any]:
    email = str(profile.email or "").strip().lower()
    password = str(profile.password or "")
    state_path = _normalize_state_output_path(str(config.storageStatePath or "").strip(), email)
    if not email or not password:
        return {"ok": False, "stage": "validate", "errorCode": "missing_credentials"}
    try:
        storage_state = json.loads(Path(state_path).read_text(encoding="utf-8"))
    except Exception as error:
        return {
            "ok": False,
            "stage": "load_state",
            "errorCode": "storage_state_missing",
            "errorMessage": str(error),
        }
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
    request_ctx = None
    timeout_sec = max(60.0, min(float(config.timeoutSeconds or 360.0), 900.0))
    try:
        request_ctx = await asyncio.to_thread(
            _build_http_provider_request_context,
            storage_state=storage_state,
            proxy_url=str(config.proxyUrl or "").strip(),
            impersonate=_resolve_http_provider_curl_impersonate(),
        )
        blocked_otp_codes: set[str] = set()
        try:
            previous_code = await _read_password_reset_otp_code(
                email=email,
                config=dataclasses.replace(config, otpTimeoutSeconds=3.0, otpIntervalSeconds=1.0),
                log=log,
                not_before_ts=0.0,
            )
            if previous_code:
                blocked_otp_codes.add(previous_code)
        except Exception:
            pass
        otp_sent_at = time.time()
        boot_info = await _bootstrap_http_login_session(
            request_ctx=request_ctx,
            trace=trace,
            timeout_ms=int(min(timeout_sec * 1000.0, 60_000)),
            authorization_params={
                "post_login_add_password": "true",
                "login_hint": email,
            },
        )
        verification_page = await _request_html_page(
            request_ctx=request_ctx,
            stage="http_password_add_verification_page",
            url=str(boot_info.get("loginUrl") or "https://auth.openai.com/email-verification"),
            trace=trace,
            timeout_ms=int(min(timeout_sec * 1000.0, 60_000)),
            referer_url="https://chatgpt.com/",
            max_redirects=6,
        )
        verification_url = str(verification_page.get("url") or "")
        if "/error" in verification_url.lower():
            detail = _extract_auth_error_detail(verification_url)
            raise RuntimeError(
                f"password_add_bootstrap_failed: {detail or '添加密码授权入口返回错误页'}"
            )
        _, _, verification_form = _parse_about_you_html(
            url=verification_url,
            html_text=str(verification_page.get("text") or ""),
        )
        if "/email-verification" not in verification_url.lower() or not isinstance(
            verification_form, _HtmlFormSnapshot
        ):
            raise RuntimeError("password_add_otp_form_missing: 未进入添加密码的邮箱验证码页面")

        # Live auth.openai.com email-verification is an SPA.  POSTing the HTML form
        # to /email-verification for OTP validation returns HTTP 500; validate via the
        # accounts API.  HTML POST is still used for intent=resend only.
        max_otp_attempts = 3
        last_otp_error = ""
        continue_url = ""
        otp_validate_status = 0
        otp_validate_payload: dict[str, Any] = {}
        for otp_attempt in range(1, max_otp_attempts + 1):
            if otp_attempt > 1:
                resend_started = time.time()
                log.info(
                    f"补设密码：重新发送邮箱验证码（attempt={otp_attempt}/{max_otp_attempts}）。"
                )
                resend_ok = False
                for resend_path, resend_method in (
                    ("/email-otp/resend", "POST"),
                    ("/email-otp/send", "GET"),
                ):
                    send_res = await _request_auth_api_with_context(
                        request_ctx,
                        stage=f"http_password_reset_otp_resend_{otp_attempt}_{resend_path.strip('/').replace('/', '_')}",
                        path=resend_path,
                        method=resend_method,
                        timeout_ms=int(min(timeout_sec * 1000.0, 60_000)),
                        trace=trace,
                        referer_url=verification_url or "https://auth.openai.com/email-verification",
                        accept="application/json",
                        include_json_content_type=True,
                        json_body={},
                    )
                    send_status = int(send_res.get("status") or 0)
                    send_payload = (
                        send_res.get("payload")
                        if isinstance(send_res.get("payload"), dict)
                        else {}
                    )
                    send_continue = str(_extract_continue_url(send_payload) or "").strip()
                    if send_continue:
                        verification_url = send_continue
                    if send_status in _SUCCESS_STATUS:
                        resend_ok = True
                        break
                if not resend_ok:
                    resend_page = await _request_html_page(
                        request_ctx=request_ctx,
                        stage=f"http_password_reset_otp_html_resend_{otp_attempt}",
                        url=urljoin(
                            verification_url or "https://auth.openai.com/email-verification",
                            "/email-verification",
                        ),
                        trace=trace,
                        timeout_ms=int(min(timeout_sec * 1000.0, 60_000)),
                        method="POST",
                        referer_url=verification_url or "https://auth.openai.com/email-verification",
                        body_text=urlencode({"intent": "resend"}),
                        trace_body_text="intent=resend",
                        max_redirects=6,
                    )
                    resend_status = int(resend_page.get("status") or 0)
                    resend_url = str(resend_page.get("url") or "")
                    if resend_status < 500 and "/error" not in resend_url.lower():
                        resend_ok = True
                        if resend_url:
                            verification_url = resend_url
                if not resend_ok:
                    last_otp_error = "password_reset_otp_resend_failed"
                    continue
                otp_sent_at = resend_started

            otp_code = await _read_password_reset_otp_code(
                email=email,
                config=config,
                log=log,
                not_before_ts=max(0.0, otp_sent_at - 3.0),
                blocked_codes=blocked_otp_codes,
            )
            if not re.fullmatch(r"\d{6}", otp_code):
                last_otp_error = "password_reset_otp_invalid: 未读取到有效的六位邮箱验证码"
                continue

            otp_validate_res = await _request_auth_api_with_context(
                request_ctx,
                stage=f"http_password_reset_verify_otp_{otp_attempt}",
                path="/email-otp/validate",
                method="POST",
                timeout_ms=int(min(timeout_sec * 1000.0, 60_000)),
                trace=trace,
                referer_url=verification_url or "https://auth.openai.com/email-verification",
                json_body={"code": otp_code},
                trace_json_body={"code": "***"},
            )
            otp_validate_status = int(otp_validate_res.get("status") or 0)
            otp_validate_payload = (
                otp_validate_res.get("payload")
                if isinstance(otp_validate_res.get("payload"), dict)
                else {}
            )
            otp_validate_text = str(otp_validate_res.get("text") or "")
            otp_error_code, otp_error_message = _extract_error(
                otp_validate_payload,
                otp_validate_text,
            )
            if otp_validate_status in _SUCCESS_STATUS and not otp_error_code and not otp_error_message:
                continue_url = str(_extract_continue_url(otp_validate_payload) or "").strip()
                break

            detail = str(
                otp_error_message
                or otp_error_code
                or f"HTTP {otp_validate_status}"
            ).strip()
            last_otp_error = detail
            low = f"{otp_error_code}\n{otp_error_message}\n{otp_validate_text}".lower()
            if otp_validate_status == 429 or any(
                marker in low
                for marker in (
                    "max_check_attempts",
                    "too many tries",
                    "too many attempts",
                    "rate limit",
                )
            ):
                raise RuntimeError(
                    f"password_reset_otp_cooldown: 邮箱验证码尝试次数已达上限：{detail}"
                )
            if (otp_validate_status == 401) or any(
                marker in low
                for marker in (
                    "wrong_email_otp_code",
                    "invalid_code",
                    "incorrect code",
                    "wrong code",
                )
            ):
                blocked_otp_codes.add(str(otp_code))
                last_otp_error = f"password_reset_otp_invalid: {detail}"
                continue
            raise RuntimeError(f"password_reset_otp_failed: {detail}")
        else:
            raise RuntimeError(
                last_otp_error
                or "password_reset_otp_invalid: 未读取到有效的六位邮箱验证码"
            )
        if not continue_url and otp_validate_status not in _SUCCESS_STATUS:
            raise RuntimeError(
                last_otp_error or f"password_reset_otp_failed: HTTP {otp_validate_status}"
            )
        page_type = ""
        page_obj = otp_validate_payload.get("page")
        if isinstance(page_obj, dict):
            page_type = str(page_obj.get("type") or "").strip().lower().replace("-", "_")
        new_password_url = str(continue_url or "").strip()
        if new_password_url:
            opened_url, _opened_text = await _open_continue_url(
                request_ctx=request_ctx,
                continue_url=new_password_url,
                trace=trace,
                timeout_ms=int(min(timeout_sec * 1000.0, 60_000)),
                stage_name="http_password_reset_otp_continue",
            )
            if opened_url:
                new_password_url = opened_url
        if not new_password_url:
            if page_type in {
                "new_password",
                "reset_password",
                "reset_password_new_password",
                "create_password",
            }:
                new_password_url = "https://auth.openai.com/reset-password/new-password"
            else:
                raise RuntimeError(
                    "password_reset_new_password_form_missing: "
                    f"OTP 验证后未进入新密码页面（HTTP {otp_validate_status}，"
                    f"URL={_sanitize_url_for_log(continue_url)}"
                    f"{f'，page={page_type}' if page_type else ''}）"
                )
        # Live add-password page is also an SPA.  HTML form POST to
        # /reset-password/new-password returns HTTP 500; submit via accounts API.
        password_add_res = await _request_auth_api_with_context(
            request_ctx,
            stage="http_password_reset_submit",
            path="/password/add",
            method="POST",
            timeout_ms=int(min(timeout_sec * 1000.0, 60_000)),
            trace=trace,
            referer_url=new_password_url or "https://auth.openai.com/reset-password/new-password",
            json_body={"password": password},
            trace_json_body={"password": "***"},
        )
        password_add_status = int(password_add_res.get("status") or 0)
        password_add_payload = (
            password_add_res.get("payload")
            if isinstance(password_add_res.get("payload"), dict)
            else {}
        )
        password_add_text = str(password_add_res.get("text") or "")
        password_error_code, password_error_message = _extract_error(
            password_add_payload,
            password_add_text,
        )
        final_url = str(_extract_continue_url(password_add_payload) or "").strip()
        password_already_set = False
        if password_add_status not in _SUCCESS_STATUS or password_error_code or password_error_message:
            detail = str(
                password_error_message
                or password_error_code
                or f"HTTP {password_add_status}"
            ).strip()
            low = f"{password_error_code}\n{password_error_message}\n{password_add_text}".lower()
            if "/mfa-challenge" in f"{final_url}\n{password_add_text}".lower():
                raise RuntimeError("password_reset_mfa_required: 补密码发生在 2FA 已启用之后")
            if any(
                marker in low
                for marker in (
                    "already have a password",
                    "password already",
                    "already_set",
                    "password_already_exists",
                )
            ):
                # A previous successful /password/add left the account with credentials.
                # Treat this as remote password readiness rather than a hard failure.
                password_already_set = True
                log.info("远端已存在密码，按补设成功处理并继续刷新登录态。")
            else:
                # Some sessions require password/reset instead of password/add.
                password_reset_res = await _request_auth_api_with_context(
                    request_ctx,
                    stage="http_password_reset_submit_fallback",
                    path="/password/reset",
                    method="POST",
                    timeout_ms=int(min(timeout_sec * 1000.0, 60_000)),
                    trace=trace,
                    referer_url=new_password_url or "https://auth.openai.com/reset-password/new-password",
                    json_body={"password": password},
                    trace_json_body={"password": "***"},
                )
                password_reset_status = int(password_reset_res.get("status") or 0)
                password_reset_payload = (
                    password_reset_res.get("payload")
                    if isinstance(password_reset_res.get("payload"), dict)
                    else {}
                )
                password_reset_text = str(password_reset_res.get("text") or "")
                reset_error_code, reset_error_message = _extract_error(
                    password_reset_payload,
                    password_reset_text,
                )
                if (
                    password_reset_status in _SUCCESS_STATUS
                    and not reset_error_code
                    and not reset_error_message
                ):
                    password_add_payload = password_reset_payload
                    final_url = str(_extract_continue_url(password_reset_payload) or "").strip()
                else:
                    raise RuntimeError(f"password_reset_rejected: 远端未接受新密码（{detail}）")
        if password_already_set and not final_url:
            final_url = "https://chatgpt.com/"
        if final_url:
            opened_final_url, _opened_final_text = await _open_continue_url(
                request_ctx=request_ctx,
                continue_url=final_url,
                trace=trace,
                timeout_ms=int(min(timeout_sec * 1000.0, 60_000)),
                stage_name="http_password_reset_submit_continue",
            )
            if opened_final_url:
                final_url = opened_final_url
        if "/mfa-challenge" in str(final_url or "").lower():
            raise RuntimeError("password_reset_mfa_required: 补密码发生在 2FA 已启用之后")
        if "/reset-password/new-password" in str(final_url or "").lower():
            raise RuntimeError(
                "password_reset_rejected: 远端未接受新密码（仍停留在 new-password 页面）"
            )
        updated_state = await _read_request_context_storage_state(request_ctx)
        try:
            session_snapshot = await _fetch_session_after_login(
                request_ctx=request_ctx,
                trace=trace,
                timeout_ms=int(min(timeout_sec * 1000.0, 60_000)),
            )
            session_payload = (
                session_snapshot.get("payload")
                if isinstance(session_snapshot.get("payload"), dict)
                else {}
            )
            updated_state = _augment_storage_state_payload(
                storage_state=updated_state,
                session_payload=session_payload,
                session_status=int(session_snapshot.get("status") or 0),
                session_error=str(session_snapshot.get("error") or ""),
            )
        except Exception as error:
            log.warn(f"密码已设置，但刷新 Session 失败：{error}")
        await asyncio.to_thread(_write_json_file, state_path, updated_state)
        return {
            "ok": True,
            "stage": "password_reset_complete",
            "storageStatePath": state_path,
            "remotePasswordSet": True,
            "remotePasswordMode": "post_registration_password_reset",
            "finalUrl": _sanitize_url_for_log(final_url),
        }
    except Exception as error:
        error_text = str(error or "").strip()
        error_code = "password_reset_failed"
        if ":" in error_text:
            error_code = str(error_text.split(":", 1)[0] or error_code).strip()
        log.error(f"注册后补设密码失败：{error_text}")
        return {
            "ok": False,
            "stage": "set_password",
            "errorCode": error_code,
            "errorMessage": error_text,
            "storageStatePath": state_path,
            "remotePasswordSet": False,
            "remotePasswordMode": "post_registration_password_reset",
        }
    finally:
        if request_ctx is not None:
            try:
                await request_ctx.dispose()
            except Exception:
                pass


async def _load_about_you_form(
    *,
    request_ctx: Any,
    continue_url: str,
    trace: _TraceWriter,
    timeout_ms: int,
) -> dict[str, Any]:
    page_res = await _request_html_page(
        request_ctx=request_ctx,
        stage="http_register_about_you_page",
        url=str(continue_url or "").strip() or "https://auth.openai.com/about-you",
        trace=trace,
        timeout_ms=timeout_ms,
        method="GET",
        referer_url="https://auth.openai.com/about-you",
        max_redirects=6,
    )
    title, body_text, form = _parse_about_you_html(url=str(page_res.get("url") or ""), html_text=str(page_res.get("text") or ""))
    looks_like = _looks_like_about_you_page(
        url=str(page_res.get("url") or ""),
        title=title,
        body_text=body_text,
        form=form,
    )
    trace.write(
        {
            "ts": _iso_now(),
            "stage": "http_register_about_you_page_parsed",
            "responseUrl": _sanitize_url_for_log(str(page_res.get("url") or "")),
            "looksLikeAboutYou": bool(looks_like),
            "formAction": str(form.action or "") if form is not None else "",
            "formMethod": str(form.method or "") if form is not None else "",
            "inputNames": [str(item.name or "") for item in (form.inputs if form is not None else ())][:20],
            "title": _compress_debug_text(title, limit=120),
        }
    )
    return {
        **page_res,
        "title": title,
        "bodyText": body_text,
        "form": form,
        "looksLikeAboutYou": bool(looks_like),
    }


async def _submit_about_you_form_http(
    *,
    request_ctx: Any,
    continue_url: str,
    full_name: str,
    birthdate: str,
    trace: _TraceWriter,
    timeout_ms: int,
) -> dict[str, Any]:
    loaded = await _load_about_you_form(
        request_ctx=request_ctx,
        continue_url=continue_url,
        trace=trace,
        timeout_ms=timeout_ms,
    )
    response_url = str(loaded.get("url") or "").strip()
    response_text = str(loaded.get("text") or "")
    if _response_looks_blocked(
        status=int(loaded.get("status") or 0),
        response_url=response_url,
        text=response_text,
    ):
        return {
            "attempted": False,
            "ok": False,
            "reason": "challenge_blocked",
            "afterUrl": response_url,
            "afterPayload": {},
        }
    if not bool(loaded.get("looksLikeAboutYou")):
        payload = _build_after_page_payload(url=response_url)
        already_advanced = bool(payload) or (response_url and "/about-you" not in response_url.lower())
        return {
            "attempted": False,
            "ok": bool(already_advanced),
            "reason": "already_advanced" if already_advanced else "about_you_page_missing",
            "afterUrl": response_url,
            "afterPayload": payload,
        }
    form = loaded.get("form")
    if not isinstance(form, _HtmlFormSnapshot):
        return {
            "attempted": False,
            "ok": False,
            "reason": "form_missing",
            "afterUrl": response_url,
            "afterPayload": {},
        }
    method_text = str(form.method or "POST").strip().upper() or "POST"
    action_url = str(urljoin(response_url or continue_url, str(form.action or "").strip() or response_url or continue_url)).strip()
    body_text = _build_about_you_form_body(form=form, full_name=full_name, birthdate=birthdate)
    if method_text == "GET":
        separator = "&" if "?" in action_url else "?"
        submit_url = f"{action_url}{separator}{body_text}" if body_text else action_url
        submit_res = await _request_html_page(
            request_ctx=request_ctx,
            stage="http_register_about_you_submit",
            url=submit_url,
            trace=trace,
            timeout_ms=timeout_ms,
            method="GET",
            referer_url=response_url or continue_url,
            max_redirects=8,
        )
    else:
        submit_res = await _request_html_page(
            request_ctx=request_ctx,
            stage="http_register_about_you_submit",
            url=action_url,
            trace=trace,
            timeout_ms=timeout_ms,
            method="POST",
            referer_url=response_url or continue_url,
            body_text=body_text,
            max_redirects=8,
        )
    after_url = str(submit_res.get("url") or action_url).strip()
    after_text = str(submit_res.get("text") or "")
    if _response_looks_blocked(
        status=int(submit_res.get("status") or 0),
        response_url=after_url,
        text=after_text,
    ):
        return {
            "attempted": True,
            "ok": False,
            "reason": "challenge_blocked",
            "afterUrl": after_url,
            "afterPayload": {},
        }
    after_title, after_body, after_form = _parse_about_you_html(url=after_url, html_text=after_text)
    still_about_you = _looks_like_about_you_page(
        url=after_url,
        title=after_title,
        body_text=after_body,
        form=after_form,
    )
    after_payload = _build_after_page_payload(url=after_url)
    result = {
        "attempted": True,
        "ok": bool(int(submit_res.get("status") or 0) in _SUCCESS_STATUS and not still_about_you),
        "reason": "submitted" if int(submit_res.get("status") or 0) in _SUCCESS_STATUS and not still_about_you else "about_you_not_advanced",
        "afterUrl": after_url,
        "afterPayload": after_payload,
    }
    trace.write(
        {
            "ts": _iso_now(),
            "stage": "http_register_about_you_submit_parsed",
            "status": int(submit_res.get("status") or 0),
            "afterUrl": _sanitize_url_for_log(after_url),
            "stillAboutYou": bool(still_about_you),
            "reason": str(result.get("reason") or ""),
            "title": _compress_debug_text(after_title, limit=120),
        }
    )
    return result


async def _request_with_sentinel_candidates(
    *,
    request_ctx: Any,
    stage_prefix: str,
    path: str,
    flow_name: str,
    referer_url: str,
    request_bodies: tuple[dict[str, Any], ...],
    sentinel_candidates: list[tuple[str, dict[str, str]]],
    trace: _TraceWriter,
    timeout_ms: int,
    open_continue_url_on_success: bool = True,
) -> dict[str, Any]:
    candidates = list(sentinel_candidates or [])
    if not candidates:
        candidates = [("default", {})]
    bodies = [dict(item) for item in request_bodies if isinstance(item, dict)]
    if not bodies:
        bodies = [{}]
    last_result: dict[str, Any] = {
        "status": 0,
        "payload": {},
        "text": "",
        "url": "",
        "errorCode": "",
        "errorMessage": "",
        "continueUrl": "",
        "candidateName": "",
        "requestBody": {},
    }
    for body_index, json_body in enumerate(bodies, start=1):
        for candidate_name, candidate_headers in candidates:
            stage_name = f"{stage_prefix}_{body_index}_{candidate_name}"
            response = await _request_auth_api_with_context(
                request_ctx,
                stage=stage_name,
                path=path,
                method="POST",
                timeout_ms=timeout_ms,
                trace=trace,
                referer_url=referer_url,
                json_body=dict(json_body),
                extra_headers=dict(candidate_headers or {}),
            )
            status = int(response.get("status") or 0)
            payload = response.get("payload")
            text = str(response.get("text") or "")
            continue_url = str(_extract_continue_url(payload) or "").strip()
            err_code, err_msg = _extract_error(payload, text)
            last_result = {
                **response,
                "status": status,
                "payload": payload if isinstance(payload, dict) else {},
                "text": text,
                "url": str(response.get("url") or "").strip(),
                "errorCode": str(err_code or "").strip(),
                "errorMessage": str(err_msg or "").strip(),
                "continueUrl": continue_url,
                "candidateName": str(candidate_name or "").strip(),
                "requestBody": dict(json_body),
            }
            trace.write(
                {
                    "ts": _iso_now(),
                    "stage": f"{stage_name}_parsed",
                    "status": int(status),
                    "candidateName": str(candidate_name or "").strip(),
                    "continueUrl": _sanitize_url_for_log(continue_url),
                    "errorCode": str(err_code or "").strip(),
                    "errorMessage": str(err_msg or "").strip(),
                    "hints": _collect_auth_step_hints(payload),
                }
            )
            if status not in _SUCCESS_STATUS:
                continue
            if continue_url and open_continue_url_on_success:
                await _open_continue_url(
                    request_ctx=request_ctx,
                    continue_url=continue_url,
                    trace=trace,
                    timeout_ms=timeout_ms,
                    stage_name=f"{stage_name}_continue_page",
                )
            return last_result
    return last_result


async def _refresh_register_sentinel_header_candidates(
    *,
    request_ctx: Any,
    sentinel_header_candidates: dict[str, list[tuple[str, dict[str, str]]]],
    resolved_proxy_url: str,
    trace: _TraceWriter,
    timeout_ms: int,
    flow_names: tuple[str, ...] = (
        _REGISTER_PASSWORD_FLOW,
        _REGISTER_PROFILE_FLOW,
    ),
) -> dict[str, list[tuple[str, dict[str, str]]]]:
    if all(_http_sentinel_prefers_fallback_first(flow_name) for flow_name in flow_names):
        return {
            flow_name: list(sentinel_header_candidates.get(flow_name) or [])
            for flow_name in (
                _REGISTER_AUTHORIZE_FLOW,
                _REGISTER_PASSWORD_FLOW,
                _REGISTER_PROFILE_FLOW,
            )
        }
    merged = {
        flow_name: list(sentinel_header_candidates.get(flow_name) or [])
        for flow_name in (
            _REGISTER_AUTHORIZE_FLOW,
            _REGISTER_PASSWORD_FLOW,
            _REGISTER_PROFILE_FLOW,
        )
    }
    sentinel_storage_state_path = ""
    try:
        state_payload = await _read_request_context_storage_state(request_ctx)
        if not (isinstance(state_payload, dict) and state_payload.get("cookies")):
            return merged
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fh:
            json.dump(state_payload, fh, ensure_ascii=False)
            sentinel_storage_state_path = fh.name
        refreshed = await _collect_http_sentinel_header_candidates_for_flows(
            flow_names=flow_names,
            playwright=None,
            storage_state_path=sentinel_storage_state_path,
            proxy_opt=_build_playwright_proxy_option(resolved_proxy_url),
            trace=trace,
            timeout_ms=timeout_ms,
        )
    except Exception:
        return merged
    finally:
        if sentinel_storage_state_path:
            Path(sentinel_storage_state_path).unlink(missing_ok=True)
    for flow_name in flow_names:
        existing_names = {str(name or "").strip() for name, _ in merged.get(flow_name, [])}
        refreshed_candidates = list(refreshed.get(flow_name) or [])
        for candidate_name, candidate_headers in reversed(refreshed_candidates):
            normalized_name = str(candidate_name or "").strip()
            if normalized_name in existing_names:
                continue
            merged.setdefault(flow_name, []).append((candidate_name, candidate_headers))
            existing_names.add(normalized_name)
    return merged


async def _submit_register_password_http(
    *,
    request_ctx: Any,
    email: str,
    password: str,
    referer_url: str,
    sentinel_header_candidates: dict[str, list[tuple[str, dict[str, str]]]],
    trace: _TraceWriter,
    timeout_ms: int,
) -> dict[str, Any]:
    password_candidates = list(sentinel_header_candidates.get(_REGISTER_PASSWORD_FLOW) or [])
    response = await _request_with_sentinel_candidates(
        request_ctx=request_ctx,
        stage_prefix="http_register_password",
        path="/user/register",
        flow_name=_REGISTER_PASSWORD_FLOW,
        referer_url=referer_url,
        request_bodies=({"username": email, "password": password},),
        sentinel_candidates=password_candidates,
        trace=trace,
        timeout_ms=timeout_ms,
    )
    if _register_password_response_accepted(response):
        return response

    err_code = str(response.get("errorCode") or "").strip()
    err_msg = str(response.get("errorMessage") or "").strip()
    response_text = str(response.get("text") or "")
    if _is_unknown_parameter_error(
        err_code=err_code,
        err_msg=err_msg,
        text=response_text,
        parameter_name="password",
    ):
        compat_response = await _request_with_sentinel_candidates(
            request_ctx=request_ctx,
            stage_prefix="http_register_password_compat",
            path="/user/register",
            flow_name=_REGISTER_PASSWORD_FLOW,
            referer_url=referer_url,
            request_bodies=(
                {"username": email, "password": {"kind": "password", "value": password}},
                {"username": email, "credential": {"kind": "password", "value": password}},
            ),
            sentinel_candidates=password_candidates,
            trace=trace,
            timeout_ms=timeout_ms,
        )
        if _register_password_response_accepted(compat_response):
            return compat_response
        response = compat_response
        err_code = str(response.get("errorCode") or "").strip()
        err_msg = str(response.get("errorMessage") or "").strip()
        response_text = str(response.get("text") or "")

    if _is_invalid_authorization_step(err_code=err_code, err_msg=err_msg, text=response_text):
        authorize_candidates = list(sentinel_header_candidates.get(_REGISTER_AUTHORIZE_FLOW) or [])
        fallback_response = await _request_with_sentinel_candidates(
            request_ctx=request_ctx,
            stage_prefix="http_register_password_fallback",
            path="/authorize/continue",
            flow_name=_REGISTER_AUTHORIZE_FLOW,
            referer_url=referer_url,
            request_bodies=(
                {
                    "username": {"kind": "email", "value": email},
                    "password": str(password),
                },
                {
                    "username": {"kind": "email", "value": email},
                    "password": {"kind": "password", "value": password},
                },
                {"password": {"kind": "password", "value": password}},
            ),
            sentinel_candidates=authorize_candidates,
            trace=trace,
            timeout_ms=timeout_ms,
        )
        if _register_password_response_accepted(fallback_response):
            return fallback_response
        response = fallback_response

    return response


async def _bootstrap_http_register_session(
    *,
    request_ctx: Any,
    trace: _TraceWriter,
    timeout_ms: int,
) -> dict[str, Any]:
    boot_info = await _bootstrap_http_login_session(
        request_ctx=request_ctx,
        trace=trace,
        timeout_ms=timeout_ms,
    )
    register_entry = await _request_html_page(
        request_ctx=request_ctx,
        stage="http_register_create_account_entry",
        url="https://auth.openai.com/create-account",
        trace=trace,
        timeout_ms=timeout_ms,
        method="GET",
        referer_url=str(boot_info.get("loginUrl") or "https://auth.openai.com/log-in"),
        max_redirects=6,
    )
    register_entry_url = str(register_entry.get("url") or "https://auth.openai.com/create-account").strip()
    register_entry_text = str(register_entry.get("text") or "")
    register_entry_status = int(register_entry.get("status") or 0)
    if _response_looks_blocked(
        status=register_entry_status,
        response_url=register_entry_url,
        text=register_entry_text,
    ):
        raise RuntimeError("http_register_challenge_blocked: 注册入口被 Cloudflare challenge 拦截，纯 HTTP 无法继续。")
    if register_entry_status not in _SUCCESS_STATUS:
        raise RuntimeError(f"http_register_bootstrap_failed: 注册入口返回 HTTP {register_entry_status or 0}。")
    return {
        **boot_info,
        "registerUrl": register_entry_url or "https://auth.openai.com/create-account",
    }


async def _finalize_http_register_storage_state(
    *,
    request_ctx: Any,
    trace: _TraceWriter,
    output_path: str,
    timeout_sec: float,
    proxy_url: str,
    impersonate: str,
) -> dict[str, Any]:
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
        direct_payload, direct_status, direct_text = await _request_json_with_context(
            request_ctx,
            url="https://chatgpt.com/api/auth/session",
            timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
        )
        direct_error = ""
    except Exception as error:
        direct_payload, direct_status, direct_text = {}, 0, ""
        direct_error = str(error or "").strip()
    direct_payload = direct_payload if isinstance(direct_payload, dict) else {}
    direct_token = str(extract_access_token_from_session_payload(direct_payload) or "").strip()
    direct_summary = extract_session_summary_from_payload(
        direct_payload,
        status=int(direct_status or 0),
        error_text=direct_error,
        updated_at=_iso_now(),
    )
    trace.write(
        {
            "ts": _iso_now(),
            "stage": "http_register_session_direct_probe",
            "status": int(direct_status or 0),
            "accessTokenLen": int(len(direct_token)),
            "selectedWorkspaceId": str(direct_summary.get("selectedWorkspaceId") or "").strip(),
            "selectedWorkspaceName": _compress_debug_text(direct_summary.get("selectedWorkspaceName"), limit=120),
            "planType": str(direct_summary.get("accountPlanType") or "").strip(),
            "error": _compress_debug_text(direct_error, limit=220),
            "bodyLen": len(str(direct_text or "")),
        }
    )
    if int(direct_status or 0) == 200 and direct_token:
        return await _finalize_http_register_storage_state_fast(
            request_ctx=request_ctx,
            trace=trace,
            output_path=output_path,
            session_payload=direct_payload,
            session_status=int(direct_status or 0),
            session_error=direct_error,
        )

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
            "stage": "http_register_session_bridge_state_ready",
            "cookieCount": int(len(bridged_storage_state.get("cookies") or [])),
            "originCount": int(len(bridged_storage_state.get("origins") or [])),
        }
    )
    try:
        request_ctx = await _rebuild_request_context_with_storage_state(
            request_ctx=request_ctx,
            storage_state=bridged_storage_state,
            proxy_url=proxy_url,
            impersonate=impersonate,
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
                "stage": "http_register_session_bridge_context_rebuild_failed",
                "error": _compress_debug_text(str(error or ""), limit=240),
            }
        )

    session_snapshot = await _fetch_session_after_login(
        request_ctx=request_ctx,
        trace=trace,
        timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
    )
    session_payload = session_snapshot.get("payload") if isinstance(session_snapshot.get("payload"), dict) else {}
    session_status = int(session_snapshot.get("status") or 0)
    session_error = str(session_snapshot.get("error") or "").strip()
    storage_state = await _read_request_context_storage_state(request_ctx)
    final_state_payload = _augment_storage_state_payload(
        storage_state=storage_state,
        session_payload=session_payload,
        session_status=session_status,
        session_error=session_error,
    )
    await asyncio.to_thread(_write_json_file, output_path, final_state_payload)
    session_snapshot_path = await asyncio.to_thread(
        _write_auth_session_snapshot,
        output_path=output_path,
        session_payload=session_payload,
        session_status=session_status,
        session_error=session_error,
        source="https://chatgpt.com/api/auth/session",
    )
    codex_token_result = {"ok": False, "jsonPath": "", "txtPath": ""}
    if not _defer_workspace_token_creation():
        codex_token_result = await _create_codex_wham_auth_credential(
            request_ctx=request_ctx,
            trace=trace,
            output_path=output_path,
            session_payload=session_payload,
            session_status=session_status,
            session_error=session_error,
            timeout_sec=timeout_sec,
        )
    summary = extract_session_summary_from_payload(
        session_payload,
        status=int(session_status),
        error_text=session_error,
        updated_at=_iso_now(),
    )
    return {
        "requestCtx": request_ctx,
        "sessionPayload": session_payload,
        "sessionStatus": int(session_status),
        "sessionError": session_error,
        "sessionSummary": dict(summary),
        "sessionSnapshotPath": session_snapshot_path,
        "codexTokenJsonPath": str(codex_token_result.get("jsonPath") or "").strip(),
        "codexTokenTxtPath": str(codex_token_result.get("txtPath") or "").strip(),
        "codexTokenCreated": bool(codex_token_result.get("ok")),
    }


async def _finalize_http_register_storage_state_fast(
    *,
    request_ctx: Any,
    trace: _TraceWriter,
    output_path: str,
    session_payload: dict[str, Any],
    session_status: int = 200,
    session_error: str = "",
) -> dict[str, Any]:
    try:
        storage_state = await _read_request_context_storage_state(request_ctx)
    except Exception:
        storage_state = _build_empty_storage_state_payload()
    final_state_payload = _augment_storage_state_payload(
        storage_state=storage_state,
        session_payload=session_payload,
        session_status=session_status,
        session_error=session_error,
    )
    await asyncio.to_thread(_write_json_file, output_path, final_state_payload)
    session_snapshot_path = await asyncio.to_thread(
        _write_auth_session_snapshot,
        output_path=output_path,
        session_payload=session_payload,
        session_status=session_status,
        session_error=session_error,
        source="https://chatgpt.com/api/auth/session",
    )
    codex_token_result = {"ok": False, "jsonPath": "", "txtPath": ""}
    if not _defer_workspace_token_creation():
        codex_token_result = await _create_codex_wham_auth_credential(
            request_ctx=request_ctx,
            trace=trace,
            output_path=output_path,
            session_payload=session_payload,
            session_status=session_status,
            session_error=str(session_error or "").strip(),
            timeout_sec=60.0,
        )
    summary = extract_session_summary_from_payload(
        session_payload,
        status=int(session_status),
        error_text=str(session_error or "").strip(),
        updated_at=_iso_now(),
    )
    trace.write(
        {
            "ts": _iso_now(),
            "stage": "http_register_fast_finalize",
            "sessionStatus": int(session_status or 0),
            "accessTokenLen": int(len(str(extract_access_token_from_session_payload(session_payload) or "").strip())),
            "planType": str(summary.get("accountPlanType") or "").strip(),
            "selectedWorkspaceId": str(summary.get("selectedWorkspaceId") or "").strip(),
            "sessionSnapshotPath": session_snapshot_path,
            "codexTokenCreated": bool(codex_token_result.get("ok")),
            "codexTokenJsonPath": str(codex_token_result.get("jsonPath") or ""),
            "codexTokenTxtPath": str(codex_token_result.get("txtPath") or ""),
        }
    )
    return {
        "requestCtx": request_ctx,
        "sessionPayload": session_payload,
        "sessionStatus": int(session_status),
        "sessionError": str(session_error or "").strip(),
        "sessionSummary": dict(summary),
        "sessionSnapshotPath": session_snapshot_path,
        "codexTokenJsonPath": str(codex_token_result.get("jsonPath") or "").strip(),
        "codexTokenTxtPath": str(codex_token_result.get("txtPath") or "").strip(),
        "codexTokenCreated": bool(codex_token_result.get("ok")),
    }


async def _submit_register_profile_http(
    *,
    request_ctx: Any,
    continue_url: str,
    full_name: str,
    birthdate: str,
    sentinel_header_candidates: dict[str, list[str]],
    trace: _TraceWriter,
    timeout_sec: float,
    log: _LogSink,
) -> dict[str, Any]:
    profile_submit_url = str(continue_url or "").strip() or "https://auth.openai.com/about-you"
    profile_timeout_ms = int(max(15_000, float(timeout_sec) * 1000.0 / 3.0))
    create_account_tried = False
    create_account_result: dict[str, Any] = {}
    about_you_result: dict[str, Any] = {
        "attempted": False,
        "ok": False,
        "reason": "skipped",
        "afterUrl": "",
    }

    if _prefer_direct_create_account():
        create_account_tried = True
        log.info("[ChatGPT HTTP 注册] profile step: trying direct create_account first.")
        create_account_result = await _request_with_sentinel_candidates(
            request_ctx=request_ctx,
            stage_prefix="http_register_profile",
            path="/create_account",
            flow_name=_REGISTER_PROFILE_FLOW,
            referer_url=profile_submit_url,
            request_bodies=(
                {"name": full_name, "birthdate": birthdate},
            ),
            sentinel_candidates=list(sentinel_header_candidates.get(_REGISTER_PROFILE_FLOW) or []),
            trace=trace,
            timeout_ms=profile_timeout_ms,
            open_continue_url_on_success=False,
        )
        if int(create_account_result.get("status") or 0) in _SUCCESS_STATUS:
            return {
                "ok": True,
                "payload": create_account_result.get("payload") if isinstance(create_account_result.get("payload"), dict) else {},
                "continueUrl": str(create_account_result.get("continueUrl") or "").strip(),
                "aboutYou": dict(about_you_result),
            }
        log.warn(
            "[ChatGPT HTTP 注册] profile step: direct create_account did not advance; "
            f"falling back to about-you form (reason={str(create_account_result.get('errorCode') or 'unknown')})."
        )

    about_you_result = await _submit_about_you_form_http(
        request_ctx=request_ctx,
        continue_url=profile_submit_url,
        full_name=full_name,
        birthdate=birthdate,
        trace=trace,
        timeout_ms=profile_timeout_ms,
    )
    if bool(about_you_result.get("ok")):
        payload = about_you_result.get("afterPayload") if isinstance(about_you_result.get("afterPayload"), dict) else {}
        return {
            "ok": True,
            "payload": payload,
            "continueUrl": str(_extract_continue_url(payload) or about_you_result.get("afterUrl") or "").strip(),
            "aboutYou": dict(about_you_result),
        }

    if not create_account_tried:
        log.warn(
            "[ChatGPT HTTP 注册] about-you form did not advance; "
            f"falling back to create_account API (reason={str(about_you_result.get('reason') or 'unknown')})."
        )
        create_account_result = await _request_with_sentinel_candidates(
            request_ctx=request_ctx,
            stage_prefix="http_register_profile",
            path="/create_account",
            flow_name=_REGISTER_PROFILE_FLOW,
            referer_url=profile_submit_url,
            request_bodies=(
                {"name": full_name, "birthdate": birthdate},
            ),
            sentinel_candidates=list(sentinel_header_candidates.get(_REGISTER_PROFILE_FLOW) or []),
            trace=trace,
            timeout_ms=profile_timeout_ms,
            open_continue_url_on_success=False,
        )

    if int(create_account_result.get("status") or 0) in _SUCCESS_STATUS:
        return {
            "ok": True,
            "payload": create_account_result.get("payload") if isinstance(create_account_result.get("payload"), dict) else {},
            "continueUrl": str(create_account_result.get("continueUrl") or "").strip(),
            "aboutYou": dict(about_you_result),
        }

    return {
        "ok": False,
        "status": int(create_account_result.get("status") or 0),
        "errorCode": str(create_account_result.get("errorCode") or "create_account_failed"),
        "errorMessage": str(create_account_result.get("errorMessage") or "").strip(),
        "aboutYou": dict(about_you_result),
    }


async def run_http_oauth_inline_signup_from_interactive_page(
    *,
    request_ctx: Any,
    interactive_url: str,
    email: str,
    password: str,
    full_name: str = "",
    birth_date: str = "",
    trace: _TraceWriter,
    log: _LogSink,
    timeout_sec: float,
    otp_timeout_sec: float = 180.0,
    otp_interval_sec: float = 2.0,
    use_managed_mail_otp: bool = False,
    managed_mail_provider: str = "",
    managed_mail_jwt: str = "",
    managed_mail_api_base: str = "",
    managed_mail_frontend_base: str = "",
    managed_mail_latest_n: int = 20,
    use_domain_mail_otp: bool = False,
    domain_mail_api_base: str = "",
    domain_mail_domain: str = "",
    domain_mail_token: str = "",
    domain_mail_latest_n: int = 20,
    use_imap_otp: bool = True,
    imap_host: str = "imap.2925.com",
    imap_port: int = 993,
    imap_user: str = "",
    imap_pass: str = "",
    imap_folder: str = "Inbox",
    imap_latest_n: int = 50,
    imap_auth_type: str = "password",
    imap_oauth_client_id: str = "",
    imap_oauth_refresh_token: str = "",
    imap_password_fallback: bool = False,
    imap_pop3_fallback: bool = False,
) -> dict[str, Any]:
    """在 OAuth authorize 交互页内走注册（screen_hint=signup），非独立 HTTP 注册。"""
    safe_email = str(email or "").strip().lower()
    interactive = str(interactive_url or "").strip()
    if not safe_email or "@" not in safe_email:
        return {"ok": False, "error": "invalid_email", "final_payload": {}, "final_continue_url": ""}
    if not interactive:
        return {"ok": False, "error": "missing_interactive_url", "final_payload": {}, "final_continue_url": ""}

    resolved_name = str(full_name or "").strip() or random_full_name()
    resolved_birth = str(birth_date or "").strip() or random_birth_date()
    timeout_ms = int(max(15_000, float(timeout_sec) * 1000.0 / 3.0))
    resolved_proxy_url = str(
        resolve_proxy_for_url(interactive or "https://auth.openai.com/create-account") or ""
    ).strip()
    sentinel_proxy_opt = _build_playwright_proxy_option(resolved_proxy_url)
    sentinel_storage_state_path = ""
    try:
        state_payload = await _read_request_context_storage_state(request_ctx)
        if isinstance(state_payload, dict) and state_payload.get("cookies"):
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fh:
                json.dump(state_payload, fh, ensure_ascii=False)
                sentinel_storage_state_path = fh.name
    except Exception:
        sentinel_storage_state_path = ""

    try:
        sentinel_header_candidates = await _collect_http_sentinel_header_candidates_for_flows(
            flow_names=(
                _REGISTER_AUTHORIZE_FLOW,
                _REGISTER_PASSWORD_FLOW,
                _REGISTER_PROFILE_FLOW,
            ),
            playwright=None,
            storage_state_path=sentinel_storage_state_path,
            proxy_opt=sentinel_proxy_opt,
            trace=trace,
            timeout_ms=int(max(12_000, float(timeout_sec) * 1000.0 / 3.0)),
        )
    finally:
        if sentinel_storage_state_path:
            Path(sentinel_storage_state_path).unlink(missing_ok=True)
    email_step_res = await _request_with_sentinel_candidates(
        request_ctx=request_ctx,
        stage_prefix="http_oauth_inline_signup_email",
        path="/authorize/continue",
        flow_name=_REGISTER_AUTHORIZE_FLOW,
        referer_url=interactive,
        request_bodies=(
            {"username": {"kind": "email", "value": safe_email}, "screen_hint": "signup"},
            {"username": {"kind": "email", "value": safe_email}},
        ),
        sentinel_candidates=list(sentinel_header_candidates.get(_REGISTER_AUTHORIZE_FLOW) or []),
        trace=trace,
        timeout_ms=timeout_ms,
    )
    if int(email_step_res.get("status") or 0) not in _SUCCESS_STATUS:
        return {
            "ok": False,
            "error": str(email_step_res.get("errorMessage") or email_step_res.get("errorCode") or "signup_email_failed"),
            "final_payload": email_step_res.get("payload") if isinstance(email_step_res.get("payload"), dict) else {},
            "final_continue_url": str(email_step_res.get("continueUrl") or "").strip(),
        }

    email_payload = email_step_res.get("payload") if isinstance(email_step_res.get("payload"), dict) else {}
    email_continue_url = str(email_step_res.get("continueUrl") or _extract_continue_url(email_payload) or "").strip()
    email_otp_result = await _submit_http_otp_if_required(
        request_ctx=request_ctx,
        payload=email_payload,
        safe_email=safe_email,
        trace=trace,
        log=log,
        timeout_sec=timeout_sec,
        otp_timeout_sec=float(otp_timeout_sec),
        otp_interval_sec=float(otp_interval_sec),
        normalized_totp_secret="",
        use_managed_mail_otp=bool(use_managed_mail_otp),
        managed_mail_provider=str(managed_mail_provider or "").strip(),
        managed_mail_jwt=str(managed_mail_jwt or "").strip(),
        managed_mail_api_base=str(managed_mail_api_base or "").strip(),
        managed_mail_frontend_base=str(managed_mail_frontend_base or "").strip(),
        managed_mail_latest_n=int(managed_mail_latest_n or 20),
        use_domain_mail_otp=bool(use_domain_mail_otp),
        domain_mail_api_base=str(domain_mail_api_base or "").strip(),
        domain_mail_domain=str(domain_mail_domain or "").strip(),
        domain_mail_token=str(domain_mail_token or ""),
        domain_mail_latest_n=int(domain_mail_latest_n or 20),
        use_imap_otp=bool(use_imap_otp),
        imap_host=str(imap_host or "imap.2925.com").strip() or "imap.2925.com",
        imap_port=int(imap_port or 993),
        imap_user=str(imap_user or "").strip(),
        imap_pass=str(imap_pass or ""),
        imap_folder=str(imap_folder or "Inbox").strip() or "Inbox",
        imap_latest_n=int(imap_latest_n or 10),
        imap_auth_type=str(imap_auth_type or "password").strip() or "password",
        imap_oauth_client_id=str(imap_oauth_client_id or "").strip(),
        imap_oauth_refresh_token=str(imap_oauth_refresh_token or "").strip(),
        imap_password_fallback=bool(imap_password_fallback),
        imap_pop3_fallback=bool(imap_pop3_fallback),
    )
    if bool(email_otp_result.get("handled")):
        resolved_payload = email_otp_result.get("payload")
        resolved_continue = str(email_otp_result.get("continue_url") or "").strip()
        if isinstance(resolved_payload, dict):
            email_payload = resolved_payload
        elif resolved_continue:
            email_payload = {"continue_url": resolved_continue}
        if resolved_continue:
            email_continue_url = resolved_continue

    final_payload = email_payload if isinstance(email_payload, dict) else {}
    final_continue_url = str(email_continue_url or _extract_continue_url(final_payload) or "").strip()
    password_submission_mode = _register_password_submission_mode(final_payload, final_continue_url)
    if not password_submission_mode:
        trace.write(
            {
                "ts": _iso_now(),
                "stage": "http_oauth_inline_signup_password_step_missing",
                "continueUrl": _sanitize_url_for_log(final_continue_url),
                "pageType": _extract_auth_page_type(final_payload),
            }
        )
        return {
            "ok": False,
            "error": "remote_password_step_missing",
            "final_payload": final_payload,
            "final_continue_url": final_continue_url,
            "remote_password_set": False,
            "remote_password_mode": "not_attempted",
        }

    if password_submission_mode == "post_otp_about_you_recovery":
        trace.write(
            {
                "ts": _iso_now(),
                "stage": "http_oauth_inline_signup_password_recovery_start",
                "continueUrl": _sanitize_url_for_log(final_continue_url),
            }
        )
    sentinel_header_candidates = await _refresh_register_sentinel_header_candidates(
        request_ctx=request_ctx,
        sentinel_header_candidates=sentinel_header_candidates,
        resolved_proxy_url=resolved_proxy_url,
        trace=trace,
        timeout_ms=int(max(12_000, float(timeout_sec) * 1000.0 / 3.0)),
        flow_names=(_REGISTER_PASSWORD_FLOW,),
    )

    password_res = await _submit_register_password_http(
        request_ctx=request_ctx,
        email=safe_email,
        password=str(password or ""),
        referer_url=(
            "https://auth.openai.com/create-account/password"
            if password_submission_mode == "post_otp_about_you_recovery"
            else (final_continue_url or interactive)
        ),
        sentinel_header_candidates=sentinel_header_candidates,
        trace=trace,
        timeout_ms=timeout_ms,
    )
    if not _register_password_response_accepted(password_res):
        return {
            "ok": False,
            "error": str(
                password_res.get("errorMessage")
                or password_res.get("errorCode")
                or "remote_password_not_set"
            ),
            "error_code": "remote_password_not_set",
            "final_payload": password_res.get("payload") if isinstance(password_res.get("payload"), dict) else {},
            "final_continue_url": str(password_res.get("continueUrl") or "").strip(),
            "remote_password_set": False,
            "remote_password_mode": password_submission_mode,
        }

    submitted_payload = password_res.get("payload") if isinstance(password_res.get("payload"), dict) else {}
    submitted_continue_url = str(password_res.get("continueUrl") or _extract_continue_url(submitted_payload) or "").strip()
    if submitted_payload or submitted_continue_url or password_submission_mode != "post_otp_about_you_recovery":
        final_payload = submitted_payload
        final_continue_url = submitted_continue_url
    final_otp_result = (
        await _submit_http_otp_if_required(
            request_ctx=request_ctx,
            payload=final_payload,
            safe_email=safe_email,
            trace=trace,
            log=log,
            timeout_sec=timeout_sec,
            otp_timeout_sec=float(otp_timeout_sec),
            otp_interval_sec=float(otp_interval_sec),
            normalized_totp_secret="",
            use_managed_mail_otp=bool(use_managed_mail_otp),
            managed_mail_provider=str(managed_mail_provider or "").strip(),
            managed_mail_jwt=str(managed_mail_jwt or "").strip(),
            managed_mail_api_base=str(managed_mail_api_base or "").strip(),
            managed_mail_frontend_base=str(managed_mail_frontend_base or "").strip(),
            managed_mail_latest_n=int(managed_mail_latest_n or 20),
            use_domain_mail_otp=bool(use_domain_mail_otp),
            domain_mail_api_base=str(domain_mail_api_base or "").strip(),
            domain_mail_domain=str(domain_mail_domain or "").strip(),
            domain_mail_token=str(domain_mail_token or ""),
            domain_mail_latest_n=int(domain_mail_latest_n or 20),
            use_imap_otp=bool(use_imap_otp),
            imap_host=str(imap_host or "imap.2925.com").strip() or "imap.2925.com",
            imap_port=int(imap_port or 993),
            imap_user=str(imap_user or "").strip(),
            imap_pass=str(imap_pass or ""),
            imap_folder=str(imap_folder or "Inbox").strip() or "Inbox",
            imap_latest_n=int(imap_latest_n or 10),
            imap_auth_type=str(imap_auth_type or "password").strip() or "password",
            imap_oauth_client_id=str(imap_oauth_client_id or "").strip(),
            imap_oauth_refresh_token=str(imap_oauth_refresh_token or "").strip(),
            imap_password_fallback=bool(imap_password_fallback),
            imap_pop3_fallback=bool(imap_pop3_fallback),
            preferred_send_path="/email-otp/send",
        )
        if password_submission_mode == "signup_password_step"
        else {"handled": False}
    )
    if bool(final_otp_result.get("handled")):
        resolved_final_payload = final_otp_result.get("payload")
        resolved_final_continue_url = str(final_otp_result.get("continue_url") or "").strip()
        if isinstance(resolved_final_payload, dict):
            final_payload = resolved_final_payload
        elif resolved_final_continue_url:
            final_payload = {"continue_url": resolved_final_continue_url}
        if resolved_final_continue_url:
            final_continue_url = resolved_final_continue_url

    if (not final_continue_url) and _payload_points_to_about_you(final_payload):
        final_continue_url = "https://auth.openai.com/about-you"
    if final_continue_url and ("/about-you" not in final_continue_url.lower()) and (not _payload_points_to_about_you(final_payload)):
        return {
            "ok": True,
            "signup_route": "oauth_inline",
            "final_payload": final_payload,
            "final_continue_url": final_continue_url,
            "remote_password_set": True,
            "remote_password_mode": password_submission_mode,
        }

    sentinel_header_candidates = await _refresh_register_sentinel_header_candidates(
        request_ctx=request_ctx,
        sentinel_header_candidates=sentinel_header_candidates,
        resolved_proxy_url=resolved_proxy_url,
        trace=trace,
        timeout_ms=int(max(12_000, float(timeout_sec) * 1000.0 / 3.0)),
        flow_names=(_REGISTER_PROFILE_FLOW,),
    )
    profile_result: dict[str, Any] = {}
    if _prefer_direct_create_account():
        profile_result = await _submit_register_profile_http(
            request_ctx=request_ctx,
            continue_url=final_continue_url or "https://auth.openai.com/about-you",
            full_name=resolved_name,
            birthdate=resolved_birth,
            sentinel_header_candidates=sentinel_header_candidates,
            trace=trace,
            timeout_sec=timeout_sec,
            log=log,
        )
        if not bool(profile_result.get("ok")):
            return {
                "ok": False,
                "error": str(profile_result.get("errorMessage") or profile_result.get("errorCode") or "signup_profile_failed"),
                "final_payload": profile_result.get("payload") if isinstance(profile_result.get("payload"), dict) else {},
                "final_continue_url": str(profile_result.get("continueUrl") or "").strip(),
            }
        final_payload = profile_result.get("payload") if isinstance(profile_result.get("payload"), dict) else {}
        final_continue_url = str(profile_result.get("continueUrl") or _extract_continue_url(final_payload) or "").strip()
    else:
        about_you_result = await _submit_about_you_form_http(
            request_ctx=request_ctx,
            continue_url=final_continue_url or "https://auth.openai.com/about-you",
            full_name=resolved_name,
            birthdate=resolved_birth,
            trace=trace,
            timeout_ms=timeout_ms,
        )
        if not bool(about_you_result.get("ok")):
            profile_res = await _request_with_sentinel_candidates(
                request_ctx=request_ctx,
                stage_prefix="http_oauth_inline_signup_profile",
                path="/create_account",
                flow_name=_REGISTER_PROFILE_FLOW,
                referer_url=final_continue_url or "https://auth.openai.com/about-you",
                request_bodies=({"name": resolved_name, "birthdate": resolved_birth},),
                sentinel_candidates=list(sentinel_header_candidates.get(_REGISTER_PROFILE_FLOW) or []),
                trace=trace,
                timeout_ms=timeout_ms,
            )
            if int(profile_res.get("status") or 0) not in _SUCCESS_STATUS:
                return {
                    "ok": False,
                    "error": str(profile_res.get("errorMessage") or profile_res.get("errorCode") or "signup_profile_failed"),
                    "final_payload": profile_res.get("payload") if isinstance(profile_res.get("payload"), dict) else {},
                    "final_continue_url": str(profile_res.get("continueUrl") or "").strip(),
                }
            final_payload = profile_res.get("payload") if isinstance(profile_res.get("payload"), dict) else {}
            final_continue_url = str(profile_res.get("continueUrl") or _extract_continue_url(final_payload) or "").strip()
        else:
            final_payload = (
                about_you_result.get("afterPayload")
                if isinstance(about_you_result.get("afterPayload"), dict)
                else {}
            )
            final_continue_url = str(
                _extract_continue_url(final_payload)
                or about_you_result.get("afterUrl")
                or final_continue_url
                or ""
            ).strip()

    if final_continue_url:
        try:
            await _open_continue_url(
                request_ctx=request_ctx,
                continue_url=final_continue_url,
                trace=trace,
                timeout_ms=timeout_ms,
                stage_name="http_oauth_inline_signup_finalize_continue",
            )
        except Exception:
            pass

    return {
        "ok": True,
        "signup_route": "oauth_inline",
        "final_payload": final_payload if isinstance(final_payload, dict) else {},
        "final_continue_url": final_continue_url,
        "remote_password_set": True,
        "remote_password_mode": password_submission_mode,
    }


def _registration_phone_step(payload: Any, continue_url: str) -> str:
    page_type = _extract_auth_page_type(payload).replace("-", "_")
    if page_type in {"phone_otp_select_channel", "phone_otp_channel_selection"}:
        return "select_channel"
    if page_type in {
        "add_phone",
        "phone_number_verification",
        "phone_otp_verification",
        "phone_verification",
    }:
        return "add_phone"
    url_text = str(continue_url or "").strip().lower()
    try:
        payload_text = json.dumps(payload, ensure_ascii=False, default=str).lower()
    except Exception:
        payload_text = str(payload or "").lower()
    merged = f"{url_text}\n{payload_text}"
    if "/phone-otp/select-channel" in merged:
        return "select_channel"
    if "/add-phone" in merged or "/phone-verification" in merged or "/phone-otp" in merged:
        return "add_phone"
    return ""


def _registration_phone_forced_whatsapp(
    payload: Any,
    *,
    text: str = "",
    url: str = "",
) -> bool:
    channel_keys = {
        "channel",
        "selected_channel",
        "delivery_channel",
        "delivery_method",
        "verification_channel",
    }

    def selected_in(value: Any) -> bool:
        if isinstance(value, dict):
            for key, item in value.items():
                normalized_key = str(key or "").strip().lower().replace("-", "_")
                if normalized_key in channel_keys:
                    candidates = [item]
                    if isinstance(item, dict):
                        candidates.extend(item.get(name) for name in ("type", "name", "value"))
                    if any(str(candidate or "").strip().lower() in {"whatsapp", "whats_app"} for candidate in candidates):
                        return True
                if isinstance(item, (dict, list)) and selected_in(item):
                    return True
        elif isinstance(value, list):
            return any(selected_in(item) for item in value if isinstance(item, (dict, list)))
        return False

    if selected_in(payload):
        return True
    lowered_url = str(url or "").strip().lower()
    if "/whatsapp" in lowered_url or "channel=whatsapp" in lowered_url:
        return True
    normalized_text = re.sub(r"\s+", " ", str(text or "")).strip().lower()
    forced_phrases = (
        "sent to whatsapp",
        "sent via whatsapp",
        "delivered to whatsapp",
        "delivered via whatsapp",
        "check your whatsapp",
        "check whatsapp",
        "open whatsapp",
    )
    return any(phrase in normalized_text for phrase in forced_phrases)


async def _submit_register_phone_if_required(
    *,
    request_ctx: Any,
    payload: Any,
    continue_url: str,
    phone_config: dict[str, Any],
    safe_email: str,
    trace: Any,
    log: Any,
    timeout_sec: float,
    otp_timeout_sec: float,
) -> dict[str, Any]:
    step = _registration_phone_step(payload, continue_url)
    if not step:
        return {
            "handled": False,
            "payload": payload if isinstance(payload, dict) else {},
            "continue_url": str(continue_url or "").strip(),
        }

    candidate: Any = None
    completed = False
    referer_url = str(continue_url or "").strip()

    async def cancel_candidate() -> None:
        nonlocal completed
        try:
            await asyncio.to_thread(blacklist_http_phone, candidate)
            completed = True
        except Exception:
            pass

    async def require_sms_send_result(send_result: dict[str, Any]) -> tuple[Any, str]:
        status = int(send_result.get("status") or 0)
        response_payload = send_result.get("payload")
        response_text = str(send_result.get("text") or "")
        problem = ""
        whatsapp = False
        if status not in _SUCCESS_STATUS:
            error_code, error_message = _extract_error(response_payload, response_text)
            problem = str(error_message or error_code or f"HTTP {status}")
        else:
            whatsapp = _registration_phone_forced_whatsapp(
                response_payload,
                text=response_text,
            )
            if whatsapp:
                problem = "phone provider was switched to WhatsApp instead of SMS"
        if not problem:
            return response_payload, response_text
        await cancel_candidate()
        if whatsapp:
            raise RuntimeError(f"http_register_add_phone_failed: {problem}")
        raise RuntimeError(f"http_register_add_phone_failed: phone send failed: {problem}")

    try:
        if step == "add_phone":
            candidate = await asyncio.to_thread(
                acquire_http_phone_candidate,
                dict(phone_config or {}),
                log_fn=log.info,
                owner_key=str(safe_email or "").strip(),
            )
            phone_number = str(getattr(candidate, "phone", "") or "").strip()
            if not phone_number:
                raise RuntimeError("http_register_add_phone_failed: phone provider returned an empty number")
            send_res = await _request_auth_api_with_context(
                request_ctx,
                stage="http_register_add_phone_send",
                path="/add-phone/send",
                method="POST",
                timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                trace=trace,
                referer_url=referer_url or "https://auth.openai.com/add-phone",
                json_body={"phone_number": phone_number},
                trace_json_body={"phone_number": "***"},
            )
        else:
            candidate = await asyncio.to_thread(
                acquire_pending_http_phone_candidate,
                dict(phone_config or {}),
                log_fn=log.info,
                owner_key=str(safe_email or "").strip(),
            )
            if candidate is None:
                raise RuntimeError(
                    "http_register_add_phone_failed: SMS channel selection has no pending phone activation"
                )
            send_res = await _request_auth_api_with_context(
                request_ctx,
                stage="http_register_phone_otp_select_sms",
                path="/phone-otp/select-channel",
                method="POST",
                timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                trace=trace,
                referer_url=referer_url or "https://auth.openai.com/phone-otp/select-channel",
                json_body={"channel": "sms"},
            )

        send_payload, _send_text = await require_sms_send_result(send_res)
        send_continue_url = str(_extract_continue_url(send_payload) or referer_url or "").strip()
        validation_referer = send_continue_url or referer_url
        sms_channel_selected = step == "select_channel"
        for navigation_index in range(3):
            resolved_url = ""
            resolved_text = ""
            if send_continue_url:
                resolved_url, resolved_text = await _open_continue_url(
                    request_ctx=request_ctx,
                    continue_url=send_continue_url,
                    trace=trace,
                    timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                    stage_name=f"http_register_phone_continue_{navigation_index + 1}",
                )
                validation_referer = resolved_url or send_continue_url
            navigation_step = _registration_phone_step(
                send_payload,
                resolved_url or send_continue_url,
            )
            if navigation_step == "select_channel" and not sms_channel_selected:
                select_res = await _request_auth_api_with_context(
                    request_ctx,
                    stage="http_register_phone_otp_select_sms",
                    path="/phone-otp/select-channel",
                    method="POST",
                    timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                    trace=trace,
                    referer_url=resolved_url or send_continue_url or "https://auth.openai.com/phone-otp/select-channel",
                    json_body={"channel": "sms"},
                )
                send_payload, _select_text = await require_sms_send_result(select_res)
                sms_channel_selected = True
                send_continue_url = str(_extract_continue_url(send_payload) or "").strip()
                if not send_continue_url:
                    break
                continue
            if _registration_phone_forced_whatsapp(
                send_payload,
                text=resolved_text,
                url=resolved_url or send_continue_url,
            ):
                await cancel_candidate()
                raise RuntimeError(
                    "http_register_add_phone_failed: phone page was switched to WhatsApp instead of SMS"
                )
            if navigation_step != "select_channel" or sms_channel_selected:
                break

        code = await asyncio.to_thread(
            wait_for_http_phone_code,
            candidate,
            timeout=int(max(30.0, float(otp_timeout_sec or 180.0))),
        )
        if not str(code or "").strip():
            raise RuntimeError("http_register_add_phone_failed: SMS verification code is empty")
        validate_res = await _request_auth_api_with_context(
            request_ctx,
            stage="http_register_phone_otp_validate",
            path="/phone-otp/validate",
            method="POST",
            timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
            trace=trace,
            referer_url=validation_referer or "https://auth.openai.com/phone-verification",
            json_body={"code": str(code).strip()},
            trace_json_body={"code": "***"},
        )
        validate_status = int(validate_res.get("status") or 0)
        validate_payload = validate_res.get("payload")
        validate_text = str(validate_res.get("text") or "")
        error_code, error_message = _extract_error(validate_payload, validate_text)
        if validate_status not in _SUCCESS_STATUS or error_code or error_message:
            detail = str(error_message or error_code or f"HTTP {validate_status}")
            raise RuntimeError(f"http_register_add_phone_failed: phone validation failed: {detail}")

        next_url = str(_extract_continue_url(validate_payload) or "").strip()
        resolved_url = ""
        resolved_text = ""
        if next_url:
            resolved_url, resolved_text = await _open_continue_url(
                request_ctx=request_ctx,
                continue_url=next_url,
                trace=trace,
                timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                stage_name="http_register_phone_validate_continue",
            )
        progress_url = str(resolved_url or next_url or "").strip()
        still_on_phone = bool(
            _registration_phone_step({}, progress_url)
            or _registration_phone_step(validate_payload, "")
            or _registration_phone_forced_whatsapp(
                validate_payload,
                text=resolved_text or validate_text,
                url=progress_url,
            )
        )
        if still_on_phone or not progress_url:
            raise RuntimeError(
                "http_register_add_phone_failed: phone validation did not leave the phone verification step"
            )

        await asyncio.to_thread(mark_http_phone_completed, candidate)
        completed = True
        trace.write(
            {
                "ts": _iso_now(),
                "stage": "http_register_phone_verified",
                "source": str(getattr(candidate, "source", "") or ""),
                "continueUrl": _sanitize_url_for_log(progress_url),
            }
        )
        log.info("[ChatGPT HTTP register] SMS phone verification completed.")
        return {
            "handled": True,
            "payload": validate_payload if isinstance(validate_payload, dict) else {},
            "continue_url": progress_url,
        }
    finally:
        if candidate is not None and not completed:
            try:
                await asyncio.to_thread(dispose_http_phone_after_failure, candidate)
            except Exception:
                pass


async def run_chatgpt_http_register(
    *,
    profile: ChatGptHttpRegisterProfile,
    config: ChatGptHttpRegisterConfig,
    logInfo: Optional[LogFn] = None,
    logWarn: Optional[LogFn] = None,
    logError: Optional[LogFn] = None,
    stageReporter: Optional[Callable[[dict[str, Any]], Any]] = None,
) -> ChatGptHttpRegisterResult:
    email = str(profile.email or "").strip().lower()
    password = str(profile.password or "")
    activate_http_stage_feature_session(email, "chatgpt_http_register")
    if (not email) or ("@" not in email):
        return _build_result(
            success=False,
            stage="validate_profile",
            error_code="invalid_email",
            message="HTTP 注册失败：邮箱格式不正确。",
            trace_path="",
        )
    if not str(password).strip():
        return _build_result(
            success=False,
            stage="validate_profile",
            error_code="missing_password",
            message="HTTP 注册失败：密码不能为空。",
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
    timeout_sec = max(60.0, min(float(config.timeoutSeconds or 360.0), 900.0))
    resolved_proxy_url = str(config.proxyUrl or "").strip() or str(
        resolve_proxy_for_url("https://auth.openai.com/create-account") or ""
    ).strip()
    resolved_impersonate = _resolve_http_provider_curl_impersonate()
    request_ctx = None
    last_known_url = ""
    bootstrap_authorize_url = ""
    account_creation_accepted = False
    remote_password_set = False
    remote_password_mode = "not_attempted"

    try:
        log.info(f"【ChatGPT HTTP 注册】开始纯 HTTP 注册：{safe_email}")
        request_ctx = await asyncio.to_thread(
            _build_http_provider_request_context,
            storage_state=_build_empty_storage_state_payload(),
            proxy_url=resolved_proxy_url,
            impersonate=resolved_impersonate,
        )
        trace.write(
            {
                "ts": _iso_now(),
                "stage": "http_register_context_ready",
                "proxy": _mask_proxy_url_for_log(resolved_proxy_url),
                "impersonate": resolved_impersonate or "",
                "storageStatePath": output_path,
                "stageFeature": get_http_stage_feature_summary(),
            }
        )

        sentinel_header_candidates: dict[str, list[tuple[str, dict[str, str]]]] = {}
        email_step_res: dict[str, Any] = {}
        for bootstrap_attempt in range(1, 3):
            boot_info = await _bootstrap_http_register_session(
                request_ctx=request_ctx,
                trace=trace,
                timeout_ms=min(int(timeout_sec * 1000.0), 60_000),
            )
            interactive_url = str(
                boot_info.get("registerUrl")
                or boot_info.get("loginUrl")
                or "https://auth.openai.com/create-account"
            ).strip()
            bootstrap_authorize_url = str(boot_info.get("authorizeUrl") or bootstrap_authorize_url or "").strip()
            last_known_url = interactive_url or last_known_url
            log.info(
                f"【ChatGPT HTTP 注册】初始化注册会话完成（attempt={bootstrap_attempt}/2, "
                f"hasAuthSession={bool(boot_info.get('hasAuthSessionCookie'))}）。"
            )
            await _report_http_stage(
                stageReporter,
                stage="bootstrap_session",
                step_name="初始化注册会话",
                current_url=interactive_url,
                detail=f"attempt={bootstrap_attempt}/2",
            )
            sentinel_header_candidates = await _collect_http_sentinel_header_candidates_for_flows(
                flow_names=(
                    _REGISTER_AUTHORIZE_FLOW,
                    _REGISTER_PASSWORD_FLOW,
                    _REGISTER_PROFILE_FLOW,
                ),
                playwright=None,
                storage_state_path="",
                proxy_opt=_build_playwright_proxy_option(resolved_proxy_url),
                trace=trace,
                timeout_ms=int(max(12_000, float(timeout_sec) * 1000.0 / 3.0)),
            )
            email_step_res = await _request_with_sentinel_candidates(
                request_ctx=request_ctx,
                stage_prefix="http_register_email",
                path="/authorize/continue",
                flow_name=_REGISTER_AUTHORIZE_FLOW,
                referer_url=interactive_url,
                request_bodies=(
                    {
                        "username": {"kind": "email", "value": email},
                        "screen_hint": "signup",
                    },
                    {
                        "username": {"kind": "email", "value": email},
                    },
                ),
                sentinel_candidates=list(sentinel_header_candidates.get(_REGISTER_AUTHORIZE_FLOW) or []),
                trace=trace,
                timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
            )
            error_code = str(email_step_res.get("errorCode") or "").strip()
            if int(email_step_res.get("status") or 0) in _SUCCESS_STATUS:
                break
            if error_code in {"invalid_state", "preauth_cookie_invalid"} and bootstrap_attempt < 2:
                log.warn("【ChatGPT HTTP 注册】注册 client/session 已失效，准备重建后重试。")
                continue
            err_message = str(email_step_res.get("errorMessage") or "").strip()
            email_status = int(email_step_res.get("status") or 0)
            return _build_result(
                success=False,
                stage="submit_email",
                error_code=error_code or "submit_email_failed",
                message=f"HTTP 注册失败：邮箱提交失败：{err_message or ('HTTP ' + str(email_status))}",
                trace_path=trace.path,
                extra={
                    "status": email_status,
                    "storageStatePath": output_path,
                },
            )

        email_payload = email_step_res.get("payload") if isinstance(email_step_res.get("payload"), dict) else {}
        email_continue_url = str(email_step_res.get("continueUrl") or _extract_continue_url(email_payload) or "").strip()
        last_known_url = email_continue_url or last_known_url
        await _report_http_stage(
            stageReporter,
            stage="submit_email",
            step_name="提交邮箱",
            current_url=email_continue_url or last_known_url,
        )
        # Follow the live password-first signup sequence: /user/register is
        # valid only while the authorization transaction is explicitly on the
        # create-account/password step.  Never retry it after OTP/about-you.
        password_submission_mode = _register_password_submission_mode(
            email_payload,
            email_continue_url,
        )
        if password_submission_mode == "signup_password_step":
            remote_password_mode = password_submission_mode
            await _report_http_stage(
                stageReporter,
                stage="submit_password",
                step_name="设置密码",
                current_url=email_continue_url or "https://auth.openai.com/create-account/password",
            )
            sentinel_header_candidates = await _refresh_register_sentinel_header_candidates(
                request_ctx=request_ctx,
                sentinel_header_candidates=sentinel_header_candidates,
                resolved_proxy_url=resolved_proxy_url,
                trace=trace,
                timeout_ms=int(max(12_000, float(timeout_sec) * 1000.0 / 3.0)),
                flow_names=(_REGISTER_PASSWORD_FLOW,),
            )
            password_res = await _submit_register_password_http(
                request_ctx=request_ctx,
                email=email,
                password=password,
                referer_url=email_continue_url or "https://auth.openai.com/create-account/password",
                sentinel_header_candidates=sentinel_header_candidates,
                trace=trace,
                timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
            )
            if not _register_password_response_accepted(password_res):
                password_status = int(password_res.get("status") or 0)
                password_error_message = str(password_res.get("errorMessage") or "").strip()
                return _build_result(
                    success=False,
                    stage="submit_password",
                    error_code="remote_password_not_set",
                    message=f"HTTP 注册失败：远端密码设置未被接受：{password_error_message or ('HTTP ' + str(password_status))}",
                    trace_path=trace.path,
                    extra={
                        "storageStatePath": output_path,
                        "remotePasswordSet": False,
                        "remotePasswordMode": remote_password_mode,
                        "remotePasswordErrorCode": str(password_res.get("errorCode") or ""),
                    },
                )
            remote_password_set = True
            account_creation_accepted = True
            email_payload = (
                password_res.get("payload")
                if isinstance(password_res.get("payload"), dict)
                else {}
            )
            email_continue_url = str(
                password_res.get("continueUrl")
                or _extract_continue_url(email_payload)
                or ""
            ).strip()
            last_known_url = email_continue_url or last_known_url
            await _report_http_stage(
                stageReporter,
                stage="password_submitted",
                step_name="远端密码设置完成",
                current_url=email_continue_url,
            )
        else:
            remote_password_mode = "not_attempted"
            trace.write(
                {
                    "ts": _iso_now(),
                    "stage": "http_register_password_skipped",
                    "reason": "remote_did_not_offer_password_step_before_email_otp",
                    "continueUrl": _sanitize_url_for_log(email_continue_url),
                    "pageType": _extract_auth_page_type(email_payload),
                }
            )

        email_otp_result = await _submit_http_otp_if_required(
            request_ctx=request_ctx,
            payload=email_payload,
            safe_email=email,
            trace=trace,
            log=log,
            timeout_sec=timeout_sec,
            otp_timeout_sec=float(config.otpTimeoutSeconds or 300.0),
            otp_interval_sec=float(config.otpIntervalSeconds or 3.0),
            normalized_totp_secret="",
            use_managed_mail_otp=bool(config.useManagedMailOtp),
            managed_mail_provider=str(config.managedMailProvider or "").strip(),
            managed_mail_jwt=str(config.managedMailJwt or "").strip(),
            managed_mail_api_base=str(config.managedMailApiBase or "").strip(),
            managed_mail_frontend_base=str(config.managedMailFrontendBase or "").strip(),
            managed_mail_latest_n=int(config.managedMailLatestN or 20),
            otp_api_url=str(config.otpApiUrl or "").strip(),
            use_domain_mail_otp=False,
            domain_mail_api_base="",
            domain_mail_domain="",
            domain_mail_token="",
            domain_mail_latest_n=20,
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
        )
        if bool(email_otp_result.get("handled")):
            resolved_email_payload = email_otp_result.get("payload")
            email_continue_url = str(email_otp_result.get("continue_url") or "").strip()
            if isinstance(resolved_email_payload, dict):
                email_payload = resolved_email_payload
            elif email_continue_url:
                email_payload = {"continue_url": email_continue_url}
            else:
                email_payload = {}
            last_known_url = email_continue_url or last_known_url
            await _report_http_stage(
                stageReporter,
                stage="email_otp_completed",
                step_name="邮箱 OTP 验证完成",
                current_url=email_continue_url,
        )

        final_payload = email_payload if isinstance(email_payload, dict) else {}
        final_continue_url = str(email_continue_url or _extract_continue_url(final_payload) or "").strip()
        password_submission_mode = _register_password_submission_mode(final_payload, final_continue_url)
        remote_password_mode = (
            remote_password_mode
            if remote_password_set
            else (
                "not_attempted"
                if password_submission_mode == "post_otp_about_you_recovery"
                else (password_submission_mode or "not_attempted")
            )
        )
        if password_submission_mode == "post_otp_about_you_recovery":
            trace.write(
                {
                    "ts": _iso_now(),
                    "stage": "http_register_password_skipped_after_otp",
                    "reason": "password_registration_is_only_valid_before_email_otp",
                    "continueUrl": _sanitize_url_for_log(final_continue_url),
                    "pageType": _extract_auth_page_type(final_payload),
                }
            )
        elif not password_submission_mode:
            trace.write(
                {
                    "ts": _iso_now(),
                    "stage": "http_register_password_step_missing",
                    "continueUrl": _sanitize_url_for_log(final_continue_url),
                    "pageType": _extract_auth_page_type(final_payload),
                }
            )
            return _build_result(
                success=False,
                stage="submit_password",
                error_code="remote_password_step_missing",
                message="HTTP 注册失败：远端未提供密码设置步骤，账号密码尚未生效。",
                trace_path=trace.path,
                extra={
                    "storageStatePath": output_path,
                    "remotePasswordSet": False,
                    "remotePasswordMode": remote_password_mode,
                },
            )

        await _report_http_stage(
            stageReporter,
            stage="submit_password",
            step_name=(
                "补设远端密码"
                if password_submission_mode == "post_otp_about_you_recovery"
                else "设置密码"
            ),
            current_url=email_continue_url or last_known_url,
        )
        sentinel_header_candidates = await _refresh_register_sentinel_header_candidates(
            request_ctx=request_ctx,
            sentinel_header_candidates=sentinel_header_candidates,
            resolved_proxy_url=resolved_proxy_url,
            trace=trace,
            timeout_ms=int(max(12_000, float(timeout_sec) * 1000.0 / 3.0)),
            flow_names=(_REGISTER_PASSWORD_FLOW,),
        )
        password_res = (
            {
                "status": 200,
                "payload": final_payload,
                "continueUrl": final_continue_url,
                "errorCode": "",
                "errorMessage": "",
            }
            if password_submission_mode == "post_otp_about_you_recovery"
            else await _submit_register_password_http(
                request_ctx=request_ctx,
                email=email,
                password=password,
                referer_url=final_continue_url or "https://auth.openai.com/create-account/password",
                sentinel_header_candidates=sentinel_header_candidates,
                trace=trace,
                timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
            )
        )
        if not _register_password_response_accepted(password_res):
            password_status = int(password_res.get("status") or 0)
            password_error_message = str(password_res.get("errorMessage") or "").strip()
            return _build_result(
                success=False,
                stage="submit_password",
                error_code="remote_password_not_set",
                message=f"HTTP 注册失败：远端密码设置未被接受：{password_error_message or ('HTTP ' + str(password_status))}",
                trace_path=trace.path,
                extra={
                    "storageStatePath": output_path,
                    "remotePasswordSet": False,
                    "remotePasswordMode": remote_password_mode,
                    "remotePasswordErrorCode": str(password_res.get("errorCode") or ""),
                },
            )
        remote_password_set = remote_password_set or password_submission_mode == "signup_password_step"
        # /user/register accepted the requested account credentials.  The
        # authenticated ChatGPT session can still be deferred (for example
        # when the next page is add-phone), so keep this evidence separate
        # from access-token readiness.
        account_creation_accepted = True

        submitted_payload = password_res.get("payload") if isinstance(password_res.get("payload"), dict) else {}
        submitted_continue_url = str(password_res.get("continueUrl") or _extract_continue_url(submitted_payload) or "").strip()
        if submitted_payload or submitted_continue_url or password_submission_mode != "post_otp_about_you_recovery":
            final_payload = submitted_payload
            final_continue_url = submitted_continue_url
        last_known_url = final_continue_url or last_known_url
        await _report_http_stage(
            stageReporter,
            stage="password_submitted",
            step_name="远端密码设置完成",
            current_url=final_continue_url,
        )
        final_otp_result = (
            await _submit_http_otp_if_required(
                request_ctx=request_ctx,
                payload=final_payload,
                safe_email=email,
                trace=trace,
                log=log,
                timeout_sec=timeout_sec,
                otp_timeout_sec=float(config.otpTimeoutSeconds or 300.0),
                otp_interval_sec=float(config.otpIntervalSeconds or 3.0),
                normalized_totp_secret="",
                use_managed_mail_otp=bool(config.useManagedMailOtp),
                managed_mail_provider=str(config.managedMailProvider or "").strip(),
                managed_mail_jwt=str(config.managedMailJwt or "").strip(),
                managed_mail_api_base=str(config.managedMailApiBase or "").strip(),
                managed_mail_frontend_base=str(config.managedMailFrontendBase or "").strip(),
                managed_mail_latest_n=int(config.managedMailLatestN or 20),
                otp_api_url=str(config.otpApiUrl or "").strip(),
                use_domain_mail_otp=False,
                domain_mail_api_base="",
                domain_mail_domain="",
                domain_mail_token="",
                domain_mail_latest_n=20,
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
                preferred_send_path="/email-otp/send",
            )
            if password_submission_mode == "signup_password_step"
            else {"handled": False}
        )
        if bool(final_otp_result.get("handled")):
            resolved_final_payload = final_otp_result.get("payload")
            resolved_final_continue_url = str(final_otp_result.get("continue_url") or "").strip()
            if isinstance(resolved_final_payload, dict):
                final_payload = resolved_final_payload
            elif resolved_final_continue_url:
                final_payload = {"continue_url": resolved_final_continue_url}
            if resolved_final_continue_url:
                final_continue_url = resolved_final_continue_url
            last_known_url = final_continue_url or last_known_url
            await _report_http_stage(
                stageReporter,
                stage="post_password_otp_completed",
                step_name="密码后 OTP 验证完成",
                current_url=final_continue_url,
            )

        stage = "submit_profile"
        full_name, birthdate = _resolve_profile_name_birthday(profile)
        if (not final_continue_url) and _payload_points_to_about_you(final_payload):
            final_continue_url = "https://auth.openai.com/about-you"
        if final_continue_url and ("/about-you" not in final_continue_url.lower()) and (not _payload_points_to_about_you(final_payload)):
            trace.write(
                {
                    "ts": _iso_now(),
                    "stage": "http_register_profile_skip_already_advanced",
                    "continueUrl": _sanitize_url_for_log(final_continue_url),
                    "pageType": _extract_auth_page_type(final_payload),
                }
            )
        else:
            await _report_http_stage(
                stageReporter,
                stage="submit_profile",
                step_name="填写资料",
                current_url=final_continue_url or "https://auth.openai.com/about-you",
            )
            profile_result: dict[str, Any] = {}
            if _prefer_direct_create_account():
                profile_result = await _submit_register_profile_http(
                    request_ctx=request_ctx,
                    continue_url=final_continue_url or "https://auth.openai.com/about-you",
                    full_name=full_name,
                    birthdate=birthdate,
                    sentinel_header_candidates=sentinel_header_candidates,
                    trace=trace,
                    timeout_sec=timeout_sec,
                    log=log,
                )
                if not bool(profile_result.get("ok")):
                    about_you_meta = profile_result.get("aboutYou") if isinstance(profile_result.get("aboutYou"), dict) else {}
                    profile_status = int(profile_result.get("status") or 0)
                    profile_error_message = str(profile_result.get("errorMessage") or "").strip()
                    return _build_result(
                        success=False,
                        stage=stage,
                        error_code=str(profile_result.get("errorCode") or "create_account_failed"),
                        message=f"HTTP ע��ʧ�ܣ������ύʧ�ܣ�{profile_error_message or ('HTTP ' + str(profile_status))}",
                        trace_path=trace.path,
                        extra={
                            "storageStatePath": output_path,
                            "remotePasswordSet": remote_password_set,
                            "remotePasswordMode": remote_password_mode,
                            "aboutYou": {
                                "attempted": bool(about_you_meta.get("attempted")),
                                "reason": str(about_you_meta.get("reason") or ""),
                                "afterUrl": str(about_you_meta.get("afterUrl") or ""),
                            },
                        },
                    )
            about_you_result = (
                {
                    "ok": True,
                    "afterPayload": profile_result.get("payload") if isinstance(profile_result.get("payload"), dict) else {},
                    "afterUrl": str(profile_result.get("continueUrl") or "").strip(),
                }
                if profile_result
                else await _submit_about_you_form_http(
                    request_ctx=request_ctx,
                    continue_url=final_continue_url or "https://auth.openai.com/about-you",
                    full_name=full_name,
                    birthdate=birthdate,
                    trace=trace,
                    timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                )
            )
            if bool(about_you_result.get("ok")):
                account_creation_accepted = True
                final_payload = (
                    about_you_result.get("afterPayload")
                    if isinstance(about_you_result.get("afterPayload"), dict)
                    else {}
                )
                final_continue_url = str(
                    _extract_continue_url(final_payload)
                    or about_you_result.get("afterUrl")
                    or final_continue_url
                    or ""
                ).strip()
                log.info("【ChatGPT HTTP 注册】about-you 表单已通过纯 HTTP 提交。")
            else:
                log.warn(
                    "【ChatGPT HTTP 注册】about-you 纯 HTTP 表单未推进，准备回退 create_account API。"
                    f"（reason={str(about_you_result.get('reason') or 'unknown')}）"
                )
                profile_res = await _request_with_sentinel_candidates(
                    request_ctx=request_ctx,
                    stage_prefix="http_register_profile",
                    path="/create_account",
                    flow_name=_REGISTER_PROFILE_FLOW,
                    referer_url=final_continue_url or "https://auth.openai.com/about-you",
                    request_bodies=(
                        {"name": full_name, "birthdate": birthdate},
                    ),
                    sentinel_candidates=list(sentinel_header_candidates.get(_REGISTER_PROFILE_FLOW) or []),
                    trace=trace,
                    timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                )
                if int(profile_res.get("status") or 0) not in _SUCCESS_STATUS:
                    profile_status = int(profile_res.get("status") or 0)
                    profile_error_message = str(profile_res.get("errorMessage") or "").strip()
                    return _build_result(
                        success=False,
                        stage=stage,
                        error_code=str(profile_res.get("errorCode") or "create_account_failed"),
                        message=f"HTTP 注册失败：资料提交失败：{profile_error_message or ('HTTP ' + str(profile_status))}",
                        trace_path=trace.path,
                        extra={
                            "storageStatePath": output_path,
                            "remotePasswordSet": remote_password_set,
                            "remotePasswordMode": remote_password_mode,
                            "aboutYou": {
                                "attempted": bool(about_you_result.get("attempted")),
                                "reason": str(about_you_result.get("reason") or ""),
                                "afterUrl": str(about_you_result.get("afterUrl") or ""),
                            },
                        },
                    )
                account_creation_accepted = True
                final_payload = profile_res.get("payload") if isinstance(profile_res.get("payload"), dict) else {}
                final_continue_url = str(profile_res.get("continueUrl") or _extract_continue_url(final_payload) or "").strip()

        registration_phone_step = _registration_phone_step(final_payload, final_continue_url)
        if registration_phone_step:
            # Reaching add-phone means the email/account portion advanced far
            # enough for a later, explicitly requested phone-binding pass.  Do
            # not rent a number from the registration flow itself.
            account_creation_accepted = True

        if final_continue_url:
            last_known_url = final_continue_url or last_known_url
            direct_token_result: dict[str, Any] = {}
            if _prefer_direct_register_token_exchange() and bootstrap_authorize_url:
                try:
                    direct_token_result = await _try_http_login_direct_token_exchange_from_continue_url(
                        request_ctx=request_ctx,
                        authorize_url=bootstrap_authorize_url,
                        continue_url=final_continue_url,
                        trace=trace,
                        timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                    )
                except Exception as error:
                    trace.write(
                        {
                            "ts": _iso_now(),
                            "stage": "http_register_direct_token_exchange_failed",
                            "continueUrl": _sanitize_url_for_log(final_continue_url),
                            "authorizeUrl": _sanitize_url_for_log(bootstrap_authorize_url),
                            "error": _compress_debug_text(str(error or ""), limit=240),
                        }
                    )
                    direct_token_result = {}
            direct_session_payload = (
                direct_token_result.get("sessionPayload")
                if isinstance(direct_token_result.get("sessionPayload"), dict)
                else {}
            )
            if direct_session_payload and extract_access_token_from_session_payload(direct_session_payload):
                finalize_result = await _finalize_http_register_storage_state_fast(
                    request_ctx=request_ctx,
                    trace=trace,
                    output_path=output_path,
                    session_payload=direct_session_payload,
                    session_status=int(direct_token_result.get("status") or 200),
                    session_error="",
                )
                request_ctx = finalize_result.get("requestCtx")
                session_payload = finalize_result.get("sessionPayload") if isinstance(finalize_result.get("sessionPayload"), dict) else {}
                summary = dict(finalize_result.get("sessionSummary") or {})
                session_status = int(finalize_result.get("sessionStatus") or 0)
                session_snapshot_path = str(finalize_result.get("sessionSnapshotPath") or "").strip()
                codex_token_json_path = str(finalize_result.get("codexTokenJsonPath") or "").strip()
                codex_token_txt_path = str(finalize_result.get("codexTokenTxtPath") or "").strip()
                codex_token_created = bool(finalize_result.get("codexTokenCreated"))
                access_token_present = bool(extract_access_token_from_session_payload(session_payload))
                log.success(f"【ChatGPT HTTP 注册】注册成功，已写入完整登录态：{safe_email}")
                await _report_http_stage(
                    stageReporter,
                    stage="registration_authenticated",
                    step_name="注册完成",
                    current_url=final_continue_url or last_known_url,
                )
                return _build_result(
                    success=True,
                    stage="registration_authenticated",
                    error_code="",
                    message=f"HTTP 注册成功：已写入完整登录态（{safe_email}）。",
                    trace_path=trace.path,
                    extra={
                        "storageStatePath": output_path,
                        "sessionStatus": session_status,
                        "sessionSummary": summary,
                        "accessTokenPresent": access_token_present,
                        "sessionSnapshotPath": session_snapshot_path,
                        "codexTokenJsonPath": codex_token_json_path,
                        "codexTokenTxtPath": codex_token_txt_path,
                        "codexTokenCreated": codex_token_created,
                        "accountCreationAccepted": True,
                        "phoneRequired": False,
                        "remotePasswordSet": remote_password_set,
                        "remotePasswordMode": remote_password_mode,
                    },
                )
            await _report_http_stage(
                stageReporter,
                stage="finalize_continue",
                step_name="进入完成页",
                current_url=final_continue_url,
            )
            try:
                await _open_continue_url(
                    request_ctx=request_ctx,
                    continue_url=final_continue_url,
                    trace=trace,
                    timeout_ms=int(max(15_000, float(timeout_sec) * 1000.0 / 3.0)),
                    stage_name="http_register_finalize_continue_url",
                )
            except Exception as error:
                trace.write(
                    {
                        "ts": _iso_now(),
                        "stage": "http_register_finalize_continue_url_failed",
                        "continueUrl": _sanitize_url_for_log(final_continue_url),
                        "error": _compress_debug_text(str(error or ""), limit=240),
                    }
                )

        finalize_result = await _finalize_http_register_storage_state(
            request_ctx=request_ctx,
            trace=trace,
            output_path=output_path,
            timeout_sec=timeout_sec,
            proxy_url=resolved_proxy_url,
            impersonate=resolved_impersonate,
        )
        request_ctx = finalize_result.get("requestCtx")
        session_payload = finalize_result.get("sessionPayload") if isinstance(finalize_result.get("sessionPayload"), dict) else {}
        summary = dict(finalize_result.get("sessionSummary") or {})
        session_status = int(finalize_result.get("sessionStatus") or 0)
        session_snapshot_path = str(finalize_result.get("sessionSnapshotPath") or "").strip()
        codex_token_json_path = str(finalize_result.get("codexTokenJsonPath") or "").strip()
        codex_token_txt_path = str(finalize_result.get("codexTokenTxtPath") or "").strip()
        codex_token_created = bool(finalize_result.get("codexTokenCreated"))
        access_token_present = bool(extract_access_token_from_session_payload(session_payload))
        if access_token_present:
            completion_stage = "registration_authenticated"
            completion_error_code = ""
            completion_message = f"HTTP 注册成功：已写入完整登录态（{safe_email}）。"
            completion_success = True
            completion_step_name = "注册完成"
            log.success(f"【ChatGPT HTTP 注册】注册成功，已写入完整登录态：{safe_email}")
        elif registration_phone_step:
            completion_stage = "registration_phone_required"
            completion_error_code = "phone_required"
            completion_message = "邮箱注册阶段已完成，平台要求绑定手机号；已停止在后期绑号步骤，未自动租号。"
            completion_success = False
            completion_step_name = "等待后期绑定手机号"
            log.warn("【ChatGPT HTTP 注册】邮箱阶段已完成，当前停在 add-phone；注册流程未调用接码服务。")
        elif account_creation_accepted:
            completion_stage = "registration_session_pending"
            completion_error_code = "session_missing"
            completion_message = "账号创建请求已被接受，但登录 Session 尚未返回 accessToken。"
            completion_success = False
            completion_step_name = "等待补全登录态"
            log.warn("【ChatGPT HTTP 注册】账号创建请求已被接受，但完整登录 Session 尚未建立。")
        else:
            completion_stage = "registration_state_ambiguous"
            completion_error_code = "session_missing"
            completion_message = "邮箱注册流程已推进，但无法确认账号创建状态，且登录 Session 未返回 accessToken。"
            completion_success = False
            completion_step_name = "等待确认注册状态"
            log.warn("【ChatGPT HTTP 注册】流程已推进，但无法确认账号创建状态，且 Session 尚未建立。")
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
            message=completion_message,
            trace_path=trace.path,
            extra={
                "storageStatePath": output_path,
                "sessionStatus": session_status,
                "sessionSummary": summary,
                "accessTokenPresent": access_token_present,
                "sessionSnapshotPath": session_snapshot_path,
                "codexTokenJsonPath": codex_token_json_path,
                "codexTokenTxtPath": codex_token_txt_path,
                "codexTokenCreated": codex_token_created,
                "accountCreationAccepted": bool(account_creation_accepted),
                "phoneRequired": bool(registration_phone_step),
                "remotePasswordSet": remote_password_set,
                "remotePasswordMode": remote_password_mode,
            },
        )
    except Exception as error:
        error_text = str(error or "").strip()
        error_code = "http_register_failed"
        stage = "exception"
        message_text = error_text or "unknown"
        if ":" in error_text:
            prefix, suffix = error_text.split(":", 1)
            normalized_prefix = str(prefix or "").strip()
            normalized_suffix = str(suffix or "").strip()
            if normalized_prefix:
                error_code = normalized_prefix
            if normalized_suffix:
                message_text = normalized_suffix
        await _report_http_stage(
            stageReporter,
            stage="exception",
            step_name="注册失败",
            current_url=last_known_url,
            error_message=error_text,
        )
        trace.write(
            {
                "ts": _iso_now(),
                "stage": "http_register_exception",
                "error": _compress_debug_text(error_text, limit=320),
            }
        )
        log.error(f"【ChatGPT HTTP 注册】失败：{error_text}")
        return _build_result(
            success=False,
            stage=stage,
            error_code=error_code,
            message=f"HTTP 注册失败：{message_text}",
            trace_path=trace.path,
            extra={"storageStatePath": output_path},
        )
    finally:
        if request_ctx is not None:
            try:
                await request_ctx.dispose()
            except Exception:
                pass
