from __future__ import annotations

import datetime
import dataclasses
import hashlib
import html
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from email import message_from_string
from email.header import decode_header
from email.message import Message
from email.utils import getaddresses, parsedate_to_datetime
from typing import Any, Callable, Optional

from code_utils import extractVerificationCode

try:
    from curl_cffi import requests as curl_cffi_requests
except Exception:
    curl_cffi_requests = None  # type: ignore[assignment]


LogFn = Callable[[str], None]

_DEFAULT_CODE_KEYWORDS = [
    "ChatGPT",
    "OpenAI",
    "验证码",
    "验证码",
    "verification",
    "verify",
    "code",
    "安全代码",
    "安全代码",
]
_EMAIL_RE = re.compile(r"(?i)([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,})")
_MANAGED_MAIL_CURL_IMPERSONATE_CANDIDATES: tuple[str, ...] = ("chrome142", "chrome136", "chrome133a", "chrome131")
_DEFAULT_MANAGED_MAIL_PROVIDER = "cloudflare_temp_email"


@dataclasses.dataclass(frozen=True, slots=True)
class _ManagedMailStoreRef:
    store_key: str
    record_id: str


def _resolve_managed_mail_browser_identity_headers(impersonate: str = "") -> dict[str, str]:
    normalized = str(impersonate or "").strip().lower()
    matched = re.search(r"chrome(\d+)", normalized)
    major = str(matched.group(1) or "").strip() if matched else ""
    if not major:
        major = "136"
    return {
        "user-agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{major}.0.0.0 Safari/537.36"
        ),
        "sec-ch-ua": f'"Chromium";v="{major}", "Not-A.Brand";v="24", "Google Chrome";v="{major}"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
    }


def _safe_log(fn: Optional[LogFn], message: str) -> None:
    if not callable(fn):
        return
    try:
        fn(str(message or "").strip())
    except Exception:
        return


def _normalize_external_base_url(raw: str, *, default: str = "") -> str:
    text = str(raw or "").strip() or str(default or "").strip()
    if not text:
        return ""
    return text.rstrip("/")


def _parse_optional_env_flag(raw: Any) -> bool | None:
    text = str(raw or "").strip().lower()
    if not text:
        return None
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return None


def _get_managed_mail_domain() -> str:
    return (
        str(os.getenv("AIO_TEMP_MAIL_DOMAIN") or os.getenv("TEMP_MAIL_DOMAIN") or "lhyaaa.indevs.in")
        .strip()
        .lower()
        .lstrip("@")
    )


def _get_managed_mail_api_base() -> str:
    return _normalize_external_base_url(
        str(os.getenv("AIO_TEMP_MAIL_API_BASE") or os.getenv("TEMP_MAIL_API_BASE") or "").strip(),
        default="https://apimail.lhyaaa.indevs.in",
    )


def _get_managed_mail_frontend_base() -> str:
    return _normalize_external_base_url(
        str(os.getenv("AIO_TEMP_MAIL_FRONTEND_BASE") or os.getenv("TEMP_MAIL_FRONTEND_BASE") or "").strip(),
        default="https://mail.lhyaaa.indevs.in",
    )


def _get_managed_mail_provider() -> str:
    return str(
        os.getenv("AIO_TEMP_MAIL_PROVIDER")
        or os.getenv("TEMP_MAIL_PROVIDER")
        or _DEFAULT_MANAGED_MAIL_PROVIDER
    ).strip() or _DEFAULT_MANAGED_MAIL_PROVIDER


def _build_managed_mail_view_url(*, mail_jwt: str, frontend_base: str = "") -> str:
    base = _normalize_external_base_url(str(frontend_base or "").strip(), default=_get_managed_mail_frontend_base())
    token = str(mail_jwt or "").strip()
    if not base:
        return ""
    if not token:
        return base
    return f"{base}/?jwt={urllib.parse.quote(token, safe='')}"


def is_email_otp_imap_fallback_enabled(default: bool = False) -> bool:
    forced = _parse_optional_env_flag(os.getenv("AIO_EMAIL_OTP_IMAP_FALLBACK_ENABLED") or "")
    if forced is None:
        return bool(default)
    return bool(forced)


def should_auto_repair_managed_mail_jwt(email: str) -> bool:
    normalized_email = str(email or "").strip().lower()
    if ("@" not in normalized_email) or (not normalized_email):
        return False
    _, email_domain = normalized_email.rsplit("@", 1)
    forced = _parse_optional_env_flag(
        os.getenv("AIO_TEMP_MAIL_ENABLE_NEW_POOL_JWT") or os.getenv("TEMP_MAIL_ENABLE_NEW_POOL_JWT") or ""
    )
    if forced is not None:
        return bool(forced)
    managed_domain = _get_managed_mail_domain()
    return bool(email_domain and managed_domain and email_domain == managed_domain)


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(str(text or "").encode("utf-8")).hexdigest()


def _normalize_profile(profile: Any) -> dict[str, str]:
    if not isinstance(profile, dict):
        profile = {}
    mail_jwt = str(profile.get("mail_jwt") or profile.get("mailJwt") or "").strip()
    mail_api_base = _normalize_external_base_url(
        str(profile.get("mail_api_base") or profile.get("mailApiBase") or "").strip(),
        default=_get_managed_mail_api_base() if mail_jwt else "",
    )
    mail_frontend_base = _normalize_external_base_url(
        str(profile.get("mail_frontend_base") or profile.get("mailFrontendBase") or "").strip(),
        default=_get_managed_mail_frontend_base() if mail_jwt else "",
    )
    mail_provider = str(profile.get("mail_provider") or profile.get("mailProvider") or "").strip()
    if mail_jwt and (not mail_provider):
        mail_provider = _get_managed_mail_provider()
    return {
        "mail_provider": mail_provider,
        "mail_jwt": mail_jwt,
        "mail_api_base": mail_api_base,
        "mail_frontend_base": mail_frontend_base,
        "mail_view_url": _build_managed_mail_view_url(mail_jwt=mail_jwt, frontend_base=mail_frontend_base),
    }


def _extract_profile_from_entity(entity: Any) -> dict[str, str]:
    return _normalize_profile(
        {
            "mail_provider": getattr(entity, "mail_provider", ""),
            "mail_jwt": getattr(entity, "mail_jwt", ""),
            "mail_api_base": getattr(entity, "mail_api_base", ""),
            "mail_frontend_base": getattr(entity, "mail_frontend_base", ""),
        }
    )


def _decode_mime_words(value: str) -> str:
    if not value:
        return ""
    parts = decode_header(value)
    out: list[str] = []
    for text, enc in parts:
        if isinstance(text, bytes):
            out.append(text.decode(enc or "utf-8", errors="replace"))
        else:
            out.append(str(text))
    return "".join(out)


def _html_to_text(value: str) -> str:
    if not value:
        return ""
    text = str(value)
    text = re.sub(r"(?is)<(script|style)\b.*?>.*?</\1>", " ", text)
    text = re.sub(r"(?is)<br\b[^>]*>", "\n", text)
    text = re.sub(r"(?is)</p\s*>", "\n", text)
    text = re.sub(r"(?is)</div\s*>", "\n", text)
    text = re.sub(r"(?is)<[^>]+>", " ", text)
    text = html.unescape(text)
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    text = re.sub(r"\n\s*", "\n", text)
    return text.strip()


def _get_text_body(msg: Message) -> str:
    if msg.is_multipart():
        for part in msg.walk():
            ctype = str(part.get_content_type() or "").strip().lower()
            disp = str(part.get("Content-Disposition", "") or "")
            if ctype == "text/plain" and "attachment" not in disp.lower():
                payload = part.get_payload(decode=True) or b""
                charset = part.get_content_charset() or "utf-8"
                return payload.decode(charset, errors="replace")
        for part in msg.walk():
            ctype = str(part.get_content_type() or "").strip().lower()
            disp = str(part.get("Content-Disposition", "") or "")
            if ctype == "text/html" and "attachment" not in disp.lower():
                payload = part.get_payload(decode=True) or b""
                charset = part.get_content_charset() or "utf-8"
                return _html_to_text(payload.decode(charset, errors="replace"))
    else:
        payload = msg.get_payload(decode=True) or b""
        charset = msg.get_content_charset() or "utf-8"
        text = payload.decode(charset, errors="replace")
        if str(msg.get_content_type() or "").strip().lower() == "text/html":
            return _html_to_text(text)
        return text
    return ""


def _collect_recipient_emails(msg: Message, fallback_address: str = "") -> set[str]:
    emails: set[str] = set()
    if str(fallback_address or "").strip():
        emails.add(str(fallback_address or "").strip().lower())

    headers_to_check = (
        "To",
        "Cc",
        "Delivered-To",
        "Envelope-To",
        "X-Envelope-To",
        "X-Original-To",
        "X-Forwarded-To",
        "X-Real-To",
        "X-Rcpt-To",
        "Original-Recipient",
        "Final-Recipient",
    )
    for header_name in headers_to_check:
        value = msg.get(header_name)
        if not value:
            continue
        decoded = _decode_mime_words(str(value))
        for _name, address in getaddresses([decoded]):
            if address:
                emails.add(str(address).strip().lower())
        for address in _EMAIL_RE.findall(decoded):
            emails.add(str(address).strip().lower())
    return emails


def _extract_message_timestamp(mail: dict[str, Any], msg: Message | None) -> float:
    raw_created_at = str(mail.get("created_at") or mail.get("createdAt") or "").strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        if raw_created_at:
            try:
                dt = datetime.datetime.strptime(raw_created_at, fmt).replace(tzinfo=datetime.timezone.utc)
                return float(dt.timestamp())
            except Exception:
                pass
    if msg is not None:
        try:
            raw_date = str(msg.get("Date", "") or "").strip()
            if raw_date:
                return float(parsedate_to_datetime(raw_date).timestamp())
        except Exception:
            pass
    return 0.0


def _perform_managed_mail_json_request(
    *,
    method: str,
    mail_api_base: str,
    path: str,
    mail_frontend_base: str = "",
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
    timeout: float = 30.0,
) -> tuple[int, dict[str, Any], str]:
    base = str(mail_api_base or "").strip().rstrip("/")
    if not base:
        return 0, {}, "managed_mail_api_base_missing"
    target_url = f"{base}{path}"
    request_method = str(method or "GET").upper()
    request_headers = {"accept": "application/json"}
    if isinstance(headers, dict):
        request_headers.update({str(k): str(v) for k, v in headers.items() if str(v or "").strip()})
    frontend_base = str(mail_frontend_base or "").strip().rstrip("/")
    if frontend_base:
        request_headers.setdefault("origin", frontend_base)
        request_headers.setdefault("referer", f"{frontend_base}/")
    browser_identity_headers = _resolve_managed_mail_browser_identity_headers()
    request_headers.setdefault("user-agent", str(browser_identity_headers.get("user-agent") or "").strip() or "Mozilla/5.0")
    payload_bytes: bytes | None = None
    if body is not None:
        request_headers.setdefault("content-type", "application/json")
        payload_bytes = json.dumps(body, ensure_ascii=False).encode("utf-8")

    def _normalize_response(status_code: int, raw_text: str) -> tuple[int, dict[str, Any], str]:
        try:
            payload = json.loads(raw_text or "{}")
        except Exception:
            payload = {}
        if not isinstance(payload, dict):
            payload = {"raw": payload}
        return int(status_code or 0), payload, raw_text

    curl_last_result: tuple[int, dict[str, Any], str] | None = None
    if curl_cffi_requests is not None:
        for impersonate in _MANAGED_MAIL_CURL_IMPERSONATE_CANDIDATES:
            try:
                curl_headers = dict(request_headers)
                impersonated_headers = _resolve_managed_mail_browser_identity_headers(impersonate)
                curl_headers["user-agent"] = str(impersonated_headers.get("user-agent") or curl_headers.get("user-agent") or "Mozilla/5.0")
                response = curl_cffi_requests.request(
                    request_method,
                    target_url,
                    headers=curl_headers,
                    data=payload_bytes,
                    timeout=max(5.0, float(timeout or 0.0)),
                    allow_redirects=False,
                    default_headers=False,
                    impersonate=str(impersonate or "").strip() or None,
                )
                status_code = int(getattr(response, "status_code", 0) or 0)
                raw_text = str(getattr(response, "text", "") or "")
                normalized = _normalize_response(status_code, raw_text)
                if 200 <= status_code < 400:
                    return normalized
                curl_last_result = normalized
            except Exception:
                continue

    req = urllib.request.Request(target_url, data=payload_bytes, headers=request_headers, method=request_method)
    try:
        with urllib.request.urlopen(req, timeout=max(5.0, float(timeout or 0.0))) as resp:
            raw_text = resp.read().decode("utf-8", errors="ignore")
            status_code = int(getattr(resp, "status", 200) or 200)
    except urllib.error.HTTPError as error:
        status_code = int(getattr(error, "code", 500) or 500)
        try:
            raw_text = error.read().decode("utf-8", errors="ignore")
        except Exception:
            raw_text = str(error or "")
    except Exception as error:
        return 0, {}, str(error or "")
    normalized = _normalize_response(status_code, raw_text)
    if 200 <= int(status_code or 0) < 400:
        return normalized
    return curl_last_result or normalized


def poll_managed_mail_verification_code_sync(
    *,
    email: str,
    mail_jwt: str,
    mail_api_base: str,
    mail_frontend_base: str = "",
    mail_provider: str = "",
    otp_timeout_sec: float,
    otp_interval_sec: float,
    blocked_codes: set[str] | None = None,
    not_before_ts: float = 0.0,
    latest_n: int = 20,
    log_info: Optional[LogFn] = None,
    log_warn: Optional[LogFn] = None,
) -> str:
    normalized_email = str(email or "").strip().lower()
    token = str(mail_jwt or "").strip()
    api_base = str(mail_api_base or "").strip()
    if not token or not api_base:
        return ""

    blocked = blocked_codes or set()
    poll_limit = max(1, min(int(latest_n or 20), 100))
    deadline = time.time() + max(3.0, float(otp_timeout_sec or 120.0))
    poll_interval = max(1.0, float(otp_interval_sec or 3.0))

    _safe_log(
        log_info,
        (
            "开始通过托管邮箱 JWT 自动取码："
            f"provider={str(mail_provider or '').strip() or 'managed_mail'}，target={normalized_email or 'current_mailbox'}"
        ),
    )

    while time.time() <= deadline:
        query_string = urllib.parse.urlencode({"limit": poll_limit, "offset": 0})
        status_code, payload, raw_text = _perform_managed_mail_json_request(
            method="GET",
            mail_api_base=api_base,
            mail_frontend_base=mail_frontend_base,
            path=f"/api/mails?{query_string}",
            headers={"authorization": f"Bearer {token}"},
            timeout=min(20.0, max(5.0, poll_interval + 5.0)),
        )
        mails_payload = payload.get("mails")
        if not isinstance(mails_payload, list):
            mails_payload = payload.get("results")
        mails = mails_payload if isinstance(mails_payload, list) else []
        if status_code and status_code < 400:
            for mail in mails:
                if not isinstance(mail, dict):
                    continue
                raw_mail = str(mail.get("raw") or "").strip()
                try:
                    msg = message_from_string(raw_mail) if raw_mail else None
                except Exception:
                    msg = None
                received_ts = _extract_message_timestamp(mail, msg)
                if received_ts and received_ts < float(not_before_ts or 0.0):
                    continue
                recipients = _collect_recipient_emails(msg, fallback_address=str(mail.get("address") or ""))
                if normalized_email and recipients and normalized_email not in recipients:
                    continue
                subject = _decode_mime_words(str(msg.get("Subject", "") or "")) if msg is not None else ""
                body_text = _get_text_body(msg) if msg is not None else ""
                searchable_text = "\n".join(part for part in (subject, body_text) if str(part or "").strip())
                code_value = extractVerificationCode(
                    searchable_text,
                    keywords=list(_DEFAULT_CODE_KEYWORDS),
                    blockedCodes=blocked,
                )
                if code_value:
                    _safe_log(log_info, f"托管邮箱 JWT 已获取到验证码：target={normalized_email or 'current_mailbox'}")
                    return str(code_value).strip()
        else:
            _safe_log(
                log_warn,
                f"托管邮箱 JWT 取码请求失败：status={int(status_code or 0)}，detail={str(payload.get('message') or raw_text or '').strip()}",
            )
        time.sleep(poll_interval)

    _safe_log(log_warn, f"托管邮箱 JWT 在超时内未获取到可用验证码：target={normalized_email or 'current_mailbox'}")
    return ""


def _collect_team_store_candidate(
    *,
    store: Any,
    store_key: str,
    normalized_email: str,
    refs: list[_ManagedMailStoreRef],
    password_candidates: list[str],
) -> dict[str, str]:
    if store is None:
        return {}
    try:
        entity = store.find_team_by_email(normalized_email)
    except Exception:
        entity = None
    if entity is None:
        return {}
    record_id = str(getattr(entity, "team_id", "") or "").strip()
    if record_id:
        refs.append(_ManagedMailStoreRef(store_key=store_key, record_id=record_id))
    password_value = ""
    try:
        password_value = str(getattr(store, "get_team_password")(record_id) or "").strip() if record_id else ""
    except Exception:
        password_value = ""
    if not password_value:
        password_value = str(getattr(entity, "password", "") or "").strip()
    if password_value:
        password_candidates.append(password_value)
    return _extract_profile_from_entity(entity)


def _collect_account_store_candidate(
    *,
    store: Any,
    store_key: str,
    normalized_email: str,
    refs: list[_ManagedMailStoreRef],
    password_candidates: list[str],
) -> dict[str, str]:
    if store is None:
        return {}
    try:
        accounts = list(getattr(store, "list_accounts")() or [])
    except Exception:
        accounts = []
    first_profile: dict[str, str] = {}
    for account in accounts:
        account_email = str(getattr(account, "email", "") or "").strip().lower()
        if account_email != normalized_email:
            continue
        record_id = str(getattr(account, "slot_id", "") or "").strip()
        if record_id:
            refs.append(_ManagedMailStoreRef(store_key=store_key, record_id=record_id))
        password_value = str(getattr(account, "password", "") or "").strip()
        if password_value:
            password_candidates.append(password_value)
        profile = _extract_profile_from_entity(account)
        if str(profile.get("mail_jwt") or "").strip():
            return profile
        if not first_profile:
            first_profile = profile
    return first_profile


def _patch_store_mail_profile(
    *,
    store: Any,
    ref: _ManagedMailStoreRef,
    profile: dict[str, str],
) -> None:
    if store is None:
        return
    payload = {
        "mail_provider": str(profile.get("mail_provider") or "").strip(),
        "mail_jwt": str(profile.get("mail_jwt") or "").strip(),
        "mail_api_base": str(profile.get("mail_api_base") or "").strip(),
        "mail_frontend_base": str(profile.get("mail_frontend_base") or "").strip(),
    }
    if not payload["mail_jwt"]:
        return
    try:
        if ref.store_key in {"team_pool", "new_pool"}:
            getattr(store, "patch_team")(ref.record_id, **payload)
        else:
            getattr(store, "patch_account")(ref.record_id, **payload)
    except Exception:
        return


def _apply_mail_profile_to_refs(
    *,
    refs: list[_ManagedMailStoreRef],
    profile: dict[str, str],
    team_store: Any = None,
    new_account_store: Any = None,
    personal_pool_store: Any = None,
    personal_master_pool_store: Any = None,
) -> None:
    stores = {
        "team_pool": team_store,
        "new_pool": new_account_store,
        "personal_pool": personal_pool_store,
        "personal_master_pool": personal_master_pool_store,
    }
    for ref in refs:
        _patch_store_mail_profile(store=stores.get(ref.store_key), ref=ref, profile=profile)


def _try_address_login_sync(*, email: str, password: str) -> tuple[int, dict[str, Any], str]:
    return _perform_managed_mail_json_request(
        method="POST",
        mail_api_base=_get_managed_mail_api_base(),
        mail_frontend_base=_get_managed_mail_frontend_base(),
        path="/api/address_login",
        body={"email": email, "password": _sha256_hex(password)},
    )


def _create_address_sync(*, email: str) -> tuple[int, dict[str, Any], str]:
    local_part, domain = str(email or "").strip().lower().split("@", 1)
    return _perform_managed_mail_json_request(
        method="POST",
        mail_api_base=_get_managed_mail_api_base(),
        mail_frontend_base=_get_managed_mail_frontend_base(),
        path="/api/new_address",
        body={"name": local_part, "domain": domain},
    )


def _change_address_password_sync(*, jwt: str, old_password: str, new_password: str) -> tuple[int, dict[str, Any], str]:
    return _perform_managed_mail_json_request(
        method="POST",
        mail_api_base=_get_managed_mail_api_base(),
        mail_frontend_base=_get_managed_mail_frontend_base(),
        path="/api/address_change_password",
        headers={"authorization": f"Bearer {jwt}"},
        body={
            "old_password": _sha256_hex(old_password),
            "new_password": _sha256_hex(new_password),
        },
    )


def _repair_managed_mail_profile_sync(
    *,
    normalized_email: str,
    password_candidates: list[str],
    log_info: Optional[LogFn] = None,
    log_warn: Optional[LogFn] = None,
) -> dict[str, str]:
    desired_password = ""
    for candidate in password_candidates:
        text = str(candidate or "").strip()
        if text:
            desired_password = text
            break

    api_base = _get_managed_mail_api_base()
    frontend_base = _get_managed_mail_frontend_base()
    provider = _get_managed_mail_provider()
    last_error = ""

    if desired_password:
        login_status, login_payload, login_raw = _try_address_login_sync(email=normalized_email, password=desired_password)
        login_jwt = str(login_payload.get("jwt") or "").strip()
        if login_status == 200 and login_jwt:
            _safe_log(log_info, f"托管邮箱 JWT 自动补齐成功：已通过地址密码登录恢复 JWT，target={normalized_email}")
            return {
                "mail_provider": provider,
                "mail_jwt": login_jwt,
                "mail_api_base": api_base,
                "mail_frontend_base": frontend_base,
                "mail_view_url": _build_managed_mail_view_url(mail_jwt=login_jwt, frontend_base=frontend_base),
                "repair_mode": "address_login",
            }
        last_error = str(login_payload.get("message") or login_raw or f"HTTP {login_status or 0}").strip()

    create_status, create_payload, create_raw = _create_address_sync(email=normalized_email)
    created_jwt = str(create_payload.get("jwt") or "").strip()
    created_address = str(create_payload.get("address") or "").strip().lower()
    created_password = str(create_payload.get("password") or "").strip()
    if create_status == 200 and created_jwt and created_address == normalized_email:
        if desired_password and created_password:
            change_status, _change_payload, change_raw = _change_address_password_sync(
                jwt=created_jwt,
                old_password=created_password,
                new_password=desired_password,
            )
            if change_status == 200:
                verify_status, verify_payload, verify_raw = _try_address_login_sync(
                    email=normalized_email,
                    password=desired_password,
                )
                verify_jwt = str(verify_payload.get("jwt") or "").strip()
                if verify_status == 200 and verify_jwt:
                    _safe_log(log_info, f"托管邮箱 JWT 自动补齐成功：已重建地址并同步邮箱密码，target={normalized_email}")
                    return {
                        "mail_provider": provider,
                        "mail_jwt": verify_jwt,
                        "mail_api_base": api_base,
                        "mail_frontend_base": frontend_base,
                        "mail_view_url": _build_managed_mail_view_url(mail_jwt=verify_jwt, frontend_base=frontend_base),
                        "repair_mode": "created_and_synced_password",
                    }
                last_error = str(verify_payload.get("message") or verify_raw or f"HTTP {verify_status or 0}").strip()
            else:
                last_error = str(change_raw or f"HTTP {change_status or 0}").strip()
        _safe_log(log_info, f"托管邮箱 JWT 自动补齐成功：已重建地址并拿到 JWT，target={normalized_email}")
        return {
            "mail_provider": provider,
            "mail_jwt": created_jwt,
            "mail_api_base": api_base,
            "mail_frontend_base": frontend_base,
            "mail_view_url": _build_managed_mail_view_url(mail_jwt=created_jwt, frontend_base=frontend_base),
            "repair_mode": "created_with_generated_password",
        }

    last_error = str(create_payload.get("message") or create_raw or f"HTTP {create_status or 0}").strip() or last_error
    _safe_log(
        log_warn,
        f"托管邮箱 JWT 自动补齐失败：target={normalized_email}，detail={last_error or 'unknown'}",
    )
    return {
        "mail_provider": provider,
        "mail_jwt": "",
        "mail_api_base": api_base,
        "mail_frontend_base": frontend_base,
        "mail_view_url": "",
        "repair_mode": "",
        "error": last_error,
    }


def resolve_managed_mail_profile_sync(
    *,
    email: str,
    explicit_profile: dict[str, Any] | None = None,
    account_password: str = "",
    team_store: Any = None,
    new_account_store: Any = None,
    personal_pool_store: Any = None,
    personal_master_pool_store: Any = None,
    log_info: Optional[LogFn] = None,
    log_warn: Optional[LogFn] = None,
) -> dict[str, Any]:
    normalized_email = str(email or "").strip().lower()
    empty_profile = {
        "mail_provider": "",
        "mail_jwt": "",
        "mail_api_base": "",
        "mail_frontend_base": "",
        "mail_view_url": "",
        "source": "",
        "repair_mode": "",
        "auto_repaired": False,
        "managed_domain_matched": False,
        "imap_fallback_enabled": bool(is_email_otp_imap_fallback_enabled()),
        "error": "",
    }
    if ("@" not in normalized_email) or (not normalized_email):
        return empty_profile

    explicit = _normalize_profile(explicit_profile or {})
    if str(explicit.get("mail_jwt") or "").strip():
        return {
            **empty_profile,
            **explicit,
            "source": "explicit",
        }

    refs: list[_ManagedMailStoreRef] = []
    password_candidates: list[str] = []
    direct_password = str(account_password or "").strip()
    if direct_password:
        password_candidates.append(direct_password)

    for collector in (
        lambda: _collect_team_store_candidate(
            store=new_account_store,
            store_key="new_pool",
            normalized_email=normalized_email,
            refs=refs,
            password_candidates=password_candidates,
        ),
        lambda: _collect_team_store_candidate(
            store=team_store,
            store_key="team_pool",
            normalized_email=normalized_email,
            refs=refs,
            password_candidates=password_candidates,
        ),
        lambda: _collect_account_store_candidate(
            store=personal_pool_store,
            store_key="personal_pool",
            normalized_email=normalized_email,
            refs=refs,
            password_candidates=password_candidates,
        ),
        lambda: _collect_account_store_candidate(
            store=personal_master_pool_store,
            store_key="personal_master_pool",
            normalized_email=normalized_email,
            refs=refs,
            password_candidates=password_candidates,
        ),
    ):
        profile = collector()
        if str(profile.get("mail_jwt") or "").strip():
            return {
                **empty_profile,
                **profile,
                "source": "store",
            }

    managed_domain_matched = bool(should_auto_repair_managed_mail_jwt(normalized_email))
    if not managed_domain_matched:
        return {
            **empty_profile,
            "managed_domain_matched": False,
            "error": "mail_jwt_missing_for_non_managed_domain",
        }

    deduped_passwords: list[str] = []
    seen_passwords: set[str] = set()
    for candidate in password_candidates:
        text = str(candidate or "").strip()
        if (not text) or (text in seen_passwords):
            continue
        seen_passwords.add(text)
        deduped_passwords.append(text)

    repaired = _repair_managed_mail_profile_sync(
        normalized_email=normalized_email,
        password_candidates=deduped_passwords,
        log_info=log_info,
        log_warn=log_warn,
    )
    if str(repaired.get("mail_jwt") or "").strip():
        _apply_mail_profile_to_refs(
            refs=refs,
            profile=repaired,
            team_store=team_store,
            new_account_store=new_account_store,
            personal_pool_store=personal_pool_store,
            personal_master_pool_store=personal_master_pool_store,
        )
        return {
            **empty_profile,
            **repaired,
            "source": "auto_repair",
            "auto_repaired": True,
            "managed_domain_matched": True,
        }

    return {
        **empty_profile,
        "managed_domain_matched": True,
        "error": str(repaired.get("error") or "managed_mail_jwt_unavailable").strip() or "managed_mail_jwt_unavailable",
    }
