# -*- coding: utf-8 -*-
"""域名邮箱（Ferret Mail）OTP 取码 provider。

对接 Ferret Mail API（http://<host>:<port>/ui-api/messages），轮询指定别名邮箱，
从邮件的 code 字段或正文中提取 OpenAI 验证码。与 managed_mail / imap 取码并列，
作为 _submit_http_otp_if_required 的第三条取码路径。

接口参考：域名邮箱API文档.md
    GET /ui-api/messages?domain=...&email=...&page=1&pageSize=N
    Authorization: <domain_token>
    返回 {"code":200,"data":[{...,"code":"123456","receivedAt":<ms>,...}], ...}
"""
from __future__ import annotations

import re
import time
from typing import Any, Callable, Optional

import requests

LogFn = Callable[[str], None]

# 6 位数字验证码（前后不接其它数字），与 local_phone_api 的识别口径一致
_CODE_PATTERN = re.compile(r"(?<!\d)(\d{6})(?!\d)")
# 仅在出现验证码语义关键词的邮件里做正文兜底，避免误抓正文里的无关 6 位数字
_CODE_CONTEXT_KEYWORDS = (
    "verification code",
    "verification",
    "one-time",
    "code",
    "验证码",
    "openai",
    "chatgpt",
)


def _safe_log(log: Optional[LogFn], message: str) -> None:
    if callable(log):
        try:
            log(str(message))
        except Exception:
            pass


def _normalize_base(base: str) -> str:
    return str(base or "").strip().rstrip("/")


def _to_ms_ts(value: Any) -> float:
    """Ferret 的 receivedAt 是毫秒时间戳，统一转成秒以便和 not_before_ts 比较。"""
    try:
        num = float(value)
    except (TypeError, ValueError):
        return 0.0
    if num <= 0:
        return 0.0
    # 毫秒级（13 位）转秒
    return num / 1000.0 if num > 1e11 else num


def _extract_code_from_mail(mail: dict[str, Any], blocked: set[str]) -> str:
    """优先用 Ferret 已识别出的 code 字段，其次从 subject/text 正文兜底提取。"""
    # 1. Ferret 服务端已识别的验证码字段
    direct = str(mail.get("code") or "").strip()
    if direct and _CODE_PATTERN.fullmatch(direct) and direct not in blocked:
        return direct

    # 2. 正文兜底：仅在含验证码语义的邮件里抓 6 位数字
    subject = str(mail.get("subject") or "")
    text = str(mail.get("text") or "")
    searchable = f"{subject}\n{text}"
    low = searchable.lower()
    if not any(kw in low for kw in _CODE_CONTEXT_KEYWORDS):
        return ""
    for match in _CODE_PATTERN.finditer(searchable):
        candidate = match.group(1)
        if candidate and candidate not in blocked:
            return candidate
    return ""


def poll_domain_mail_verification_code_sync(
    *,
    email: str,
    api_base: str,
    domain: str,
    token: str,
    otp_timeout_sec: float,
    otp_interval_sec: float,
    blocked_codes: set[str] | None = None,
    not_before_ts: float = 0.0,
    latest_n: int = 20,
    log_info: Optional[LogFn] = None,
    log_warn: Optional[LogFn] = None,
) -> str:
    """轮询域名邮箱取 OpenAI 验证码，成功返回 6 位 code，超时返回空串。"""
    normalized_email = str(email or "").strip().lower()
    base = _normalize_base(api_base)
    dom = str(domain or "").strip()
    tok = str(token or "").strip()
    if not base or not tok or not normalized_email:
        _safe_log(log_warn, "域名邮箱取码参数不全（api_base/token/email 缺失），跳过。")
        return ""
    if not dom and "@" in normalized_email:
        dom = normalized_email.split("@", 1)[1]

    blocked = blocked_codes or set()
    page_size = max(1, min(int(latest_n or 20), 100))
    deadline = time.time() + max(3.0, float(otp_timeout_sec or 120.0))
    poll_interval = max(1.0, float(otp_interval_sec or 3.0))
    headers = {"Authorization": tok}
    messages_url = f"{base}/ui-api/messages"
    changes_url = f"{base}/ui-api/changes"
    since_ms = int(max(0.0, float(not_before_ts or 0.0)) * 1000.0)

    _safe_log(
        log_info,
        f"开始通过域名邮箱自动取码：domain={dom or '?'}，target={normalized_email}",
    )

    def _read_messages() -> tuple[int, dict[str, Any]]:
        resp = requests.get(
            messages_url,
            headers=headers,
            params={
                "domain": dom,
                "email": normalized_email,
                "page": 1,
                "pageSize": page_size,
            },
            timeout=min(20.0, max(8.0, poll_interval + 6.0)),
        )
        try:
            payload = resp.json()
        except Exception:
            payload = {}
        return int(resp.status_code or 0), payload if isinstance(payload, dict) else {}

    while time.time() <= deadline:
        try:
            status_code, payload = _read_messages()
        except Exception as exc:
            _safe_log(log_warn, f"域名邮箱取码请求异常：{exc}")
            time.sleep(poll_interval)
            continue

        if status_code and status_code < 400 and isinstance(payload, dict):
            mails = payload.get("data")
            if not isinstance(mails, list):
                mails = []
            # 按 receivedAt 降序，优先取最新邮件，避免命中注册时残留的旧验证码。
            def _mail_ts(m: Any) -> float:
                return _to_ms_ts(m.get("receivedAt")) if isinstance(m, dict) else 0.0

            mails_sorted = sorted(
                (m for m in mails if isinstance(m, dict)),
                key=_mail_ts,
                reverse=True,
            )
            for mail in mails_sorted:
                received = _to_ms_ts(mail.get("receivedAt"))
                if received:
                    since_ms = max(since_ms, int(received * 1000.0))
                if received and received < float(not_before_ts or 0.0):
                    continue
                code_value = _extract_code_from_mail(mail, blocked)
                if code_value:
                    _safe_log(log_info, f"域名邮箱已获取到验证码：target={normalized_email}")
                    return code_value
        else:
            detail = ""
            if isinstance(payload, dict):
                detail = str(payload.get("message") or "").strip()
            _safe_log(
                log_warn,
                f"域名邮箱取码请求失败：status={int(status_code or 0)}，detail={detail}",
            )

        remaining = deadline - time.time()
        if remaining <= 0:
            break
        try:
            wait_timeout = min(25.0, max(3.0, remaining))
            change_resp = requests.get(
                changes_url,
                headers=headers,
                params={
                    "domain": dom,
                    "email": normalized_email,
                    "since": since_ms,
                },
                timeout=wait_timeout + 3.0,
            )
            change_payload = change_resp.json() if change_resp.content else {}
            if isinstance(change_payload, dict):
                latest = _to_ms_ts(change_payload.get("latest") or change_payload.get("latestReceivedAt"))
                if latest:
                    since_ms = max(since_ms, int(latest * 1000.0))
                if bool(change_payload.get("changed")):
                    continue
            time.sleep(min(poll_interval, remaining))
        except Exception:
            time.sleep(min(poll_interval, remaining))

    _safe_log(log_warn, f"域名邮箱在超时内未获取到可用验证码：target={normalized_email}")
    return ""


__all__ = ["poll_domain_mail_verification_code_sync"]
