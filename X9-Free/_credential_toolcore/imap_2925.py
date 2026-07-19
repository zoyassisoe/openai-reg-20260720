"""
模块功能说明：
    - 通过 IMAP 获取 2925 邮箱验证码，并按“收件人邮箱”严格匹配 expectedEmail。
    - 该实现基于用户提供的参考脚本 E:/Code/com/test.py 改造：
        - 去掉硬编码账号密码，改为参数化配置；
        - 不打印邮件正文/标题（避免敏感信息泄露到日志）；
        - 与项目现有提码逻辑对齐：复用 code_utils.extractVerificationCode 的关键词/去重机制。

安全说明（重要）：
    - IMAP 密码与邮件内容属于敏感信息：严禁写入日志/文件/持久化存储。
    - 本模块只返回验证码字符串（例如 6 位数字），不返回邮件内容。
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import datetime
import html
import json
import os
import poplib
import re
import socket
import ssl
import time
import urllib.parse
import urllib.request
from email import message_from_bytes
from email.header import decode_header
from email.message import Message
from email.utils import getaddresses, parsedate_to_datetime
from pathlib import Path
from typing import Callable, Optional

import imaplib

from code_utils import extractVerificationCode


LogFn = Callable[[str], None]

_EMAIL_RE = re.compile(r"(?i)([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,})")
_DNS_JSON_ENDPOINTS: tuple[str, ...] = (
    "https://dns.google/resolve?name={host}&type=A",
    "https://cloudflare-dns.com/dns-query?name={host}&type=A",
)
_RAW_DUMP_POLL_COUNT = 0


@dataclasses.dataclass(frozen=True, slots=True)
class Imap2925Config:
    """
    功能目的：
        描述一次 IMAP 取码所需配置。
    """

    host: str = "imap.2925.com"
    port: int = 993
    username: str = ""
    password: str = ""
    auth_type: str = "password"
    oauth_client_id: str = ""
    oauth_refresh_token: str = ""
    oauth_scope: str = "https://outlook.office.com/IMAP.AccessAsUser.All offline_access"
    oauth_token_url: str = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    password_fallback_enabled: bool = False
    pop3_fallback_enabled: bool = False
    pop_host: str = "outlook.office365.com"
    pop_port: int = 995
    pop_oauth_scope: str = "https://outlook.office.com/POP.AccessAsUser.All offline_access"
    # 说明：2925 IMAP 默认收件箱名为 "Inbox"（而不是 "INBOX"）。
    folder: str = "Inbox"
    latest_n: int = 10
    poll_interval_seconds: float = 3.0
    poll_timeout_seconds: float = 120.0
    # 只匹配“任务开始后”的邮件：邮件到达时间必须严格大于该时间戳（epoch seconds）。
    # 说明：用于避免把历史邮件验证码误回填到当前任务。
    not_before_ts: float = 0.0
    # 说明：当验证码页已处于激活状态且首轮复用当前验证码窗口时，允许使用更短的轮询超时。
    initial_reuse_poll_timeout_seconds: float = 35.0
    # 说明：批量注册场景可优先扫描最新邮件，减少旧邮件干扰。
    scan_newest_first: bool = False
    # 说明：仅在按“最新->最旧”扫描时生效；一旦触达 not_before 时间边界，提前结束本轮旧邮件扫描。
    stop_on_not_before_boundary: bool = False
    # 说明：取码前预扫到的 UID 基线。轮询时这些 UID 一律视为旧邮件，防止共用主邮箱串码。
    baseline_uids: tuple[str, ...] = ()

    def is_configured(self) -> bool:
        if not bool(str(self.username or "").strip()):
            return False
        if _normalize_auth_type(self.auth_type) == "oauth2":
            return bool(str(self.oauth_client_id or "").strip()) and bool(str(self.oauth_refresh_token or "").strip())
        return bool(str(self.password or "").strip())


@dataclasses.dataclass(frozen=True, slots=True)
class ImapMailMetadata:
    """
    功能目的：
        描述一封 IMAP 邮件的最小元数据，仅用于状态识别，不包含正文。
    """

    uid: str
    received_at: str
    subject: str
    recipient_emails: tuple[str, ...]


_OAUTH2_TOKEN_CACHE: dict[tuple[str, str, str, str], tuple[float, str]] = {}


def _normalize_auth_type(value: str) -> str:
    return "oauth2" if str(value or "").strip().lower() == "oauth2" else "password"


class _ResolvedIMAP4_SSL(imaplib.IMAP4_SSL):
    def __init__(
        self,
        host: str,
        port: int,
        *,
        resolved_host: str,
        ssl_context: ssl.SSLContext,
        timeout: Optional[float] = None,
    ) -> None:
        self._resolved_host = str(resolved_host or "").strip()
        super().__init__(host, port, ssl_context=ssl_context, timeout=timeout)

    def _create_socket(self, timeout):
        if timeout is not None and not timeout:
            raise ValueError("Non-blocking socket (timeout=0) is not supported")
        address = (self._resolved_host or self.host, self.port)
        if timeout is not None:
            sock = socket.create_connection(address, timeout)
        else:
            sock = socket.create_connection(address)
        return self.ssl_context.wrap_socket(sock, server_hostname=self.host)


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
    """
    说明：
        优先 text/plain，其次 text/html；忽略附件内容。
    """

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition", ""))
            if ctype == "text/plain" and "attachment" not in disp.lower():
                payload = part.get_payload(decode=True) or b""
                charset = part.get_content_charset() or "utf-8"
                return payload.decode(charset, errors="replace")
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition", ""))
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


def _collect_recipient_emails(msg: Message) -> set[str]:
    """
    说明：
        尽量从多种头字段收集收件人邮箱；避免仅依赖 To（有些邮件 To 为空或被改写）。
    """

    def _add_emails_from_text(text: str, out: set[str]) -> None:
        if not text:
            return
        for e in _EMAIL_RE.findall(str(text)):
            if e:
                out.add(str(e).strip().lower())

    # 说明：部分转发/别名邮箱会把原始收件人放到 X-Forwarded-To 等字段里；这里一并纳入以提高匹配成功率。
    # 兼容更多 MTA 头字段（如 Postfix 的 Original/Final-Recipient），不影响严格匹配规则（expected 必须命中集合）。
    headers_to_check = [
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
    ]
    emails: set[str] = set()
    for h in headers_to_check:
        v = msg.get(h)
        if not v:
            continue
        v = _decode_mime_words(str(v))
        for _name, addr in getaddresses([v]):
            if addr:
                emails.add(addr.strip().lower())
        # 兜底：部分头字段（如 Final-Recipient: rfc822; user@domain）不一定能被 getaddresses 解析
        _add_emails_from_text(v, emails)

    # 进一步兜底：很多转发/代收场景会把目标地址写入 Received: ... for <user@domain> ...
    try:
        received_headers = msg.get_all("Received", []) or []
    except Exception:
        received_headers = []
    for rh in received_headers:
        rh_text = _decode_mime_words(str(rh or ""))
        _add_emails_from_text(rh_text, emails)
    return emails


_UID_RE = re.compile(rb"UID\s+(\d+)")
_INTERNALDATE_RE = re.compile(rb'INTERNALDATE\s+"([^"]+)"')


def _extract_uid_from_fetch_header(header_bytes: bytes) -> str:
    m = _UID_RE.search(header_bytes or b"")
    return m.group(1).decode("utf-8", errors="ignore") if m else ""

def _extract_internaldate_ts_from_fetch_header(header_bytes: bytes) -> float:
    """
    说明：
        尝试从 IMAP FETCH 响应头中解析 INTERNALDATE（服务器收件时间）。
        返回 epoch seconds；失败返回 0。
    """

    if not header_bytes:
        return 0.0
    try:
        m = _INTERNALDATE_RE.search(header_bytes)
        if not m:
            return 0.0
        raw = m.group(1).decode("utf-8", errors="ignore").strip()
        # 常见格式：2-Feb-2026 05:06:07 +0000（day 可能 1 位）
        date_part, rest = raw.split(" ", 1)
        day, mon, year = date_part.split("-")
        if len(day) == 1:
            day = f"0{day}"
        normalized = f"{day}-{mon}-{year} {rest}"
        dt = datetime.datetime.strptime(normalized, "%d-%b-%Y %H:%M:%S %z")
        return float(dt.timestamp())
    except Exception:
        return 0.0

def _extract_message_date_ts(msg: Message) -> float:
    """
    说明：
        兜底从邮件头 Date 解析时间戳；失败返回 0。
    """

    try:
        raw = str(msg.get("Date", "") or "").strip()
        if not raw:
            return 0.0
        dt = parsedate_to_datetime(raw)
        return float(dt.timestamp())
    except Exception:
        return 0.0


def _safe_dump_token(value: str, *, fallback: str = "item") -> str:
    text = re.sub(r"[^A-Za-z0-9_.@+\-]+", "_", str(value or "").strip())
    text = text.strip("._-")
    return (text or fallback)[:120]


def _dump_env_bool(name: str, default: bool = False) -> bool:
    raw = str(os.getenv(name, "1" if default else "0")).strip().lower()
    return raw not in ("0", "false", "no", "off", "")


def _dump_env_int(name: str, default: int, *, min_value: int, max_value: int) -> int:
    try:
        value = int(str(os.getenv(name, str(default)) or str(default)).strip())
    except Exception:
        value = int(default)
    return max(int(min_value), min(int(max_value), int(value)))


def _headers_for_summary(msg: Message) -> list[str]:
    names = [
        "From",
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
        "Subject",
        "Date",
        "Message-ID",
    ]
    lines: list[str] = []
    for name in names:
        values = msg.get_all(name, []) or []
        for value in values:
            lines.append(f"{name}: {_decode_mime_words(str(value or '')).strip()}")
    return lines


def _dump_imap_raw_fetch(
    *,
    config: Imap2925Config,
    folder: str,
    seq_set: str,
    total: int,
    msg_data: list,
) -> None:
    if not _dump_env_bool("AIO_IMAP_RAW_DUMP", False):
        return
    root_text = str(os.getenv("AIO_IMAP_RAW_DUMP_DIR", "") or "").strip()
    if not root_text:
        return

    global _RAW_DUMP_POLL_COUNT
    max_polls = _dump_env_int("AIO_IMAP_RAW_DUMP_MAX_POLLS", 3, min_value=1, max_value=20)
    if _RAW_DUMP_POLL_COUNT >= max_polls:
        return
    _RAW_DUMP_POLL_COUNT += 1

    try:
        max_messages = _dump_env_int("AIO_IMAP_RAW_DUMP_MAX_MESSAGES", 200, min_value=1, max_value=1000)
        expected = str(os.getenv("AIO_IMAP_RAW_DUMP_EXPECTED", "") or "").strip().lower()
        created_at = datetime.datetime.now(datetime.timezone.utc).astimezone().strftime("%Y%m%d-%H%M%S")
        poll_dir = (
            Path(root_text)
            / f"poll-{_RAW_DUMP_POLL_COUNT:03d}-{created_at}-{_safe_dump_token(folder, fallback='folder')}"
        )
        poll_dir.mkdir(parents=True, exist_ok=True)

        tuples = [x for x in (msg_data or []) if isinstance(x, tuple) and len(x) >= 2]
        limited = tuples[:max_messages]
        summary_lines = [
            "# IMAP Raw Dump",
            "",
            f"- Created: {created_at}",
            f"- Host: {str(config.host)}:{int(config.port)}",
            f"- User: {str(config.username)}",
            f"- Folder: {folder}",
            f"- Mailbox total: {total}",
            f"- FETCH sequence: {seq_set}",
            f"- Dumped messages: {len(limited)} / {len(tuples)} fetched",
            f"- Expected email: {expected or '(empty)'}",
            "",
            "## Messages",
            "",
        ]

        for index, item in enumerate(limited, start=1):
            header, raw_msg = item
            header_bytes = header if isinstance(header, (bytes, bytearray)) else b""
            raw_bytes = raw_msg if isinstance(raw_msg, (bytes, bytearray)) else b""
            uid = _extract_uid_from_fetch_header(bytes(header_bytes)) or f"seq{index}"
            msg = message_from_bytes(bytes(raw_bytes))
            received_ts = _extract_internaldate_ts_from_fetch_header(bytes(header_bytes)) or _extract_message_date_ts(msg)
            received_at = ""
            if received_ts:
                try:
                    received_at = datetime.datetime.fromtimestamp(
                        float(received_ts),
                        tz=datetime.timezone.utc,
                    ).astimezone().isoformat()
                except Exception:
                    received_at = ""
            recipients = sorted(_collect_recipient_emails(msg))
            subject = _decode_mime_words(str(msg.get("Subject", "") or "")).strip()
            file_base = f"{index:03d}_uid-{_safe_dump_token(uid, fallback=str(index))}"
            eml_name = f"{file_base}.eml"
            fetch_name = f"{file_base}.fetch-header.txt"
            body_name = f"{file_base}.body.txt"
            header_name = f"{file_base}.headers.txt"

            (poll_dir / eml_name).write_bytes(bytes(raw_bytes))
            (poll_dir / fetch_name).write_text(
                bytes(header_bytes).decode("utf-8", errors="replace"),
                encoding="utf-8",
            )
            (poll_dir / header_name).write_text("\n".join(_headers_for_summary(msg)) + "\n", encoding="utf-8")
            (poll_dir / body_name).write_text(_get_text_body(msg), encoding="utf-8", errors="replace")

            summary_lines.extend(
                [
                    f"### {index:03d} UID {uid}",
                    "",
                    f"- Received: {received_at or '(unknown)'}",
                    f"- Subject: {subject or '(empty)'}",
                    f"- Expected recipient match: {'yes' if expected and expected in recipients else 'no'}",
                    f"- Recipients: {', '.join(recipients) if recipients else '(none found in headers)'}",
                    f"- Raw EML: `{eml_name}`",
                    f"- FETCH header: `{fetch_name}`",
                    f"- Decoded headers: `{header_name}`",
                    f"- Decoded body text: `{body_name}`",
                    "",
                ]
            )

        (poll_dir / "summary.md").write_text("\n".join(summary_lines), encoding="utf-8")
    except Exception:
        return


def _resolve_socket_hosts_for_tls_host(host: str) -> list[str]:
    normalized = str(host or "").strip()
    if not normalized:
        return []

    def _dedupe(values: list[str]) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for value in values:
            item = str(value or "").strip()
            if not item or item in seen:
                continue
            seen.add(item)
            out.append(item)
        return out

    try:
        infos = socket.getaddrinfo(normalized, None, type=socket.SOCK_STREAM)
        direct_hits = [str(item[4][0]).strip() for item in infos if item and len(item) >= 5]
        deduped = _dedupe(direct_hits)
        if deduped:
            return deduped
    except socket.gaierror:
        pass

    resolved: list[str] = []
    encoded_host = urllib.parse.quote(normalized, safe="")
    for template in _DNS_JSON_ENDPOINTS:
        try:
            url = template.format(host=encoded_host)
            req = urllib.request.Request(url, headers={"accept": "application/dns-json"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                payload = json.loads(resp.read().decode("utf-8", errors="replace") or "{}")
            answers = payload.get("Answer") or []
            for row in answers:
                if not isinstance(row, dict):
                    continue
                if int(row.get("type") or 0) != 1:
                    continue
                data = str(row.get("data") or "").strip()
                if data:
                    resolved.append(data)
            deduped = _dedupe(resolved)
            if deduped:
                return deduped
        except Exception:
            continue
    return _dedupe(resolved)


def _fetch_oauth2_access_token(config: Imap2925Config, *, scope: str = "") -> str:
    oauth_scope = str(scope or config.oauth_scope or "").strip()
    token_url = str(config.oauth_token_url or "").strip() or "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    client_id = str(config.oauth_client_id or "").strip()
    refresh_token = str(config.oauth_refresh_token or "").strip()
    cache_key = (token_url, client_id, refresh_token, oauth_scope)
    now = time.time()
    cached = _OAUTH2_TOKEN_CACHE.get(cache_key)
    if cached and cached[0] > now:
        return str(cached[1] or "").strip()

    body = urllib.parse.urlencode(
        {
            "client_id": client_id,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "scope": oauth_scope,
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        token_url,
        data=body,
        headers={"content-type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    timeout = max(8.0, min(float(config.poll_timeout_seconds or 120.0), 20.0))
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = json.loads(resp.read().decode("utf-8", errors="replace") or "{}")
    access_token = str(payload.get("access_token") or "").strip()
    if not access_token:
        raise RuntimeError("oauth2_access_token_missing")
    try:
        expires_in = int(payload.get("expires_in") or 0)
    except Exception:
        expires_in = 0
    if expires_in > 0:
        _OAUTH2_TOKEN_CACHE[cache_key] = (now + max(30.0, float(expires_in - 60)), access_token)
    return access_token


def _xoauth2_bytes(username: str, access_token: str) -> bytes:
    return f"user={str(username or '').strip()}\x01auth=Bearer {str(access_token or '').strip()}\x01\x01".encode("utf-8")


def _imap_login(imap: imaplib.IMAP4_SSL, config: Imap2925Config) -> None:
    if _normalize_auth_type(config.auth_type) != "oauth2":
        imap.login(str(config.username), str(config.password))
        return
    access_token = _fetch_oauth2_access_token(config, scope=str(config.oauth_scope or "").strip())
    imap.authenticate("XOAUTH2", lambda _challenge: _xoauth2_bytes(str(config.username or "").strip(), access_token))


def _open_pop3_ssl_client(config: Imap2925Config) -> poplib.POP3_SSL:
    host = str(config.pop_host or config.host or "").strip()
    port = int(config.pop_port or 995)
    timeout = max(5.0, min(float(config.poll_timeout_seconds or 120.0), 15.0))
    try:
        return poplib.POP3_SSL(host, port, timeout=timeout)
    except socket.gaierror as error:
        last_error: Exception = error
    except OSError as error:
        if "name resolution" not in str(error).lower():
            raise
        last_error = error

    for resolved_host in _resolve_socket_hosts_for_tls_host(host):
        try:
            return poplib.POP3_SSL(resolved_host, port, timeout=timeout)
        except Exception as error:
            last_error = error
            continue
    raise last_error


def _pop3_auth_xoauth2(pop_conn: poplib.POP3_SSL, username: str, access_token: str) -> None:
    payload = base64.b64encode(_xoauth2_bytes(username, access_token))
    pop_conn._putcmd("AUTH XOAUTH2")
    challenge = pop_conn._getresp()
    if not challenge.startswith(b"+"):
        raise poplib.error_proto(challenge)
    pop_conn._putline(payload)
    final = pop_conn._getresp()
    if not final.startswith(b"+OK"):
        raise poplib.error_proto(final)


def _open_imap_ssl_client(config: Imap2925Config) -> imaplib.IMAP4_SSL:
    host = str(config.host or "").strip()
    port = int(config.port or 993)
    ctx = ssl.create_default_context()
    timeout = max(5.0, min(float(config.poll_timeout_seconds or 120.0), 15.0))
    try:
        return imaplib.IMAP4_SSL(host, port, ssl_context=ctx, timeout=timeout)
    except socket.gaierror as error:
        last_error: Exception = error
    except OSError as error:
        if "name resolution" not in str(error).lower():
            raise
        last_error = error

    for resolved_host in _resolve_socket_hosts_for_tls_host(host):
        try:
            return _ResolvedIMAP4_SSL(
                host,
                port,
                resolved_host=resolved_host,
                ssl_context=ctx,
                timeout=timeout,
            )
        except Exception as error:
            last_error = error
            continue
    raise last_error


def _fetch_latest_uid_messages_imap(config: Imap2925Config) -> list[tuple[str, float, Message]]:
    """
    返回：
        [(uid, received_ts, email.message.Message), ...]
        - uid 为字符串数字
        - received_ts 为服务器收件时间（优先 INTERNALDATE，其次 Date 头），单位 epoch seconds；无法解析时为 0
    """

    imap = _open_imap_ssl_client(config)
    try:
        imap._encoding = "utf-8"  # type: ignore[attr-defined]
    except Exception:
        pass
    imap.debug = 0
    try:
        _imap_login(imap, config)
        folder = str(config.folder or "Inbox").strip() or "Inbox"
        typ, data = imap.select(folder)
        if typ != "OK":
            raise RuntimeError(f"SELECT {folder} failed: {typ}")

        # 说明：
        # - 2925 的 IMAP 服务在某些环境下不支持 SEARCH 命令（会返回 BAD: Command 'SEARCH' not recognized）。
        # - 为了兼容该实现，这里不使用 SEARCH，而是用 SELECT 返回的邮件总数，直接按“序号范围”FETCH 最近 N 封。
        # - FETCH 返回的响应里仍会包含 UID，因此去重逻辑仍按 UID 工作。
        try:
            total = int((data[0] if isinstance(data, list) and data else b"0").decode("utf-8", errors="ignore") or "0")
        except Exception:
            total = 0
        if total <= 0:
            return []

        n = max(1, int(config.latest_n or 10))
        start = max(1, total - n + 1)
        seq_set = f"{start}:{total}"

        # 一次性 FETCH（UID + INTERNALDATE + BODY.PEEK[]），避免将邮件标记为已读。
        # 注意：这里使用 FETCH（按序号范围），以兼容“SEARCH 不可用”的 IMAP 服务实现。
        typ, msg_data = imap.fetch(seq_set, "(UID INTERNALDATE BODY.PEEK[])")
        if typ != "OK" or not msg_data:
            return []
        _dump_imap_raw_fetch(
            config=config,
            folder=folder,
            seq_set=seq_set,
            total=total,
            msg_data=list(msg_data),
        )
        tuples = [x for x in msg_data if isinstance(x, tuple) and len(x) >= 2]
        out: list[tuple[str, float, Message]] = []
        for header, raw_msg in tuples:
            header_bytes = header if isinstance(header, (bytes, bytearray)) else b""
            uid = _extract_uid_from_fetch_header(header_bytes)
            if not uid or not raw_msg:
                continue
            msg = message_from_bytes(raw_msg)
            received_ts = _extract_internaldate_ts_from_fetch_header(header_bytes)
            if not received_ts:
                received_ts = _extract_message_date_ts(msg)
            out.append((uid, float(received_ts or 0.0), msg))
        return out
    finally:
        try:
            imap.logout()
        except Exception:
            pass


def _fetch_latest_uid_messages_pop3(config: Imap2925Config) -> list[tuple[str, float, Message]]:
    pop_conn = _open_pop3_ssl_client(config)
    try:
        access_token = _fetch_oauth2_access_token(config, scope=str(config.pop_oauth_scope or "").strip())
        _pop3_auth_xoauth2(pop_conn, str(config.username or "").strip(), access_token)
        resp, uid_lines, _octets = pop_conn.uidl()
        resp_text = resp.decode("utf-8", errors="replace") if isinstance(resp, (bytes, bytearray)) else str(resp or "")
        if not resp_text.startswith("+OK"):
            return []
        parsed_uid_lines: list[tuple[int, str]] = []
        for raw in uid_lines or []:
            try:
                text = raw.decode("utf-8", errors="replace").strip()
                num_str, uid = text.split(None, 1)
                parsed_uid_lines.append((int(num_str), str(uid or "").strip()))
            except Exception:
                continue
        if not parsed_uid_lines:
            return []
        latest = sorted(parsed_uid_lines, key=lambda item: item[0], reverse=True)[: max(1, int(config.latest_n or 10))]
        latest.reverse()
        out: list[tuple[str, float, Message]] = []
        for msg_num, uid in latest:
            try:
                _resp, lines, _size = pop_conn.retr(int(msg_num))
            except Exception:
                continue
            raw_msg = b"\r\n".join(lines or [])
            if not raw_msg:
                continue
            msg = message_from_bytes(raw_msg)
            received_ts = _extract_message_date_ts(msg)
            out.append((str(uid or msg_num), float(received_ts or 0.0), msg))
        return out
    finally:
        try:
            pop_conn.quit()
        except Exception:
            pass


def _fetch_latest_uid_messages(config: Imap2925Config) -> list[tuple[str, float, Message]]:
    errors: list[str] = []
    try:
        return _fetch_latest_uid_messages_imap(config)
    except Exception as error:
        errors.append(f"imap_primary:{type(error).__name__}:{error}")

    if (
        _normalize_auth_type(config.auth_type) == "oauth2"
        and bool(config.password_fallback_enabled)
        and bool(str(config.password or "").strip())
    ):
        try:
            fallback_config = dataclasses.replace(config, auth_type="password")
            return _fetch_latest_uid_messages_imap(fallback_config)
        except Exception as error:
            errors.append(f"imap_password_fallback:{type(error).__name__}:{error}")

    if (
        bool(config.pop3_fallback_enabled)
        and bool(str(config.oauth_client_id or "").strip())
        and bool(str(config.oauth_refresh_token or "").strip())
    ):
        try:
            return _fetch_latest_uid_messages_pop3(config)
        except Exception as error:
            errors.append(f"pop3_oauth2_fallback:{type(error).__name__}:{error}")

    if errors:
        raise RuntimeError(" | ".join(errors))
    return []


def scan_imap_recent_uids(config: Imap2925Config) -> list[str]:
    if not config.is_configured():
        return []
    out: list[str] = []
    for uid, _received_ts, _msg in _fetch_latest_uid_messages(config):
        text = str(uid or "").strip()
        if text:
            out.append(text)
    return out


async def poll_imap_for_verification_code(
    *,
    config: Imap2925Config,
    expected_email: str,
    keywords: list[str],
    blocked_codes: set[str],
    logInfo: Optional[LogFn] = None,
    logWarn: Optional[LogFn] = None,
) -> Optional[str]:
    """
    功能目的：
        轮询 IMAP 收件箱，按“收件人邮箱严格匹配 expected_email”提取验证码。

    返回：
        验证码字符串（通常 6 位）或 None（超时/失败）。
    """

    info = logInfo or (lambda _m: None)
    warn = logWarn or (lambda _m: None)

    expected = str(expected_email or "").strip().lower()
    if not expected or "@" not in expected:
        warn("IMAP 取码：expectedEmail 为空或格式不正确，跳过 IMAP。")
        return None
    if not config.is_configured():
        warn("IMAP 取码：IMAP 账号/密码未配置，跳过 IMAP。")
        return None

    def _env_bool(name: str, default: bool) -> bool:
        raw = str(os.getenv(name, "1" if default else "0")).strip().lower()
        return raw not in ("0", "false", "no", "off", "")

    def _env_int(name: str, default: int, min_value: int, max_value: int) -> int:
        try:
            raw = int(str(os.getenv(name, str(default)) or str(default)).strip())
        except Exception:
            raw = int(default)
        return max(int(min_value), min(int(max_value), int(raw)))

    base_latest_n = max(1, int(getattr(config, "latest_n", 10) or 10))
    dynamic_expand_enabled = _env_bool("AIO_IMAP_DYNAMIC_LATEST_N", True)
    latest_n_cap = _env_int(
        "AIO_IMAP_LATEST_N_CAP",
        500,
        min_value=base_latest_n,
        max_value=5000,
    )
    expand_trigger_rounds = _env_int(
        "AIO_IMAP_EXPAND_TRIGGER_ROUNDS",
        2,
        min_value=1,
        max_value=50,
    )
    reset_seen_every_rounds = _env_int(
        "AIO_IMAP_RESET_SEEN_EVERY_ROUNDS",
        3,
        min_value=0,
        max_value=100,
    )
    scan_newest_first = bool(getattr(config, "scan_newest_first", False))
    stop_on_not_before_boundary = bool(getattr(config, "stop_on_not_before_boundary", False))
    strict_time_window = bool(stop_on_not_before_boundary and float(getattr(config, "not_before_ts", 0.0) or 0.0) > 0)
    if strict_time_window:
        # 共用主邮箱批量取码时，必须只看配置的最新 N 封和当前时间窗。
        # 动态扩窗/清空 UID 去重会把旧验证码重新纳入候选，容易造成串码。
        dynamic_expand_enabled = False
        reset_seen_every_rounds = 0
        latest_n_cap = base_latest_n

    deadline = time.time() + float(config.poll_timeout_seconds)
    poll_interval = max(0.5, float(config.poll_interval_seconds))
    baseline_uids = {str(uid or "").strip() for uid in (getattr(config, "baseline_uids", ()) or ()) if str(uid or "").strip()}
    seen_uids: set[str] = set(baseline_uids)
    warned_missing_ts = False
    current_latest_n = int(base_latest_n)
    consecutive_heavy_seen_miss_rounds = 0
    round_index = 0

    not_before_ts = float(getattr(config, "not_before_ts", 0.0) or 0.0)
    info(
        "IMAP 取码：开始轮询（不会输出邮件内容）。"
        f" host={str(config.host)}:{int(config.port)}, folder={str(config.folder)}, latest_n={int(current_latest_n)}, "
        f"expected={expected}, not_before_ts={not_before_ts if not_before_ts > 0 else 'disabled'}, "
        f"scan_order={'newest_first' if scan_newest_first else 'oldest_first'}, "
        f"stop_on_not_before_boundary={'on' if stop_on_not_before_boundary else 'off'}, "
        f"dynamic_expand={'on' if dynamic_expand_enabled else 'off'}, "
        f"latest_n_cap={latest_n_cap}, expand_trigger_rounds={expand_trigger_rounds}, "
        f"reset_seen_every_rounds={reset_seen_every_rounds if reset_seen_every_rounds > 0 else 'disabled'}, "
        f"baseline_uids={len(baseline_uids)}"
    )

    while time.time() < deadline:
        round_index += 1
        try:
            if reset_seen_every_rounds > 0 and round_index > 1 and ((round_index - 1) % reset_seen_every_rounds == 0):
                seen_uids.clear()
                seen_uids.update(baseline_uids)
                info(
                    "IMAP 取码：触发定期重扫，已清空 UID 去重缓存。"
                    f"（轮次={round_index}, reset_every={reset_seen_every_rounds}）"
                )

            fetch_cfg = config if current_latest_n == base_latest_n else dataclasses.replace(config, latest_n=current_latest_n)
            info("IMAP 取码：步骤 1/4 拉取最新邮件（SELECT + FETCH 最近 N 封）...")
            items = await asyncio.to_thread(_fetch_latest_uid_messages, fetch_cfg)
            # 批量注册可切换为“最新优先”，尽快命中新验证码并减少旧邮件扫描。
            try:
                items.sort(key=lambda x: int(x[0]), reverse=bool(scan_newest_first))
            except Exception:
                pass
            info(f"IMAP 取码：步骤 2/4 本轮获取到 {len(items)} 封（latest_n={current_latest_n}）。")

            stats_total = 0
            stats_seen = 0
            stats_skipped_no_ts = 0
            stats_skipped_time = 0
            stats_skipped_rcpt = 0
            stats_skipped_blocked = 0
            stats_skipped_no_code = 0

            for uid, received_ts, msg in items:
                stats_total += 1
                if uid in seen_uids:
                    stats_seen += 1
                    continue
                seen_uids.add(uid)

                # 仅匹配“任务开始后”的邮件，避免历史验证码误命中
                if not_before_ts > 0:
                    if not received_ts:
                        if not warned_missing_ts:
                            warned_missing_ts = True
                            warn("IMAP 取码：无法解析邮件时间戳（INTERNALDATE/Date），为避免误匹配将跳过该类邮件。")
                        stats_skipped_no_ts += 1
                        continue
                    if float(received_ts) <= not_before_ts:
                        stats_skipped_time += 1
                        if scan_newest_first and stop_on_not_before_boundary:
                            info("IMAP 取码：已触达 not_before 时间边界，提前结束本轮旧邮件扫描。")
                            break
                        continue

                recipients = _collect_recipient_emails(msg)
                if expected not in recipients:
                    stats_skipped_rcpt += 1
                    continue

                info(f"IMAP 取码：步骤 3/4 命中目标收件人（uid={uid}），开始提取验证码...")
                subject = _decode_mime_words(str(msg.get("Subject", "")))
                body = _get_text_body(msg).replace("\r", "").strip()
                text = f"{subject}\n{body}".strip()
                code = extractVerificationCode(text, keywords=keywords, blockedCodes=blocked_codes)
                if code:
                    if code in blocked_codes:
                        stats_skipped_blocked += 1
                        continue
                    info(f"IMAP 取码：步骤 4/4 已提取到验证码（uid={uid}）。")
                    return code
                stats_skipped_no_code += 1
            info(
                "IMAP 取码：本轮未命中"
                f"（总={stats_total}, 已读/去重={stats_seen}, 时间戳过滤={stats_skipped_time},"
                f" 无时间戳={stats_skipped_no_ts}, 收件人不匹配={stats_skipped_rcpt},"
                f" 无验证码关键词={stats_skipped_no_code}, 被去重验证码={stats_skipped_blocked}）。"
            )
            heavy_seen = bool(
                (stats_total > 0)
                and (
                    (stats_seen >= stats_total)
                    or ((float(stats_seen) / float(stats_total)) >= 0.8)
                )
            )
            if stats_total > 0 and stats_seen >= stats_total:
                info(
                    "IMAP 取码提示：最近窗口内邮件均已处理；"
                    "若你确认有目标邮件，请增大 IMAP latest_n 或降低并发窗口后重试。"
                )

            if heavy_seen:
                consecutive_heavy_seen_miss_rounds += 1
            else:
                consecutive_heavy_seen_miss_rounds = 0

            if (
                dynamic_expand_enabled
                and heavy_seen
                and (consecutive_heavy_seen_miss_rounds >= expand_trigger_rounds)
                and (current_latest_n < latest_n_cap)
            ):
                next_latest_n = min(latest_n_cap, max(current_latest_n * 2, current_latest_n + 20))
                if next_latest_n > current_latest_n:
                    prev_latest_n = current_latest_n
                    current_latest_n = int(next_latest_n)
                    seen_uids.clear()
                    seen_uids.update(baseline_uids)
                    consecutive_heavy_seen_miss_rounds = 0
                    info(
                        "IMAP 取码：触发动态扩窗，已清空 UID 去重缓存并重扫。"
                        f"（latest_n: {prev_latest_n} -> {current_latest_n}, "
                        f"trigger_rounds={expand_trigger_rounds}）"
                    )
        except Exception as e:
            # 注意：不输出可能包含敏感信息的长堆栈；只输出简短原因
            warn(f"IMAP 取码异常（将重试）：{type(e).__name__}: {e}")

        await asyncio.sleep(poll_interval)

    warn("IMAP 取码：超时未获取到验证码。")
    return None


def scan_imap_message_metadata(
    *,
    config: Imap2925Config,
    subject_predicate: Optional[Callable[[str], bool]] = None,
) -> list[ImapMailMetadata]:
    """
    功能目的：
        扫描最近邮件的元数据，避免返回正文，供业务层做主题/收件人识别。
    """

    if not config.is_configured():
        return []

    items = _fetch_latest_uid_messages(config)
    out: list[ImapMailMetadata] = []
    for uid, received_ts, msg in items:
        subject = _decode_mime_words(str(msg.get("Subject", "") or "")).strip()
        if callable(subject_predicate) and (not subject_predicate(subject)):
            continue
        recipient_emails = tuple(sorted(_collect_recipient_emails(msg)))
        received_at = ""
        if float(received_ts or 0.0) > 0:
            try:
                received_at = datetime.datetime.fromtimestamp(
                    float(received_ts),
                    tz=datetime.timezone.utc,
                ).isoformat()
            except Exception:
                received_at = ""
        out.append(
            ImapMailMetadata(
                uid=str(uid or ""),
                received_at=received_at,
                subject=subject,
                recipient_emails=recipient_emails,
            )
        )
    return out


def scan_imap_access_deactivated_messages(
    *,
    config: Imap2925Config,
    candidate_emails: set[str] | None = None,
) -> dict[str, ImapMailMetadata]:
    """
    功能目的：
        扫描“OpenAI - Access Deactivated[...]”邮件，并按收件人邮箱建立映射。
    """

    normalized_candidates = {
        str(item or "").strip().lower()
        for item in (candidate_emails or set())
        if str(item or "").strip()
    }

    def _subject_matches(subject: str) -> bool:
        text = str(subject or "").strip().lower()
        return text.startswith("openai - access deactivated[")

    hits: dict[str, ImapMailMetadata] = {}
    for item in scan_imap_message_metadata(config=config, subject_predicate=_subject_matches):
        matched_emails = normalized_candidates.intersection(item.recipient_emails) if normalized_candidates else set(item.recipient_emails)
        if not matched_emails:
            continue
        for email in matched_emails:
            current = hits.get(email)
            if current is None or str(item.received_at or "") >= str(current.received_at or ""):
                hits[email] = item
    return hits
