from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import struct
import time
from pathlib import Path
from typing import Any


def normalize_totp_secret(secret: str) -> str:
    """规范化 TOTP 密钥，统一为去空格的大写 Base32 文本。"""

    return re.sub(r"\s+", "", str(secret or "").strip()).upper()


def load_totp_secret_from_storage_state(storage_state_path: str) -> str:
    """从 storage_state 根节点或 mfa_summary 中读取 TOTP 密钥。"""

    safe_path = str(storage_state_path or "").strip()
    if not safe_path:
        return ""

    try:
        payload = json.loads(Path(safe_path).expanduser().read_text(encoding="utf-8") or "{}")
    except Exception:
        return ""
    if not isinstance(payload, dict):
        return ""

    summary = payload.get("mfa_summary") if isinstance(payload.get("mfa_summary"), dict) else {}
    for value in (
        summary.get("secret"),
        payload.get("mfa_totp_secret"),
        payload.get("mfaTotpSecret"),
    ):
        normalized = normalize_totp_secret(str(value or ""))
        if normalized:
            return normalized
    return ""


def generate_totp_code(secret: str, *, for_time: int | None = None) -> str:
    """基于 Base32 TOTP 密钥生成 6 位验证码。"""

    normalized = normalize_totp_secret(secret)
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


def totp_seconds_remaining(*, now_ts: float | None = None, interval: int = 30) -> int:
    """返回当前 TOTP 码剩余有效秒数。"""

    safe_interval = max(1, int(interval or 30))
    current_ts = float(time.time() if now_ts is None else now_ts)
    elapsed = int(current_ts) % safe_interval
    remaining = safe_interval - elapsed
    return safe_interval if remaining <= 0 else remaining


def build_totp_view(secret: str, *, now_ts: float | None = None) -> dict[str, Any]:
    """返回手动展示 TOTP 时常用的密钥/验证码/剩余秒数摘要。"""

    normalized = normalize_totp_secret(secret)
    if not normalized:
        return {
            "secret": "",
            "code": "",
            "seconds_remaining": 0,
        }
    return {
        "secret": normalized,
        "code": generate_totp_code(normalized, for_time=int(time.time() if now_ts is None else now_ts)),
        "seconds_remaining": totp_seconds_remaining(now_ts=now_ts),
    }
