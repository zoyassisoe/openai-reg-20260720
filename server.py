from __future__ import annotations

import base64
import concurrent.futures
import csv
import email
import email.policy
import hashlib
import hmac
import imaplib
import ipaddress
import io
import json
import os
import queue
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

import requests

from enable_totp_mfa import (
    ChatGptTotpMfaError,
    enable_totp_mfa_via_storage_state,
    generate_totp_code,
    normalize_totp_secret,
    read_access_token_via_cookie_header,
    read_auth_session_via_cookie_header,
)
from enable_totp_mfa.module import load_cookie_header_from_storage_state, try_read_oai_did_from_storage_state
from sms_provider import create_sms_provider


ROOT = Path(__file__).resolve().parent
PUBLIC_DIR = ROOT / "public"
DATA_DIR = Path(os.environ.get("REG_2FA_DATA_DIR") or (ROOT / "data")).expanduser().resolve()
X9_RUNTIME_ROOT = Path(os.environ.get("X9_ISOLATED_ROOT") or (DATA_DIR / "x9")).expanduser().resolve()
TOOLCORE_DIR = ROOT / "X9-Free" / "_credential_toolcore"
if str(TOOLCORE_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLCORE_DIR))
from code_utils import defaultCodeKeywords, extractVerificationCode  # noqa: E402
JOBS_PATH = DATA_DIR / "jobs.json"
SETTINGS_PATH = DATA_DIR / "settings.json"
SECRETS_PATH = DATA_DIR / "secrets.json"
RUN_DIR = Path(os.environ.get("REG_2FA_RUN_DIR") or (DATA_DIR / "runs")).expanduser().resolve()
AUDIT_PATH = DATA_DIR / "audit.jsonl"
SMS_ACTIVATIONS_DIR = DATA_DIR / "sms-activations"
MANUAL_PHONE_DIR = DATA_DIR / "manual-phone"
RUNNER_PATH = ROOT / "runner.py"

DEFAULT_HOST = str(os.environ.get("REG_2FA_HOST") or "0.0.0.0")
DEFAULT_PORT = int(os.environ.get("REG_2FA_PORT") or "5188")
ACCESS_USERNAME = str(os.environ.get("REG_2FA_USERNAME") or "admin")
ACCESS_PASSWORD = str(os.environ.get("REG_2FA_PASSWORD") or "")

JOBS_LOCK = threading.RLock()
RUNTIME_LOCK = threading.RLock()
ACCOUNT_LOCKS_LOCK = threading.Lock()
ACCOUNT_LOCKS: dict[str, threading.Lock] = {}
STOP_EVENT = threading.Event()
SMS_RECOVERY_COMPLETE = threading.Event()
SMS_RECOVERY_COMPLETE.set()
MANUAL_PHONE_LOCK = threading.Lock()
RUNTIME: dict[str, Any] = {
    "running": False,
    "startedAt": "",
    "finishedAt": "",
    "active": {},
    "logs": [],
    "logSeq": 0,
    "worker": None,
    "operation": "idle",
    "activeJobIds": [],
    "proxyCursor": 0,
    "total": 0,
    "completed": 0,
    "success": 0,
    "failed": 0,
    "totalCount": 0,
    "completedCount": 0,
    "successCount": 0,
    "failedCount": 0,
    "manualPhoneJobId": "",
    "manualPhoneSessionId": "",
}

EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
RUNNABLE_STATUSES = {
    "queued",
    "registration_failed",
    "session_pending",
    "mfa_failed",
    "stopped",
    "interrupted",
}
PRIVATE_JOB_KEYS = {"accountPassword", "provider", "storageStatePath", "atPath", "tracePath"}
SETTINGS_DEFAULTS = {
    "concurrency": 1,
    "registerTimeoutSeconds": 360,
    "otpTimeoutSeconds": 180,
    "otpIntervalSeconds": 2,
    "proxy": "",
    "proxyPool": [],
    "proxyStrategy": "round_robin",
    "trace": False,
    "autoEnableMfaAfterRegistration": True,
    "smsProvider": "",
    "smsApiKey": "",
    "smsCountry": "52",
    "smsService": "dr",
    "smsMaxPrice": -1.0,
    "smsReusePhone": False,
    "smsPhoneSuccessMax": 3,
    "smsAutoCountry": False,
    "smsAllowedCountries": [],
    "smsAutoMinStock": 20,
    "smsAutoMaxPrice": -1.0,
    "smsStrictWhitelist": False,
    "smsMaxPhoneAttempts": 0,
    "smsPerPhoneTimeout": 80,
}
PROXY_STRATEGIES = {"single", "round_robin", "random", "sticky"}
IP_CHECK_URLS = (
    "https://api.ipify.org?format=json",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
)
IP_GEO_URLS = (
    "https://ipwho.is/{ip}",
    "https://ipapi.co/{ip}/json/",
)
FIRST_NAMES = (
    "Adrian", "Aiden", "Alex", "Amelia", "Andrew", "Audrey", "Benjamin", "Blake", "Caleb", "Cameron",
    "Charlotte", "Chloe", "Daniel", "Dylan", "Eleanor", "Elijah", "Emily", "Ethan", "Evelyn", "Gabriel",
    "Grace", "Hannah", "Henry", "Isaac", "Isla", "Jack", "James", "Julia", "Leo", "Lily", "Lucas", "Mason",
    "Maya", "Mia", "Nathan", "Nora", "Oliver", "Owen", "Ruby", "Ryan", "Samuel", "Sofia", "Theo", "Violet",
)
LAST_NAMES = (
    "Anderson", "Baker", "Bennett", "Brooks", "Campbell", "Carter", "Clark", "Collins", "Cooper", "Davis",
    "Edwards", "Evans", "Foster", "Garcia", "Gray", "Green", "Hall", "Harris", "Hayes", "Hill", "Howard",
    "Hughes", "Jackson", "James", "Kelly", "King", "Lee", "Lewis", "Martin", "Mitchell", "Moore", "Morgan",
    "Morris", "Nelson", "Parker", "Reed", "Rivera", "Roberts", "Scott", "Stewart", "Taylor", "Thomas", "Walker", "Young",
)
NAME_POOL_SIZE = len(FIRST_NAMES) * len(LAST_NAMES)


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def allocate_display_name(email: str, used_names: set[str]) -> str:
    digest = hashlib.sha256(str(email or "").strip().lower().encode("utf-8")).digest()
    start = int.from_bytes(digest[:8], "big") % NAME_POOL_SIZE
    for offset in range(NAME_POOL_SIZE):
        index = (start + offset) % NAME_POOL_SIZE
        candidate = f"{FIRST_NAMES[index // len(LAST_NAMES)]} {LAST_NAMES[index % len(LAST_NAMES)]}"
        if candidate.casefold() not in used_names:
            used_names.add(candidate.casefold())
            return candidate
    raise RuntimeError("注册姓名池已耗尽")


def decode_access_token_metadata(token: str) -> dict[str, Any]:
    value = str(token or "").strip()
    payload: dict[str, Any] = {}
    try:
        encoded = value.split(".")[1]
        encoded += "=" * ((4 - len(encoded) % 4) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(encoded.encode("ascii")).decode("utf-8"))
        if isinstance(decoded, dict):
            payload = decoded
    except Exception:
        payload = {}
    try:
        expires_at = int(payload.get("exp") or 0)
    except Exception:
        expires_at = 0
    return {
        "present": bool(value),
        "expiresAtEpoch": expires_at,
        "expiresAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expires_at)) if expires_at else "",
        "expired": bool(expires_at and expires_at <= int(time.time())),
        "length": len(value),
    }


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(str(path), os.O_RDONLY)
    except (AttributeError, OSError):
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def write_json_atomic(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    with temp.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.chmod(temp, 0o600)
    except OSError:
        pass
    os.replace(temp, path)
    _fsync_directory(path.parent)


def write_text_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    with temp.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(str(text or ""))
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.chmod(temp, 0o600)
    except OSError:
        pass
    os.replace(temp, path)
    _fsync_directory(path.parent)


def read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def append_audit(action: str, *, job_id: str = "", email: str = "", detail: str = "") -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    record = {
        "at": utc_now(),
        "action": str(action or ""),
        "jobId": str(job_id or ""),
        "email": str(email or ""),
        "detail": str(detail or "")[:500],
    }
    with JOBS_LOCK:
        with AUDIT_PATH.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
            handle.flush()
        try:
            os.chmod(AUDIT_PATH, 0o600)
        except OSError:
            pass


def normalize_proxy_url(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if "://" not in text:
        parts = text.split(":")
        if len(parts) == 2:
            text = f"http://{parts[0]}:{parts[1]}"
        elif len(parts) == 4:
            host, port, username, password = parts
            text = (
                f"http://{urllib.parse.quote(username, safe='')}:{urllib.parse.quote(password, safe='')}"
                f"@{host}:{port}"
            )
        else:
            raise ValueError(f"代理格式无效: {text}")
    parsed = urllib.parse.urlsplit(text)
    if parsed.scheme.lower() not in {"http", "https", "socks5", "socks5h"} or not parsed.hostname or not parsed.port:
        raise ValueError(f"代理格式无效: {text}")
    if parsed.scheme.lower() == "socks5":
        # Always resolve OpenAI/ChatGPT hostnames through the SOCKS proxy.  A
        # plain socks5 URL lets Requests/curl resolve DNS locally, which can
        # leak the local resolver and can make an otherwise healthy proxy fail
        # when local DNS returns a synthetic address.
        text = urllib.parse.urlunsplit(("socks5h", parsed.netloc, parsed.path, parsed.query, parsed.fragment))
    return text


def normalize_proxy_pool(value: Any) -> list[str]:
    rows = value if isinstance(value, list) else str(value or "").replace("\r", "").split("\n")
    output: list[str] = []
    seen: set[str] = set()
    for row in rows:
        proxy = normalize_proxy_url(row)
        if proxy and proxy not in seen:
            seen.add(proxy)
            output.append(proxy)
    return output


def mask_proxy_url(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return "直连"
    try:
        parsed = urllib.parse.urlsplit(text)
        host = parsed.hostname or ""
        port = f":{parsed.port}" if parsed.port else ""
        user = urllib.parse.unquote(parsed.username or "")
        auth = f"{user}:***@" if user else ""
        return f"{parsed.scheme}://{auth}{host}{port}"
    except Exception:
        return "已配置代理"


def _normalize_sms_country_list(value: Any) -> list[str]:
    if isinstance(value, list):
        items = [str(item or "").strip() for item in value]
    else:
        text = str(value or "").replace(";", ",")
        items = [part.strip() for part in text.split(",")]
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _safe_settings_float(value: Any, default: float) -> float:
    try:
        if value in (None, ""):
            return float(default)
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def _safe_settings_int(value: Any, default: int) -> int:
    try:
        if value in (None, ""):
            return int(default)
        return int(value)
    except (TypeError, ValueError):
        return int(default)


def load_settings() -> dict[str, Any]:
    raw = read_json(SETTINGS_PATH, {})
    raw = raw if isinstance(raw, dict) else {}
    sms_provider = str(raw.get("smsProvider") or "").strip().lower()
    if sms_provider not in {"", "smsbower", "herosms"}:
        sms_provider = ""
    sms_max_price = _safe_settings_float(raw.get("smsMaxPrice", -1), -1.0)
    sms_auto_max_price = _safe_settings_float(raw.get("smsAutoMaxPrice", -1), -1.0)
    return {
        "concurrency": max(1, min(10, int(raw.get("concurrency") or SETTINGS_DEFAULTS["concurrency"]))),
        "registerTimeoutSeconds": max(60, min(1800, int(raw.get("registerTimeoutSeconds") or 360))),
        "otpTimeoutSeconds": max(30, min(600, int(raw.get("otpTimeoutSeconds") or 180))),
        "otpIntervalSeconds": max(1, min(15, int(raw.get("otpIntervalSeconds") or 2))),
        "proxy": str(raw.get("proxy") or "").strip(),
        "proxyPool": normalize_proxy_pool(raw.get("proxyPool") or []),
        "proxyStrategy": str(raw.get("proxyStrategy") or "round_robin")
        if str(raw.get("proxyStrategy") or "round_robin") in PROXY_STRATEGIES
        else "round_robin",
        "trace": bool(raw.get("trace", False)),
        "autoEnableMfaAfterRegistration": True,
        "smsProvider": sms_provider,
        "smsApiKey": str(raw.get("smsApiKey") or "").strip(),
        "smsCountry": str(raw.get("smsCountry") or "52").strip() or "52",
        "smsService": str(raw.get("smsService") or "dr").strip() or "dr",
        "smsMaxPrice": sms_max_price,
        "smsReusePhone": bool(raw.get("smsReusePhone", False)),
        "smsPhoneSuccessMax": max(0, min(10, _safe_settings_int(raw.get("smsPhoneSuccessMax", 3), 3))),
        "smsAutoCountry": bool(raw.get("smsAutoCountry", False)),
        "smsAllowedCountries": _normalize_sms_country_list(raw.get("smsAllowedCountries")),
        "smsAutoMinStock": max(1, min(1000, _safe_settings_int(raw.get("smsAutoMinStock", 20), 20))),
        "smsAutoMaxPrice": sms_auto_max_price,
        "smsStrictWhitelist": bool(raw.get("smsStrictWhitelist", False)),
        "smsMaxPhoneAttempts": max(0, min(20, _safe_settings_int(raw.get("smsMaxPhoneAttempts", 0), 0))),
        "smsPerPhoneTimeout": max(40, min(600, _safe_settings_int(raw.get("smsPerPhoneTimeout", 80), 80))),
    }


def save_settings(payload: dict[str, Any]) -> dict[str, Any]:
    current = load_settings()
    incoming = payload if isinstance(payload, dict) else {}
    for key in SETTINGS_DEFAULTS:
        if key in incoming:
            current[key] = incoming[key]
    sms_provider = str(current.get("smsProvider") or "").strip().lower()
    if sms_provider not in {"", "smsbower", "herosms"}:
        raise ValueError("不支持的接码服务")
    sms_api_key = str(current.get("smsApiKey") or "").strip()
    if sms_provider and not sms_api_key:
        raise ValueError("启用接码服务时必须填写 API Key")
    sms_max_price = _safe_settings_float(current.get("smsMaxPrice", -1), -1.0)
    sms_auto_max_price = _safe_settings_float(current.get("smsAutoMaxPrice", -1), -1.0)
    normalized = {
        "concurrency": max(1, min(10, int(current.get("concurrency") or 1))),
        "registerTimeoutSeconds": max(60, min(1800, int(current.get("registerTimeoutSeconds") or 360))),
        "otpTimeoutSeconds": max(30, min(600, int(current.get("otpTimeoutSeconds") or 180))),
        "otpIntervalSeconds": max(1, min(15, int(current.get("otpIntervalSeconds") or 2))),
        "proxy": str(current.get("proxy") or "").strip(),
        "proxyPool": normalize_proxy_pool(current.get("proxyPool") or []),
        "proxyStrategy": str(current.get("proxyStrategy") or "round_robin")
        if str(current.get("proxyStrategy") or "round_robin") in PROXY_STRATEGIES
        else "round_robin",
        "trace": bool(current.get("trace")),
        "autoEnableMfaAfterRegistration": True,
        "smsProvider": sms_provider,
        "smsApiKey": sms_api_key,
        "smsCountry": str(current.get("smsCountry") or "52").strip() or "52",
        "smsService": str(current.get("smsService") or "dr").strip() or "dr",
        "smsMaxPrice": sms_max_price,
        "smsReusePhone": bool(current.get("smsReusePhone", False)),
        "smsPhoneSuccessMax": max(0, min(10, _safe_settings_int(current.get("smsPhoneSuccessMax", 3), 3))),
        "smsAutoCountry": bool(current.get("smsAutoCountry", False)),
        "smsAllowedCountries": _normalize_sms_country_list(current.get("smsAllowedCountries")),
        "smsAutoMinStock": max(1, min(1000, _safe_settings_int(current.get("smsAutoMinStock", 20), 20))),
        "smsAutoMaxPrice": sms_auto_max_price,
        "smsStrictWhitelist": bool(current.get("smsStrictWhitelist", False)),
        "smsMaxPhoneAttempts": max(0, min(20, _safe_settings_int(current.get("smsMaxPhoneAttempts", 0), 0))),
        "smsPerPhoneTimeout": max(40, min(600, _safe_settings_int(current.get("smsPerPhoneTimeout", 80), 80))),
    }
    write_json_atomic(SETTINGS_PATH, normalized)
    return normalized


def public_settings(settings: dict[str, Any] | None = None) -> dict[str, Any]:
    values = dict(settings or load_settings())
    proxy_pool = list(values.pop("proxyPool", []) or [])
    sms_api_key = str(values.pop("smsApiKey", "") or "")
    return {
        **values,
        "proxy": "",
        "proxyConfigured": bool(values.get("proxy")),
        "proxyPool": [],
        "proxyPoolConfigured": bool(proxy_pool),
        "proxyPoolCount": len(proxy_pool),
        "proxyPoolLabels": [mask_proxy_url(proxy) for proxy in proxy_pool],
        "smsApiKey": "",
        "smsApiKeyConfigured": bool(sms_api_key),
        "smsApiKeyProvided": bool(sms_api_key),
    }


def build_sms_provider_config(settings: dict[str, Any] | None = None) -> dict[str, Any]:
    values = settings or load_settings()
    allowed = _normalize_sms_country_list(values.get("smsAllowedCountries"))
    return {
        "sms_provider": str(values.get("smsProvider") or "").strip().lower(),
        "sms_api_key": str(values.get("smsApiKey") or "").strip(),
        "sms_country": str(values.get("smsCountry") or "52").strip() or "52",
        "sms_service": str(values.get("smsService") or "dr").strip() or "dr",
        "sms_max_price": values.get("smsMaxPrice", -1),
        "sms_reuse_phone": bool(values.get("smsReusePhone", False)),
        "sms_phone_success_max": int(values.get("smsPhoneSuccessMax") or 3),
        "sms_auto_select_country": bool(values.get("smsAutoCountry", False)),
        "sms_allowed_countries": ",".join(allowed),
        "sms_auto_min_stock": int(values.get("smsAutoMinStock") or 20),
        "sms_auto_max_price": values.get("smsAutoMaxPrice", -1),
        "sms_strict_whitelist": bool(values.get("smsStrictWhitelist", False)),
        "sms_max_phone_attempts": int(values.get("smsMaxPhoneAttempts") or 0),
        "sms_per_phone_timeout": int(values.get("smsPerPhoneTimeout") or 80),
        "proxy": str(values.get("proxy") or "").strip(),
    }


def list_sms_countries(provider: str = "") -> dict[str, Any]:
    from sms_provider import OPENAI_SMS_COUNTRIES, SMS_COUNTRY_NAMES_CN, create_sms_provider

    settings = load_settings()
    provider_key = str(provider or settings.get("smsProvider") or "smsbower").strip().lower()
    if provider_key not in {"smsbower", "herosms"}:
        provider_key = "smsbower"
    countries: list[dict[str, Any]] = []
    source = "static"
    api_key = str(settings.get("smsApiKey") or "").strip()
    if api_key:
        try:
            cfg = build_sms_provider_config(settings)
            cfg["sms_provider"] = provider_key
            rows = create_sms_provider(provider_key, cfg).get_top_countries(
                service=str(settings.get("smsService") or "dr")
            )
            for row in rows or []:
                cid = str((row or {}).get("country") or "").strip()
                if not cid:
                    continue
                countries.append(
                    {
                        "id": cid,
                        "name_cn": SMS_COUNTRY_NAMES_CN.get(cid, f"国家{cid}"),
                        "price": (row or {}).get("price"),
                        "count": (row or {}).get("count"),
                        "openai_sms_safe": cid in OPENAI_SMS_COUNTRIES,
                    }
                )
            if countries:
                source = "live"
        except Exception:
            countries = []
    if not countries:
        countries = [
            {
                "id": cid,
                "name_cn": name,
                "price": None,
                "count": None,
                "openai_sms_safe": cid in OPENAI_SMS_COUNTRIES,
            }
            for cid, name in SMS_COUNTRY_NAMES_CN.items()
        ]
    return {
        "ok": True,
        "provider": provider_key,
        "countries": countries,
        "openai_sms_safe": sorted(OPENAI_SMS_COUNTRIES),
        "source": source,
    }


def test_sms_balance() -> dict[str, Any]:
    settings = load_settings()
    provider_key = str(settings.get("smsProvider") or "").strip().lower()
    if provider_key not in {"smsbower", "herosms"}:
        raise ValueError("请先选择接码服务")
    if not str(settings.get("smsApiKey") or "").strip():
        raise ValueError("未配置接码 API Key")
    provider = create_sms_provider(provider_key, build_sms_provider_config(settings))
    balance = provider.get_balance()
    return {
        "ok": True,
        "provider": provider_key,
        "balance": balance,
        "message": f"{provider_key} 余额: {balance}",
    }


def sms_activation_journal_path(job_id: str) -> Path:
    token = hashlib.sha256(str(job_id or "").encode("utf-8")).hexdigest()[:24]
    return SMS_ACTIVATIONS_DIR / f"{token}.json"


def manual_phone_control_dir(job_id: str) -> Path:
    token = hashlib.sha256(str(job_id or "").encode("utf-8")).hexdigest()[:24]
    return MANUAL_PHONE_DIR / token


def manual_phone_status(job_id: str) -> dict[str, Any]:
    payload = read_json(manual_phone_control_dir(job_id) / "status.json", {})
    if not isinstance(payload, dict):
        payload = {}
    phase = str(payload.get("phase") or "idle").strip() or "idle"
    job = get_job(job_id)
    return {
        "ok": True,
        "jobId": str(job_id or ""),
        "phase": phase,
        "active": bool(payload.get("active")),
        "attemptId": int(payload.get("attemptId") or 0),
        "phoneMasked": str(payload.get("phoneMasked") or ""),
        "error": redact_text(str(payload.get("error") or ""), job=job)[:1000],
        "updatedAtEpoch": float(payload.get("updatedAtEpoch") or 0),
    }


def update_manual_phone_status(job_id: str, **fields: Any) -> dict[str, Any]:
    status_path = manual_phone_control_dir(job_id) / "status.json"
    payload = read_json(status_path, {})
    if not isinstance(payload, dict):
        payload = {}
    payload.update(fields)
    payload["updatedAtEpoch"] = time.time()
    write_json_atomic(status_path, payload)
    return manual_phone_status(job_id)


def _cleanup_manual_phone_transients(control_dir: Path) -> None:
    artifacts = [
        control_dir / "phone.json",
        control_dir / "code.json",
        control_dir / "code-submission.json",
    ]
    for pattern in (".phone.json.*.tmp", ".code.json.*.tmp", ".code-submission.json.*.tmp"):
        try:
            artifacts.extend(control_dir.glob(pattern))
        except OSError:
            pass
    for artifact in artifacts:
        try:
            artifact.unlink(missing_ok=True)
        except OSError:
            pass


def recover_interrupted_manual_phone_controls() -> None:
    """Invalidate interrupted sessions and remove plaintext phone/code IPC."""

    MANUAL_PHONE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        control_dirs = list(MANUAL_PHONE_DIR.iterdir())
    except OSError:
        control_dirs = []
    for control_dir in control_dirs:
        if not control_dir.is_dir() or control_dir.is_symlink():
            continue
        _cleanup_manual_phone_transients(control_dir)
        status_path = control_dir / "status.json"
        status_payload = read_json(status_path, {})
        if isinstance(status_payload, dict) and bool(status_payload.get("active")):
            status_payload.update(
                {
                    "phase": "stopped",
                    "active": False,
                    "error": "服务重启，手动绑号会话已结束；原登录态未覆盖，可重新开始。",
                    "updatedAtEpoch": time.time(),
                }
            )
            write_json_atomic(status_path, status_payload)


def _manual_phone_runtime_owned_locked(job_id: str, session_id: str) -> bool:
    """Return whether the caller still owns the active manual-phone runtime.

    RUNTIME_LOCK must be held by the caller.  A per-run owner token prevents a
    late cleanup from an older worker from clearing a newer run for the same
    job.
    """

    return bool(
        RUNTIME.get("running")
        and RUNTIME.get("operation") == "manual_phone_binding"
        and str(RUNTIME.get("manualPhoneJobId") or "") == str(job_id or "")
        and str(RUNTIME.get("manualPhoneSessionId") or "") == str(session_id or "")
        and str(session_id or "")
    )


def _release_manual_phone_runtime_locked(
    job_id: str,
    session_id: str,
    *,
    completed: bool,
    succeeded: bool,
) -> bool:
    """Release a manual-phone runtime only when the owner token still matches."""

    if not _manual_phone_runtime_owned_locked(job_id, session_id):
        return False
    completed_count = 1 if completed else 0
    RUNTIME["completed"] = completed_count
    RUNTIME["completedCount"] = completed_count
    RUNTIME["success"] = 1 if completed and succeeded else 0
    RUNTIME["successCount"] = RUNTIME["success"]
    RUNTIME["failed"] = 1 if completed and not succeeded else 0
    RUNTIME["failedCount"] = RUNTIME["failed"]
    RUNTIME["running"] = False
    RUNTIME["finishedAt"] = utc_now()
    RUNTIME["worker"] = None
    RUNTIME["operation"] = "idle"
    RUNTIME["activeJobIds"] = []
    RUNTIME["manualPhoneJobId"] = ""
    RUNTIME["manualPhoneSessionId"] = ""
    return True


def sms_activation_journal_candidates(job_id: str) -> list[Path]:
    primary = sms_activation_journal_path(job_id)
    candidates = [primary] if primary.is_file() else []
    if primary.parent.exists():
        candidates.extend(path for path in primary.parent.glob(f"{primary.name}.*.tmp") if path.is_file())
    return list(dict.fromkeys(candidates))


def cleanup_sms_activation_journal(
    path: Path,
    settings: dict[str, Any],
    *,
    job: dict[str, Any] | None = None,
) -> bool:
    if not path.exists():
        return True
    journal = read_json(path, {})
    provider_key = str(journal.get("provider") or "").strip().lower() if isinstance(journal, dict) else ""
    activation_id = str(journal.get("activationId") or "").strip() if isinstance(journal, dict) else ""
    if provider_key not in {"smsbower", "herosms"} or not activation_id:
        append_log("warn", "接码恢复记录无效，已保留供人工检查", job=job, stage="sms")
        return False
    provider_config = {
        "sms_api_key": str(settings.get("smsApiKey") or "").strip(),
        "sms_country": str(journal.get("country") or settings.get("smsCountry") or "52").strip(),
        "sms_service": str(journal.get("service") or settings.get("smsService") or "dr").strip(),
        "sms_max_price": settings.get("smsMaxPrice", -1),
        "sms_reuse_phone": False,
        "proxy": str(journal.get("proxy") or settings.get("proxy") or "").strip(),
    }
    try:
        cancelled = bool(create_sms_provider(provider_key, provider_config).cancel(activation_id))
    except Exception:
        cancelled = False
    if not cancelled:
        append_log("warn", "接码订单补偿取消未确认，恢复记录已保留以便下次重试", job=job, stage="sms")
        return False
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        append_log("warn", "接码订单已取消，但恢复记录清理失败", job=job, stage="sms")
        return False
    append_audit(
        "sms_activation_cancelled",
        job_id=str((job or {}).get("id") or ""),
        email=str((job or {}).get("email") or ""),
        detail=provider_key,
    )
    append_log("info", "已补偿取消未完成的接码订单", job=job, stage="sms")
    return True


def list_pending_sms_activation_journals() -> list[Path]:
    SMS_ACTIVATIONS_DIR.mkdir(parents=True, exist_ok=True)
    paths = {
        path
        for pattern in ("*.json", "*.json.*.tmp")
        for path in SMS_ACTIVATIONS_DIR.glob(pattern)
        if path.is_file()
    }
    return sorted(paths)


def recover_pending_sms_activations(
    settings: dict[str, Any] | None = None,
    *,
    paths: list[Path] | None = None,
) -> None:
    current_settings = dict(settings or load_settings())
    recovery_paths = list(paths) if paths is not None else list_pending_sms_activation_journals()
    for path in recovery_paths:
        cleanup_sms_activation_journal(path, current_settings)


def choose_proxy(settings: dict[str, Any], job_id: str) -> str:
    pool = list(settings.get("proxyPool") or [])
    legacy = str(settings.get("proxy") or "").strip()
    if not pool:
        return legacy
    strategy = str(settings.get("proxyStrategy") or "round_robin")
    if strategy == "single":
        return pool[0]
    if strategy == "random":
        return secrets.choice(pool)
    if strategy == "sticky":
        digest = hashlib.sha256(str(job_id or "").encode("utf-8")).digest()
        return pool[int.from_bytes(digest[:8], "big") % len(pool)]
    with RUNTIME_LOCK:
        index = int(RUNTIME.get("proxyCursor") or 0) % len(pool)
        RUNTIME["proxyCursor"] = (index + 1) % len(pool)
    return pool[index]


def settings_for_job(settings: dict[str, Any], job_id: str) -> dict[str, Any]:
    selected = dict(settings)
    selected["proxy"] = choose_proxy(settings, job_id)
    return selected


def detect_exit_ip(proxy: str = "") -> dict[str, Any]:
    proxy_url = str(proxy or "").strip()
    proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None
    errors: list[str] = []
    started = time.monotonic()
    for url in IP_CHECK_URLS:
        try:
            response = requests.get(
                url,
                proxies=proxies,
                timeout=8,
                headers={"accept": "application/json,text/plain,*/*", "user-agent": "Registration2FA/1.0"},
            )
            response.raise_for_status()
            text = str(response.text or "").strip()
            try:
                payload = response.json()
            except Exception:
                payload = {}
            candidate = str(payload.get("ip") or text).strip().splitlines()[0]
            ipaddress.ip_address(candidate)
            return {
                "ok": True,
                "ip": candidate,
                "elapsedMs": int((time.monotonic() - started) * 1000),
                "endpoint": urllib.parse.urlsplit(url).netloc,
            }
        except Exception as error:
            message = str(error)
            if proxy_url:
                message = message.replace(proxy_url, mask_proxy_url(proxy_url))
            errors.append(f"{urllib.parse.urlsplit(url).netloc}: {message}")
    return {
        "ok": False,
        "ip": "",
        "elapsedMs": int((time.monotonic() - started) * 1000),
        "error": " | ".join(errors)[:1000] or "无法检测出口 IP",
    }


def lookup_ip_geolocation(ip: str) -> dict[str, Any]:
    value = str(ip or "").strip()
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return {"ok": False, "error": "IP 地址无效"}
    errors: list[str] = []
    for template in IP_GEO_URLS:
        url = template.format(ip=urllib.parse.quote(value, safe=""))
        try:
            response = requests.get(
                url,
                timeout=8,
                headers={"accept": "application/json", "user-agent": "Registration2FA/1.0"},
            )
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                raise RuntimeError("地理接口返回格式无效")
            if payload.get("success") is False or payload.get("error") is True:
                raise RuntimeError(str(payload.get("message") or payload.get("reason") or "地理接口查询失败"))
            connection = payload.get("connection") if isinstance(payload.get("connection"), dict) else {}
            timezone = payload.get("timezone") if isinstance(payload.get("timezone"), dict) else {}
            country = str(payload.get("country") or payload.get("country_name") or "").strip()
            region = str(payload.get("region") or payload.get("region_name") or "").strip()
            city = str(payload.get("city") or "").strip()
            organization = str(
                connection.get("isp")
                or connection.get("org")
                or payload.get("org")
                or payload.get("isp")
                or ""
            ).strip()
            timezone_name = str(timezone.get("id") or payload.get("timezone") or "").strip()
            if not any((country, region, city, organization)):
                raise RuntimeError("地理接口未返回位置数据")
            return {
                "ok": True,
                "country": country,
                "region": region,
                "city": city,
                "organization": organization,
                "timezone": timezone_name,
                "location": " · ".join(item for item in (country, region, city) if item),
                "provider": urllib.parse.urlsplit(url).netloc,
            }
        except Exception as error:
            errors.append(f"{urllib.parse.urlsplit(url).netloc}: {error}")
    return {"ok": False, "error": " | ".join(errors)[:1000] or "无法查询 IP 地理位置"}


def detect_local_network() -> dict[str, Any]:
    hostname = socket.gethostname()
    addresses: set[str] = set()
    try:
        for info in socket.getaddrinfo(hostname, None, family=socket.AF_INET):
            address = str(info[4][0] or "")
            if address and not address.startswith("127."):
                addresses.add(address)
    except OSError:
        pass
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(("1.1.1.1", 53))
        addresses.add(str(probe.getsockname()[0]))
        probe.close()
    except OSError:
        pass
    direct = detect_exit_ip()
    geo = lookup_ip_geolocation(str(direct.get("ip") or "")) if direct.get("ok") else {"ok": False}
    return {
        "ok": True,
        "hostname": hostname,
        "localIps": sorted(addresses),
        "publicIp": str(direct.get("ip") or ""),
        "publicIpOk": bool(direct.get("ok")),
        "publicIpError": str(direct.get("error") or ""),
        "elapsedMs": int(direct.get("elapsedMs") or 0),
        "geo": geo,
    }


def test_proxy_pool(proxies: list[str]) -> list[dict[str, Any]]:
    def test_one(item: tuple[int, str]) -> dict[str, Any]:
        index, proxy = item
        result = detect_exit_ip(proxy)
        if result.get("ok"):
            result["geo"] = lookup_ip_geolocation(str(result.get("ip") or ""))
        return {"index": index + 1, "proxy": mask_proxy_url(proxy), **result}

    indexed = list(enumerate(proxies))
    if not indexed:
        return []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(6, len(indexed))) as executor:
        results = list(executor.map(test_one, indexed))
    return sorted(results, key=lambda item: int(item.get("index") or 0))


def load_jobs() -> list[dict[str, Any]]:
    rows = read_json(JOBS_PATH, [])
    return [dict(row) for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def save_jobs(rows: list[dict[str, Any]]) -> None:
    write_json_atomic(JOBS_PATH, rows)


def load_secret_store() -> dict[str, dict[str, str]]:
    payload = read_json(SECRETS_PATH, {})
    if not isinstance(payload, dict):
        return {}
    return {
        str(job_id): {str(key): str(value) for key, value in values.items()}
        for job_id, values in payload.items()
        if isinstance(values, dict)
    }


def save_secret_store(payload: dict[str, dict[str, str]]) -> None:
    write_json_atomic(SECRETS_PATH, payload)


def hydrate_job(job: dict[str, Any]) -> dict[str, Any]:
    hydrated = dict(job)
    values = load_secret_store().get(str(job.get("id") or ""), {})
    hydrated["accountPassword"] = str(values.get("accountPassword") or "")
    provider = dict(job.get("provider") or {}) if isinstance(job.get("provider"), dict) else {}
    mode = str(provider.get("mode") or "api")
    if mode == "api":
        provider["apiUrl"] = str(values.get("apiUrl") or "")
    else:
        provider["password"] = str(values.get("mailPassword") or "")
        if mode == "outlook_oauth":
            provider["refreshToken"] = str(values.get("refreshToken") or "")
    hydrated["provider"] = provider
    return hydrated


def get_job(job_id: str) -> dict[str, Any] | None:
    with JOBS_LOCK:
        row = next((dict(item) for item in load_jobs() if str(item.get("id")) == str(job_id)), None)
        return hydrate_job(row) if row is not None else None


def update_job(job_id: str, **changes: Any) -> dict[str, Any] | None:
    with JOBS_LOCK:
        rows = load_jobs()
        updated = None
        for row in rows:
            if str(row.get("id")) != str(job_id):
                continue
            row.update(changes)
            row["updatedAt"] = utc_now()
            updated = dict(row)
            break
        if updated is not None:
            save_jobs(rows)
        return updated


def access_token_from_state(payload: dict[str, Any]) -> str:
    if not isinstance(payload, dict):
        return ""
    return str(
        payload.get("session_access_token")
        or payload.get("accessToken")
        or payload.get("access_token")
        or ""
    ).strip()


def _decode_access_token_claims(token: str) -> dict[str, Any]:
    value = str(token or "").strip()
    parts = value.split(".")
    if len(parts) < 2:
        return {}
    payload = parts[1]
    payload += "=" * (-len(payload) % 4)
    try:
        data = json.loads(base64.urlsafe_b64decode(payload.encode("utf-8")))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def access_token_requires_password_login(payload: dict[str, Any] | str) -> bool:
    token = (
        access_token_from_state(payload)
        if isinstance(payload, dict)
        else str(payload or "").strip()
    )
    if not token:
        return True
    claims = _decode_access_token_claims(token)
    if not claims:
        return False
    auth = claims.get("https://api.openai.com/auth")
    auth_payload = auth if isinstance(auth, dict) else {}
    if bool(auth_payload.get("is_signup")):
        return True
    amr = auth_payload.get("amr")
    if isinstance(amr, list):
        normalized = {
            str(item or "").strip().lower()
            for item in amr
            if str(item or "").strip()
        }
        if normalized and not any(
            marker in value
            for value in normalized
            for marker in ("pwd", "password", "passkey")
        ):
            # OTP-only signup sessions can call many endpoints but MFA enroll
            # still returns token_revoked/401 until a password login is completed.
            return True
    return False


def at_job_fields(token: str, *, updated_at: str = "", source: str = "") -> dict[str, Any]:
    metadata = decode_access_token_metadata(token)
    return {
        "atPresent": bool(metadata["present"]),
        "atStatus": "expired" if metadata["expired"] else ("available" if metadata["present"] else "missing"),
        "atExpiresAt": str(metadata["expiresAt"] or ""),
        "atExpired": bool(metadata["expired"]),
        "atUpdatedAt": str(updated_at or utc_now()) if metadata["present"] else "",
        "atSource": str(source or ""),
    }


def normalize_plan_type(value: Any) -> str:
    plan = str(value or "").strip().lower()
    if not plan:
        return ""
    aliases = {
        "chatgptplus": "plus",
        "chatgpt_plus": "plus",
        "chatgptplusplan": "plus",
        "plusplan": "plus",
        "plus_monthly": "plus",
        "plus_yearly": "plus",
        "go": "go",
        "freeplan": "free",
        "chatgptfreeplan": "free",
        "teamplan": "team",
        "proplan": "pro",
        "enterpriseplan": "enterprise",
    }
    return aliases.get(plan, plan)


def extract_plan_type_from_token(token: str) -> str:
    claims = _decode_access_token_claims(token)
    if not claims:
        return ""
    auth = claims.get("https://api.openai.com/auth")
    auth_payload = auth if isinstance(auth, dict) else {}
    plan = str(
        auth_payload.get("chatgpt_plan_type")
        or auth_payload.get("plan_type")
        or claims.get("chatgpt_plan_type")
        or ""
    ).strip().lower()
    return normalize_plan_type(plan)


def extract_plan_type_from_session_payload(payload: dict[str, Any] | None, token: str = "") -> str:
    data = payload if isinstance(payload, dict) else {}
    account = data.get("account") if isinstance(data.get("account"), dict) else {}
    plan = normalize_plan_type(
        account.get("planType")
        or account.get("plan_type")
        or data.get("planType")
        or data.get("plan_type")
    )
    if plan:
        return plan
    token_value = str(token or access_token_from_state(data) or "").strip()
    if token_value:
        return extract_plan_type_from_token(token_value)
    return ""


def _plan_timestamp(*values: Any) -> str:
    best = ""
    for value in values:
        text = str(value or "").strip()
        if text and text > best:
            best = text
    return best


def extract_plan_type_from_job(job: dict[str, Any], *, prefer_cached: bool = True) -> str:
    candidates: list[tuple[str, str, str]] = []

    def add_candidate(plan: Any, updated_at: Any, source: str) -> None:
        normalized = normalize_plan_type(plan)
        if not normalized:
            return
        candidates.append((normalized, _plan_timestamp(updated_at), source))

    if prefer_cached:
        add_candidate(job.get("planType"), job.get("planUpdatedAt"), "job_cache")

    state_path = job_state_path(job)
    if state_path.exists():
        state = read_json(state_path, {})
        if isinstance(state, dict):
            summary = state.get("session_summary") if isinstance(state.get("session_summary"), dict) else {}
            add_candidate(
                summary.get("accountPlanType")
                or summary.get("planType")
                or summary.get("plan_type")
                or summary.get("chatgpt_plan_type"),
                summary.get("updatedAt") or state.get("session_access_token_updated_at"),
                "session_summary",
            )
            token = access_token_from_state(state)
            add_candidate(
                extract_plan_type_from_token(token),
                state.get("session_access_token_updated_at") or summary.get("updatedAt"),
                "session_token",
            )

    credential = read_success_credential(job)
    if isinstance(credential, dict):
        add_candidate(
            credential.get("chatgpt_plan_type") or credential.get("plan_type"),
            credential.get("last_refresh") or credential.get("expired"),
            "success_credential",
        )
        token = str(credential.get("access_token") or "").strip()
        add_candidate(
            extract_plan_type_from_token(token),
            credential.get("last_refresh") or credential.get("expired"),
            "success_token",
        )

    if not candidates:
        return ""

    # Prefer the newest observation. When timestamps tie, prefer non-free over free
    # and prefer ChatGPT session sources over cached job fields.
    source_rank = {
        "session_summary": 4,
        "session_token": 3,
        "success_credential": 2,
        "success_token": 2,
        "job_cache": 1,
    }

    def sort_key(item: tuple[str, str, str]) -> tuple:
        plan, updated_at, source = item
        return (
            updated_at or "",
            1 if plan not in {"free", "unknown"} else 0,
            source_rank.get(source, 0),
        )

    plan, _updated_at, _source = max(candidates, key=sort_key)
    return plan


def build_session_summary(session_payload: dict[str, Any], *, token: str = "", source: str = "") -> dict[str, Any]:
    data = session_payload if isinstance(session_payload, dict) else {}
    token_value = str(token or access_token_from_state(data) or "").strip()
    account = data.get("account") if isinstance(data.get("account"), dict) else {}
    user = data.get("user") if isinstance(data.get("user"), dict) else {}
    plan = extract_plan_type_from_session_payload(data, token_value)
    account_id = str(
        account.get("id")
        or account.get("accountId")
        or account.get("account_id")
        or ""
    ).strip()
    structure = str(account.get("structure") or data.get("structure") or "").strip().lower()
    return {
        "updatedAt": utc_now(),
        "httpStatus": 200,
        "error": "",
        "source": str(source or "auth_session"),
        "accessTokenPresent": bool(token_value),
        "accessTokenLength": len(token_value),
        "accountPlanType": plan,
        "accountStructure": structure,
        "accountId": account_id,
        "accountIdPresent": bool(account_id),
        "hasUser": bool(user or account),
        "hasAccount": bool(account),
        "hasSessionTokenField": bool(token_value or data.get("sessionToken") or data.get("authProvider")),
        "hasAuthProvider": bool(data.get("authProvider") or data.get("auth_provider")),
        "hasExpires": bool(data.get("expires") or data.get("sessionExpires") or data.get("exp")),
    }


def _path_within(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except (OSError, ValueError):
        return False


def job_state_path(job: dict[str, Any]) -> Path:
    email = str(job.get("email") or "").strip()
    expected = X9_RUNTIME_ROOT / "登录态" / f"{email}.json"
    candidate_text = str(job.get("storageStatePath") or "").strip()
    candidate = Path(candidate_text).expanduser() if candidate_text else expected
    if candidate_text and _path_within(candidate, DATA_DIR):
        return candidate.resolve(strict=False)
    return expected.resolve(strict=False)


def job_at_path(job: dict[str, Any]) -> Path:
    email = str(job.get("email") or "").strip()
    expected = X9_RUNTIME_ROOT / "AT文本" / f"{email}.txt"
    candidate_text = str(job.get("atPath") or "").strip()
    candidate = Path(candidate_text).expanduser() if candidate_text else expected
    if candidate_text and _path_within(candidate, DATA_DIR):
        return candidate.resolve(strict=False)
    return expected.resolve(strict=False)


def job_success_credential_path(job: dict[str, Any]) -> Path:
    email = str(job.get("email") or "").strip()
    expected = X9_RUNTIME_ROOT / "成功凭证" / f"{email}.json"
    candidate_text = str(job.get("successCredentialPath") or "").strip()
    candidate = Path(candidate_text).expanduser() if candidate_text else expected
    if candidate_text and _path_within(candidate, DATA_DIR):
        return candidate.resolve(strict=False)
    return expected.resolve(strict=False)


def _decode_jwt_payload_local(token: str) -> dict[str, Any]:
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


def read_success_credential(job: dict[str, Any]) -> dict[str, Any]:
    path = job_success_credential_path(job)
    if not path.exists():
        return {}
    payload = read_json(path, {})
    return payload if isinstance(payload, dict) else {}


def success_credential_has_rt(payload: dict[str, Any] | None) -> bool:
    if not isinstance(payload, dict):
        return False
    token_exchange = payload.get("token_exchange") if isinstance(payload.get("token_exchange"), dict) else {}
    refresh_token = str(payload.get("refresh_token") or token_exchange.get("refresh_token") or "").strip()
    access_token = str(payload.get("access_token") or token_exchange.get("access_token") or "").strip()
    return bool(refresh_token and access_token)


def build_cpa_rtjson(payload: dict[str, Any], *, email: str = "") -> dict[str, Any]:
    token_exchange = payload.get("token_exchange") if isinstance(payload.get("token_exchange"), dict) else {}
    access_token = str(payload.get("access_token") or token_exchange.get("access_token") or "").strip()
    refresh_token = str(payload.get("refresh_token") or token_exchange.get("refresh_token") or "").strip()
    id_token = str(payload.get("id_token") or token_exchange.get("id_token") or "").strip()
    email_text = str(payload.get("email") or email or "").strip().lower()
    if not access_token or not refresh_token:
        raise RuntimeError("成功凭证缺少 access_token/refresh_token")
    at_claims = _decode_jwt_payload_local(access_token)
    auth_claims = at_claims.get("https://api.openai.com/auth") if isinstance(at_claims, dict) else {}
    auth_claims = auth_claims if isinstance(auth_claims, dict) else {}
    account_id = str(payload.get("account_id") or auth_claims.get("chatgpt_account_id") or "").strip()
    expired = str(payload.get("expired") or "").strip()
    if not expired:
        exp = at_claims.get("exp")
        if isinstance(exp, int) and exp > 0:
            expired = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(exp))
    last_refresh = str(payload.get("last_refresh") or "").strip() or utc_now()
    return {
        "type": "codex",
        "email": email_text,
        "expired": expired,
        "id_token": id_token,
        "account_id": account_id,
        "access_token": access_token,
        "last_refresh": last_refresh,
        "refresh_token": refresh_token,
    }


def build_sub2api_payload(payload: dict[str, Any], *, email: str = "", group_ids: list[int] | None = None) -> dict[str, Any]:
    cpa = build_cpa_rtjson(payload, email=email)
    access_token = str(cpa.get("access_token") or "")
    id_token = str(cpa.get("id_token") or "")
    access_claims = _decode_jwt_payload_local(access_token)
    access_auth = access_claims.get("https://api.openai.com/auth") if isinstance(access_claims, dict) else {}
    access_auth = access_auth if isinstance(access_auth, dict) else {}
    id_auth = _decode_jwt_payload_local(id_token).get("https://api.openai.com/auth")
    id_auth = id_auth if isinstance(id_auth, dict) else {}
    expires_at = access_claims.get("exp")
    if not isinstance(expires_at, int) or expires_at <= 0:
        expires_at = int(time.time()) + 863999
    organization_id = str(id_auth.get("organization_id") or access_auth.get("organization_id") or access_auth.get("poid") or "").strip()
    if not organization_id:
        orgs = id_auth.get("organizations") or []
        if isinstance(orgs, list):
            for item in orgs:
                if isinstance(item, dict):
                    organization_id = str(item.get("id") or "").strip()
                    if organization_id:
                        break
    return {
        "name": str(cpa.get("email") or email or "").strip().lower(),
        "notes": "",
        "platform": "openai",
        "type": "oauth",
        "credentials": {
            "access_token": access_token,
            "refresh_token": str(cpa.get("refresh_token") or ""),
            "expires_in": 863999,
            "expires_at": expires_at,
            "chatgpt_account_id": str(cpa.get("account_id") or access_auth.get("chatgpt_account_id") or ""),
            "chatgpt_user_id": str(access_auth.get("chatgpt_user_id") or ""),
            "organization_id": organization_id,
            "client_id": "app_EMoamEEZ73f0CkXaXp7hrann",
            "id_token": id_token,
        },
        "extra": {"email": str(cpa.get("email") or email or "").strip().lower()},
        "group_ids": list(group_ids or [2]),
        "concurrency": 10,
        "priority": 1,
        "auto_pause_on_expired": True,
    }


def mark_job_rt_status(job_id: str, *, success: bool, path: str = "", error: str = "") -> None:
    update_job(
        job_id,
        rtStatus="available" if success else "missing",
        rtPresent=bool(success),
        rtError=str(error or "")[:500],
        rtUpdatedAt=utc_now() if success else str((get_job(job_id) or {}).get("rtUpdatedAt") or ""),
        successCredentialPath=str(path or "") if success else str((get_job(job_id) or {}).get("successCredentialPath") or ""),
    )


def ensure_job_metadata() -> None:
    with JOBS_LOCK:
        jobs = load_jobs()
        changed = False
        used_names: set[str] = set()
        for job in jobs:
            if str(job.get("registrationStatus") or "") == "registered" and str(job.get("fullName") or "").strip():
                used_names.add(str(job.get("fullName") or "").strip().casefold())
        for job in jobs:
            phone_defaults = {
                "phoneStatus": "phone_unknown",
                "phoneMasked": "",
                "phoneProvider": "",
                "phoneError": "",
                "phoneQueuedAt": "",
                "phoneStartedAt": "",
                "phoneFinishedAt": "",
                "phoneBoundAt": "",
                "rtStatus": "missing",
                "rtPresent": False,
                "rtError": "",
                "rtUpdatedAt": "",
                "note": "",
                "group": "",
                "archived": False,
                "planType": "",
                "planUpdatedAt": "",
            }
            for key, value in phone_defaults.items():
                if key not in job:
                    job[key] = value
                    changed = True
            plan = extract_plan_type_from_job(job, prefer_cached=False)
            if plan and normalize_plan_type(job.get("planType")) != plan:
                job["planType"] = plan
                job["planUpdatedAt"] = str(job.get("planUpdatedAt") or utc_now())
                changed = True
            full_name = str(job.get("fullName") or "").strip()
            if str(job.get("registrationStatus") or "") != "registered":
                if not full_name or full_name.casefold() in used_names:
                    full_name = allocate_display_name(str(job.get("email") or ""), used_names)
                    job["fullName"] = full_name
                    changed = True
                else:
                    used_names.add(full_name.casefold())
            state_path = job_state_path(job)
            state = read_json(state_path, {}) if state_path.exists() else {}
            token = access_token_from_state(state)
            fields = at_job_fields(
                token,
                updated_at=str(state.get("session_access_token_updated_at") or job.get("atUpdatedAt") or "") if isinstance(state, dict) else "",
                source=str(job.get("atSource") or "registration"),
            )
            for key, value in fields.items():
                if job.get(key) != value:
                    job[key] = value
                    changed = True
        if changed:
            save_jobs(jobs)


def _provider_summary(provider: dict[str, Any]) -> dict[str, Any]:
    mode = str(provider.get("mode") or "api")
    if mode == "api":
        endpoint = str(provider.get("apiEndpoint") or "")
        return {"mode": mode, "label": "API", "endpoint": endpoint}
    if mode == "outlook_oauth":
        return {
            "mode": mode,
            "label": "Outlook OAuth",
            "endpoint": str(provider.get("host") or "outlook.office365.com"),
        }
    return {"mode": mode, "label": "IMAP", "endpoint": str(provider.get("host") or "")}


def _elapsed(job: dict[str, Any]) -> int:
    started = float(job.get("startedTs") or 0)
    if not started:
        return 0
    finished = float(job.get("finishedTs") or 0)
    end = finished or time.time()
    return max(0, int(end - started))


def public_job(job: dict[str, Any]) -> dict[str, Any]:
    clean = {key: value for key, value in job.items() if key not in PRIVATE_JOB_KEYS}
    clean["provider"] = _provider_summary(job.get("provider") if isinstance(job.get("provider"), dict) else {})
    clean["elapsedSeconds"] = _elapsed(job)
    clean["error"] = redact_text(str(clean.get("error") or ""), job=job)
    clean["phoneError"] = redact_text(str(clean.get("phoneError") or ""), job=job)
    clean["rtError"] = redact_text(str(clean.get("rtError") or ""), job=job)
    has_rt = success_credential_has_rt(read_success_credential(job))
    clean["rtPresent"] = bool(clean.get("rtPresent") or has_rt)
    clean["rtStatus"] = str(clean.get("rtStatus") or ("available" if has_rt else "missing"))
    clean["note"] = str(clean.get("note") or "")
    clean["group"] = str(clean.get("group") or "").strip()
    clean["archived"] = bool(clean.get("archived"))
    plan = extract_plan_type_from_job(job, prefer_cached=False) or normalize_plan_type(clean.get("planType"))
    clean["planType"] = plan
    clean["planUpdatedAt"] = str(clean.get("planUpdatedAt") or "")
    clean.pop("successCredentialPath", None)
    return clean


def normalize_group_name(value: Any) -> str:
    text = str(value or "").strip()
    text = re.sub(r"\s+", " ", text)
    return text[:40]


def update_jobs_meta(ids: list[str], *, changes: dict[str, Any]) -> dict[str, Any]:
    requested = [str(value).strip() for value in ids if str(value).strip()]
    if not requested:
        raise ValueError("ids must be a non-empty array")
    allowed = {}
    if "note" in changes:
        allowed["note"] = str(changes.get("note") or "")[:200]
    if "group" in changes:
        allowed["group"] = normalize_group_name(changes.get("group"))
    if "archived" in changes:
        allowed["archived"] = bool(changes.get("archived"))
    if not allowed:
        raise ValueError("no supported fields to update")
    updated = 0
    missing: list[str] = []
    with JOBS_LOCK:
        rows = load_jobs()
        by_id = {str(job.get("id") or ""): job for job in rows}
        for job_id in requested:
            job = by_id.get(job_id)
            if not job:
                missing.append(job_id)
                continue
            job.update(allowed)
            job["updatedAt"] = utc_now()
            updated += 1
        if updated:
            save_jobs(rows)
    append_audit(
        "jobs_meta_updated",
        detail=f"count={updated} fields={','.join(sorted(allowed.keys()))}",
    )
    return {"ok": True, "updated": updated, "missing": missing, "fields": allowed}


def _known_secrets(job: dict[str, Any] | None) -> list[str]:
    if not job:
        return []
    provider = job.get("provider") if isinstance(job.get("provider"), dict) else {}
    stored = load_secret_store().get(str(job.get("id") or ""), {})
    settings = load_settings()
    values = [
        job.get("accountPassword"),
        provider.get("apiUrl"),
        provider.get("password"),
        provider.get("refreshToken"),
        settings.get("proxy"),
        *(settings.get("proxyPool") or []),
        settings.get("smsApiKey"),
        *stored.values(),
    ]
    state_path = job_state_path(job)
    if state_path.exists():
        state = read_json(state_path, {})
        summary = state.get("mfa_summary") if isinstance(state, dict) else {}
        if isinstance(summary, dict):
            values.append(summary.get("secret"))
        values.append(access_token_from_state(state if isinstance(state, dict) else {}))
    return [str(value) for value in values if str(value or "")]


def redact_text(value: str, *, job: dict[str, Any] | None = None) -> str:
    text = str(value or "")
    for secret_value in sorted(_known_secrets(job), key=len, reverse=True):
        text = text.replace(secret_value, "***")
    text = re.sub(r"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s,;]+", r"\1***", text)
    text = re.sub(r"(?i)([?&](?:token|key|secret|password|code)=)[^&\s]+", r"\1***", text)
    text = re.sub(r'(?i)("(?:code|secret|password|refresh_token|access_token)"\s*:\s*")[^"]+(\")', r"\1***\2", text)
    text = re.sub(r"(?<!\w)\+\d{7,15}(?!\w)", lambda match: mask_phone_number(match.group(0)), text)
    return text[:4000]


def append_log(level: str, message: str, *, job: dict[str, Any] | None = None, stage: str = "system") -> None:
    with RUNTIME_LOCK:
        RUNTIME["logSeq"] = int(RUNTIME.get("logSeq") or 0) + 1
        entry = {
            "seq": RUNTIME["logSeq"],
            "at": time.strftime("%H:%M:%S"),
            "level": str(level or "info").lower(),
            "jobId": str((job or {}).get("id") or ""),
            "email": str((job or {}).get("email") or ""),
            "stage": str(stage or "system"),
            "message": redact_text(message, job=job),
        }
        RUNTIME["logs"].append(entry)
        RUNTIME["logs"] = RUNTIME["logs"][-1200:]


def basic_auth_valid(header: str) -> bool:
    if not ACCESS_PASSWORD:
        return True
    scheme, separator, encoded = str(header or "").partition(" ")
    if not separator or scheme.lower() != "basic":
        return False
    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
    except Exception:
        return False
    username, separator, password = decoded.partition(":")
    return bool(separator) and hmac.compare_digest(username, ACCESS_USERNAME) and hmac.compare_digest(password, ACCESS_PASSWORD)


def make_password() -> str:
    return "A9!" + secrets.token_urlsafe(15) + "z"


def normalize_mode(value: str) -> str:
    mode = str(value or "api").strip().lower()
    aliases = {
        "api_url": "api",
        "imap_password": "imap",
        "outlook": "outlook_oauth",
        "outlook_oauth2": "outlook_oauth",
        "oauth2": "outlook_oauth",
    }
    return aliases.get(mode, mode)


def bool_value(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    if text in {"1", "true", "yes", "on", "y"}:
        return True
    if text in {"0", "false", "no", "off", "n", ""}:
        return False
    return default


def int_value(value: Any, default: int, minimum: int = 1, maximum: int = 65535) -> int:
    try:
        parsed = int(str(value).strip())
    except Exception:
        parsed = default
    return max(minimum, min(maximum, parsed))


def _clean_email(value: Any) -> str:
    return str(value or "").strip().lower()


def _provider_from_row(row: dict[str, Any], mode: str, defaults: dict[str, Any]) -> dict[str, Any]:
    merged = dict(defaults or {})
    merged.update({key: value for key, value in row.items() if value not in (None, "")})
    if mode == "api":
        return {"mode": mode, "apiUrl": str(merged.get("otp_api_url") or merged.get("apiUrl") or "").strip()}
    if mode == "imap":
        return {
            "mode": mode,
            "host": str(merged.get("imap_host") or merged.get("host") or "").strip(),
            "port": int_value(merged.get("imap_port") or merged.get("port"), 993),
            "username": str(merged.get("imap_user") or merged.get("username") or "").strip(),
            "password": str(merged.get("imap_password") or merged.get("password") or ""),
            "folder": str(merged.get("imap_folder") or merged.get("folder") or "Inbox").strip(),
            "latestN": int_value(merged.get("imap_latest_n") or merged.get("latestN"), 80, 1, 500),
        }
    return {
        "mode": "outlook_oauth",
        "host": str(merged.get("imap_host") or merged.get("host") or "outlook.office365.com").strip(),
        "port": int_value(merged.get("imap_port") or merged.get("port"), 993),
        "username": str(merged.get("imap_user") or merged.get("username") or merged.get("email") or "").strip(),
        "clientId": str(merged.get("outlook_client_id") or merged.get("clientId") or "").strip(),
        "refreshToken": str(merged.get("outlook_refresh_token") or merged.get("refreshToken") or "").strip(),
        "folder": str(merged.get("imap_folder") or merged.get("folder") or "INBOX").strip(),
        "password": str(merged.get("imap_password") or merged.get("password") or ""),
        "passwordFallback": bool_value(merged.get("passwordFallback")),
        "pop3Fallback": bool_value(merged.get("pop3Fallback"), True),
        "latestN": int_value(merged.get("imap_latest_n") or merged.get("latestN"), 80, 1, 500),
    }


def validate_provider(provider: dict[str, Any]) -> list[str]:
    mode = str(provider.get("mode") or "")
    if mode == "api":
        url = str(provider.get("apiUrl") or "")
        parsed = urllib.parse.urlsplit(url)
        return [] if parsed.scheme in {"http", "https"} and parsed.netloc else ["取码 API URL 无效"]
    if mode == "imap":
        missing = [label for label, key in (("IMAP 主机", "host"), ("IMAP 用户名", "username"), ("IMAP 密码", "password")) if not str(provider.get(key) or "")]
        return [f"缺少 {', '.join(missing)}"] if missing else []
    if mode == "outlook_oauth":
        missing = [label for label, key in (("邮箱用户名", "username"), ("client_id", "clientId"), ("refresh_token", "refreshToken")) if not str(provider.get(key) or "")]
        return [f"缺少 {', '.join(missing)}"] if missing else []
    return ["不支持的取码模式"]


def test_source(payload: dict[str, Any]) -> dict[str, Any]:
    mode = normalize_mode(str(payload.get("mode") or "api"))
    email = _clean_email(payload.get("email"))
    raw_provider = payload.get("provider") if isinstance(payload.get("provider"), dict) else {}
    sample_text = str(payload.get("text") or "").strip()
    if sample_text:
        sample_rows = _parse_import_rows(sample_text, mode, raw_provider)
        if sample_rows:
            sample = dict(sample_rows[0])
            email = _clean_email(sample.get("email")) or email
            mode = normalize_mode(str(sample.get("otp_mode") or mode))
            sample["email"] = email
            provider = _provider_from_row(sample, mode, raw_provider)
        else:
            provider = _provider_from_row({"email": email}, mode, raw_provider)
    else:
        provider = _provider_from_row({"email": email}, mode, raw_provider)
    errors = validate_provider(provider)
    if errors:
        raise ValueError("；".join(errors))
    started = time.monotonic()
    if mode == "api":
        url = str(provider.get("apiUrl") or "")
        if "{email}" in url:
            if not EMAIL_RE.match(email):
                raise ValueError("URL 包含 {email} 时需要先填写一个有效邮箱")
            url = url.replace("{email}", urllib.parse.quote(email, safe=""))
        request = urllib.request.Request(
            url,
            headers={"accept": "text/html,application/json,text/plain,*/*", "user-agent": "Registration2FA/1.0"},
        )
        with urllib.request.urlopen(request, timeout=15) as response:
            body = response.read(2 * 1024 * 1024).decode("utf-8", errors="replace")
            status = int(response.getcode() or 0)
        return {
            "ok": True,
            "mode": mode,
            "message": f"API 可访问，HTTP {status}",
            "codeDetected": bool(re.search(r"(?<!\d)\d{6}(?!\d)", body)),
            "elapsedMs": int((time.monotonic() - started) * 1000),
        }

    connection = None
    try:
        connection = imaplib.IMAP4_SSL(
            str(provider.get("host") or ""),
            int(provider.get("port") or 993),
            timeout=15,
        )
        if mode == "imap":
            connection.login(str(provider.get("username") or ""), str(provider.get("password") or ""))
        else:
            token_body = urllib.parse.urlencode(
                {
                    "client_id": str(provider.get("clientId") or ""),
                    "grant_type": "refresh_token",
                    "refresh_token": str(provider.get("refreshToken") or ""),
                    "scope": "https://outlook.office.com/IMAP.AccessAsUser.All offline_access",
                }
            ).encode("utf-8")
            token_request = urllib.request.Request(
                "https://login.microsoftonline.com/common/oauth2/v2.0/token",
                data=token_body,
                headers={"content-type": "application/x-www-form-urlencoded"},
                method="POST",
            )
            with urllib.request.urlopen(token_request, timeout=15) as token_response:
                token_payload = json.loads(token_response.read().decode("utf-8", errors="replace") or "{}")
            access_token = str(token_payload.get("access_token") or "")
            if not access_token:
                raise RuntimeError("Microsoft token 响应缺少 access_token")
            username = str(provider.get("username") or "")
            auth = f"user={username}\x01auth=Bearer {access_token}\x01\x01".encode("utf-8")
            connection.authenticate("XOAUTH2", lambda _challenge: auth)
        select_status, _ = connection.select(str(provider.get("folder") or "INBOX"), readonly=True)
        if str(select_status or "").upper() != "OK":
            raise RuntimeError("邮箱文件夹不可用")
        return {
            "ok": True,
            "mode": mode,
            "message": "IMAP OAuth 可用" if mode == "outlook_oauth" else "IMAP 登录可用",
            "elapsedMs": int((time.monotonic() - started) * 1000),
        }
    finally:
        if connection is not None:
            try:
                connection.logout()
            except Exception:
                pass


def extract_verification_code(value: Any) -> str:
    if isinstance(value, dict):
        preferred_keys = ("code", "otp", "verification_code", "verificationCode")
        for key in preferred_keys:
            if key in value:
                code = extract_verification_code(value.get(key))
                if code:
                    return code
        for item in value.values():
            code = extract_verification_code(item)
            if code:
                return code
        return ""
    if isinstance(value, list):
        for item in value:
            code = extract_verification_code(item)
            if code:
                return code
        return ""
    text = str(value or "")
    # Prefer the shared mail-preview extractor so CSS colors like #000000 / #202123
    # and tracking-link digits are not treated as OTP codes.
    code = str(
        extractVerificationCode(
            text,
            keywords=list(defaultCodeKeywords)
            + ["校验码", "动态码", "登录码", "one-time", "one time"],
            blockedCodes=set(),
        )
        or ""
    ).strip()
    if re.fullmatch(r"\d{6}", code) and len(set(code)) > 1:
        return code
    return ""


def _message_text(message: email.message.EmailMessage) -> str:
    parts: list[str] = [str(message.get("Subject") or "")]
    if message.is_multipart():
        for part in message.walk():
            if part.get_content_maintype() == "multipart" or part.get_content_disposition() == "attachment":
                continue
            if part.get_content_type() not in {"text/plain", "text/html"}:
                continue
            try:
                parts.append(str(part.get_content() or ""))
            except Exception:
                payload = part.get_payload(decode=True) or b""
                parts.append(payload.decode(part.get_content_charset() or "utf-8", errors="replace"))
    else:
        try:
            parts.append(str(message.get_content() or ""))
        except Exception:
            payload = message.get_payload(decode=True) or b""
            parts.append(payload.decode(message.get_content_charset() or "utf-8", errors="replace"))
    return "\n".join(parts)


def fetch_email_verification_code(job: dict[str, Any]) -> dict[str, Any]:
    email_address = _clean_email(job.get("email"))
    provider = job.get("provider") if isinstance(job.get("provider"), dict) else {}
    mode = normalize_mode(str(provider.get("mode") or "api"))
    started = time.monotonic()
    if mode == "api":
        url = str(provider.get("apiUrl") or "").strip()
        errors = validate_provider({"mode": "api", "apiUrl": url})
        if errors:
            raise ValueError("；".join(errors))
        request = urllib.request.Request(
            url,
            headers={"accept": "text/html,application/json,text/plain,*/*", "user-agent": "Registration2FA/1.0"},
        )
        with urllib.request.urlopen(request, timeout=15) as response:
            raw = response.read(2 * 1024 * 1024)
            content_type = str(response.headers.get("content-type") or "")
        text = raw.decode("utf-8", errors="replace")
        parsed: Any = text
        if "json" in content_type.lower() or text.lstrip().startswith(("{", "[")):
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                parsed = text
        code = extract_verification_code(parsed)
    else:
        errors = validate_provider(provider)
        if errors:
            raise ValueError("；".join(errors))
        connection = imaplib.IMAP4_SSL(
            str(provider.get("host") or ""),
            int(provider.get("port") or 993),
            timeout=15,
        )
        try:
            if mode == "imap":
                connection.login(str(provider.get("username") or ""), str(provider.get("password") or ""))
            else:
                token_body = urllib.parse.urlencode(
                    {
                        "client_id": str(provider.get("clientId") or ""),
                        "grant_type": "refresh_token",
                        "refresh_token": str(provider.get("refreshToken") or ""),
                        "scope": "https://outlook.office.com/IMAP.AccessAsUser.All offline_access",
                    }
                ).encode("utf-8")
                token_request = urllib.request.Request(
                    "https://login.microsoftonline.com/common/oauth2/v2.0/token",
                    data=token_body,
                    headers={"content-type": "application/x-www-form-urlencoded"},
                    method="POST",
                )
                with urllib.request.urlopen(token_request, timeout=15) as token_response:
                    token_payload = json.loads(token_response.read().decode("utf-8", errors="replace") or "{}")
                access_token = str(token_payload.get("access_token") or "")
                if not access_token:
                    raise RuntimeError("Microsoft token 响应缺少 access_token")
                username = str(provider.get("username") or "")
                auth = f"user={username}\x01auth=Bearer {access_token}\x01\x01".encode("utf-8")
                connection.authenticate("XOAUTH2", lambda _challenge: auth)
            status, _ = connection.select(str(provider.get("folder") or "INBOX"), readonly=True)
            if str(status or "").upper() != "OK":
                raise RuntimeError("邮箱文件夹不可用")
            search_status, search_data = connection.uid("search", None, "ALL")
            if str(search_status or "").upper() != "OK":
                raise RuntimeError("无法读取邮箱邮件列表")
            uids = str((search_data or [b""])[0].decode("ascii", errors="ignore")).split()
            latest_n = max(1, min(500, int(provider.get("latestN") or 80)))
            code = ""
            for uid in reversed(uids[-latest_n:]):
                fetch_status, rows = connection.uid("fetch", uid, "(RFC822)")
                if str(fetch_status or "").upper() != "OK":
                    continue
                raw_message = next(
                    (item[1] for item in rows or [] if isinstance(item, tuple) and len(item) > 1 and isinstance(item[1], bytes)),
                    b"",
                )
                if not raw_message:
                    continue
                message = email.message_from_bytes(raw_message, policy=email.policy.default)
                recipients = " ".join(
                    str(message.get(name) or "")
                    for name in ("To", "Delivered-To", "X-Original-To", "Envelope-To")
                ).lower()
                if email_address and email_address not in recipients:
                    continue
                code = extract_verification_code(_message_text(message))
                if code:
                    break
        finally:
            try:
                connection.logout()
            except Exception:
                pass
    if not code:
        raise LookupError("最近邮件中没有找到有效的 6 位验证码（已忽略 CSS 颜色/链接中的数字）")
    return {
        "ok": True,
        "email": email_address,
        "code": code,
        "mode": mode,
        "source": _provider_summary(provider).get("label") or mode,
        "fetchedAt": utc_now(),
        "elapsedMs": int((time.monotonic() - started) * 1000),
    }


def _parse_delimited_lines(text: str, mode: str, defaults: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for raw_line in str(text or "").replace("\r", "").split("\n"):
        line = raw_line.strip().lstrip("\ufeff")
        if not line:
            continue
        parts = [part.strip() for part in line.split("----")]
        row: dict[str, Any] = {"email": parts[0] if parts else "", "otp_mode": mode}
        if mode == "api" and len(parts) > 1:
            row["otp_api_url"] = parts[2] if len(parts) > 2 and not parts[1].lower().startswith(("http://", "https://")) else parts[1]
        elif mode == "imap":
            if len(parts) >= 5 and parts[2].lower().startswith(("http://", "https://")):
                row.update({"imap_user": parts[3], "imap_password": parts[4]})
            else:
                keys = ("imap_user", "imap_password", "imap_host", "imap_port", "imap_folder")
                row.update({key: parts[index + 1] for index, key in enumerate(keys) if len(parts) > index + 1})
        elif mode == "outlook_oauth":
            if len(parts) >= 7:
                row.update(
                    {
                        "imap_user": parts[3] if "@" in parts[3] else parts[0],
                        "imap_password": parts[4] or parts[1],
                        "outlook_client_id": parts[5],
                        "outlook_refresh_token": parts[6],
                    }
                )
            elif len(parts) == 3:
                row.update({"imap_user": parts[0], "outlook_client_id": parts[1], "outlook_refresh_token": parts[2]})
            else:
                keys = ("imap_user", "outlook_client_id", "outlook_refresh_token", "imap_host", "imap_port", "imap_folder")
                row.update({key: parts[index + 1] for index, key in enumerate(keys) if len(parts) > index + 1})
        rows.append(row)
    return rows


def _parse_import_rows(text: str, selected_mode: str, defaults: dict[str, Any]) -> list[dict[str, Any]]:
    clean = str(text or "").strip()
    first_line = clean.splitlines()[0].lower() if clean else ""
    if "email" in first_line and "," in first_line:
        return [dict(row) for row in csv.DictReader(io.StringIO(clean))]
    return _parse_delimited_lines(clean, selected_mode, defaults)


def import_jobs(payload: dict[str, Any]) -> dict[str, Any]:
    text = str(payload.get("text") or "")
    selected_mode = normalize_mode(str(payload.get("mode") or "api"))
    defaults = payload.get("defaults") if isinstance(payload.get("defaults"), dict) else {}
    account_defaults = payload.get("accountDefaults") if isinstance(payload.get("accountDefaults"), dict) else {}
    parsed_rows = _parse_import_rows(text, selected_mode, defaults)
    api_row_count = sum(1 for row in parsed_rows if normalize_mode(str(row.get("otp_mode") or selected_mode)) == "api")
    added = 0
    skipped = 0
    errors: list[dict[str, Any]] = []
    with JOBS_LOCK:
        jobs = load_jobs()
        secret_store = load_secret_store()
        existing = {_clean_email(job.get("email")) for job in jobs}
        used_names = {
            str(job.get("fullName") or "").strip().casefold()
            for job in jobs
            if str(job.get("fullName") or "").strip()
        }
        for line_number, row in enumerate(parsed_rows, start=2 if parsed_rows and "email" in text.splitlines()[0].lower() else 1):
            email = _clean_email(row.get("email"))
            mode = normalize_mode(str(row.get("otp_mode") or selected_mode))
            row_with_email = dict(row)
            row_with_email["email"] = email
            row_errors = []
            if not EMAIL_RE.match(email):
                row_errors.append("邮箱格式无效")
            if mode not in {"api", "imap", "outlook_oauth"}:
                provider = {"mode": mode}
                row_errors.append("不支持的取码模式")
            else:
                provider = _provider_from_row(row_with_email, mode, defaults if mode == selected_mode else {})
                if mode == "api":
                    api_url = str(provider.get("apiUrl") or "")
                    explicit_url = str(row.get("otp_api_url") or row.get("apiUrl") or "").strip()
                    if "{email}" in api_url:
                        provider["apiUrl"] = api_url.replace("{email}", urllib.parse.quote(email, safe=""))
                    elif api_row_count > 1 and not explicit_url:
                        row_errors.append("批量 API 默认 URL 必须包含 {email}，或每行提供独立 URL")
                row_errors.extend(validate_provider(provider))
            if email in existing:
                row_errors.append("邮箱已在队列中")
            requested_name = str(row.get("full_name") or row.get("fullName") or "").strip()
            if not requested_name and len(parsed_rows) == 1:
                requested_name = str(account_defaults.get("fullName") or "").strip()
            if requested_name and requested_name.casefold() in used_names:
                row_errors.append("注册姓名已被其他任务使用")
            if row_errors:
                skipped += 1
                errors.append({"line": line_number, "email": email, "errors": row_errors})
                continue
            now = utc_now()
            job_id = f"{int(time.time() * 1000)}-{secrets.token_hex(4)}"
            full_name = requested_name or allocate_display_name(email, used_names)
            used_names.add(full_name.casefold())
            account_password = str(
                row.get("account_password")
                or row.get("accountPassword")
                or account_defaults.get("accountPassword")
                or ""
            ) or make_password()
            secret_store[job_id] = {
                "accountPassword": account_password,
                "apiUrl": str(provider.get("apiUrl") or ""),
                "mailPassword": str(provider.get("password") or ""),
                "refreshToken": str(provider.get("refreshToken") or ""),
            }
            safe_provider = dict(provider)
            if mode == "api":
                parsed_url = urllib.parse.urlsplit(str(safe_provider.pop("apiUrl", "") or ""))
                safe_provider["apiEndpoint"] = urllib.parse.urlunsplit((parsed_url.scheme, parsed_url.netloc, parsed_url.path, "", ""))
                safe_provider["apiUrlProvided"] = True
            else:
                safe_provider.pop("password", None)
                safe_provider["passwordProvided"] = bool(secret_store[job_id]["mailPassword"])
                if mode == "outlook_oauth":
                    safe_provider.pop("refreshToken", None)
                    safe_provider["refreshTokenProvided"] = True
            jobs.append(
                {
                    "id": job_id,
                    "email": email,
                    "fullName": full_name,
                    "birthDate": str(row.get("birth_date") or row.get("birthDate") or account_defaults.get("birthDate") or "").strip(),
                    "provider": safe_provider,
                    "status": "queued",
                    "registrationStatus": "pending",
                    "mfaStatus": "pending",
                    "stage": "queued",
                    "error": "",
                    "secretMasked": "",
                    "localSecretPresent": False,
                    "atPresent": False,
                    "atStatus": "missing",
                    "atExpiresAt": "",
                    "atExpired": False,
                    "atUpdatedAt": "",
                    "atSource": "",
                    "phoneStatus": "phone_unknown",
                    "phoneMasked": "",
                    "phoneProvider": "",
                    "phoneError": "",
                    "phoneQueuedAt": "",
                    "phoneStartedAt": "",
                    "phoneFinishedAt": "",
                    "phoneBoundAt": "",
                    "rtStatus": "missing",
                    "rtPresent": False,
                    "rtError": "",
                    "rtUpdatedAt": "",
                    "note": "",
                    "group": "",
                    "archived": False,
                    "planType": "",
                    "planUpdatedAt": "",
                    "createdAt": now,
                    "updatedAt": now,
                    "startedTs": 0,
                    "finishedTs": 0,
                }
            )
            existing.add(email)
            added += 1
        if added:
            save_secret_store(secret_store)
            save_jobs(jobs)
    append_log("info", f"导入 {added} 个任务，跳过 {skipped} 个")
    return {"ok": True, "added": added, "skipped": skipped, "errors": errors}


def account_lock(email: str) -> threading.Lock:
    key = _clean_email(email)
    with ACCOUNT_LOCKS_LOCK:
        return ACCOUNT_LOCKS.setdefault(key, threading.Lock())


def _runner_input(
    job: dict[str, Any],
    settings: dict[str, Any],
    *,
    operation: str = "register",
    mfa_totp_secret: str = "",
    phone_verification_override: dict[str, Any] | None = None,
) -> dict[str, Any]:
    sms_provider = str(settings.get("smsProvider") or "").strip().lower()
    sms_api_key = str(settings.get("smsApiKey") or "").strip()
    if isinstance(phone_verification_override, dict):
        phone_verification = dict(phone_verification_override)
    else:
        phone_verification = (
            {
                **build_sms_provider_config(settings),
                "sms_reuse_phone": bool(settings.get("smsReusePhone", False)),
            }
            if sms_provider and sms_api_key and operation == "bind_phone"
            else {}
        )
    return {
        "operation": operation,
        "email": job.get("email"),
        "accountPassword": job.get("accountPassword"),
        "fullName": job.get("fullName"),
        "birthDate": job.get("birthDate"),
        "provider": job.get("provider"),
        "proxy": settings.get("proxy"),
        "trace": settings.get("trace"),
        "registerTimeoutSeconds": settings.get("registerTimeoutSeconds"),
        "otpTimeoutSeconds": settings.get("otpTimeoutSeconds"),
        "otpIntervalSeconds": settings.get("otpIntervalSeconds"),
        "mfaTotpSecret": mfa_totp_secret,
        "phone_verification": phone_verification,
        "storageStatePath": str(job_state_path(job)) if operation in {"bind_phone", "set_password"} else "",
    }


def _terminate_runner_process(process: subprocess.Popen[str], *, grace_seconds: float = 3.0) -> None:
    if process.poll() is not None:
        return
    try:
        process.terminate()
    except Exception:
        pass
    try:
        process.wait(timeout=max(0.1, float(grace_seconds)))
        return
    except Exception:
        pass
    try:
        process.kill()
    except Exception:
        pass
    try:
        process.wait(timeout=2)
    except Exception:
        pass


def run_registration(
    job: dict[str, Any],
    settings: dict[str, Any],
    *,
    operation: str = "register",
    mfa_totp_secret: str = "",
    phone_verification_override: dict[str, Any] | None = None,
) -> tuple[bool, dict[str, Any]]:
    job_id = str(job.get("id") or "")
    operation_stage = {
        "login": "login",
        "bind_phone": "phone_binding",
        "set_password": "set_password",
    }.get(operation, "registration")
    runner_payload = _runner_input(
        job,
        settings,
        operation=operation,
        mfa_totp_secret=mfa_totp_secret,
        phone_verification_override=phone_verification_override,
    )
    phone_verification = (
        runner_payload.get("phone_verification")
        if isinstance(runner_payload.get("phone_verification"), dict)
        else {}
    )
    sms_phone_verification_enabled = bool(
        str(phone_verification.get("sms_provider") or "").strip()
        and str(phone_verification.get("sms_api_key") or "").strip()
    )
    manual_phone_enabled = bool(str(phone_verification.get("manual_phone_control_path") or "").strip())
    if sms_phone_verification_enabled and not SMS_RECOVERY_COMPLETE.wait(timeout=120):
        raise RuntimeError("接码订单启动恢复仍在进行，请稍后重试")
    activation_journal_path = sms_activation_journal_path(job_id)
    if activation_journal_path.exists() and not activation_journal_path.is_file():
        if sms_phone_verification_enabled:
            raise RuntimeError("接码恢复路径无效，无法安全开始租号")
    elif sms_phone_verification_enabled:
        for journal_candidate in sms_activation_journal_candidates(job_id):
            cleaned = cleanup_sms_activation_journal(journal_candidate, settings, job=job)
            if not cleaned:
                raise RuntimeError("上次接码订单仍未确认取消，请稍后重试")
    run_path = RUN_DIR / job_id
    if run_path.exists():
        shutil.rmtree(run_path, ignore_errors=True)
    run_path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(run_path, 0o700)
    except OSError:
        pass
    runner_state_path: Path | None = None
    if operation in {"bind_phone", "set_password"}:
        canonical_state_path = job_state_path(job)
        canonical_state = read_json(canonical_state_path, {}) if canonical_state_path.exists() else {}
        if not isinstance(canonical_state, dict) or not canonical_state:
            raise RuntimeError(f"storage_state is missing or invalid for {operation}")
        runner_state_path = run_path / "storage-state.json"
        write_json_atomic(runner_state_path, canonical_state)
        runner_payload["storageStatePath"] = str(runner_state_path.resolve(strict=False))
    input_path = run_path / "input.json"
    write_json_atomic(input_path, runner_payload)
    isolated_x9_root = (run_path / "x9") if operation == "login" else X9_RUNTIME_ROOT
    allowed_environment = {
        "PATH",
        "PYTHONPATH",
        "LANG",
        "LC_ALL",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "TZ",
        "HOME",
        "NO_PROXY",
    }
    env = {key: value for key, value in os.environ.items() if key in allowed_environment}
    env.update(
        {
            "PYTHONIOENCODING": "utf-8",
            "PYTHONUNBUFFERED": "1",
            "X9_ISOLATED_ROOT": str(isolated_x9_root),
            "AIO_DEFER_WORKSPACE_TOKEN": "1",
            "AIO_CODEX_AUTH_MIRROR_DIR": str(X9_RUNTIME_ROOT / "codex_mirror"),
            "TMPDIR": str(run_path / "tmp"),
            "TMP": str(run_path / "tmp"),
            "TEMP": str(run_path / "tmp"),
            "XDG_CACHE_HOME": str(run_path / "cache"),
        }
    )
    if sms_phone_verification_enabled:
        env["REG_2FA_SMS_ACTIVATION_PATH"] = str(activation_journal_path)
    (run_path / "tmp").mkdir(parents=True, exist_ok=True)
    (run_path / "cache").mkdir(parents=True, exist_ok=True)
    command = [sys.executable, str(RUNNER_PATH), str(input_path)]
    result_payload: dict[str, Any] = {}
    process = subprocess.Popen(
        command,
        cwd=str(ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )
    with RUNTIME_LOCK:
        RUNTIME["active"][job_id] = process
    line_queue: queue.Queue[str | None] = queue.Queue()

    def read_output() -> None:
        try:
            if process.stdout:
                for line in process.stdout:
                    line_queue.put(line)
        finally:
            line_queue.put(None)

    threading.Thread(target=read_output, daemon=True).start()
    deadline = time.monotonic() + (
        max(1800, int(settings.get("registerTimeoutSeconds") or 360) + 60)
        if manual_phone_enabled
        else int(settings.get("registerTimeoutSeconds") or 360) + 60
    )
    output_finished = False
    try:
        while not output_finished:
            if STOP_EVENT.is_set():
                _terminate_runner_process(process)
                raise RuntimeError("任务已停止")
            if time.monotonic() > deadline:
                _terminate_runner_process(process)
                raise RuntimeError("注册任务超时")
            try:
                line = line_queue.get(timeout=0.25)
            except queue.Empty:
                if process.poll() is not None:
                    continue
                continue
            if line is None:
                output_finished = True
                continue
            clean = line.rstrip()
            if clean.startswith("__ISOLATED_JOB_RESULT__="):
                try:
                    result_payload = json.loads(clean.split("=", 1)[1])
                except Exception:
                    result_payload = {"success": False, "message": "runner 返回无效 JSON"}
            elif clean:
                append_log("info", clean, job=job, stage=operation_stage)
        return_code = process.wait(timeout=5)
        success = bool(result_payload.get("success")) and return_code == 0
        if not result_payload:
            result_payload = {"success": False, "message": f"runner 未返回结果，exit={return_code}"}
        if operation == "login" and bool(result_payload.get("success")):
            temp_state_path = Path(str(result_payload.get("storageStatePath") or ""))
            temp_state = read_json(temp_state_path, {}) if temp_state_path.exists() else {}
            result_payload["_storageStatePayload"] = temp_state if isinstance(temp_state, dict) else {}
            result_payload["_accessToken"] = access_token_from_state(temp_state)
        if operation in {"bind_phone", "set_password"} and success:
            temp_state = read_json(runner_state_path, {}) if runner_state_path and runner_state_path.exists() else {}
            if not isinstance(temp_state, dict) or not isinstance(temp_state.get("cookies"), list):
                success = False
                result_payload["success"] = False
                result_payload["stage"] = f"{operation}_state_invalid"
                result_payload["message"] = f"{operation} runner returned an invalid storage_state"
            else:
                result_payload["_storageStatePayload"] = temp_state
                result_payload["storageStatePath"] = str(job_state_path(job))
        return success, result_payload
    finally:
        _terminate_runner_process(process, grace_seconds=1.0)
        with RUNTIME_LOCK:
            RUNTIME["active"].pop(job_id, None)
        if sms_phone_verification_enabled:
            for journal_candidate in sms_activation_journal_candidates(job_id):
                cleanup_sms_activation_journal(journal_candidate, settings, job=job)
        shutil.rmtree(run_path, ignore_errors=True)


def _storage_state(job: dict[str, Any]) -> tuple[Path, dict[str, Any]]:
    path = job_state_path(job)
    return path, read_json(path, {}) if path.exists() else {}


def persist_phone_binding_storage_state(job: dict[str, Any], replacement_state: dict[str, Any]) -> None:
    if not isinstance(replacement_state, dict) or not isinstance(replacement_state.get("cookies"), list):
        raise RuntimeError("phone binding result contains an invalid storage_state")
    state_path, current_state = _storage_state(job)
    payload = dict(current_state or {})
    payload.update(replacement_state)
    current_summary = current_state.get("mfa_summary") if isinstance(current_state, dict) else None
    if isinstance(current_summary, dict) and current_summary:
        payload["mfa_summary"] = dict(current_summary)
    token = access_token_from_state(payload)
    if token:
        persist_access_token(job, token, source="phone_binding", replacement_state=payload)
    else:
        write_json_atomic(state_path, payload)


def persist_mfa_summary(
    job: dict[str, Any],
    *,
    status: str,
    secret: str = "",
    session_id: str = "",
    factor_id: str = "",
) -> dict[str, Any]:
    path, payload = _storage_state(job)
    if not path or not path.exists() or not isinstance(payload, dict):
        raise RuntimeError("登录态文件不存在，无法保存 TOTP secret")
    current = payload.get("mfa_summary") if isinstance(payload.get("mfa_summary"), dict) else {}
    normalized_secret = normalize_totp_secret(secret or str(current.get("secret") or ""))
    summary = {
        **current,
        "status": status,
        "factorType": "totp",
        "secret": normalized_secret,
        "secretMasked": mask_secret(normalized_secret),
        "sessionId": str(session_id or current.get("sessionId") or "") if status != "enabled" else "",
        "factorId": str(factor_id or current.get("factorId") or ""),
        "updatedAt": utc_now(),
    }
    payload["mfa_summary"] = summary
    write_json_atomic(path, payload)
    return summary


def persist_access_token(
    job: dict[str, Any],
    token: str,
    *,
    source: str,
    replacement_state: dict[str, Any] | None = None,
    session_payload: dict[str, Any] | None = None,
    plan_type: str = "",
) -> dict[str, Any]:
    value = str(token or "").strip()
    if not value:
        raise RuntimeError("登录结果缺少 ChatGPT access token")
    state_path, current_state = _storage_state(job)
    payload = dict(replacement_state or current_state or {})
    old_summary = current_state.get("mfa_summary") if isinstance(current_state, dict) else {}
    if isinstance(old_summary, dict) and old_summary:
        payload["mfa_summary"] = dict(old_summary)
    metadata = decode_access_token_metadata(value)
    updated_at = utc_now()
    payload["session_access_token"] = value
    payload["accessToken"] = value
    payload["session_access_token_status"] = 200
    payload["session_access_token_error"] = ""
    payload["session_access_token_updated_at"] = updated_at
    payload["session_access_token_exp"] = int(metadata.get("expiresAtEpoch") or 0)
    payload["session_access_token_expires_at"] = str(metadata.get("expiresAt") or "")
    payload.setdefault("email", str(job.get("email") or ""))
    plan = normalize_plan_type(plan_type)
    if isinstance(session_payload, dict) and session_payload:
        summary = build_session_summary(session_payload, token=value, source=source)
        payload["session_summary"] = summary
        plan = plan or normalize_plan_type(summary.get("accountPlanType"))
    if not plan:
        existing_summary = payload.get("session_summary") if isinstance(payload.get("session_summary"), dict) else {}
        plan = normalize_plan_type(existing_summary.get("accountPlanType")) or extract_plan_type_from_token(value)
    write_json_atomic(state_path, payload)
    at_path = job_at_path(job)
    write_text_atomic(at_path, value)
    fields = at_job_fields(value, updated_at=updated_at, source=source)
    if plan:
        fields["planType"] = plan
        fields["planUpdatedAt"] = updated_at
    update_job(
        str(job.get("id") or ""),
        **fields,
        storageStatePath=str(state_path),
        atPath=str(at_path),
        atError="",
    )
    return fields


def refresh_access_token_from_session(job: dict[str, Any], settings: dict[str, Any]) -> str:
    state_path = job_state_path(job)
    if not state_path.exists():
        raise RuntimeError("登录态不存在")
    cookie_header = load_cookie_header_from_storage_state(
        storage_state_path=str(state_path),
        target_host="chatgpt.com",
    )
    if not cookie_header:
        raise RuntimeError("登录态中没有可用的 ChatGPT cookies")
    session_payload = read_auth_session_via_cookie_header(
        cookie_header=cookie_header,
        oai_device_id=try_read_oai_did_from_storage_state(str(state_path)),
        timeout_ms=60_000,
        proxy=str(settings.get("proxy") or "").strip() or None,
    )
    if not isinstance(session_payload, dict) or not session_payload:
        raise RuntimeError("现有会话未返回 auth/session")
    token = access_token_from_state(session_payload)
    if not token:
        raise RuntimeError("现有会话未返回 access token")
    persist_access_token(
        job,
        token,
        source="session_refresh",
        session_payload=session_payload,
        plan_type=extract_plan_type_from_session_payload(session_payload, token),
    )
    return token


def fetch_full_session(job: dict[str, Any], settings: dict[str, Any]) -> dict[str, Any]:
    job_id = str(job.get("id") or "")
    email_value = str(job.get("email") or "")
    with account_lock(email_value):
        state_path = job_state_path(job)
        if not state_path.exists():
            raise RuntimeError("登录态不存在")

        def read_current_session() -> dict[str, Any]:
            cookie_header = load_cookie_header_from_storage_state(
                storage_state_path=str(state_path),
                target_host="chatgpt.com",
            )
            if not cookie_header:
                return {}
            try:
                payload = read_auth_session_via_cookie_header(
                    cookie_header=cookie_header,
                    oai_device_id=try_read_oai_did_from_storage_state(str(state_path)),
                    timeout_ms=60_000,
                    proxy=str(settings.get("proxy") or "").strip() or None,
                )
            except Exception:
                return {}
            return payload if isinstance(payload, dict) else {}

        session_payload = read_current_session()
        token = access_token_from_state(session_payload)
        if not token:
            state_payload = read_json(state_path, {})
            summary = state_payload.get("mfa_summary") if isinstance(state_payload, dict) else {}
            totp_secret = normalize_totp_secret(
                str(summary.get("secret") or "") if isinstance(summary, dict) else ""
            )
            append_log("warn", "Session 已失效，开始重新登录（密码优先，邮箱验证码兜底）", job=job, stage="full_session")
            success, result = run_registration(
                get_job(job_id) or job,
                settings,
                operation="login",
                mfa_totp_secret=totp_secret,
            )
            if not success:
                raise RuntimeError(str(result.get("message") or result.get("errorCode") or "重新登录失败"))
            replacement_state = (
                result.get("_storageStatePayload")
                if isinstance(result.get("_storageStatePayload"), dict)
                else {}
            )
            token = str(result.get("_accessToken") or access_token_from_state(replacement_state) or "").strip()
            if not token:
                raise RuntimeError("重新登录成功，但没有返回 access token")
            persist_access_token(
                get_job(job_id) or job,
                token,
                source="session_relogin",
                replacement_state=replacement_state,
            )
            session_payload = read_current_session()
            token = access_token_from_state(session_payload)
            if not token:
                raise RuntimeError("重新登录后仍未取得完整 Session")
        session_user = session_payload.get("user")
        session_email = (
            str(session_user.get("email") or "").strip()
            if isinstance(session_user, dict)
            else ""
        )
        if session_email and session_email.casefold() != email_value.strip().casefold():
            raise RuntimeError("Session 账号与当前任务不匹配")
        latest_job = get_job(job_id) or job
        persist_access_token(
            latest_job,
            token,
            source="full_session",
            session_payload=session_payload if isinstance(session_payload, dict) else None,
            plan_type=extract_plan_type_from_session_payload(
                session_payload if isinstance(session_payload, dict) else {},
                token,
            ),
        )
        return {
            "ok": True,
            "source": "https://chatgpt.com/api/auth/session",
            "fetchedAt": utc_now(),
            "session": session_payload,
            "planType": extract_plan_type_from_session_payload(
                session_payload if isinstance(session_payload, dict) else {},
                token,
            ),
        }


def mask_secret(secret: str) -> str:
    value = normalize_totp_secret(secret)
    if not value:
        return ""
    if len(value) <= 8:
        return value[:1] + "*" * max(1, len(value) - 2) + value[-1:]
    return value[:4] + "*" * max(4, len(value) - 8) + value[-4:]


def mask_phone_number(phone: str) -> str:
    value = re.sub(r"\s+", "", str(phone or "").strip())
    if not value:
        return ""
    if "*" in value:
        return value[:32]
    if len(value) <= 6:
        return "*" * len(value)
    return f"{value[:3]}***{value[-3:]}"


def run_mfa(job: dict[str, Any], settings: dict[str, Any]) -> tuple[bool, str]:
    job_id = str(job.get("id") or "")
    update_job(job_id, status="mfa_enrolling", mfaStatus="enrolling", stage="mfa_info", error="")

    def mfa_log(message: str) -> None:
        latest = get_job(job_id) or job
        append_log("info", message, job=latest, stage="mfa")

    def before_activate(enrollment: dict[str, Any]) -> None:
        latest = get_job(job_id) or job
        summary = persist_mfa_summary(
            latest,
            status="pending_activation",
            secret=str(enrollment.get("secret") or ""),
            session_id=str(enrollment.get("sessionId") or ""),
            factor_id=str(enrollment.get("factorId") or ""),
        )
        update_job(
            job_id,
            status="mfa_enrolling",
            mfaStatus="secret_saved",
            stage="mfa_secret_saved",
            secretMasked=str(summary.get("secretMasked") or ""),
            localSecretPresent=True,
        )
        append_audit("mfa_secret_saved", job_id=job_id, email=str(job.get("email") or ""))
        if STOP_EVENT.is_set():
            raise RuntimeError("任务已停止，TOTP secret 已保存但尚未激活")

    latest = get_job(job_id) or job
    state_path = str(latest.get("storageStatePath") or "")
    if not state_path or not Path(state_path).exists():
        expected = job_state_path(latest)
        state_path = str(expected) if expected.exists() else state_path
    if not state_path or not Path(state_path).exists():
        return False, "注册登录态不存在"
    state_payload = read_json(Path(state_path), {})
    if access_token_requires_password_login(state_payload if isinstance(state_payload, dict) else {}):
        append_log(
            "warn",
            "当前 AT 仍是注册/OTP 会话，开通 2FA 前先用密码登录刷新 Session",
            job=latest,
            stage="mfa",
        )
        recovered, recovery_result = _recover_post_registration_session(latest, settings)
        if not recovered:
            return False, redact_text(
                str(recovery_result.get("message") or recovery_result.get("errorCode") or "密码登录刷新 Session 失败"),
                job=latest,
            )
        latest = get_job(job_id) or latest
        state_path = str(latest.get("storageStatePath") or state_path)
        if not state_path or not Path(state_path).exists():
            expected = job_state_path(latest)
            state_path = str(expected) if expected.exists() else state_path
        if not state_path or not Path(state_path).exists():
            return False, "密码登录后登录态不存在"
    try:
        result = enable_totp_mfa_via_storage_state(
            storage_state_path=state_path,
            timeout_ms=60_000,
            log=mfa_log,
            proxy=str(settings.get("proxy") or "").strip() or None,
            before_activate=before_activate,
        )
    except ChatGptTotpMfaError as error:
        status = int(getattr(error, "status", 0) or 0)
        code = str(getattr(error, "code", "") or "").strip().lower()
        if status == 401 or code in {"token_revoked", "invalid_token", "unauthorized"}:
            append_log(
                "warn",
                "2FA 鉴权失败，尝试用密码登录刷新 Session 后重试",
                job=get_job(job_id) or latest,
                stage="mfa",
            )
            recovered, recovery_result = _recover_post_registration_session(
                get_job(job_id) or latest,
                settings,
            )
            if not recovered:
                return False, redact_text(
                    str(
                        recovery_result.get("message")
                        or recovery_result.get("errorCode")
                        or f"{error.stage or 'mfa'}: {error}"
                    ),
                    job=get_job(job_id) or latest,
                )
            latest = get_job(job_id) or latest
            retry_state_path = str(latest.get("storageStatePath") or "")
            if not retry_state_path or not Path(retry_state_path).exists():
                expected = job_state_path(latest)
                retry_state_path = str(expected) if expected.exists() else ""
            if not retry_state_path:
                return False, "密码登录后登录态不存在"
            try:
                result = enable_totp_mfa_via_storage_state(
                    storage_state_path=retry_state_path,
                    timeout_ms=60_000,
                    log=mfa_log,
                    proxy=str(settings.get("proxy") or "").strip() or None,
                    before_activate=before_activate,
                )
            except ChatGptTotpMfaError as retry_error:
                return False, f"{retry_error.stage or 'mfa'}: {retry_error}"
            except Exception as retry_error:
                return False, str(retry_error)
        else:
            return False, f"{error.stage or 'mfa'}: {error}"
    except Exception as error:
        return False, str(error)

    latest = get_job(job_id) or latest
    _, state_payload = _storage_state(latest)
    summary = state_payload.get("mfa_summary") if isinstance(state_payload, dict) else {}
    local_secret = normalize_totp_secret(str((summary or {}).get("secret") or "")) if isinstance(summary, dict) else ""
    if bool(result.get("alreadyEnabled")) and not local_secret:
        update_job(
            job_id,
            status="mfa_secret_missing",
            mfaStatus="secret_missing",
            stage="mfa_secret_missing",
            localSecretPresent=False,
        )
        append_audit("mfa_secret_missing", job_id=job_id, email=str(job.get("email") or ""))
        return False, "远端已开启 2FA，但本地没有 TOTP secret"
    final_secret = normalize_totp_secret(str(result.get("secret") or "")) or local_secret
    try:
        final_summary = persist_mfa_summary(
            latest,
            status="enabled",
            secret=final_secret,
            factor_id=str(result.get("factorId") or ""),
        )
    except Exception as error:
        return False, f"2FA 已激活，但完成状态落盘失败: {error}"
    update_job(
        job_id,
        status="ready",
        mfaStatus="enabled",
        stage="ready",
        secretMasked=str(final_summary.get("secretMasked") or ""),
        localSecretPresent=bool(final_secret),
        factorId=str(final_summary.get("factorId") or ""),
        error="",
        finishedTs=time.time(),
    )
    append_audit("mfa_enabled", job_id=job_id, email=str(job.get("email") or ""))
    return True, ""


def _recover_post_registration_session(
    job: dict[str, Any],
    settings: dict[str, Any],
) -> tuple[bool, dict[str, Any]]:
    job_id = str(job.get("id") or "")
    state_path, state_payload = _storage_state(job)
    mfa_summary = state_payload.get("mfa_summary") if isinstance(state_payload, dict) else {}
    mfa_totp_secret = normalize_totp_secret(
        str(mfa_summary.get("secret") or "") if isinstance(mfa_summary, dict) else ""
    )
    update_job(job_id, status="session_recovering", stage="session_recovering", error="")
    append_log("warn", "账号注册事务已推进，开始用同一邮箱补全登录 Session（不会调用接码服务）", job=job, stage="session")
    try:
        success, result = run_registration(
            get_job(job_id) or job,
            settings,
            operation="login",
            mfa_totp_secret=mfa_totp_secret,
        )
    except Exception as error:
        return False, {"message": str(error), "stage": "login_runner_exception", "errorCode": type(error).__name__}
    if not success:
        return False, result
    replacement_state = result.get("_storageStatePayload") if isinstance(result.get("_storageStatePayload"), dict) else {}
    token = str(result.get("_accessToken") or access_token_from_state(replacement_state) or "").strip()
    if not token:
        return False, {
            **result,
            "message": "邮箱登录完成，但结果仍缺少 accessToken",
            "stage": "login_session_missing",
            "errorCode": "session_missing",
        }
    latest = get_job(job_id) or job
    try:
        persist_access_token(
            latest,
            token,
            source="post_registration_login",
            replacement_state=replacement_state,
        )
    except Exception as error:
        return False, {
            **result,
            "message": f"登录 Session 已取得，但本地保存失败：{error}",
            "stage": "login_state_persist_failed",
            "errorCode": type(error).__name__,
        }
    update_job(
        job_id,
        status="registered",
        registrationStatus="registered",
        mfaStatus=str((get_job(job_id) or latest).get("mfaStatus") or "pending"),
        stage="registration_session_recovered",
        error="",
    )
    append_log("success", "邮箱登录 Session 与 AT 已补全", job=get_job(job_id) or latest, stage="session")
    return True, result


def run_one(job_id: str, settings: dict[str, Any]) -> None:
    job = get_job(job_id)
    if not job:
        return
    with account_lock(str(job.get("email") or "")):
        job_settings = settings_for_job(settings, job_id)
        auto_enable_mfa = True
        proxy_label = mask_proxy_url(str(job_settings.get("proxy") or ""))
        update_job(job_id, proxyLabel=proxy_label)
        append_log("info", f"ChatGPT 网络出口: {proxy_label}", job=job, stage="network")
        if STOP_EVENT.is_set():
            update_job(job_id, status="stopped", stage="stopped", finishedTs=time.time())
            return
        previous_error = str(job.get("error") or "")
        started = float(job.get("startedTs") or 0) or time.time()
        update_job(job_id, startedTs=started, finishedTs=0, error="")
        latest = get_job(job_id) or job
        expected_state = X9_RUNTIME_ROOT / "登录态" / f"{str(latest.get('email') or '').strip()}.json"
        current_state_path = job_state_path(latest)
        current_state = read_json(current_state_path, {}) if current_state_path.exists() else {}
        expected_payload = read_json(expected_state, {}) if expected_state.exists() else {}
        state_payload = current_state if isinstance(current_state, dict) and current_state else expected_payload
        has_token = bool(access_token_from_state(state_payload if isinstance(state_payload, dict) else {}))
        has_cookies = bool(isinstance(state_payload, dict) and state_payload.get("cookies"))
        registration_status = str(latest.get("registrationStatus") or "")
        registration_ready = registration_status == "registered" and has_token and has_cookies

        resume_password = bool(
            has_cookies
            and not bool(latest.get("remotePasswordSet"))
            and (
                str(latest.get("stage") or "") == "set_password"
                or str(latest.get("remotePasswordMode") or "") == "post_registration_password_reset"
            )
        )
        if resume_password:
            update_job(
                job_id,
                status="registering",
                registrationStatus="running",
                stage="set_password",
                error="",
            )
            latest = get_job(job_id) or latest
            append_log("info", "继续上次未完成的远端密码补设", job=latest, stage="set_password")
            try:
                password_ok, password_result = run_registration(
                    latest,
                    job_settings,
                    operation="set_password",
                )
            except Exception as error:
                password_ok = False
                password_result = {"message": str(error), "stage": "set_password"}
            if not password_ok:
                message = redact_text(
                    str(password_result.get("message") or password_result.get("errorCode") or "远端密码补设失败"),
                    job=latest,
                )
                update_job(
                    job_id,
                    status="registration_failed",
                    registrationStatus="failed",
                    mfaStatus="pending",
                    stage="set_password",
                    error=message,
                    finishedTs=time.time(),
                    remotePasswordSet=False,
                    remotePasswordMode="post_registration_password_reset",
                    remotePasswordStatus="failed",
                )
                append_log("error", message, job=get_job(job_id) or latest, stage="set_password")
                return
            replacement_state = password_result.get("_storageStatePayload")
            if not isinstance(replacement_state, dict):
                raise RuntimeError("密码补设成功，但 runner 未返回登录态")
            persist_phone_binding_storage_state(latest, replacement_state)
            update_job(
                job_id,
                status="registered",
                registrationStatus="registered",
                mfaStatus="pending",
                stage="password_set",
                error="",
                finishedTs=0,
                remotePasswordSet=True,
                remotePasswordMode="post_registration_password_reset",
                remotePasswordStatus="set",
            )
            latest = get_job(job_id) or latest
            if access_token_requires_password_login(replacement_state):
                append_log(
                    "warn",
                    "密码补设后的 AT 仍是注册会话，先用密码登录刷新后再开 2FA",
                    job=latest,
                    stage="session",
                )
                recovered, recovery_result = _recover_post_registration_session(latest, job_settings)
                if not recovered:
                    message = redact_text(
                        str(recovery_result.get("message") or recovery_result.get("errorCode") or "密码登录刷新 Session 失败"),
                        job=latest,
                    )
                    update_job(
                        job_id,
                        status="session_pending",
                        registrationStatus="session_pending",
                        stage="session_pending",
                        error=message,
                        finishedTs=time.time(),
                    )
                    append_log("error", message, job=get_job(job_id) or latest, stage="session")
                    return
                latest = get_job(job_id) or latest
            registration_ready = True
            append_log("success", "远端密码补设完成，继续开启 2FA", job=latest, stage="set_password")

        if (not registration_ready) and has_token and has_cookies:
            recovered_path = current_state_path if current_state else expected_state
            update_job(
                job_id,
                status="registered",
                registrationStatus="registered",
                stage="registration_recovered",
                storageStatePath=str(recovered_path),
                error="",
            )
            latest = get_job(job_id) or latest
            registration_ready = True
            append_log("warn", "检测到完整注册登录态，已跳过重复注册", job=latest, stage="registration")

        legacy_session_error = (
            "session 响应缺少 accessToken" in previous_error
            and has_cookies
        )
        session_pending = registration_status == "session_pending" or legacy_session_error
        if (not registration_ready) and session_pending:
            pending_path = current_state_path if current_state_path.exists() else expected_state
            update_job(
                job_id,
                status="session_pending",
                registrationStatus="session_pending",
                stage="session_pending",
                storageStatePath=str(pending_path),
                error="",
            )
            latest = get_job(job_id) or latest
            recovered, recovery_result = _recover_post_registration_session(latest, job_settings)
            if recovered:
                registration_ready = True
                latest = get_job(job_id) or latest
            else:
                recovery_stage = str(recovery_result.get("stage") or "login_session_missing")
                message = redact_text(
                    str(recovery_result.get("message") or recovery_result.get("errorCode") or "登录 Session 尚未建立"),
                    job=latest,
                )
                if recovery_stage == "login_phone_required":
                    update_job(
                        job_id,
                        status="phone_required",
                        registrationStatus="phone_required",
                        stage="registration_phone_required",
                        error="平台要求绑定手机号；请使用批量绑手机，注册阶段未租号",
                        finishedTs=time.time(),
                    )
                else:
                    update_job(
                        job_id,
                        status="session_pending",
                        registrationStatus="session_pending",
                        stage="session_pending",
                        error=message,
                        finishedTs=time.time(),
                    )
                append_log("warn", message, job=get_job(job_id) or latest, stage="session")
                return

        if (not registration_ready) and registration_status == "phone_required":
            update_job(job_id, status="phone_required", stage="registration_phone_required", finishedTs=time.time())
            return

        if not registration_ready:
            update_job(job_id, status="registering", registrationStatus="running", stage="registering")
            append_log("info", "开始邮箱注册账号（不会调用手机号接码服务）", job=latest, stage="registration")
            try:
                success, result = run_registration(latest, job_settings)
            except Exception as error:
                status = "stopped" if STOP_EVENT.is_set() else "registration_failed"
                update_job(
                    job_id,
                    status=status,
                    registrationStatus="failed",
                    stage=status,
                    error=redact_text(str(error), job=latest),
                    finishedTs=time.time(),
                )
                append_log("error", str(error), job=latest, stage="registration")
                return
            result_stage = str(result.get("stage") or "")
            result_state_path = str(result.get("storageStatePath") or expected_state)
            remote_password_set = bool(result.get("remotePasswordSet"))
            remote_password_mode = str(result.get("remotePasswordMode") or "not_attempted")
            remote_password_status = "set" if remote_password_set else (
                "failed" if result_stage in {"submit_password", "set_password"} else "not_attempted"
            )
            remote_password_fields = {
                "remotePasswordSet": remote_password_set,
                "remotePasswordMode": remote_password_mode,
                "remotePasswordStatus": remote_password_status,
            }
            if not success and result_stage == "registration_phone_required":
                update_job(
                    job_id,
                    status="phone_required",
                    registrationStatus="phone_required",
                    mfaStatus="pending",
                    stage="registration_phone_required",
                    storageStatePath=result_state_path,
                    tracePath=str(result.get("tracePath") or ""),
                    error="平台要求绑定手机号；请使用批量绑手机，注册阶段未租号",
                    finishedTs=time.time(),
                    **remote_password_fields,
                )
                append_log("warn", "邮箱阶段已结束，等待你后期批量绑定手机号；本次未租号", job=get_job(job_id) or latest, stage="registration")
                return
            pending_stages = {
                "registration_session_pending",
                "registration_state_ambiguous",
                "post_register_session_missing",
            }
            if not success and result_stage in pending_stages:
                update_job(
                    job_id,
                    status="session_pending",
                    registrationStatus="session_pending",
                    mfaStatus="pending",
                    stage="session_pending",
                    storageStatePath=result_state_path,
                    tracePath=str(result.get("tracePath") or ""),
                    error="",
                    **remote_password_fields,
                )
                latest = get_job(job_id) or latest
                recovered, recovery_result = _recover_post_registration_session(latest, job_settings)
                if not recovered:
                    recovery_stage = str(recovery_result.get("stage") or "login_session_missing")
                    message = redact_text(
                        str(recovery_result.get("message") or recovery_result.get("errorCode") or "登录 Session 尚未建立"),
                        job=latest,
                    )
                    if recovery_stage == "login_phone_required":
                        update_job(
                            job_id,
                            status="phone_required",
                            registrationStatus="phone_required",
                            stage="registration_phone_required",
                            error="平台要求绑定手机号；请使用批量绑手机，注册阶段未租号",
                            finishedTs=time.time(),
                        )
                    else:
                        update_job(
                            job_id,
                            status="session_pending",
                            registrationStatus="session_pending",
                            stage="session_pending",
                            error=message,
                            finishedTs=time.time(),
                        )
                    append_log("warn", message, job=get_job(job_id) or latest, stage="session")
                    return
                registration_ready = True
                latest = get_job(job_id) or latest
            elif not success:
                message = str(result.get("message") or result.get("errorCode") or "注册失败")
                update_job(
                    job_id,
                    status="registration_failed",
                    registrationStatus="failed",
                    stage=result_stage or "registration_failed",
                    error=redact_text(message, job=latest),
                    finishedTs=time.time(),
                    **remote_password_fields,
                )
                append_log("error", message, job=latest, stage="registration")
                return
            else:
                update_job(
                    job_id,
                    status="registered",
                    registrationStatus="registered",
                    mfaStatus="pending",
                    stage="registered",
                    storageStatePath=result_state_path,
                    atPath=str(result.get("atPath") or ""),
                    tracePath=str(result.get("tracePath") or ""),
                    error="",
                    finishedTs=0 if auto_enable_mfa else time.time(),
                    **remote_password_fields,
                )
                registered_job = get_job(job_id) or latest
                registered_state_path = job_state_path(registered_job)
                registered_state = read_json(registered_state_path, {}) if registered_state_path.exists() else {}
                registered_token = access_token_from_state(registered_state if isinstance(registered_state, dict) else {})
                if not registered_token:
                    update_job(
                        job_id,
                        status="session_pending",
                        registrationStatus="session_pending",
                        stage="session_pending",
                    )
                    recovered, recovery_result = _recover_post_registration_session(get_job(job_id) or registered_job, job_settings)
                    if not recovered:
                        message = redact_text(
                            str(recovery_result.get("message") or recovery_result.get("errorCode") or "登录 Session 尚未建立"),
                            job=registered_job,
                        )
                        update_job(
                            job_id,
                            status="session_pending",
                            registrationStatus="session_pending",
                            stage="session_pending",
                            error=message,
                            finishedTs=time.time(),
                        )
                        append_log("warn", message, job=get_job(job_id) or registered_job, stage="session")
                        return
                else:
                    persist_access_token(registered_job, registered_token, source="registration")
                registration_ready = True
                latest = get_job(job_id) or latest
                message = "账号注册完成，准备自动开启 2FA" if auto_enable_mfa else "账号注册完成，可稍后批量开启 2FA"
                append_log("success", message, job=get_job(job_id) or latest, stage="registration")

        if not auto_enable_mfa:
            update_job(
                job_id,
                status="registered",
                registrationStatus="registered",
                mfaStatus=str((get_job(job_id) or latest).get("mfaStatus") or "pending"),
                stage="registered",
                error="",
                finishedTs=time.time(),
            )
            return
        if STOP_EVENT.is_set():
            update_job(job_id, status="stopped", stage="stopped", finishedTs=time.time())
            return
        pre_mfa_job = get_job(job_id) or latest
        pre_mfa_state_path = job_state_path(pre_mfa_job)
        pre_mfa_state = read_json(pre_mfa_state_path, {}) if pre_mfa_state_path.exists() else {}
        if access_token_requires_password_login(pre_mfa_state if isinstance(pre_mfa_state, dict) else {}):
            append_log(
                "warn",
                "注册后 AT 仍是 OTP/注册会话，开通 2FA 前先用密码登录刷新 Session",
                job=pre_mfa_job,
                stage="session",
            )
            recovered, recovery_result = _recover_post_registration_session(pre_mfa_job, job_settings)
            if not recovered:
                message = redact_text(
                    str(recovery_result.get("message") or recovery_result.get("errorCode") or "密码登录刷新 Session 失败"),
                    job=pre_mfa_job,
                )
                update_job(
                    job_id,
                    status="session_pending",
                    registrationStatus="session_pending",
                    stage="session_pending",
                    error=message,
                    finishedTs=time.time(),
                )
                append_log("error", message, job=get_job(job_id) or pre_mfa_job, stage="session")
                return
        success, error = run_mfa(get_job(job_id) or latest, job_settings)
        if not success:
            current = get_job(job_id) or latest
            if str(current.get("status") or "") != "mfa_secret_missing":
                update_job(
                    job_id,
                    status="mfa_failed",
                    mfaStatus="failed",
                    stage="mfa_failed",
                    error=redact_text(error, job=current),
                    finishedTs=time.time(),
                )
            append_log("error", error, job=current, stage="mfa")
            return
        append_log("success", "注册与 TOTP 2FA 已完成", job=get_job(job_id) or latest, stage="ready")


def run_at_refresh_one(job_id: str, settings: dict[str, Any]) -> None:
    job = get_job(job_id)
    if not job:
        return
    with account_lock(str(job.get("email") or "")):
        job_settings = settings_for_job(settings, job_id)
        proxy_label = mask_proxy_url(str(job_settings.get("proxy") or ""))
        update_job(job_id, proxyLabel=proxy_label)
        append_log("info", f"AT 刷新网络出口: {proxy_label}", job=job, stage="network")
        if str(job.get("registrationStatus") or "") != "registered":
            update_job(job_id, atStatus="refresh_failed", atError="账号尚未注册完成")
            return
        previous_status = str(job.get("status") or "ready")
        previous_stage = str(job.get("stage") or "ready")
        update_job(job_id, atStatus="refreshing", atError="", stage="at_refreshing")
        append_log("info", "开始刷新 ChatGPT AT", job=job, stage="at_refresh")
        try:
            refresh_access_token_from_session(job, job_settings)
            update_job(job_id, status=previous_status, stage=previous_stage)
            append_audit("access_token_refreshed", job_id=job_id, email=str(job.get("email") or ""), detail="session")
            append_log("success", "已通过现有会话取得最新 AT", job=get_job(job_id) or job, stage="at_refresh")
            return
        except Exception as error:
            append_log("warn", f"现有会话刷新失败，准备模拟完整登录: {error}", job=job, stage="at_refresh")
        _, state_payload = _storage_state(job)
        summary = state_payload.get("mfa_summary") if isinstance(state_payload, dict) else {}
        totp_secret = normalize_totp_secret(str((summary or {}).get("secret") or "")) if isinstance(summary, dict) else ""
        latest = get_job(job_id) or job
        try:
            success, result = run_registration(
                latest,
                job_settings,
                operation="login",
                mfa_totp_secret=totp_secret,
            )
        except Exception as error:
            success = False
            result = {"message": str(error), "stage": "login_runner_exception"}
        if not success:
            message = redact_text(str(result.get("message") or result.get("errorCode") or "模拟登录失败"), job=latest)
            update_job(
                job_id,
                status=previous_status,
                stage="at_refresh_failed",
                atStatus="refresh_failed",
                atError=message,
            )
            append_log("error", message, job=latest, stage="at_refresh")
            return
        replacement_state = result.get("_storageStatePayload") if isinstance(result.get("_storageStatePayload"), dict) else {}
        token = str(result.get("_accessToken") or access_token_from_state(replacement_state) or "").strip()
        try:
            persist_access_token(latest, token, source="full_login", replacement_state=replacement_state)
            if totp_secret:
                current = get_job(job_id) or latest
                persist_mfa_summary(current, status="enabled", secret=totp_secret)
            update_job(job_id, status=previous_status, stage=previous_stage, atError="")
        except Exception as error:
            update_job(
                job_id,
                status=previous_status,
                stage="at_refresh_failed",
                atStatus="refresh_failed",
                atError=redact_text(str(error), job=latest),
            )
            append_log("error", f"最新 AT 落盘失败: {error}", job=latest, stage="at_refresh")
            return
        append_audit("access_token_refreshed", job_id=job_id, email=str(job.get("email") or ""), detail="full_login")
        append_log("success", "模拟登录完成，最新 AT 已保存", job=get_job(job_id) or latest, stage="at_refresh")


def _phone_binding_state_error(job: dict[str, Any]) -> str:
    if str(job.get("registrationStatus") or "") not in {"registered", "phone_required"}:
        return "account_not_registered"
    state_path = job_state_path(job)
    if not state_path.exists() or not state_path.is_file():
        return "storage_state_missing"
    state = read_json(state_path, {})
    if not isinstance(state, dict):
        return "storage_state_invalid"
    cookies = state.get("cookies")
    if not isinstance(cookies, list) or not any(
        isinstance(cookie, dict) and str(cookie.get("name") or "").strip() and str(cookie.get("value") or "").strip()
        for cookie in cookies
    ):
        return "storage_state_has_no_cookies"
    return ""


def _phone_from_runner_result(result: dict[str, Any]) -> tuple[str, str]:
    masked = str(result.get("phoneMasked") or result.get("phone_masked") or "").strip()
    raw = str(
        result.get("boundPhone")
        or result.get("phoneNumber")
        or result.get("bound_phone")
        or result.get("phone_number")
        or result.get("phone")
        or ""
    ).strip()
    if not raw:
        values = result.get("boundPhoneNumbers") or result.get("bound_phone_numbers")
        if isinstance(values, list):
            raw = next((str(value).strip() for value in values if str(value or "").strip()), "")
    return raw, mask_phone_number(masked or raw)


def run_phone_binding_one(
    job_id: str,
    settings: dict[str, Any],
    *,
    manual_control_path: str = "",
) -> bool:
    job = get_job(job_id)
    if not job:
        return False
    email_value = str(job.get("email") or "")
    provider = "manual" if str(manual_control_path or "").strip() else str(settings.get("smsProvider") or "").strip().lower()
    with account_lock(email_value):
        latest = get_job(job_id) or job
        registration_status_before = str(latest.get("registrationStatus") or "")
        if STOP_EVENT.is_set():
            update_job(
                job_id,
                phoneStatus="phone_stopped",
                phoneProvider=provider,
                phoneError="phone binding stopped",
                phoneFinishedAt=utc_now(),
            )
            return False
        state_error = _phone_binding_state_error(latest)
        if state_error:
            update_job(
                job_id,
                phoneStatus="phone_failed",
                phoneProvider=provider,
                phoneError=state_error,
                phoneFinishedAt=utc_now(),
            )
            append_audit("phone_binding_failed", job_id=job_id, email=email_value, detail=state_error)
            return False
        started_at = utc_now()
        update_job(
            job_id,
            phoneStatus="phone_binding",
            phoneProvider=provider,
            phoneError="",
            phoneStartedAt=started_at,
            phoneFinishedAt="",
        )
        append_audit("phone_binding_started", job_id=job_id, email=email_value, detail=f"provider={provider}")
        append_log("info", "开始后期绑定手机号", job=latest, stage="phone_binding")
        job_settings = settings_for_job(settings, job_id)
        _state_path, state_payload = _storage_state(latest)
        mfa_summary = state_payload.get("mfa_summary") if isinstance(state_payload, dict) else {}
        mfa_totp_secret = normalize_totp_secret(
            str(mfa_summary.get("secret") or "") if isinstance(mfa_summary, dict) else ""
        )
        try:
            success, result = run_registration(
                latest,
                job_settings,
                operation="bind_phone",
                mfa_totp_secret=mfa_totp_secret,
                phone_verification_override=(
                    {
                        "manual_phone_control_path": str(manual_control_path),
                        "manual_phone_timeout_seconds": 1800,
                        "proxy": str(job_settings.get("proxy") or "").strip(),
                    }
                    if str(manual_control_path or "").strip()
                    else None
                ),
            )
        except Exception as error:
            success = False
            result = {"message": str(error), "stage": "phone_binding_runner_exception"}
        if not success:
            stopped = STOP_EVENT.is_set()
            message = redact_text(
                str(result.get("message") or result.get("errorCode") or "phone binding failed"),
                job=latest,
            )
            update_job(
                job_id,
                phoneStatus="phone_stopped" if stopped else "phone_failed",
                phoneProvider=provider,
                phoneError="phone binding stopped" if stopped else message,
                phoneFinishedAt=utc_now(),
            )
            action = "phone_binding_stopped" if stopped else "phone_binding_failed"
            append_audit(action, job_id=job_id, email=email_value, detail=str(result.get("stage") or "runner"))
            append_log("warn" if stopped else "error", message, job=latest, stage="phone_binding")
            return False
        _raw_phone, masked_phone = _phone_from_runner_result(result)
        if not masked_phone:
            message = "phone binding runner did not return a bound phone number"
            update_job(
                job_id,
                phoneStatus="phone_failed",
                phoneProvider=provider,
                phoneError=message,
                phoneFinishedAt=utc_now(),
            )
            append_audit("phone_binding_failed", job_id=job_id, email=email_value, detail="missing_bound_phone")
            append_log("error", message, job=latest, stage="phone_binding")
            return False
        state_warning = ""
        replacement_state = result.get("_storageStatePayload")
        try:
            persist_phone_binding_storage_state(
                latest,
                replacement_state if isinstance(replacement_state, dict) else {},
            )
        except Exception as error:
            # The remote OTP was already accepted and the provider order was settled.
            # Keep the account marked as bound so a retry cannot rent a second number.
            state_warning = redact_text(f"手机号已绑定，但本地登录态更新失败: {error}", job=latest)
            append_audit(
                "phone_binding_state_persist_warning",
                job_id=job_id,
                email=email_value,
                detail="persist_storage_state",
            )
            append_log("warn", state_warning, job=latest, stage="phone_binding")
        finished_at = utc_now()
        success_credential_path = str(result.get("successCredentialPath") or "").strip()
        credential_payload_data = read_json(Path(success_credential_path), {}) if success_credential_path else {}
        if not success_credential_has_rt(credential_payload_data if isinstance(credential_payload_data, dict) else {}):
            existing_payload = read_success_credential(latest)
            if success_credential_has_rt(existing_payload):
                success_credential_path = str(job_success_credential_path(latest))
                credential_payload_data = existing_payload
        if success_credential_has_rt(credential_payload_data if isinstance(credential_payload_data, dict) else {}):
            mark_job_rt_status(job_id, success=True, path=success_credential_path or str(job_success_credential_path(latest)))
            append_log("success", "绑号后 RT 已落库", job=latest, stage="rt_export")
        else:
            rt_error = "phone bound but success credential/RT missing"
            if "RT 导出" in str(result.get("message") or ""):
                rt_error = str(result.get("message") or rt_error)
            mark_job_rt_status(job_id, success=False, error=rt_error)
            append_log("warn", f"手机号已绑定，但 RT 未落库：{rt_error}", job=latest, stage="rt_export")
        update_job(
            job_id,
            phoneStatus="phone_bound",
            phoneMasked=masked_phone,
            phoneProvider=provider,
            phoneError=state_warning,
            phoneFinishedAt=finished_at,
            phoneBoundAt=finished_at,
        )
        if registration_status_before == "phone_required":
            session_ready = False
            current = get_job(job_id) or latest
            current_state_path, current_state = _storage_state(current)
            current_token = access_token_from_state(current_state if isinstance(current_state, dict) else {})
            try:
                if current_token:
                    persist_access_token(current, current_token, source="phone_binding")
                else:
                    refresh_access_token_from_session(current, job_settings)
                session_ready = True
            except Exception as error:
                append_log(
                    "warn",
                    f"手机号已绑定，登录 Session 仍待补全：{error}",
                    job=current,
                    stage="session",
                )
            if session_ready:
                update_job(
                    job_id,
                    status="registered",
                    registrationStatus="registered",
                    mfaStatus="pending",
                    stage="registered",
                    error="",
                    storageStatePath=str(current_state_path),
                    finishedTs=time.time(),
                )
                if bool(job_settings.get("autoEnableMfaAfterRegistration", False)):
                    mfa_success, mfa_error = run_mfa(get_job(job_id) or current, job_settings)
                    if not mfa_success:
                        current = get_job(job_id) or current
                        if str(current.get("status") or "") != "mfa_secret_missing":
                            update_job(
                                job_id,
                                status="mfa_failed",
                                registrationStatus="registered",
                                mfaStatus="failed",
                                stage="mfa_failed",
                                error=redact_text(mfa_error, job=current),
                                finishedTs=time.time(),
                            )
            else:
                update_job(
                    job_id,
                    status="session_pending",
                    registrationStatus="session_pending",
                    mfaStatus="pending",
                    stage="session_pending",
                    error="手机号已绑定，等待邮箱登录补全 Session",
                    storageStatePath=str(current_state_path),
                    finishedTs=time.time(),
                )
        append_audit("phone_binding_completed", job_id=job_id, email=email_value, detail=f"provider={provider}")
        append_log("success", f"手机号绑定完成：{masked_phone}", job=get_job(job_id) or latest, stage="phone_binding")
        return True


def _record_phone_binding_progress(success: bool) -> None:
    with RUNTIME_LOCK:
        RUNTIME["completed"] = int(RUNTIME.get("completed") or 0) + 1
        RUNTIME["completedCount"] = RUNTIME["completed"]
        key = "success" if success else "failed"
        RUNTIME[key] = int(RUNTIME.get(key) or 0) + 1
        RUNTIME[f"{key}Count"] = RUNTIME[key]


def phone_binding_batch_worker(job_ids: list[str], settings: dict[str, Any]) -> None:
    work: queue.Queue[str] = queue.Queue()
    for job_id in job_ids:
        work.put(job_id)
    try:
        with RUNTIME_LOCK:
            RUNTIME["operation"] = "phone_binding"
            RUNTIME["activeJobIds"] = list(job_ids)
        append_log("info", f"启动 {len(job_ids)} 个后期绑号任务")

        def consume() -> None:
            while True:
                try:
                    job_id = work.get_nowait()
                except queue.Empty:
                    return
                succeeded = False
                try:
                    if STOP_EVENT.is_set():
                        current = get_job(job_id)
                        update_job(
                            job_id,
                            phoneStatus="phone_stopped",
                            phoneError="phone binding stopped",
                            phoneFinishedAt=utc_now(),
                        )
                        if current:
                            append_audit(
                                "phone_binding_stopped",
                                job_id=job_id,
                                email=str(current.get("email") or ""),
                                detail="queued",
                            )
                    else:
                        succeeded = run_phone_binding_one(job_id, settings)
                except Exception as error:
                    current = get_job(job_id) or {"id": job_id}
                    stopped = STOP_EVENT.is_set()
                    message = redact_text(str(error), job=current)
                    update_job(
                        job_id,
                        phoneStatus="phone_stopped" if stopped else "phone_failed",
                        phoneError="phone binding stopped" if stopped else message,
                        phoneFinishedAt=utc_now(),
                    )
                    append_log("error", f"后期绑号异常: {message}", job=current, stage="phone_binding")
                finally:
                    _record_phone_binding_progress(succeeded)
                    work.task_done()

        worker_count = min(max(1, int(settings.get("concurrency") or 1)), len(job_ids)) if job_ids else 0
        threads = [threading.Thread(target=consume, daemon=True) for _ in range(worker_count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    finally:
        with RUNTIME_LOCK:
            RUNTIME["running"] = False
            RUNTIME["finishedAt"] = utc_now()
            RUNTIME["worker"] = None
            RUNTIME["operation"] = "idle"
            RUNTIME["activeJobIds"] = []
        append_log("warn" if STOP_EVENT.is_set() else "success", "后期绑号批次已停止" if STOP_EVENT.is_set() else "后期绑号批次已完成")


def start_phone_binding(ids: list[str]) -> tuple[int, dict[str, Any]]:
    requested_ids = [str(value).strip() for value in ids if str(value).strip()]
    if not requested_ids:
        return 400, {"ok": False, "error": "ids must be a non-empty array"}
    settings = load_settings()
    provider = str(settings.get("smsProvider") or "").strip().lower()
    api_key = str(settings.get("smsApiKey") or "").strip()
    if provider not in {"smsbower", "herosms"}:
        return 400, {"ok": False, "error": "SMS provider must be SmsBower or HeroSMS"}
    if not api_key:
        return 400, {"ok": False, "error": "SMS API key is not configured"}
    if not SMS_RECOVERY_COMPLETE.is_set():
        return 409, {"ok": False, "error": "SMS activation recovery is still running"}
    with RUNTIME_LOCK:
        if RUNTIME["running"]:
            return 409, {"ok": False, "error": "another batch is already running"}
        RUNTIME["running"] = True
        RUNTIME["startedAt"] = utc_now()
        RUNTIME["finishedAt"] = ""
        RUNTIME["operation"] = "phone_binding"
        STOP_EVENT.clear()

    candidate_ids: list[str] = []
    skipped_items: list[dict[str, str]] = []
    try:
        with JOBS_LOCK:
            jobs = load_jobs()
            by_id = {str(job.get("id") or ""): job for job in jobs}
            seen: set[str] = set()
            for job_id in requested_ids:
                if job_id in seen:
                    skipped_items.append({"id": job_id, "reason": "duplicate"})
                    continue
                seen.add(job_id)
                job = by_id.get(job_id)
                if not job:
                    skipped_items.append({"id": job_id, "reason": "not_found"})
                    continue
                phone_status = str(job.get("phoneStatus") or "phone_unknown")
                if phone_status == "phone_bound":
                    skipped_items.append({"id": job_id, "reason": "already_bound"})
                    continue
                if phone_status in {"phone_queued", "phone_binding"}:
                    skipped_items.append({"id": job_id, "reason": "already_queued"})
                    continue
                state_error = _phone_binding_state_error(job)
                if state_error:
                    skipped_items.append({"id": job_id, "reason": state_error})
                    continue
                queued_at = utc_now()
                job.update(
                    {
                        "phoneStatus": "phone_queued",
                        "phoneMasked": "",
                        "phoneProvider": provider,
                        "phoneError": "",
                        "phoneQueuedAt": queued_at,
                        "phoneStartedAt": "",
                        "phoneFinishedAt": "",
                        "phoneBoundAt": "",
                        "updatedAt": queued_at,
                    }
                )
                candidate_ids.append(job_id)
            if candidate_ids:
                save_jobs(jobs)
        with RUNTIME_LOCK:
            RUNTIME["total"] = len(candidate_ids)
            RUNTIME["completed"] = 0
            RUNTIME["success"] = 0
            RUNTIME["failed"] = 0
            RUNTIME["totalCount"] = len(candidate_ids)
            RUNTIME["completedCount"] = 0
            RUNTIME["successCount"] = 0
            RUNTIME["failedCount"] = 0
            RUNTIME["activeJobIds"] = list(candidate_ids)
        payload = {
            "ok": True,
            "count": len(candidate_ids),
            "skipped": len(skipped_items),
            "skippedItems": skipped_items,
        }
        if not candidate_ids:
            with RUNTIME_LOCK:
                RUNTIME["running"] = False
                RUNTIME["finishedAt"] = utc_now()
                RUNTIME["operation"] = "idle"
                RUNTIME["activeJobIds"] = []
            return 200, payload
        worker = threading.Thread(
            target=phone_binding_batch_worker,
            args=(candidate_ids, settings),
            daemon=True,
        )
        with RUNTIME_LOCK:
            RUNTIME["worker"] = worker
        worker.start()
        append_audit("phone_binding_batch_started", detail=f"count={len(candidate_ids)} provider={provider}")
        return 202, payload
    except Exception:
        with RUNTIME_LOCK:
            RUNTIME["running"] = False
            RUNTIME["finishedAt"] = utc_now()
            RUNTIME["worker"] = None
            RUNTIME["operation"] = "idle"
            RUNTIME["activeJobIds"] = []
        raise


def _normalize_manual_phone_number(value: Any) -> str:
    raw = str(value or "").strip()
    digits = "".join(ch for ch in raw if ch.isdigit())
    normalized = f"+{digits}" if raw.startswith("+") else ""
    if not re.fullmatch(r"\+[1-9]\d{7,14}", normalized):
        raise ValueError("手机号格式无效，请填写 +国家码手机号，例如 +66812345678")
    return normalized


def _manual_phone_worker(
    job_id: str,
    settings: dict[str, Any],
    control_dir: Path,
    session_id: str,
) -> None:
    succeeded = False
    terminal_error = ""
    try:
        succeeded = run_phone_binding_one(
            job_id,
            settings,
            manual_control_path=str(control_dir.resolve(strict=False)),
        )
        if not succeeded:
            latest = get_job(job_id) or {}
            terminal_error = str(latest.get("phoneError") or "手动手机号绑定未完成")[:1000]
    except Exception as error:
        current = get_job(job_id) or {"id": job_id}
        terminal_error = redact_text(str(error), job=current)
        update_job(
            job_id,
            phoneStatus="phone_stopped" if STOP_EVENT.is_set() else "phone_failed",
            phoneProvider="manual",
            phoneError=terminal_error,
            phoneFinishedAt=utc_now(),
        )
        append_log("error", f"手动手机号绑定异常: {terminal_error}", job=current, stage="phone_binding")
    finally:
        # The child runner is no longer active.  Serialize final cleanup with
        # send/verify, and only touch state when this exact run still owns it.
        with MANUAL_PHONE_LOCK:
            with RUNTIME_LOCK:
                released = _release_manual_phone_runtime_locked(
                    job_id,
                    session_id,
                    completed=True,
                    succeeded=succeeded,
                )
            if released:
                status_path = control_dir / "status.json"
                status_payload = read_json(status_path, {})
                owns_control = bool(
                    isinstance(status_payload, dict)
                    and str(status_payload.get("sessionId") or "") == session_id
                )
                if owns_control:
                    update_manual_phone_status(
                        job_id,
                        phase="completed" if succeeded else ("stopped" if STOP_EVENT.is_set() else "failed"),
                        active=False,
                        error="" if succeeded else terminal_error[:1000],
                    )
                    _cleanup_manual_phone_transients(control_dir)


def send_manual_phone(job_id: str, phone_number: Any) -> tuple[int, dict[str, Any]]:
    normalized_phone = _normalize_manual_phone_number(phone_number)
    job = get_job(job_id)
    if not job:
        return 404, {"ok": False, "error": "任务不存在"}
    if str(job.get("phoneStatus") or "") == "phone_bound":
        return 409, {"ok": False, "error": "该账号已经绑定手机号"}
    state_error = _phone_binding_state_error(job)
    if state_error:
        return 409, {"ok": False, "error": state_error}

    control_dir = manual_phone_control_dir(job_id)
    with MANUAL_PHONE_LOCK:
        active_same_job = False
        session_id = ""
        with RUNTIME_LOCK:
            if RUNTIME.get("running"):
                session_id = str(RUNTIME.get("manualPhoneSessionId") or "")
                active_same_job = _manual_phone_runtime_owned_locked(job_id, session_id)
                if not active_same_job:
                    return 409, {"ok": False, "error": "另一个任务正在运行，请先等待或停止"}
            else:
                # Claim the global runtime before filesystem/job setup.  Other
                # start endpoints now see this run immediately and cannot race
                # a second worker into the initialization window.
                session_id = secrets.token_urlsafe(18)
                RUNTIME["running"] = True
                RUNTIME["startedAt"] = utc_now()
                RUNTIME["finishedAt"] = ""
                RUNTIME["operation"] = "manual_phone_binding"
                RUNTIME["manualPhoneJobId"] = job_id
                RUNTIME["manualPhoneSessionId"] = session_id
                RUNTIME["activeJobIds"] = [job_id]
                RUNTIME["total"] = 1
                RUNTIME["totalCount"] = 1
                RUNTIME["completed"] = 0
                RUNTIME["completedCount"] = 0
                RUNTIME["success"] = 0
                RUNTIME["successCount"] = 0
                RUNTIME["failed"] = 0
                RUNTIME["failedCount"] = 0
                RUNTIME["worker"] = None
                STOP_EVENT.clear()

        if active_same_job:
            status_payload = read_json(control_dir / "status.json", {})
            if not (
                isinstance(status_payload, dict)
                and bool(status_payload.get("active"))
                and str(status_payload.get("sessionId") or "") == session_id
            ):
                return 409, {"ok": False, "error": "手动绑号会话正在结束，请稍后重新开始"}
            phone_payload = read_json(control_dir / "phone.json", {})
            current = manual_phone_status(job_id)
            attempt_id = max(
                int(phone_payload.get("attemptId") or 0) if isinstance(phone_payload, dict) else 0,
                int(current.get("attemptId") or 0),
            ) + 1
            write_json_atomic(
                control_dir / "phone.json",
                {"attemptId": attempt_id, "phoneNumber": normalized_phone, "createdAtEpoch": time.time()},
            )
            append_log("info", "已提交新的手动手机号，复用当前登录会话重新发码", job=job, stage="phone_binding")
            return 202, {**manual_phone_status(job_id), "queuedAttemptId": attempt_id}

        previous_phone_fields = {
            key: job.get(key, "")
            for key in (
                "phoneStatus",
                "phoneMasked",
                "phoneProvider",
                "phoneError",
                "phoneQueuedAt",
                "phoneStartedAt",
                "phoneFinishedAt",
                "phoneBoundAt",
            )
        }
        job_updated = False
        try:
            if control_dir.exists():
                shutil.rmtree(control_dir, ignore_errors=True)
            control_dir.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(control_dir, 0o700)
            except OSError:
                pass
            write_json_atomic(
                control_dir / "status.json",
                {
                    "sessionId": session_id,
                    "jobId": job_id,
                    "phase": "starting",
                    "active": True,
                    "attemptId": 0,
                    "phoneMasked": "",
                    "error": "",
                    "updatedAtEpoch": time.time(),
                },
            )
            write_json_atomic(
                control_dir / "phone.json",
                {"attemptId": 1, "phoneNumber": normalized_phone, "createdAtEpoch": time.time()},
            )
            queued_at = utc_now()
            updated = update_job(
                job_id,
                phoneStatus="phone_queued",
                phoneMasked="",
                phoneProvider="manual",
                phoneError="",
                phoneQueuedAt=queued_at,
                phoneStartedAt="",
                phoneFinishedAt="",
                phoneBoundAt="",
            )
            if updated is None:
                raise RuntimeError("任务在手动绑号启动前已被删除")
            job_updated = True
            settings = load_settings()
            worker = threading.Thread(
                target=_manual_phone_worker,
                args=(job_id, settings, control_dir, session_id),
                daemon=True,
            )
            with RUNTIME_LOCK:
                if not _manual_phone_runtime_owned_locked(job_id, session_id):
                    raise RuntimeError("手动绑号运行态已失效")
                RUNTIME["worker"] = worker
            worker.start()
        except Exception as error:
            with RUNTIME_LOCK:
                _release_manual_phone_runtime_locked(
                    job_id,
                    session_id,
                    completed=False,
                    succeeded=False,
                )
            if job_updated:
                try:
                    update_job(job_id, **previous_phone_fields)
                except Exception:
                    pass
            try:
                update_manual_phone_status(
                    job_id,
                    sessionId=session_id,
                    jobId=job_id,
                    phase="failed",
                    active=False,
                    error=redact_text(str(error), job=job)[:1000],
                )
            except Exception:
                pass
            _cleanup_manual_phone_transients(control_dir)
            raise
        append_audit("manual_phone_binding_started", job_id=job_id, email=str(job.get("email") or ""))
        append_log("info", "已启动手动手机号绑定，会保持登录会话等待验证码", job=job, stage="phone_binding")
        return 202, {**manual_phone_status(job_id), "queuedAttemptId": 1}


def submit_manual_phone_code(job_id: str, code_value: Any) -> tuple[int, dict[str, Any]]:
    code = "".join(ch for ch in str(code_value or "") if ch.isdigit())
    if not 4 <= len(code) <= 8:
        return 400, {"ok": False, "error": "验证码格式无效"}
    job = get_job(job_id)
    if not job:
        return 404, {"ok": False, "error": "任务不存在"}
    with MANUAL_PHONE_LOCK:
        with RUNTIME_LOCK:
            session_id = str(RUNTIME.get("manualPhoneSessionId") or "")
            active = _manual_phone_runtime_owned_locked(job_id, session_id)
        if not active:
            return 409, {"ok": False, "error": "当前账号没有保持中的手动绑号会话，请先发送验证码"}
        status_payload = read_json(manual_phone_control_dir(job_id) / "status.json", {})
        if not (
            isinstance(status_payload, dict)
            and bool(status_payload.get("active"))
            and str(status_payload.get("sessionId") or "") == session_id
        ):
            return 409, {"ok": False, "error": "手动绑号会话正在结束，请稍后重新开始"}
        status = manual_phone_status(job_id)
        attempt_id = int(status.get("attemptId") or 0)
        if attempt_id <= 0 or str(status.get("phase") or "") != "waiting_code":
            return 409, {"ok": False, "error": "当前尚未进入验证码输入阶段"}
        control_dir = manual_phone_control_dir(job_id)
        submission_path = control_dir / "code-submission.json"
        previous_submission = read_json(submission_path, {})
        if (
            isinstance(previous_submission, dict)
            and int(previous_submission.get("attemptId") or 0) == attempt_id
        ):
            return 409, {"ok": False, "error": "当前手机号的验证码已提交，请等待验证结果"}
        write_json_atomic(
            submission_path,
            {"attemptId": attempt_id, "createdAtEpoch": time.time()},
        )
        try:
            write_json_atomic(
                control_dir / "code.json",
                {"attemptId": attempt_id, "code": code, "createdAtEpoch": time.time()},
            )
        except Exception:
            try:
                submission_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise
        append_log("info", "已提交手动手机验证码，正在验证", job=job, stage="phone_binding")
        return 202, manual_phone_status(job_id)


def run_mfa_one(job_id: str, settings: dict[str, Any]) -> bool:
    job = get_job(job_id)
    if not job:
        return False
    with account_lock(str(job.get("email") or "")):
        latest = get_job(job_id) or job
        if str(latest.get("registrationStatus") or "") != "registered":
            return False
        if str(latest.get("mfaStatus") or "") == "enabled":
            return True
        if STOP_EVENT.is_set():
            update_job(
                job_id,
                status="registered",
                mfaStatus="pending",
                stage="registered",
                error="",
                finishedTs=time.time(),
            )
            return False
        job_settings = settings_for_job(settings, job_id)
        proxy_label = mask_proxy_url(str(job_settings.get("proxy") or ""))
        update_job(job_id, proxyLabel=proxy_label, startedTs=time.time(), finishedTs=0)
        append_log("info", f"2FA 网络出口: {proxy_label}", job=latest, stage="network")
        success, error = run_mfa(get_job(job_id) or latest, job_settings)
        if success:
            append_log("success", "TOTP 2FA 已开启", job=get_job(job_id) or latest, stage="ready")
            return True
        current = get_job(job_id) or latest
        if STOP_EVENT.is_set():
            update_job(
                job_id,
                status="registered",
                mfaStatus="pending",
                stage="registered",
                error="",
                finishedTs=time.time(),
            )
            append_log("warn", "2FA 开启任务已停止，可稍后重试", job=current, stage="mfa")
            return False
        if str(current.get("status") or "") != "mfa_secret_missing":
            update_job(
                job_id,
                status="mfa_failed",
                registrationStatus="registered",
                mfaStatus="failed",
                stage="mfa_failed",
                error=redact_text(error, job=current),
                finishedTs=time.time(),
            )
        append_log("error", error, job=current, stage="mfa")
        return False


def _record_mfa_progress(success: bool) -> None:
    with RUNTIME_LOCK:
        RUNTIME["completed"] = int(RUNTIME.get("completed") or 0) + 1
        RUNTIME["completedCount"] = int(RUNTIME.get("completedCount") or 0) + 1
        key = "success" if success else "failed"
        count_key = "successCount" if success else "failedCount"
        RUNTIME[key] = int(RUNTIME.get(key) or 0) + 1
        RUNTIME[count_key] = int(RUNTIME.get(count_key) or 0) + 1


def mfa_batch_worker(job_ids: list[str], settings: dict[str, Any]) -> None:
    work: queue.Queue[str] = queue.Queue()
    for job_id in job_ids:
        work.put(job_id)
    try:
        with RUNTIME_LOCK:
            RUNTIME["operation"] = "mfa_enrollment"
            RUNTIME["activeJobIds"] = list(job_ids)
        worker_count = min(max(1, int(settings.get("concurrency") or 1)), len(job_ids)) if job_ids else 0
        append_log("info", f"启动 {len(job_ids)} 个 2FA 开启任务，并发 {worker_count}")

        def consume() -> None:
            while True:
                try:
                    job_id = work.get_nowait()
                except queue.Empty:
                    return
                succeeded = False
                try:
                    if STOP_EVENT.is_set():
                        update_job(
                            job_id,
                            status="registered",
                            mfaStatus="pending",
                            stage="registered",
                            error="",
                            finishedTs=time.time(),
                        )
                    else:
                        succeeded = run_mfa_one(job_id, settings)
                except Exception as error:
                    current = get_job(job_id) or {"id": job_id}
                    if STOP_EVENT.is_set():
                        update_job(
                            job_id,
                            status="registered",
                            mfaStatus="pending",
                            stage="registered",
                            error="",
                            finishedTs=time.time(),
                        )
                    else:
                        message = redact_text(str(error), job=current)
                        update_job(
                            job_id,
                            status="mfa_failed",
                            registrationStatus="registered",
                            mfaStatus="failed",
                            stage="mfa_failed",
                            error=message,
                            finishedTs=time.time(),
                        )
                        append_log("error", f"2FA 开启异常: {message}", job=current, stage="mfa")
                finally:
                    _record_mfa_progress(succeeded)
                    work.task_done()

        threads = [threading.Thread(target=consume, daemon=True) for _ in range(worker_count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    finally:
        with RUNTIME_LOCK:
            RUNTIME["running"] = False
            RUNTIME["finishedAt"] = utc_now()
            RUNTIME["worker"] = None
            RUNTIME["operation"] = "idle"
            RUNTIME["activeJobIds"] = []
        append_log("warn" if STOP_EVENT.is_set() else "success", "2FA 批次已停止" if STOP_EVENT.is_set() else "2FA 批次已完成")


def start_mfa(ids: list[str]) -> tuple[int, dict[str, Any]]:
    requested_ids = [str(value).strip() for value in ids if str(value).strip()]
    if not requested_ids:
        return 400, {"ok": False, "error": "ids must be a non-empty array"}
    with RUNTIME_LOCK:
        if RUNTIME["running"]:
            return 409, {"ok": False, "error": "已有批次正在运行"}
        RUNTIME["running"] = True
        RUNTIME["startedAt"] = utc_now()
        RUNTIME["finishedAt"] = ""
        RUNTIME["operation"] = "mfa_enrollment"
        STOP_EVENT.clear()

    candidate_ids: list[str] = []
    skipped_items: list[dict[str, str]] = []
    try:
        with JOBS_LOCK:
            jobs = load_jobs()
            by_id = {str(job.get("id") or ""): job for job in jobs}
            seen: set[str] = set()
            for job_id in requested_ids:
                if job_id in seen:
                    skipped_items.append({"id": job_id, "reason": "duplicate"})
                    continue
                seen.add(job_id)
                job = by_id.get(job_id)
                if not job:
                    skipped_items.append({"id": job_id, "reason": "not_found"})
                    continue
                if str(job.get("registrationStatus") or "") != "registered":
                    skipped_items.append({"id": job_id, "reason": "not_registered"})
                    continue
                if str(job.get("mfaStatus") or "") == "enabled":
                    skipped_items.append({"id": job_id, "reason": "already_enabled"})
                    continue
                candidate_ids.append(job_id)
                job["status"] = "registered"
                job["mfaStatus"] = "pending"
                job["stage"] = "mfa_queued"
                job["error"] = ""
                job["updatedAt"] = utc_now()
            if candidate_ids:
                save_jobs(jobs)
        with RUNTIME_LOCK:
            RUNTIME["total"] = len(candidate_ids)
            RUNTIME["completed"] = 0
            RUNTIME["success"] = 0
            RUNTIME["failed"] = 0
            RUNTIME["totalCount"] = len(candidate_ids)
            RUNTIME["completedCount"] = 0
            RUNTIME["successCount"] = 0
            RUNTIME["failedCount"] = 0
            RUNTIME["activeJobIds"] = list(candidate_ids)
        payload = {
            "ok": True,
            "count": len(candidate_ids),
            "skipped": len(skipped_items),
            "skippedItems": skipped_items,
        }
        if not candidate_ids:
            with RUNTIME_LOCK:
                RUNTIME["running"] = False
                RUNTIME["finishedAt"] = utc_now()
                RUNTIME["operation"] = "idle"
                RUNTIME["activeJobIds"] = []
            return 200, payload
        worker = threading.Thread(
            target=mfa_batch_worker,
            args=(candidate_ids, load_settings()),
            daemon=True,
        )
        with RUNTIME_LOCK:
            RUNTIME["worker"] = worker
        worker.start()
        append_audit("mfa_batch_started", detail=f"count={len(candidate_ids)}")
        return 202, payload
    except Exception:
        with RUNTIME_LOCK:
            RUNTIME["running"] = False
            RUNTIME["finishedAt"] = utc_now()
            RUNTIME["worker"] = None
            RUNTIME["operation"] = "idle"
            RUNTIME["activeJobIds"] = []
        raise


def batch_worker(job_ids: list[str], settings: dict[str, Any]) -> None:
    try:
        with RUNTIME_LOCK:
            RUNTIME["running"] = True
            RUNTIME["startedAt"] = utc_now()
            RUNTIME["finishedAt"] = ""
            RUNTIME["operation"] = "registration"
            RUNTIME["activeJobIds"] = list(job_ids)
        work: queue.Queue[str] = queue.Queue()
        for job_id in job_ids:
            work.put(job_id)
        worker_count = min(max(1, int(settings.get("concurrency") or 1)), len(job_ids)) if job_ids else 0
        append_log("info", f"启动 {len(job_ids)} 个任务，并发 {worker_count}")

        def consume() -> None:
            while not STOP_EVENT.is_set():
                try:
                    job_id = work.get_nowait()
                except queue.Empty:
                    return
                try:
                    run_one(job_id, settings)
                except Exception as error:
                    current = get_job(job_id) or {"id": job_id}
                    registration_done = str(current.get("registrationStatus") or "") == "registered"
                    update_job(
                        job_id,
                        status="mfa_failed" if registration_done else "registration_failed",
                        mfaStatus="failed" if registration_done else str(current.get("mfaStatus") or "pending"),
                        registrationStatus="registered" if registration_done else "failed",
                        stage="worker_exception",
                        error=redact_text(str(error), job=current),
                        finishedTs=time.time(),
                    )
                    append_log("error", f"任务异常: {error}", job=current, stage="worker")
                finally:
                    work.task_done()

        threads = [threading.Thread(target=consume, daemon=True) for _ in range(worker_count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    finally:
        with RUNTIME_LOCK:
            RUNTIME["running"] = False
            RUNTIME["finishedAt"] = utc_now()
            RUNTIME["worker"] = None
            RUNTIME["operation"] = "idle"
            RUNTIME["activeJobIds"] = []
        append_log("warn" if STOP_EVENT.is_set() else "success", "批次已停止" if STOP_EVENT.is_set() else "批次已完成")


def start_jobs(ids: list[str] | None = None) -> tuple[int, dict[str, Any]]:
    with RUNTIME_LOCK:
        if RUNTIME["running"]:
            return 409, {"ok": False, "error": "已有批次正在运行"}
        RUNTIME["running"] = True
        RUNTIME["startedAt"] = utc_now()
        RUNTIME["finishedAt"] = ""
        STOP_EVENT.clear()
    with JOBS_LOCK:
        jobs = load_jobs()
        selected = set(str(value) for value in (ids or []) if value)
        candidates = [
            job
            for job in jobs
            if str(job.get("status") or "") in RUNNABLE_STATUSES
            and str(job.get("registrationStatus") or "") != "registered"
            and str(job.get("registrationStatus") or "") != "phone_required"
            and (not selected or str(job.get("id")) in selected)
        ]
        for job in candidates:
            job["status"] = "queued"
            legacy_session_pending = "session 响应缺少 accessToken" in str(job.get("error") or "")
            if str(job.get("registrationStatus") or "") == "session_pending" or legacy_session_pending:
                job["registrationStatus"] = "session_pending"
            else:
                job["registrationStatus"] = "pending"
            job["mfaStatus"] = "pending"
            job["stage"] = "session_retry_queued" if str(job.get("registrationStatus") or "") == "session_pending" else "queued"
            job["error"] = ""
            job["updatedAt"] = utc_now()
        if candidates:
            save_jobs(jobs)
    if not candidates:
        with RUNTIME_LOCK:
            RUNTIME["running"] = False
            RUNTIME["finishedAt"] = utc_now()
        return 200, {"ok": True, "count": 0}
    thread = threading.Thread(
        target=batch_worker,
        args=([str(job.get("id")) for job in candidates], load_settings()),
        daemon=True,
    )
    with RUNTIME_LOCK:
        RUNTIME["worker"] = thread
    thread.start()
    return 200, {"ok": True, "count": len(candidates)}


def at_refresh_batch_worker(job_ids: list[str], settings: dict[str, Any]) -> None:
    try:
        with RUNTIME_LOCK:
            RUNTIME["operation"] = "at_refresh"
            RUNTIME["activeJobIds"] = list(job_ids)
        append_log("info", f"启动 {len(job_ids)} 个 AT 刷新任务")
        for job_id in job_ids:
            if STOP_EVENT.is_set():
                break
            try:
                run_at_refresh_one(job_id, settings)
            except Exception as error:
                current = get_job(job_id) or {"id": job_id}
                update_job(
                    job_id,
                    atStatus="refresh_failed",
                    atError=redact_text(str(error), job=current),
                    stage="at_refresh_failed",
                )
                append_log("error", f"AT 刷新异常: {error}", job=current, stage="at_refresh")
    finally:
        with RUNTIME_LOCK:
            RUNTIME["running"] = False
            RUNTIME["finishedAt"] = utc_now()
            RUNTIME["worker"] = None
            RUNTIME["operation"] = "idle"
            RUNTIME["activeJobIds"] = []
        append_log("warn" if STOP_EVENT.is_set() else "success", "AT 刷新已停止" if STOP_EVENT.is_set() else "AT 刷新批次已完成")


def start_at_refresh(ids: list[str] | None = None) -> tuple[int, dict[str, Any]]:
    with RUNTIME_LOCK:
        if RUNTIME["running"]:
            return 409, {"ok": False, "error": "已有批次正在运行"}
        RUNTIME["running"] = True
        RUNTIME["startedAt"] = utc_now()
        RUNTIME["finishedAt"] = ""
        RUNTIME["operation"] = "at_refresh"
        STOP_EVENT.clear()
    with JOBS_LOCK:
        jobs = load_jobs()
        selected = {str(value) for value in (ids or []) if value}
        candidates = [
            job
            for job in jobs
            if str(job.get("registrationStatus") or "") == "registered"
            and (not selected or str(job.get("id") or "") in selected)
        ]
    if not candidates:
        with RUNTIME_LOCK:
            RUNTIME["running"] = False
            RUNTIME["finishedAt"] = utc_now()
            RUNTIME["operation"] = "idle"
        return 200, {"ok": True, "count": 0}
    thread = threading.Thread(
        target=at_refresh_batch_worker,
        args=([str(job.get("id") or "") for job in candidates], load_settings()),
        daemon=True,
    )
    with RUNTIME_LOCK:
        RUNTIME["worker"] = thread
    thread.start()
    return 202, {"ok": True, "count": len(candidates)}


def stop_jobs() -> None:
    STOP_EVENT.set()
    with RUNTIME_LOCK:
        processes = list(RUNTIME["active"].values())
    for process in processes:
        try:
            process.terminate()
        except Exception:
            pass
    append_log("warn", "已请求停止全部任务")


def delete_jobs(ids: list[str]) -> dict[str, Any]:
    selected = {str(value).strip() for value in ids if str(value).strip()}
    if not selected:
        raise ValueError("请选择要删除的任务")
    with RUNTIME_LOCK:
        if RUNTIME["running"]:
            raise RuntimeError("运行中不能删除任务")
    with JOBS_LOCK:
        jobs = load_jobs()
        removed_jobs = [job for job in jobs if str(job.get("id") or "") in selected]
        kept = [job for job in jobs if str(job.get("id") or "") not in selected]
        if removed_jobs:
            save_jobs(kept)
            secret_store = load_secret_store()
            save_secret_store({job_id: values for job_id, values in secret_store.items() if job_id not in selected})
    for job in removed_jobs:
        append_audit("job_deleted", job_id=str(job.get("id") or ""), email=str(job.get("email") or ""))
    append_log("info", f"已删除 {len(removed_jobs)} 个任务记录")
    return {"ok": True, "removed": len(removed_jobs), "requested": len(selected)}


def recover_interrupted_jobs() -> None:
    with JOBS_LOCK:
        jobs = load_jobs()
        changed = False
        for job in jobs:
            if str(job.get("phoneStatus") or "") in {"phone_queued", "phone_binding"}:
                job["phoneStatus"] = "phone_stopped"
                job["phoneError"] = "service restarted while phone binding was active"
                job["phoneFinishedAt"] = utc_now()
                job["updatedAt"] = utc_now()
                changed = True
            if str(job.get("status") or "") == "session_recovering":
                job["status"] = "session_pending"
                job["registrationStatus"] = "session_pending"
                job["stage"] = "session_pending"
                job["error"] = "服务重启，登录 Session 可安全重试"
                job["finishedTs"] = time.time()
                job["updatedAt"] = utc_now()
                changed = True
            elif str(job.get("status") or "") in {"registering", "mfa_enrolling"}:
                job["status"] = "interrupted"
                job["stage"] = "interrupted"
                job["error"] = "服务重启，任务可安全重试"
                job["finishedTs"] = time.time()
                job["updatedAt"] = utc_now()
                changed = True
        if changed:
            save_jobs(jobs)


def state_payload() -> dict[str, Any]:
    with JOBS_LOCK:
        jobs = [public_job(job) for job in load_jobs()]
    active_jobs = [job for job in jobs if not bool(job.get("archived"))]
    archived_jobs = [job for job in jobs if bool(job.get("archived"))]
    counts = {
        "total": len(jobs),
        "active": len(active_jobs),
        "archived": len(archived_jobs),
        "queued": sum(1 for job in active_jobs if job.get("status") == "queued"),
        "running": sum(
            1
            for job in active_jobs
            if job.get("status") in {"registering", "session_recovering", "mfa_enrolling"} or job.get("atStatus") == "refreshing"
            or job.get("phoneStatus") in {"phone_queued", "phone_binding"}
        ),
        "ready": sum(1 for job in active_jobs if job.get("status") == "ready"),
        "failed": sum(1 for job in active_jobs if str(job.get("status") or "").endswith("failed") or job.get("status") == "mfa_secret_missing"),
    }
    phone_counts = {
        "unknown": sum(1 for job in active_jobs if job.get("phoneStatus") == "phone_unknown"),
        "queued": sum(1 for job in active_jobs if job.get("phoneStatus") == "phone_queued"),
        "binding": sum(1 for job in active_jobs if job.get("phoneStatus") == "phone_binding"),
        "bound": sum(1 for job in active_jobs if job.get("phoneStatus") == "phone_bound"),
        "failed": sum(1 for job in active_jobs if job.get("phoneStatus") == "phone_failed"),
        "stopped": sum(1 for job in active_jobs if job.get("phoneStatus") == "phone_stopped"),
    }
    group_counts: dict[str, int] = {}
    plan_counts: dict[str, int] = {}
    for job in jobs:
        group_name = str(job.get("group") or "").strip() or "未分组"
        group_counts[group_name] = int(group_counts.get(group_name) or 0) + 1
        plan_name = str(job.get("planType") or "").strip().lower() or "unknown"
        plan_counts[plan_name] = int(plan_counts.get(plan_name) or 0) + 1
    groups = [
        {"name": name, "count": count}
        for name, count in sorted(group_counts.items(), key=lambda item: (item[0] == "未分组", item[0].lower()))
    ]
    plans = [
        {"name": name, "count": count}
        for name, count in sorted(plan_counts.items(), key=lambda item: (-item[1], item[0]))
    ]
    with RUNTIME_LOCK:
        runtime = {
            "running": bool(RUNTIME["running"]),
            "startedAt": RUNTIME["startedAt"],
            "finishedAt": RUNTIME["finishedAt"],
            "activeCount": len(RUNTIME["active"]),
            "operation": str(RUNTIME.get("operation") or "idle"),
            "activeJobIds": list(RUNTIME.get("activeJobIds") or []),
            "total": int(RUNTIME.get("total") or 0),
            "completed": int(RUNTIME.get("completed") or 0),
            "success": int(RUNTIME.get("success") or 0),
            "failed": int(RUNTIME.get("failed") or 0),
            "totalCount": int(RUNTIME.get("totalCount") or RUNTIME.get("total") or 0),
            "completedCount": int(RUNTIME.get("completedCount") or RUNTIME.get("completed") or 0),
            "successCount": int(RUNTIME.get("successCount") or RUNTIME.get("success") or 0),
            "failedCount": int(RUNTIME.get("failedCount") or RUNTIME.get("failed") or 0),
            "logs": list(RUNTIME["logs"]),
        }
    return {
        "ok": True,
        "jobs": jobs,
        "counts": counts,
        "phoneCounts": phone_counts,
        "groups": groups,
        "plans": plans,
        "settings": public_settings(),
        "runtime": runtime,
    }


def credential_payload(job: dict[str, Any]) -> dict[str, Any]:
    _, state = _storage_state(job)
    summary = state.get("mfa_summary") if isinstance(state, dict) and isinstance(state.get("mfa_summary"), dict) else {}
    secret = normalize_totp_secret(str(summary.get("secret") or ""))
    code = generate_totp_code(secret) if secret else ""
    remaining = 30 - (int(time.time()) % 30) if secret else 0
    valid_until = ((int(time.time()) // 30) + 1) * 30 if secret else 0
    label = urllib.parse.quote(str(job.get("email") or ""), safe="")
    issuer = urllib.parse.quote("ChatGPT", safe="")
    uri = f"otpauth://totp/ChatGPT:{label}?secret={secret}&issuer={issuer}&digits=6&period=30" if secret else ""
    access_token = access_token_from_state(state if isinstance(state, dict) else {})
    at_metadata = decode_access_token_metadata(access_token)
    return {
        "email": str(job.get("email") or ""),
        "accountPassword": str(job.get("accountPassword") or ""),
        "remotePasswordSet": bool(job.get("remotePasswordSet")),
        "remotePasswordMode": str(job.get("remotePasswordMode") or ""),
        "remotePasswordStatus": str(job.get("remotePasswordStatus") or "unknown"),
        "mfaStatus": str(job.get("mfaStatus") or ""),
        "totpSecret": secret,
        "totpCode": code,
        "secondsRemaining": remaining,
        "validUntilEpoch": valid_until,
        "otpauthUri": uri,
        "factorId": str(summary.get("factorId") or job.get("factorId") or ""),
        "updatedAt": str(summary.get("updatedAt") or ""),
        "accessToken": access_token,
        "atStatus": "expired" if at_metadata["expired"] else ("available" if access_token else "missing"),
        "atExpiresAt": str(at_metadata.get("expiresAt") or job.get("atExpiresAt") or ""),
        "atUpdatedAt": str(
            (state.get("session_access_token_updated_at") if isinstance(state, dict) else "")
            or job.get("atUpdatedAt")
            or ""
        ),
        "atSource": str(job.get("atSource") or ""),
        "atError": str(job.get("atError") or ""),
        "phoneStatus": str(job.get("phoneStatus") or "phone_unknown"),
        "phoneMasked": str(job.get("phoneMasked") or ""),
        "phoneProvider": str(job.get("phoneProvider") or ""),
        "phoneError": redact_text(str(job.get("phoneError") or ""), job=job),
        "phoneQueuedAt": str(job.get("phoneQueuedAt") or ""),
        "phoneStartedAt": str(job.get("phoneStartedAt") or ""),
        "phoneFinishedAt": str(job.get("phoneFinishedAt") or ""),
        "phoneBoundAt": str(job.get("phoneBoundAt") or ""),
        "rtStatus": str(job.get("rtStatus") or ("available" if success_credential_has_rt(read_success_credential(job)) else "missing")),
        "rtPresent": bool(job.get("rtPresent") or success_credential_has_rt(read_success_credential(job))),
        "rtError": redact_text(str(job.get("rtError") or ""), job=job),
        "rtUpdatedAt": str(job.get("rtUpdatedAt") or ""),
    }


def export_lines() -> list[str]:
    with JOBS_LOCK:
        jobs = load_jobs()
    lines: list[str] = []
    for raw_job in jobs:
        if str(raw_job.get("status") or "") != "ready":
            continue
        job = hydrate_job(raw_job)
        credentials = credential_payload(job)
        provider = job.get("provider") if isinstance(job.get("provider"), dict) else {}
        values = (
            str(job.get("email") or ""),
            str(job.get("accountPassword") or ""),
            str(provider.get("apiUrl") or ""),
            str(credentials.get("totpSecret") or ""),
            str(credentials.get("accessToken") or ""),
        )
        lines.append("----".join(value.replace("\r", "").replace("\n", "") for value in values))
    return lines


def _jobs_for_export(ids: list[str] | None = None, *, phone_bound_only: bool = False) -> list[dict[str, Any]]:
    requested = [str(value).strip() for value in (ids or []) if str(value).strip()]
    with JOBS_LOCK:
        jobs = load_jobs()
    if requested:
        by_id = {str(job.get("id") or ""): job for job in jobs}
        selected = [by_id[job_id] for job_id in requested if job_id in by_id]
    else:
        selected = list(jobs)
    output: list[dict[str, Any]] = []
    for raw_job in selected:
        job = hydrate_job(raw_job)
        if phone_bound_only and str(job.get("phoneStatus") or "") != "phone_bound":
            continue
        output.append(job)
    return output


def export_rt_payloads(
    *,
    ids: list[str] | None = None,
    format_name: str = "sub2api",
    phone_bound_only: bool = True,
) -> dict[str, Any]:
    format_key = str(format_name or "sub2api").strip().lower() or "sub2api"
    if format_key not in {"sub2api", "rtjson", "cpa", "rt"}:
        raise ValueError("format must be one of: sub2api, rtjson, cpa, rt")
    jobs = _jobs_for_export(ids, phone_bound_only=phone_bound_only)
    items: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    for job in jobs:
        email = str(job.get("email") or "").strip().lower()
        payload = read_success_credential(job)
        if not success_credential_has_rt(payload):
            skipped.append({"id": str(job.get("id") or ""), "email": email, "reason": "rt_missing"})
            continue
        try:
            if format_key == "rt":
                token_exchange = payload.get("token_exchange") if isinstance(payload.get("token_exchange"), dict) else {}
                refresh_token = str(payload.get("refresh_token") or token_exchange.get("refresh_token") or "").strip()
                item = {"email": email, "refresh_token": refresh_token}
            elif format_key in {"rtjson", "cpa"}:
                item = build_cpa_rtjson(payload, email=email)
            else:
                item = build_sub2api_payload(payload, email=email)
            items.append(item)
        except Exception as error:
            skipped.append({"id": str(job.get("id") or ""), "email": email, "reason": str(error)[:200]})
    return {
        "ok": True,
        "format": format_key,
        "count": len(items),
        "skipped": len(skipped),
        "skippedItems": skipped,
        "items": items,
    }


def export_rt_text(
    *,
    ids: list[str] | None = None,
    format_name: str = "sub2api",
    phone_bound_only: bool = True,
) -> tuple[str, str, str]:
    result = export_rt_payloads(ids=ids, format_name=format_name, phone_bound_only=phone_bound_only)
    format_key = str(result.get("format") or "sub2api")
    items = result.get("items") if isinstance(result.get("items"), list) else []
    stamp = time.strftime("%Y%m%d-%H%M%S")
    if format_key == "rt":
        body = "\n".join(str(item.get("refresh_token") or "") for item in items if item.get("refresh_token"))
        if body:
            body += "\n"
        return body, "text/plain; charset=utf-8", f"rt-export-{stamp}.txt"
    if format_key in {"rtjson", "cpa"}:
        # one compact JSON object per line for bulk import tools
        body = "\n".join(json.dumps(item, ensure_ascii=False, separators=(",", ":")) for item in items)
        if body:
            body += "\n"
        return body, "application/x-ndjson; charset=utf-8", f"rtjson-export-{stamp}.ndjson"
    body = json.dumps(items, ensure_ascii=False, indent=2)
    if body and not body.endswith("\n"):
        body += "\n"
    return body, "application/json; charset=utf-8", f"sub2api-export-{stamp}.json"


class Handler(SimpleHTTPRequestHandler):
    server_version = "Registration2FA/1.0"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(PUBLIC_DIR), **kwargs)

    def log_message(self, _format, *_args):
        return

    def _security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'")

    def require_auth(self) -> bool:
        if basic_auth_valid(self.headers.get("Authorization") or ""):
            return True
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Registration + 2FA", charset="UTF-8"')
        self._security_headers()
        self.end_headers()
        return False

    def send_json(self, status: int, payload: Any, *, no_store: bool = True) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if no_store:
            self.send_header("Cache-Control", "no-store")
        self._security_headers()
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def read_body(self) -> dict[str, Any]:
        size = int(self.headers.get("Content-Length") or 0)
        if size > 5 * 1024 * 1024:
            raise ValueError("请求体过大")
        raw = self.rfile.read(size) if size else b"{}"
        payload = json.loads(raw.decode("utf-8") or "{}")
        if not isinstance(payload, dict):
            raise ValueError("请求体必须是 JSON 对象")
        return payload

    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        if url.path == "/api/health":
            self.send_json(200, {"ok": True, "service": "registration-2fa"})
            return
        if not self.require_auth():
            return
        if url.path == "/api/state":
            self.send_json(200, state_payload())
            return
        if url.path == "/api/settings/sms/countries":
            query = urllib.parse.parse_qs(url.query or "")
            provider = str((query.get("provider") or [""])[0] or "").strip()
            try:
                self.send_json(200, list_sms_countries(provider))
            except Exception as error:
                self.send_json(400, {"ok": False, "error": str(error)})
            return
        if url.path == "/api/network/local":
            result = detect_local_network()
            append_audit("local_network_detected", detail=f"public_ip_ok={result.get('publicIpOk')}")
            self.send_json(200, result)
            return
        match = re.fullmatch(r"/api/jobs/([^/]+)/phone/manual", url.path)
        if match:
            job_id = urllib.parse.unquote(match.group(1))
            if not get_job(job_id):
                self.send_json(404, {"ok": False, "error": "任务不存在"})
                return
            self.send_json(200, manual_phone_status(job_id))
            return
        match = re.fullmatch(r"/api/jobs/([^/]+)/otp", url.path)
        if match:
            job = get_job(urllib.parse.unquote(match.group(1)))
            if not job:
                self.send_json(404, {"ok": False, "error": "任务不存在"})
                return
            try:
                result = fetch_email_verification_code(job)
            except LookupError as error:
                self.send_json(404, {"ok": False, "error": str(error)})
                return
            except Exception as error:
                message = redact_text(str(error), job=job)
                append_log("error", f"邮箱取码失败: {message}", job=job, stage="mail_otp")
                self.send_json(502, {"ok": False, "error": message[:1000]})
                return
            append_audit("email_otp_revealed", job_id=str(job.get("id") or ""), email=str(job.get("email") or ""))
            append_log("success", "已读取最新邮箱验证码", job=job, stage="mail_otp")
            self.send_json(200, result)
            return
        match = re.fullmatch(r"/api/jobs/([^/]+)/credentials", url.path)
        if match:
            job = get_job(urllib.parse.unquote(match.group(1)))
            if not job:
                self.send_json(404, {"ok": False, "error": "任务不存在"})
                return
            append_audit("credentials_revealed", job_id=str(job.get("id") or ""), email=str(job.get("email") or ""))
            self.send_json(200, {"ok": True, "credentials": credential_payload(job)})
            return
        if url.path == "/api/export":
            lines = export_lines()
            body = (("\n".join(lines) + "\n") if lines else "").encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Disposition", f'attachment; filename="registration-2fa-{time.strftime("%Y%m%d-%H%M%S")}.txt"')
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self._security_headers()
            self.end_headers()
            self.wfile.write(body)
            append_audit("credentials_exported", detail=f"count={len(lines)} format=delimited-text")
            return
        if url.path == "/api/export/rt":
            query = urllib.parse.parse_qs(url.query or "")
            format_name = str((query.get("format") or ["sub2api"])[0] or "sub2api").strip().lower()
            ids_raw = str((query.get("ids") or [""])[0] or "").strip()
            ids = [part.strip() for part in ids_raw.split(",") if part.strip()] if ids_raw else []
            phone_bound_only = str((query.get("phoneBoundOnly") or ["1"])[0] or "1").strip().lower() not in {"0", "false", "no"}
            try:
                body_text, content_type, filename = export_rt_text(
                    ids=ids or None,
                    format_name=format_name,
                    phone_bound_only=phone_bound_only,
                )
            except Exception as error:
                self.send_json(400, {"ok": False, "error": str(error)})
                return
            body = body_text.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self._security_headers()
            self.end_headers()
            self.wfile.write(body)
            append_audit(
                "rt_exported",
                detail=f"count_bytes={len(body)} format={format_name} ids={len(ids)} phone_bound_only={phone_bound_only}",
            )
            return
        if url.path == "/":
            self.path = "/index.html"
        super().do_GET()

    def do_POST(self):
        if not self.require_auth():
            return
        try:
            request_path = urllib.parse.urlsplit(self.path).path
            match = re.fullmatch(r"/api/jobs/([^/]+)/phone/manual/(send|verify)", request_path)
            if match:
                job_id = urllib.parse.unquote(match.group(1))
                action = str(match.group(2) or "")
                body = self.read_body()
                if action == "send":
                    status, payload = send_manual_phone(
                        job_id,
                        body.get("phoneNumber") if "phoneNumber" in body else body.get("phone"),
                    )
                else:
                    status, payload = submit_manual_phone_code(job_id, body.get("code"))
                self.send_json(status, payload)
                return
            match = re.fullmatch(r"/api/jobs/([^/]+)/session", request_path)
            if match:
                job = get_job(urllib.parse.unquote(match.group(1)))
                if not job:
                    self.send_json(404, {"ok": False, "error": "任务不存在"})
                    return
                try:
                    job_settings = settings_for_job(load_settings(), str(job.get("id") or ""))
                    result = fetch_full_session(job, job_settings)
                except Exception as error:
                    message = redact_text(str(error), job=job)
                    append_log("error", f"获取完整 Session 失败: {message}", job=job, stage="full_session")
                    self.send_json(502, {"ok": False, "error": message[:1000]})
                    return
                append_audit(
                    "full_session_revealed",
                    job_id=str(job.get("id") or ""),
                    email=str(job.get("email") or ""),
                    detail="source=auth_session",
                )
                append_log("success", "已实时获取完整 Session", job=job, stage="full_session")
                self.send_json(200, result)
                return
            if request_path == "/api/mfa/enable":
                body = self.read_body()
                if "ids" not in body or not isinstance(body.get("ids"), list):
                    self.send_json(400, {"ok": False, "error": "ids must be explicitly provided as an array"})
                    return
                ids = body.get("ids") or []
                if not ids or not any(str(value or "").strip() for value in ids):
                    self.send_json(400, {"ok": False, "error": "ids must be a non-empty array"})
                    return
                status, payload = start_mfa([str(value) for value in ids])
                self.send_json(status, payload)
                return
            if request_path == "/api/phone/bind":
                body = self.read_body()
                if "ids" not in body or not isinstance(body.get("ids"), list):
                    self.send_json(400, {"ok": False, "error": "ids must be explicitly provided as an array"})
                    return
                ids = body.get("ids") or []
                if not ids or not any(str(value or "").strip() for value in ids):
                    self.send_json(400, {"ok": False, "error": "ids must be a non-empty array"})
                    return
                status, payload = start_phone_binding([str(value) for value in ids])
                self.send_json(status, payload)
                return
            if self.path == "/api/jobs/import":
                self.send_json(200, import_jobs(self.read_body()))
                return
            if self.path == "/api/settings":
                settings = save_settings(self.read_body())
                append_audit("settings_updated")
                self.send_json(200, {"ok": True, "settings": public_settings(settings)})
                return
            if self.path == "/api/settings/sms/test":
                try:
                    result = test_sms_balance()
                except Exception as error:
                    self.send_json(400, {"ok": False, "error": str(error)})
                    return
                append_audit("sms_balance_tested", detail=f"provider={result.get('provider')}")
                self.send_json(200, result)
                return
            if self.path == "/api/proxies/test":
                body = self.read_body()
                if "proxyPool" in body:
                    proxies = normalize_proxy_pool(body.get("proxyPool"))
                else:
                    settings = load_settings()
                    proxies = list(settings.get("proxyPool") or [])
                    if not proxies and str(settings.get("proxy") or "").strip():
                        proxies = [normalize_proxy_url(settings.get("proxy"))]
                if len(proxies) > 100:
                    raise ValueError("单次最多检测 100 个代理")
                results = test_proxy_pool(proxies)
                append_audit(
                    "proxy_pool_tested",
                    detail=f"count={len(results)} success={sum(1 for item in results if item.get('ok'))}",
                )
                self.send_json(
                    200,
                    {
                        "ok": True,
                        "count": len(results),
                        "success": sum(1 for item in results if item.get("ok")),
                        "results": results,
                    },
                )
                return
            if self.path == "/api/source/test":
                body = self.read_body()
                try:
                    result = test_source(body)
                except Exception as error:
                    message = str(error)
                    provider = body.get("provider") if isinstance(body.get("provider"), dict) else {}
                    for value in (
                        provider.get("apiUrl"),
                        provider.get("password"),
                        provider.get("refreshToken"),
                    ):
                        if str(value or ""):
                            message = message.replace(str(value), "***")
                    self.send_json(400, {"ok": False, "error": message[:1000]})
                    return
                append_audit("mail_source_tested", detail=f"mode={result.get('mode')}")
                self.send_json(200, result)
                return
            if self.path == "/api/start":
                body = self.read_body()
                ids = body.get("ids") if isinstance(body.get("ids"), list) else []
                status, payload = start_jobs([str(value) for value in ids])
                self.send_json(status, payload)
                return
            if self.path == "/api/at/refresh":
                body = self.read_body()
                ids = body.get("ids") if isinstance(body.get("ids"), list) else []
                status, payload = start_at_refresh([str(value) for value in ids])
                self.send_json(status, payload)
                return
            if self.path == "/api/stop":
                stop_jobs()
                self.send_json(200, {"ok": True})
                return
            if self.path == "/api/clear":
                with RUNTIME_LOCK:
                    if RUNTIME["running"]:
                        self.send_json(409, {"ok": False, "error": "运行中不能清空队列"})
                        return
                body = self.read_body()
                only_finished = bool(body.get("onlyFinished", True))
                include_ready = bool(body.get("includeReady", False))
                with JOBS_LOCK:
                    jobs = load_jobs()
                    removable = {"registration_failed", "mfa_failed", "stopped", "interrupted", "mfa_secret_missing"}
                    if include_ready:
                        removable.add("ready")
                    kept = [job for job in jobs if only_finished and str(job.get("status") or "") not in removable]
                    removed = len(jobs) - len(kept)
                    kept_ids = {str(job.get("id") or "") for job in kept}
                    secret_store = load_secret_store()
                    save_secret_store({job_id: values for job_id, values in secret_store.items() if job_id in kept_ids})
                    save_jobs(kept)
                append_audit("jobs_cleared", detail=f"count={removed}")
                self.send_json(200, {"ok": True, "removed": removed})
                return
            if self.path == "/api/jobs/delete":
                try:
                    body = self.read_body()
                    ids = body.get("ids")
                    if not isinstance(ids, list):
                        raise ValueError("ids 必须是数组")
                    result = delete_jobs([str(value) for value in ids])
                except RuntimeError as error:
                    self.send_json(409, {"ok": False, "error": str(error)})
                    return
                self.send_json(200, result)
                return
            if self.path == "/api/jobs/meta":
                body = self.read_body()
                ids = body.get("ids")
                if not isinstance(ids, list):
                    raise ValueError("ids 必须是数组")
                result = update_jobs_meta([str(value) for value in ids], changes=body)
                self.send_json(200, result)
                return
            self.send_json(404, {"ok": False, "error": "接口不存在"})
        except (ValueError, TypeError, json.JSONDecodeError) as error:
            self.send_json(400, {"ok": False, "error": str(error)})
        except Exception as error:
            append_log("error", f"API 异常: {error}")
            self.send_json(500, {"ok": False, "error": str(error)})

    def do_HEAD(self):
        return self.do_GET()


def main() -> int:
    if not ACCESS_PASSWORD and str(os.environ.get("REG_2FA_ALLOW_INSECURE") or "").strip() != "1":
        print("REG_2FA_PASSWORD is required", file=sys.stderr)
        return 2
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    X9_RUNTIME_ROOT.mkdir(parents=True, exist_ok=True)
    legacy_run_dir = DATA_DIR / "runs"
    if legacy_run_dir != RUN_DIR and legacy_run_dir.exists():
        shutil.rmtree(legacy_run_dir, ignore_errors=True)
    if RUN_DIR.exists():
        shutil.rmtree(RUN_DIR, ignore_errors=True)
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    if not JOBS_PATH.exists():
        write_json_atomic(JOBS_PATH, [])
    if not SECRETS_PATH.exists():
        save_secret_store({})
    if not SETTINGS_PATH.exists():
        save_settings(SETTINGS_DEFAULTS)
    SMS_ACTIVATIONS_DIR.mkdir(parents=True, exist_ok=True)
    recover_interrupted_manual_phone_controls()
    pending_sms_journals = list_pending_sms_activation_journals()
    recovery_settings = load_settings()
    def recover_startup_sms_activations() -> None:
        try:
            recover_pending_sms_activations(recovery_settings, paths=pending_sms_journals)
        finally:
            SMS_RECOVERY_COMPLETE.set()

    SMS_RECOVERY_COMPLETE.clear()
    threading.Thread(
        target=recover_startup_sms_activations,
        name="sms-activation-recovery",
        daemon=True,
    ).start()
    recover_interrupted_jobs()
    ensure_job_metadata()
    append_log("info", f"服务启动: {DEFAULT_HOST}:{DEFAULT_PORT}")
    server = ThreadingHTTPServer((DEFAULT_HOST, DEFAULT_PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop_jobs()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
