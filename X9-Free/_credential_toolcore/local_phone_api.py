from __future__ import annotations

import json
import os
import re
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

import requests

try:
    import msvcrt  # type: ignore[import-not-found]
except ImportError:
    msvcrt = None  # type: ignore[assignment]

try:
    import fcntl  # type: ignore[import-not-found]
except ImportError:
    fcntl = None  # type: ignore[assignment]

def _detect_project_dir() -> Path:
    isolated = str(os.environ.get("X9_ISOLATED_ROOT") or "").strip()
    if isolated:
        return Path(isolated).expanduser().resolve()
    here = Path(__file__).resolve()
    toolcore_dir = here.parent
    if toolcore_dir.name not in {"_toolcore", "_credential_toolcore"}:
        return toolcore_dir

    direct_parent = toolcore_dir.parent
    # X9 结构：X9/_toolcore
    if (direct_parent / "register_cli.py").is_file() and (direct_parent / "credential_cli.py").is_file():
        return direct_parent
    # protocal 结构：protocal/tools/http_auth_tool/_toolcore
    if direct_parent.name == "http_auth_tool" and len(direct_parent.parents) >= 2:
        return direct_parent.parents[1]
    return direct_parent


PROJECT_DIR = _detect_project_dir()
LOCAL_PHONE_STATE_LOCK = threading.RLock()
PHONE_CODE_PATTERN = re.compile(r"(?<!\d)(\d{6})(?!\d)")
PHONE_STATUS_PENDING = "pending"
PHONE_STATUS_DONE = "done"
PHONE_STATUS_BLACKLISTED = "blacklisted"
VALID_PHONE_STATUSES = {"", PHONE_STATUS_PENDING, PHONE_STATUS_DONE, PHONE_STATUS_BLACKLISTED}

# 冷却状态：不写入号码行（行内仍是 ""），仅在 state.cooldown_until 记录到期 epoch。
# 场景：号收到验证码但 OpenAI validate 返回 "recently used"，或发码被临时限频 ——
# 号本身没坏，等冷却到期可再用。避免把可恢复的号误当坏号永久拉黑。
COOLDOWN_STATE_KEY = "cooldown_until"
try:
    _cooldown_env_value = int(os.environ.get("LOCAL_PHONE_COOLDOWN_SECONDS", "") or "")
    DEFAULT_COOLDOWN_SECONDS = _cooldown_env_value if _cooldown_env_value > 0 else 6 * 3600
except Exception:
    DEFAULT_COOLDOWN_SECONDS = 6 * 3600


def _now_epoch() -> int:
    return int(time.time())


def _clean_cooldown_map(cooldown_raw: Any, *, now: Optional[int] = None) -> dict[str, int]:
    """清理过期的 cooldown_until（line_number_str -> expiry_epoch），返回仍有效的映射。"""
    moment = int(now if now is not None else _now_epoch())
    cleaned: dict[str, int] = {}
    if isinstance(cooldown_raw, dict):
        for key, value in cooldown_raw.items():
            try:
                expiry = int(value)
            except Exception:
                continue
            if expiry > moment:
                cleaned[str(key)] = expiry
    return cleaned


def _is_line_in_cooldown(
    cooldown_map: Optional[dict[str, int]],
    line_number: int,
    *,
    now: Optional[int] = None,
) -> bool:
    """判断指定行号是否仍处于有效冷却期。"""
    if not cooldown_map:
        return False
    expiry = cooldown_map.get(str(line_number))
    if expiry is None:
        return False
    try:
        return int(expiry) > int(now if now is not None else _now_epoch())
    except Exception:
        return False


LOCAL_PHONE_USAGE_MODE_SINGLE_USE = "single_use"
LOCAL_PHONE_USAGE_MODE_OAUTH_EMAIL_ROUND_ROBIN = "oauth_email_round_robin"
VALID_LOCAL_PHONE_USAGE_MODES = {
    LOCAL_PHONE_USAGE_MODE_SINGLE_USE,
    LOCAL_PHONE_USAGE_MODE_OAUTH_EMAIL_ROUND_ROBIN,
}
ROUND_ROBIN_GROUP_SIZE = 10
ROUND_ROBIN_MAX_SUCCESS_REUSE = 3


def get_round_robin_max_success_reuse() -> int:
    """成功复用上限；LOCAL_PHONE_MAX_SUCCESS_REUSE 可覆盖（单次尝试任务设为 1）。"""
    try:
        parsed = int(os.environ.get("LOCAL_PHONE_MAX_SUCCESS_REUSE", "") or "")
        if parsed > 0:
            return parsed
    except Exception:
        pass
    return ROUND_ROBIN_MAX_SUCCESS_REUSE


def _line_status_blocks_acquire(
    status: str,
    *,
    line_number: int,
    usage_counts: dict[str, Any] | None = None,
) -> bool:
    """True = 当前不可 acquire。done 且 usage 未达上限视为可复用（与 mark_completed 空状态一致）。"""
    normalized = str(status or "").strip().lower()
    if normalized == PHONE_STATUS_BLACKLISTED:
        return True
    if normalized == PHONE_STATUS_PENDING:
        return True
    if normalized == PHONE_STATUS_DONE:
        success_count = int((usage_counts or {}).get(str(line_number), 0) or 0)
        return success_count >= get_round_robin_max_success_reuse()
    return bool(normalized)


def _acquire_expected_statuses(current_status: str) -> set[str]:
    normalized = str(current_status or "").strip().lower()
    if normalized == PHONE_STATUS_DONE:
        return {"", PHONE_STATUS_DONE}
    return {""}


PHONE_RECORD_SEPARATOR_PIPE = "|"
PHONE_RECORD_SEPARATOR_DASH = "----"
LOCAL_PHONE_PROCESS_LOCK_FILENAME = ".phone_numbers_state.lock"
UNUSABLE_NUMBER_MARKERS = (
    "whatsapp",
    "whats app",
    "wa verification",
    "not sms",
    "sms not available",
    "unsupported channel",
    "unable to receive sms",
    "cannot receive sms",
)


class LocalPhoneApiError(RuntimeError):
    """Raised when local phone api file source cannot provide a valid phone/code."""


class LocalPhoneApiTimeoutError(LocalPhoneApiError):
    """Raised when the code URL never returns a valid verification code before timeout."""


class LocalPhoneApiUnusableNumberError(LocalPhoneApiError):
    """Raised when the selected number cannot receive the required SMS code."""


class LocalPhonePoolExhaustedError(LocalPhoneApiError):
    """Raised when the local phone pool has no available numbers left."""


@dataclass(frozen=True)
class LocalPhoneApiEntry:
    phone: str
    raw_phone: str
    code_url: str
    activation_id: str
    line_number: int
    country: str = ""
    country_slug: str = ""


def _safe_log(log: Optional[Callable[[str], None]], message: str) -> None:
    if callable(log):
        log(str(message))


def _to_positive_int(value: Any, default: int, *, minimum: int = 1) -> int:
    try:
        parsed = int(str(value).strip())
    except Exception:
        return default
    return parsed if parsed >= minimum else default


def _resolve_project_path(config: dict[str, Any], key: str, default_relative_path: str) -> Path:
    files_cfg = config.get("files", {}) if isinstance(config.get("files"), dict) else {}
    configured = str(files_cfg.get(key) or default_relative_path).strip() or default_relative_path
    candidate = Path(configured)
    if candidate.is_absolute():
        return candidate
    project_candidate = PROJECT_DIR / configured
    if project_candidate.exists():
        return project_candidate
    legacy_candidate = PROJECT_DIR / Path(configured).name
    if legacy_candidate.exists():
        return legacy_candidate
    return project_candidate


def _normalize_prefix(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if raw.startswith("+"):
        digits = "".join(ch for ch in raw[1:] if ch.isdigit())
        return f"+{digits}" if digits else ""
    digits = "".join(ch for ch in raw if ch.isdigit())
    return f"+{digits}" if digits else ""


def _is_comment_or_empty_line(raw_line: str) -> bool:
    stripped = str(raw_line or "").strip()
    return not stripped or stripped.startswith("#")


def _normalize_phone_status(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    return normalized if normalized in VALID_PHONE_STATUSES else ""


def _normalize_local_phone_usage_mode(value: Any) -> str:
    normalized = str(value or "").strip().lower() or LOCAL_PHONE_USAGE_MODE_SINGLE_USE
    if normalized not in VALID_LOCAL_PHONE_USAGE_MODES:
        raise LocalPhoneApiError(f"不支持的本地号码使用模式: {normalized}")
    return normalized


def _normalize_owner_key(value: Any) -> str:
    return str(value or "").strip().lower()


def _detect_phone_record_separator(raw_line: str) -> str:
    stripped = str(raw_line or "").strip()
    if PHONE_RECORD_SEPARATOR_DASH in stripped:
        return PHONE_RECORD_SEPARATOR_DASH
    if PHONE_RECORD_SEPARATOR_PIPE in stripped:
        return PHONE_RECORD_SEPARATOR_PIPE
    return ""


def _split_phone_record_parts(raw_line: str) -> tuple[str, list[str]] | tuple[str, None]:
    stripped = str(raw_line or "").strip()
    separator = _detect_phone_record_separator(stripped)
    if not separator:
        return "", None
    parts = [part.strip() for part in stripped.split(separator)]
    return separator, parts


def _extract_phone_record_metadata(raw_line: str) -> tuple[str, list[str]]:
    separator, parts = _split_phone_record_parts(raw_line)
    if not separator or not parts or len(parts) < 2:
        return "", []
    trailing_parts = parts[2:]
    if not trailing_parts:
        return separator, []
    last_part = trailing_parts[-1]
    if _normalize_phone_status(last_part):
        return separator, trailing_parts[:-1]
    return separator, trailing_parts


def _parse_phone_record(raw_line: str, *, line_number: int) -> tuple[str, str, str] | None:
    stripped = str(raw_line or "").strip()
    if _is_comment_or_empty_line(stripped):
        return None
    _separator, parts = _split_phone_record_parts(stripped)
    if not parts:
        return None
    if len(parts) < 2:
        return None
    phone_part = parts[0]
    code_url = parts[1]
    trailing_parts = parts[2:]
    status = ""
    if trailing_parts:
        maybe_status = _normalize_phone_status(trailing_parts[-1])
        if maybe_status:
            status = maybe_status
    if not phone_part or not code_url:
        return None
    return phone_part, code_url, status


def _serialize_phone_record(
    raw_phone: str,
    code_url: str,
    status: str = "",
    *,
    separator: str = PHONE_RECORD_SEPARATOR_PIPE,
    metadata_parts: Iterable[str] | None = None,
) -> str:
    record_separator = (
        PHONE_RECORD_SEPARATOR_DASH
        if separator == PHONE_RECORD_SEPARATOR_DASH
        else PHONE_RECORD_SEPARATOR_PIPE
    )
    components = [str(raw_phone or "").strip(), str(code_url or "").strip()]
    for part in metadata_parts or []:
        normalized_part = str(part or "").strip()
        if normalized_part:
            components.append(normalized_part)
    normalized_status = _normalize_phone_status(status)
    if normalized_status:
        components.append(normalized_status)
    return record_separator.join(components)


def _write_text_with_windows_fallback(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = str(text or "")
    try:
        if path.exists() and path.read_text(encoding="utf-8") == payload:
            return
    except Exception:
        pass

    tmp_path = path.with_suffix(f"{path.suffix}.tmp.{os.getpid()}.{uuid.uuid4().hex[:8]}")
    tmp_path.write_text(payload, encoding="utf-8")
    last_error: Exception | None = None
    for _ in range(8):
        try:
            tmp_path.replace(path)
            return
        except PermissionError as exc:
            last_error = exc
            time.sleep(0.15)
        except Exception:
            raise

    for _ in range(8):
        try:
            path.write_text(payload, encoding="utf-8")
            try:
                tmp_path.unlink(missing_ok=True)
            except Exception:
                pass
            return
        except PermissionError as exc:
            last_error = exc
            time.sleep(0.15)
        except Exception:
            raise

    try:
        tmp_path.unlink(missing_ok=True)
    except Exception:
        pass
    if last_error is not None:
        raise last_error


def _write_lines_atomic(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = "\n".join(lines)
    if lines:
        payload += "\n"
    _write_text_with_windows_fallback(path, payload)


@contextmanager
def _local_phone_process_file_lock(lock_path: Path, *, timeout_seconds: float = 60.0):
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    with open(lock_path, "a+b") as lock_file:
        while True:
            try:
                lock_file.seek(0)
                if msvcrt is not None:
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
                elif fcntl is not None:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                else:
                    raise LocalPhoneApiError("当前系统不支持本地手机号进程锁")
                break
            except (OSError, BlockingIOError):
                if time.monotonic() - started >= max(1.0, float(timeout_seconds or 60.0)):
                    raise LocalPhoneApiError(f"本地手机号进程锁获取超时: {lock_path}")
                time.sleep(0.1)
        try:
            try:
                lock_file.seek(0)
                lock_file.truncate()
                lock_file.write(f"{os.getpid()}\n".encode("utf-8", errors="ignore"))
                lock_file.flush()
            except Exception:
                pass
            yield
        finally:
            try:
                lock_file.seek(0)
                lock_file.truncate()
                lock_file.flush()
            except Exception:
                pass
            try:
                lock_file.seek(0)
                if msvcrt is not None:
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
                elif fcntl is not None:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass


def uses_local_phone_api_file(config: Optional[dict[str, Any]] = None) -> bool:
    cfg = dict(config or {})
    register_cfg = cfg.get("register", {}) if isinstance(cfg.get("register"), dict) else {}
    phone_cfg = register_cfg.get("phone", {}) if isinstance(register_cfg.get("phone"), dict) else {}
    provider = str(phone_cfg.get("provider") or "").strip().lower()
    return provider == "local_api_file"


def _resolve_inventory_next_line_number(
    state_file: Path,
    *,
    fallback: int,
) -> int:
    try:
        if not state_file.exists():
            return fallback
        payload = json.loads(state_file.read_text(encoding="utf-8-sig"))
    except Exception:
        return fallback
    if not isinstance(payload, dict):
        return fallback
    try:
        next_line_number = int(payload.get("next_line_number") or 0)
    except Exception:
        return fallback
    return next_line_number if next_line_number > 0 else fallback


def get_local_phone_inventory(config: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    cfg = dict(config or {})
    enabled = uses_local_phone_api_file(cfg)
    number_file = _resolve_project_path(cfg, "phone_numbers", "config/phone_numbers.txt")
    state_file = _resolve_project_path(cfg, "phone_numbers_state", "config/phone_numbers_state.json")
    inventory = {
        "enabled": enabled,
        "number_file": number_file,
        "state_file": state_file,
        "total": 0,
        "remaining": 0,
        "pending": 0,
        "done": 0,
        "blacklisted": 0,
        "invalid_lines": 0,
        "next_line_number": 1,
        "error": "",
    }
    if not enabled:
        return inventory
    try:
        if not number_file.exists():
            inventory["error"] = f"本地号码文件不存在: {number_file}"
            return inventory
        lines = number_file.read_text(encoding="utf-8-sig").splitlines()
    except Exception as exc:
        inventory["error"] = f"本地号码文件读取失败: {exc}"
        return inventory

    total = 0
    remaining = 0
    pending = 0
    done = 0
    blacklisted = 0
    invalid_lines = 0
    next_line_number = 1
    first_available_line = 0
    for line_number, raw_line in enumerate(lines, start=1):
        parsed = _parse_phone_record(raw_line, line_number=line_number)
        if parsed is None:
            if not _is_comment_or_empty_line(raw_line):
                invalid_lines += 1
            continue
        phone_part, code_url, status = parsed
        if not phone_part or not code_url:
            invalid_lines += 1
            continue
        total += 1
        if not status:
            remaining += 1
            if first_available_line <= 0:
                first_available_line = line_number
        elif status == PHONE_STATUS_PENDING:
            pending += 1
        elif status == PHONE_STATUS_DONE:
            done += 1
        elif status == PHONE_STATUS_BLACKLISTED:
            blacklisted += 1
    if first_available_line > 0:
        next_line_number = first_available_line
    elif total > 0:
        next_line_number = len(lines) + 1
    next_line_number = _resolve_inventory_next_line_number(
        state_file,
        fallback=next_line_number,
    )
    inventory["total"] = total
    inventory["remaining"] = remaining
    inventory["pending"] = pending
    inventory["done"] = done
    inventory["blacklisted"] = blacklisted
    inventory["invalid_lines"] = invalid_lines
    inventory["next_line_number"] = next_line_number
    return inventory


class LocalPhoneApiPhoneService:
    def __init__(
        self,
        config: Optional[dict[str, Any]] = None,
        *,
        log_fn: Optional[Callable[[str], None]] = None,
        session_factory: Optional[Callable[[], Any]] = None,
        usage_mode: str = LOCAL_PHONE_USAGE_MODE_SINGLE_USE,
    ) -> None:
        self.config = dict(config or {})
        register_cfg = self.config.get("register", {}) if isinstance(self.config.get("register"), dict) else {}
        phone_cfg = register_cfg.get("phone", {}) if isinstance(register_cfg.get("phone"), dict) else {}
        api_cfg = self.config.get("phone_api_file", {}) if isinstance(self.config.get("phone_api_file"), dict) else {}

        self.log_fn = log_fn or (lambda _msg: None)
        self.provider = str(phone_cfg.get("provider") or "").strip().lower()
        self.enabled = self.provider == "local_api_file"
        self.number_file = _resolve_project_path(self.config, "phone_numbers", "config/phone_numbers.txt")
        self.state_file = _resolve_project_path(self.config, "phone_numbers_state", "config/phone_numbers_state.json")
        self.process_lock_file = self.state_file.with_name(LOCAL_PHONE_PROCESS_LOCK_FILENAME)
        self.number_prefix = _normalize_prefix(api_cfg.get("number_prefix"))
        self.request_timeout_seconds = _to_positive_int(api_cfg.get("request_timeout_seconds"), 15, minimum=1)
        self.poll_interval_seconds = _to_positive_int(api_cfg.get("poll_interval_seconds"), 5, minimum=1)
        self.otp_timeout_seconds = _to_positive_int(api_cfg.get("otp_timeout_seconds"), 120, minimum=10)
        retry_default = _to_positive_int(phone_cfg.get("max_retry"), 2, minimum=1)
        self.max_retries = _to_positive_int(api_cfg.get("max_retries"), retry_default, minimum=1)
        self.max_attempts = _to_positive_int(api_cfg.get("max_attempts"), self.max_retries, minimum=1)
        self._session_factory = session_factory
        self.usage_mode = _normalize_local_phone_usage_mode(usage_mode)

        if self.enabled and not self.number_prefix:
            raise LocalPhoneApiError("phone_api_file.number_prefix 未配置，无法为本地号码补齐国际区号")

    def prefix_hint(self, phone: str) -> str:
        normalized = str(phone or "").strip()
        if normalized.startswith("+"):
            return normalized[:7]
        digits = "".join(ch for ch in normalized if ch.isdigit())
        return digits[:6]

    def _build_session(self) -> Any:
        if callable(self._session_factory):
            return self._session_factory()
        return requests.Session()

    @contextmanager
    def _global_state_guard(self):
        with LOCAL_PHONE_STATE_LOCK:
            with _local_phone_process_file_lock(self.process_lock_file):
                yield

    def _load_number_lines(self) -> list[str]:
        try:
            return self.number_file.read_text(encoding="utf-8-sig").splitlines()
        except Exception as exc:
            raise LocalPhoneApiError(f"本地号码文件读取失败: {exc}") from exc

    def _save_number_lines(self, lines: list[str]) -> None:
        try:
            _write_lines_atomic(self.number_file, lines)
        except Exception as exc:
            raise LocalPhoneApiError(f"本地号码文件写入失败: {exc}") from exc

    def _load_state(self) -> dict[str, Any]:
        try:
            if not self.state_file.exists():
                return {}
            payload = json.loads(self.state_file.read_text(encoding="utf-8-sig"))
        except Exception as exc:
            raise LocalPhoneApiError(f"本地号码状态文件读取失败: {exc}") from exc
        return payload if isinstance(payload, dict) else {}

    def _save_state(self, state: dict[str, Any]) -> None:
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            payload = json.dumps(state, ensure_ascii=False, indent=2)
            _write_text_with_windows_fallback(self.state_file, payload + "\n")
        except Exception as exc:
            raise LocalPhoneApiError(f"本地号码状态文件写入失败: {exc}") from exc

    def _set_line_status(
        self,
        lines: list[str],
        *,
        line_number: int,
        status: str,
        expected_statuses: Iterable[str] | None = None,
    ) -> bool:
        if line_number <= 0 or line_number > len(lines):
            return False
        parsed = _parse_phone_record(lines[line_number - 1], line_number=line_number)
        if parsed is None:
            return False
        raw_phone, code_url, current_status = parsed
        raw_line = lines[line_number - 1]
        separator, metadata_parts = _extract_phone_record_metadata(raw_line)
        if not separator:
            separator = PHONE_RECORD_SEPARATOR_PIPE
        expected = None if expected_statuses is None else {str(item or "").strip().lower() for item in expected_statuses}
        if expected is not None and current_status not in expected:
            return False
        lines[line_number - 1] = _serialize_phone_record(
            raw_phone,
            code_url,
            status,
            separator=separator,
            metadata_parts=metadata_parts,
        )
        return True

    def _update_entry_status(
        self,
        entry: LocalPhoneApiEntry,
        *,
        status: str,
        expected_statuses: Iterable[str] | None,
        log_message: str,
    ) -> bool:
        if not self.number_file.exists():
            return False
        with self._global_state_guard():
            lines = self._load_number_lines()
            if not self._set_line_status(
                lines,
                line_number=int(entry.line_number or 0),
                status=status,
                expected_statuses=expected_statuses,
            ):
                return False
            self._save_number_lines(lines)
        _safe_log(self.log_fn, log_message)
        return True

    def _list_valid_entries(
        self,
        lines: list[str],
    ) -> list[tuple[int, str, str, str]]:
        valid_entries: list[tuple[int, str, str, str]] = []
        for index, raw_line in enumerate(lines, start=1):
            parsed = _parse_phone_record(raw_line, line_number=index)
            if parsed is None:
                if not _is_comment_or_empty_line(raw_line):
                    _safe_log(self.log_fn, f"phone_api_file_bad_line: line={index} invalid")
                continue
            valid_entries.append((index, *parsed))
        return valid_entries

    def _build_round_robin_state(
        self,
        raw_state: dict[str, Any],
        *,
        valid_entries: list[tuple[int, str, str, str]],
        total_lines: int,
    ) -> dict[str, Any]:
        valid_line_numbers = {line_number for line_number, _raw_phone, _code_url, _status in valid_entries}
        usage_counts: dict[str, int] = {}
        raw_usage_counts = raw_state.get("usage_counts") if isinstance(raw_state, dict) else {}
        if isinstance(raw_usage_counts, dict):
            for key, value in raw_usage_counts.items():
                try:
                    line_number = int(str(key).strip())
                    count = int(value)
                except Exception:
                    continue
                if line_number not in valid_line_numbers:
                    continue
                usage_counts[str(line_number)] = max(0, min(count, get_round_robin_max_success_reuse()))
        pending_line_numbers = {
            line_number
            for line_number, _raw_phone, _code_url, status in valid_entries
            if status == PHONE_STATUS_PENDING
        }
        pending_by_owner: dict[str, int] = {}
        raw_pending_by_owner = raw_state.get("pending_by_owner") if isinstance(raw_state, dict) else {}
        if isinstance(raw_pending_by_owner, dict):
            for key, value in raw_pending_by_owner.items():
                owner_key = _normalize_owner_key(key)
                if not owner_key:
                    continue
                try:
                    line_number = int(str(value).strip())
                except Exception:
                    continue
                if line_number not in pending_line_numbers:
                    continue
                pending_by_owner[owner_key] = line_number
        try:
            group_index = max(int(raw_state.get("group_index") or 0), 0)
        except Exception:
            group_index = 0
        try:
            pass_index = max(int(raw_state.get("pass_index") or 0), 0)
        except Exception:
            pass_index = 0
        pass_index = min(pass_index, get_round_robin_max_success_reuse() - 1)
        try:
            offset_in_group = max(int(raw_state.get("offset_in_group") or 0), 0)
        except Exception:
            offset_in_group = 0

        group_count = (len(valid_entries) + ROUND_ROBIN_GROUP_SIZE - 1) // ROUND_ROBIN_GROUP_SIZE
        if group_count <= 0:
            group_index = 0
            pass_index = 0
            offset_in_group = 0
        elif group_index >= group_count:
            group_index = group_count
            pass_index = 0
            offset_in_group = 0
        else:
            group_start = group_index * ROUND_ROBIN_GROUP_SIZE
            group_size = len(valid_entries[group_start:group_start + ROUND_ROBIN_GROUP_SIZE])
            if group_size <= 0:
                group_index = group_count
                pass_index = 0
                offset_in_group = 0
            elif offset_in_group >= group_size:
                offset_in_group = 0

        active_success_counts: list[int] = []
        for line_number, _raw_phone, _code_url, status in valid_entries:
            if _line_status_blocks_acquire(status, line_number=line_number, usage_counts=usage_counts):
                continue
            count = int(usage_counts.get(str(line_number), 0) or 0)
            if count < get_round_robin_max_success_reuse():
                active_success_counts.append(count)
        if active_success_counts:
            pool_pass_index = min(active_success_counts)
            if pass_index != pool_pass_index:
                group_index = 0
                pass_index = pool_pass_index
                offset_in_group = 0

        cooldown_until = _clean_cooldown_map(raw_state.get(COOLDOWN_STATE_KEY))
        state = {
            "group_index": group_index,
            "pass_index": pass_index,
            "offset_in_group": offset_in_group,
            "usage_counts": usage_counts,
            "pending_by_owner": pending_by_owner,
            "cooldown_until": cooldown_until,
        }
        state["next_line_number"] = self._round_robin_next_line_number(
            valid_entries,
            state=state,
            total_lines=total_lines,
        )
        return state

    def _iterate_round_robin_positions(
        self,
        valid_entries: list[tuple[int, str, str, str]],
        *,
        state: dict[str, Any],
    ) -> Iterable[tuple[int, int, int, tuple[int, str, str, str]]]:
        positions: list[tuple[int, int, int, tuple[int, str, str, str]]] = []
        total_groups = (len(valid_entries) + ROUND_ROBIN_GROUP_SIZE - 1) // ROUND_ROBIN_GROUP_SIZE
        if total_groups <= 0:
            return
        # 先把同一组号码复用到上限，再切下一组。这样能更快摊薄号码成本，
        # 同时仍严格遵守单号码最多 get_round_robin_max_success_reuse() 次成功复用。
        for group_index in range(total_groups):
            group_start = group_index * ROUND_ROBIN_GROUP_SIZE
            group_entries = valid_entries[group_start:group_start + ROUND_ROBIN_GROUP_SIZE]
            if not group_entries:
                continue
            for pass_index in range(get_round_robin_max_success_reuse()):
                for offset_in_group in range(len(group_entries)):
                    positions.append((group_index, pass_index, offset_in_group, group_entries[offset_in_group]))
        if not positions:
            return

        start_group = max(int(state.get("group_index") or 0), 0)
        start_pass = min(max(int(state.get("pass_index") or 0), 0), get_round_robin_max_success_reuse() - 1)
        start_offset = max(int(state.get("offset_in_group") or 0), 0)
        start_index = 0
        for index, (group_index, pass_index, offset_in_group, _record) in enumerate(positions):
            if group_index == start_group and pass_index == start_pass and offset_in_group == start_offset:
                start_index = index
                break

        for position in positions[start_index:]:
            yield position
        for position in positions[:start_index]:
            yield position

    def _advance_round_robin_cursor(
        self,
        valid_entries: list[tuple[int, str, str, str]],
        *,
        group_index: int,
        pass_index: int,
        offset_in_group: int,
    ) -> dict[str, int]:
        group_start = group_index * ROUND_ROBIN_GROUP_SIZE
        group_entries = valid_entries[group_start:group_start + ROUND_ROBIN_GROUP_SIZE]
        total_groups = (len(valid_entries) + ROUND_ROBIN_GROUP_SIZE - 1) // ROUND_ROBIN_GROUP_SIZE
        if group_entries and offset_in_group + 1 < len(group_entries):
            return {
                "group_index": group_index,
                "pass_index": pass_index,
                "offset_in_group": offset_in_group + 1,
            }
        if group_index + 1 < total_groups:
            return {
                "group_index": group_index + 1,
                "pass_index": pass_index,
                "offset_in_group": 0,
            }
        if pass_index + 1 < get_round_robin_max_success_reuse():
            return {
                "group_index": 0,
                "pass_index": pass_index + 1,
                "offset_in_group": 0,
            }
        return {
            "group_index": total_groups,
            "pass_index": 0,
            "offset_in_group": 0,
        }

    def _round_robin_next_line_number(
        self,
        valid_entries: list[tuple[int, str, str, str]],
        *,
        state: dict[str, Any],
        total_lines: int,
    ) -> int:
        usage_counts = dict(state.get("usage_counts") or {})
        for _group_index, pass_index, _offset_in_group, record in self._iterate_round_robin_positions(
            valid_entries,
            state=state,
        ):
            line_number, _raw_phone, _code_url, status = record
            if _line_status_blocks_acquire(status, line_number=line_number, usage_counts=usage_counts):
                continue
            success_count = int(usage_counts.get(str(line_number), 0) or 0)
            if success_count >= get_round_robin_max_success_reuse():
                continue
            if success_count != int(pass_index):
                continue
            return int(line_number)
        return total_lines + 1

    def _save_round_robin_state(
        self,
        state: dict[str, Any],
        *,
        valid_entries: list[tuple[int, str, str, str]],
        total_lines: int,
    ) -> None:
        payload = {
            "group_index": max(int(state.get("group_index") or 0), 0),
            "pass_index": min(max(int(state.get("pass_index") or 0), 0), get_round_robin_max_success_reuse() - 1),
            "offset_in_group": max(int(state.get("offset_in_group") or 0), 0),
            "usage_counts": dict(state.get("usage_counts") or {}),
            "pending_by_owner": dict(state.get("pending_by_owner") or {}),
            "cooldown_until": _clean_cooldown_map(state.get(COOLDOWN_STATE_KEY)),
        }
        payload["next_line_number"] = self._round_robin_next_line_number(
            valid_entries,
            state=payload,
            total_lines=total_lines,
        )
        self._save_state(payload)

    def _clear_pending_by_phone(self, phone: str, *, reason: str) -> bool:
        normalized_phone = str(phone or "").strip()
        if not normalized_phone or not self.number_file.exists():
            return False
        with self._global_state_guard():
            lines = self._load_number_lines()
            updated = False
            for index, raw_line in enumerate(lines, start=1):
                parsed = _parse_phone_record(raw_line, line_number=index)
                if parsed is None:
                    continue
                raw_phone, code_url, status = parsed
                if status != PHONE_STATUS_PENDING:
                    continue
                try:
                    built_phone = self._build_phone_number(raw_phone)
                except LocalPhoneApiError:
                    continue
                if built_phone != normalized_phone:
                    continue
                separator, metadata_parts = _extract_phone_record_metadata(raw_line)
                if not separator:
                    separator = PHONE_RECORD_SEPARATOR_PIPE
                lines[index - 1] = _serialize_phone_record(
                    raw_phone,
                    code_url,
                    "",
                    separator=separator,
                    metadata_parts=metadata_parts,
                )
                updated = True
                break
            if not updated:
                return False
            self._save_number_lines(lines)
        _safe_log(self.log_fn, reason)
        return True

    def _mark_phone_blacklisted(self, phone: str) -> bool:
        normalized_phone = str(phone or "").strip()
        if not normalized_phone or not self.number_file.exists():
            return False
        with self._global_state_guard():
            lines = self._load_number_lines()
            updated = False
            for index, raw_line in enumerate(lines, start=1):
                parsed = _parse_phone_record(raw_line, line_number=index)
                if parsed is None:
                    continue
                raw_phone, code_url, _status = parsed
                try:
                    built_phone = self._build_phone_number(raw_phone)
                except LocalPhoneApiError:
                    continue
                if built_phone != normalized_phone:
                    continue
                separator, metadata_parts = _extract_phone_record_metadata(raw_line)
                if not separator:
                    separator = PHONE_RECORD_SEPARATOR_PIPE
                lines[index - 1] = _serialize_phone_record(
                    raw_phone,
                    code_url,
                    PHONE_STATUS_BLACKLISTED,
                    separator=separator,
                    metadata_parts=metadata_parts,
                )
                updated = True
                break
            if not updated:
                return False
            valid_entries = self._list_valid_entries(lines)
            state = self._build_round_robin_state(
                self._load_state(),
                valid_entries=valid_entries,
                total_lines=len(lines),
            )
            pending_by_owner = {
                owner: line
                for owner, line in dict(state.get("pending_by_owner") or {}).items()
                if int(line or 0) != int(index)
            }
            state = {
                **state,
                "pending_by_owner": pending_by_owner,
            }
            self._save_number_lines(lines)
            if self.usage_mode == LOCAL_PHONE_USAGE_MODE_OAUTH_EMAIL_ROUND_ROBIN:
                self._save_round_robin_state(
                    state,
                    valid_entries=valid_entries,
                    total_lines=len(lines),
                )
        return True

    def _mark_phone_cooldown(
        self,
        phone: str,
        seconds: Optional[int] = None,
    ) -> bool:
        normalized_phone = str(phone or "").strip()
        if not normalized_phone or not self.number_file.exists():
            return False
        try:
            cooldown_secs = int(seconds) if seconds is not None else 0  # type: ignore[arg-type]
        except Exception:
            cooldown_secs = 0
        if cooldown_secs <= 0:
            cooldown_secs = DEFAULT_COOLDOWN_SECONDS
        expiry = _now_epoch() + cooldown_secs
        with self._global_state_guard():
            lines = self._load_number_lines()
            target_index = 0
            for index, raw_line in enumerate(lines, start=1):
                parsed = _parse_phone_record(raw_line, line_number=index)
                if parsed is None:
                    continue
                raw_phone, _code_url, _status = parsed
                try:
                    built_phone = self._build_phone_number(raw_phone)
                except LocalPhoneApiError:
                    continue
                if built_phone == normalized_phone:
                    target_index = index
                    break
            if target_index <= 0:
                return False
            state = self._load_state()
            cooldown_map = _clean_cooldown_map(state.get(COOLDOWN_STATE_KEY))
            cooldown_map[str(target_index)] = expiry
            state[COOLDOWN_STATE_KEY] = cooldown_map
            self._save_state(state)
        return True

    def _build_phone_number(self, raw_phone: str) -> str:
        normalized = str(raw_phone or "").lstrip("\ufeff").strip()
        if normalized.startswith("+"):
            return normalized
        digits = "".join(ch for ch in normalized if ch.isdigit())
        if not digits:
            raise LocalPhoneApiError("本地号码文件存在无法识别的手机号内容")
        if self.number_prefix == "+1":
            if len(digits) == 11 and digits.startswith("1"):
                return f"+{digits}"
            if len(digits) == 10:
                return f"+1{digits}"
        return f"{self.number_prefix}{digits}"

    def _extract_code(self, payload: Any) -> str:
        text = str(payload or "")
        matches = PHONE_CODE_PATTERN.findall(text)
        return str(matches[-1]).strip() if matches else ""

    def _response_indicates_unusable_number(self, payload: Any) -> bool:
        text = str(payload or "").strip().lower()
        if not text:
            return False
        return any(marker in text for marker in UNUSABLE_NUMBER_MARKERS)

    def acquire_phone(
        self,
        *,
        exclude_prefixes: Optional[Iterable[str]] = None,
        owner_key: str = "",
    ) -> LocalPhoneApiEntry | None:
        if self.usage_mode == LOCAL_PHONE_USAGE_MODE_OAUTH_EMAIL_ROUND_ROBIN:
            return self._acquire_phone_round_robin(exclude_prefixes=exclude_prefixes, owner_key=owner_key)
        if not self.enabled:
            return None
        if not self.number_file.exists():
            raise LocalPhoneApiError(f"本地号码文件不存在: {self.number_file}")
        excluded = {str(item or "").strip() for item in (exclude_prefixes or []) if str(item or "").strip()}
        with self._global_state_guard():
            lines = self._load_number_lines()
            cooldown_map = _clean_cooldown_map(self._load_state().get(COOLDOWN_STATE_KEY))
            for index, raw_line in enumerate(lines, start=1):
                parsed = _parse_phone_record(raw_line, line_number=index)
                if parsed is None:
                    if not _is_comment_or_empty_line(raw_line):
                        _safe_log(self.log_fn, f"phone_api_file_bad_line: line={index} invalid")
                    continue
                raw_phone, code_url, status = parsed
                if _line_status_blocks_acquire(status, line_number=index):
                    continue
                if _is_line_in_cooldown(cooldown_map, index):
                    continue
                phone = self._build_phone_number(raw_phone)
                if any(phone.startswith(prefix) for prefix in excluded if prefix):
                    continue
                if not self._set_line_status(
                    lines,
                    line_number=index,
                    status=PHONE_STATUS_PENDING,
                    expected_statuses=_acquire_expected_statuses(status),
                ):
                    continue
                self._save_number_lines(lines)
                entry = LocalPhoneApiEntry(
                    phone=phone,
                    raw_phone=raw_phone,
                    code_url=code_url,
                    activation_id=f"local-file-line-{index}",
                    line_number=index,
                    country=self.number_prefix,
                    country_slug=self.number_prefix.lstrip("+"),
                )
                _safe_log(self.log_fn, f"phone_api_file_selected: line={index} phone={phone}")
                return entry
        raise LocalPhonePoolExhaustedError("local_phone_pool_exhausted: local phone pool exhausted")

    def _acquire_phone_round_robin(
        self,
        *,
        exclude_prefixes: Optional[Iterable[str]] = None,
        owner_key: str = "",
    ) -> LocalPhoneApiEntry | None:
        if not self.enabled:
            return None
        if not self.number_file.exists():
            raise LocalPhoneApiError(f"本地号码文件不存在: {self.number_file}")
        excluded = {str(item or "").strip() for item in (exclude_prefixes or []) if str(item or "").strip()}
        with self._global_state_guard():
            lines = self._load_number_lines()
            valid_entries = self._list_valid_entries(lines)
            if not valid_entries:
                raise LocalPhonePoolExhaustedError("local_phone_pool_exhausted: no available local phone numbers")
            state = self._build_round_robin_state(
                self._load_state(),
                valid_entries=valid_entries,
                total_lines=len(lines),
            )
            usage_counts = dict(state.get("usage_counts") or {})
            pending_by_owner = dict(state.get("pending_by_owner") or {})
            normalized_owner = _normalize_owner_key(owner_key)
            if normalized_owner:
                pending_line_number = int(pending_by_owner.get(normalized_owner) or 0)
                for line_number, raw_phone, code_url, status in valid_entries:
                    if line_number != pending_line_number or status != PHONE_STATUS_PENDING:
                        continue
                    phone = self._build_phone_number(raw_phone)
                    entry = LocalPhoneApiEntry(
                        phone=phone,
                        raw_phone=raw_phone,
                        code_url=code_url,
                        activation_id=f"local-file-line-{line_number}",
                        line_number=line_number,
                        country=self.number_prefix,
                        country_slug=self.number_prefix.lstrip("+"),
                    )
                    _safe_log(
                        self.log_fn,
                        "phone_api_file_reused_pending_round_robin: "
                        f"owner={normalized_owner} line={line_number} phone={phone}",
                    )
                    return entry
            for group_index, pass_index, offset_in_group, record in self._iterate_round_robin_positions(
                valid_entries,
                state=state,
            ):
                line_number, raw_phone, code_url, status = record
                if _line_status_blocks_acquire(status, line_number=line_number, usage_counts=usage_counts):
                    continue
                if _is_line_in_cooldown(state.get(COOLDOWN_STATE_KEY), line_number):
                    continue
                success_count = int(usage_counts.get(str(line_number), 0) or 0)
                if success_count >= get_round_robin_max_success_reuse():
                    continue
                if success_count != int(pass_index):
                    continue
                phone = self._build_phone_number(raw_phone)
                if any(phone.startswith(prefix) for prefix in excluded if prefix):
                    continue
                if not self._set_line_status(
                    lines,
                    line_number=line_number,
                    status=PHONE_STATUS_PENDING,
                    expected_statuses=_acquire_expected_statuses(status),
                ):
                    continue
                next_cursor = self._advance_round_robin_cursor(
                    valid_entries,
                    group_index=group_index,
                    pass_index=pass_index,
                    offset_in_group=offset_in_group,
                )
                updated_state = {
                    **state,
                    **next_cursor,
                    "usage_counts": usage_counts,
                }
                if normalized_owner:
                    pending_by_owner[normalized_owner] = int(line_number)
                    updated_state["pending_by_owner"] = pending_by_owner
                self._save_number_lines(lines)
                self._save_round_robin_state(
                    updated_state,
                    valid_entries=valid_entries,
                    total_lines=len(lines),
                )
                entry = LocalPhoneApiEntry(
                    phone=phone,
                    raw_phone=raw_phone,
                    code_url=code_url,
                    activation_id=f"local-file-line-{line_number}",
                    line_number=line_number,
                    country=self.number_prefix,
                    country_slug=self.number_prefix.lstrip("+"),
                )
                _safe_log(
                    self.log_fn,
                    "phone_api_file_selected_round_robin: "
                    f"group={group_index + 1} pass={pass_index + 1} line={line_number} phone={phone}",
                )
                return entry
        raise LocalPhonePoolExhaustedError("local_phone_pool_exhausted: local phone pool exhausted")

    def get_pending_owner_phone(self, owner_key: str) -> LocalPhoneApiEntry | None:
        normalized_owner = _normalize_owner_key(owner_key)
        if not normalized_owner or self.usage_mode != LOCAL_PHONE_USAGE_MODE_OAUTH_EMAIL_ROUND_ROBIN:
            return None
        if not self.enabled or not self.number_file.exists():
            return None
        with self._global_state_guard():
            lines = self._load_number_lines()
            valid_entries = self._list_valid_entries(lines)
            state = self._build_round_robin_state(
                self._load_state(),
                valid_entries=valid_entries,
                total_lines=len(lines),
            )
            pending_line_number = int(dict(state.get("pending_by_owner") or {}).get(normalized_owner) or 0)
            if pending_line_number <= 0:
                return None
            for line_number, raw_phone, code_url, status in valid_entries:
                if line_number != pending_line_number or status != PHONE_STATUS_PENDING:
                    continue
                return LocalPhoneApiEntry(
                    phone=self._build_phone_number(raw_phone),
                    raw_phone=raw_phone,
                    code_url=code_url,
                    activation_id=f"local-file-line-{line_number}",
                    line_number=line_number,
                    country=self.number_prefix,
                    country_slug=self.number_prefix.lstrip("+"),
                )
        return None

    def wait_for_code(self, entry: LocalPhoneApiEntry, *, timeout: Optional[int] = None) -> str:
        wait_seconds = _to_positive_int(timeout, self.otp_timeout_seconds, minimum=10)
        deadline = time.monotonic() + wait_seconds
        session = self._build_session()
        try:
            while True:
                try:
                    response = session.get(entry.code_url, timeout=self.request_timeout_seconds)
                except requests.RequestException as exc:
                    _safe_log(self.log_fn, f"phone_api_file_poll_error: line={entry.line_number} error={exc}")
                else:
                    status_code = int(getattr(response, "status_code", 0) or 0)
                    body = str(getattr(response, "text", "") or "")
                    if status_code == 200:
                        if self._response_indicates_unusable_number(body):
                            raise LocalPhoneApiUnusableNumberError(
                                f"本地号码不可用或被切到非 SMS 验证: 第 {entry.line_number} 行"
                            )
                        code = self._extract_code(body)
                        if code:
                            _safe_log(self.log_fn, f"phone_api_file_code_received: line={entry.line_number} code=****")
                            return code
                    else:
                        _safe_log(self.log_fn, f"phone_api_file_poll_status: line={entry.line_number} status={status_code}")
                        if 400 <= status_code < 500 and status_code not in {408, 429}:
                            raise LocalPhoneApiTimeoutError(
                                f"本地号码取码 URL 已失效或不可用: 第 {entry.line_number} 行 (HTTP {status_code})"
                            )
                if time.monotonic() >= deadline:
                    raise LocalPhoneApiTimeoutError(f"本地号码取码超时: 第 {entry.line_number} 行")
                time.sleep(self.poll_interval_seconds)
        finally:
            close = getattr(session, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:
                    pass

    def cancel(self, entry: LocalPhoneApiEntry) -> None:
        if self.usage_mode == LOCAL_PHONE_USAGE_MODE_OAUTH_EMAIL_ROUND_ROBIN:
            self._cancel_round_robin_entry(entry)
            return
        self._update_entry_status(
            entry,
            status="",
            expected_statuses={PHONE_STATUS_PENDING},
            log_message=f"phone_api_file_cancelled: line={entry.line_number}",
        )

    def _cancel_round_robin_entry(self, entry: LocalPhoneApiEntry) -> None:
        if not self.number_file.exists():
            return
        with self._global_state_guard():
            lines = self._load_number_lines()
            valid_entries = self._list_valid_entries(lines)
            if not self._set_line_status(
                lines,
                line_number=int(entry.line_number or 0),
                status="",
                expected_statuses={PHONE_STATUS_PENDING},
            ):
                return
            state = self._build_round_robin_state(
                self._load_state(),
                valid_entries=valid_entries,
                total_lines=len(lines),
            )
            pending_by_owner = {
                owner: line
                for owner, line in dict(state.get("pending_by_owner") or {}).items()
                if int(line or 0) != int(entry.line_number or 0)
            }
            state = {
                **state,
                "pending_by_owner": pending_by_owner,
            }
            self._save_number_lines(lines)
            self._save_round_robin_state(
                state,
                valid_entries=valid_entries,
                total_lines=len(lines),
            )
        _safe_log(self.log_fn, f"phone_api_file_cancelled: line={entry.line_number}")

    def cancel_order(self, entry: LocalPhoneApiEntry) -> None:
        self.cancel(entry)

    def mark_order_completed(self, entry: LocalPhoneApiEntry) -> None:
        if self.usage_mode == LOCAL_PHONE_USAGE_MODE_OAUTH_EMAIL_ROUND_ROBIN:
            self._mark_round_robin_order_completed(entry)
            return
        self._update_entry_status(
            entry,
            status=PHONE_STATUS_DONE,
            expected_statuses={PHONE_STATUS_PENDING},
            log_message=f"phone_api_file_completed: line={entry.line_number}",
        )

    def _mark_round_robin_order_completed(self, entry: LocalPhoneApiEntry) -> None:
        if not self.number_file.exists():
            return
        with self._global_state_guard():
            lines = self._load_number_lines()
            valid_entries = self._list_valid_entries(lines)
            state = self._build_round_robin_state(
                self._load_state(),
                valid_entries=valid_entries,
                total_lines=len(lines),
            )
            usage_counts = dict(state.get("usage_counts") or {})
            current_count = int(usage_counts.get(str(entry.line_number), 0) or 0)
            next_count = min(current_count + 1, get_round_robin_max_success_reuse())
            next_status = PHONE_STATUS_DONE if next_count >= get_round_robin_max_success_reuse() else ""
            if not self._set_line_status(
                lines,
                line_number=int(entry.line_number or 0),
                status=next_status,
                expected_statuses={PHONE_STATUS_PENDING},
            ):
                return
            usage_counts[str(entry.line_number)] = next_count
            pending_by_owner = {
                owner: line
                for owner, line in dict(state.get("pending_by_owner") or {}).items()
                if int(line or 0) != int(entry.line_number or 0)
            }
            updated_state = {
                **state,
                "usage_counts": usage_counts,
                "pending_by_owner": pending_by_owner,
            }
            self._save_number_lines(lines)
            self._save_round_robin_state(
                updated_state,
                valid_entries=valid_entries,
                total_lines=len(lines),
            )
        _safe_log(
            self.log_fn,
            f"phone_api_file_completed_round_robin: line={entry.line_number} success_count={next_count}",
        )

    def mark_pending_owner_completed(self, owner_key: str) -> bool:
        normalized_owner = _normalize_owner_key(owner_key)
        if not normalized_owner or self.usage_mode != LOCAL_PHONE_USAGE_MODE_OAUTH_EMAIL_ROUND_ROBIN:
            return False
        if not self.number_file.exists():
            return False
        entry_to_complete: LocalPhoneApiEntry | None = None
        with self._global_state_guard():
            lines = self._load_number_lines()
            valid_entries = self._list_valid_entries(lines)
            state = self._build_round_robin_state(
                self._load_state(),
                valid_entries=valid_entries,
                total_lines=len(lines),
            )
            pending_line_number = int(dict(state.get("pending_by_owner") or {}).get(normalized_owner) or 0)
            if pending_line_number <= 0:
                return False
            for line_number, raw_phone, code_url, status in valid_entries:
                if line_number != pending_line_number or status != PHONE_STATUS_PENDING:
                    continue
                entry_to_complete = LocalPhoneApiEntry(
                    phone=self._build_phone_number(raw_phone),
                    raw_phone=raw_phone,
                    code_url=code_url,
                    activation_id=f"local-file-line-{line_number}",
                    line_number=line_number,
                    country=self.number_prefix,
                    country_slug=self.number_prefix.lstrip("+"),
                )
                break
        if entry_to_complete is None:
            return False
        self._mark_round_robin_order_completed(entry_to_complete)
        return True

    def mark_blacklisted(self, phone: str) -> None:
        if self._mark_phone_blacklisted(phone):
            _safe_log(self.log_fn, f"phone_api_file_blacklisted: phone={phone}")
            return
        _safe_log(self.log_fn, f"phone_api_file_blacklisted: phone={phone}")

    def mark_cooldown(self, phone: str, seconds: Optional[int] = None) -> None:
        try:
            secs_int = int(seconds) if seconds is not None else 0  # type: ignore[arg-type]
        except Exception:
            secs_int = 0
        cooldown_secs = secs_int if secs_int > 0 else DEFAULT_COOLDOWN_SECONDS
        if self._mark_phone_cooldown(phone, seconds):
            _safe_log(
                self.log_fn,
                f"phone_api_file_cooldown: phone={phone} seconds={cooldown_secs}",
            )
            return
        _safe_log(
            self.log_fn,
            f"phone_api_file_cooldown: phone={phone} seconds={cooldown_secs} (phone_not_found)",
        )
