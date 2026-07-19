from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

try:
    from local_phone_api import (
        LOCAL_PHONE_USAGE_MODE_SINGLE_USE,
        LocalPhoneApiError,
        LocalPhoneApiPhoneService,
        LocalPhoneApiTimeoutError,
        LocalPhoneApiUnusableNumberError,
        uses_local_phone_api_file,
    )
except Exception:  # pragma: no cover - optional provider
    LOCAL_PHONE_USAGE_MODE_SINGLE_USE = "single_use"
    LocalPhoneApiError = RuntimeError
    LocalPhoneApiTimeoutError = RuntimeError
    class LocalPhoneApiUnusableNumberError(RuntimeError):
        pass
    LocalPhoneApiPhoneService = None  # type: ignore[assignment]

    def uses_local_phone_api_file(_config: Optional[dict[str, Any]] = None) -> bool:
        return False

try:
    from sms_provider import BaseSmsProvider, SmsActivation, create_sms_provider
except Exception:  # pragma: no cover - optional provider
    BaseSmsProvider = None  # type: ignore[assignment,misc]
    SmsActivation = None  # type: ignore[assignment,misc]
    create_sms_provider = None  # type: ignore[assignment]


class SmsPhoneTimeoutError(TimeoutError):
    pass


class SmsPhoneUnusableNumberError(RuntimeError):
    pass


class ManualPhoneReplacedError(RuntimeError):
    pass


class ManualPhoneControlTimeoutError(TimeoutError):
    pass


_SMS_PENDING_LOCK = threading.Lock()
_SMS_PENDING_BY_OWNER: dict[str, "HttpPhoneCandidate"] = {}
_MANUAL_PHONE_LOCK = threading.Lock()
_MANUAL_PHONE_SERVICES: dict[str, "ManualPhoneService"] = {}


@dataclass
class HttpPhoneCandidate:
    phone: str
    source: str
    codes: list[str] = field(default_factory=list)
    service: Any = None
    entry: Any = None
    owner_key: str = ""


@dataclass
class ManualPhoneEntry:
    attempt_id: int
    phone_number: str


def _safe_log(log_fn: Optional[Callable[[str], None]], message: str) -> None:
    if callable(log_fn):
        log_fn(str(message))


def _iter_config_scopes(config: dict[str, Any]):
    if isinstance(config, dict):
        yield config
        for key in ("registration_flow", "http_auth", "phone_verification", "add_phone"):
            value = config.get(key)
            if isinstance(value, dict):
                yield value
        register_cfg = config.get("register")
        if isinstance(register_cfg, dict):
            yield register_cfg
            phone_cfg = register_cfg.get("phone")
            if isinstance(phone_cfg, dict):
                yield phone_cfg


def _get_config_value(config: dict[str, Any], *keys: str) -> str:
    for scope in _iter_config_scopes(config):
        for key in keys:
            value = str(scope.get(key) or "").strip()
            if value:
                return value
    return ""


def _sms_provider_config(config: dict[str, Any]) -> dict[str, Any]:
    known_keys = {
        "sms_provider",
        "sms_api_key",
        "sms_country",
        "sms_service",
        "sms_max_price",
        "sms_proxy",
        "proxy",
        "sms_reuse_phone",
        "sms_phone_success_max",
        "sms_allowed_countries",
        "sms_auto_select_country",
        "sms_auto_min_stock",
        "sms_auto_max_price",
        "sms_strict_whitelist",
    }
    merged: dict[str, Any] = {}
    for scope in _iter_config_scopes(config):
        merged.update({key: scope[key] for key in known_keys if key in scope})
    return merged


def _sms_provider_enabled(config: dict[str, Any]) -> bool:
    return str(_sms_provider_config(config).get("sms_provider") or "").strip().lower() in {
        "smsbower",
        "sms_bower",
        "herosms",
        "hero_sms",
    }


def _config_bool(value: Any, default: bool = False) -> bool:
    if value in (None, ""):
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _manual_phone_control_path(config: dict[str, Any]) -> str:
    return _get_config_value(config, "manual_phone_control_path", "manual_phone_ipc_dir")


def _manual_phone_enabled(config: dict[str, Any]) -> bool:
    return bool(_manual_phone_control_path(config))


def _read_control_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _write_control_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    temp_path.write_text(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
        encoding="utf-8",
    )
    try:
        temp_path.chmod(0o600)
    except OSError:
        pass
    temp_path.replace(path)


def _normalize_manual_phone(value: Any) -> str:
    raw = str(value or "").strip()
    normalized = "".join(ch for ch in raw if ch.isdigit() or ch == "+")
    if normalized.count("+") > 1 or ("+" in normalized and not normalized.startswith("+")):
        return ""
    digits = "".join(ch for ch in normalized if ch.isdigit())
    if not normalized.startswith("+") or len(digits) < 8 or len(digits) > 15:
        return ""
    return f"+{digits}"


def _mask_manual_phone(phone: str) -> str:
    value = str(phone or "").strip()
    if len(value) <= 7:
        return "*" * len(value)
    return f"{value[:3]}***{value[-4:]}"


class ManualPhoneService:
    """File-backed phone/code bridge that keeps one OAuth request context alive."""

    def __init__(
        self,
        config: dict[str, Any],
        *,
        log_fn: Optional[Callable[[str], None]] = None,
        owner_key: str = "",
    ) -> None:
        control_path = _manual_phone_control_path(config)
        if not control_path:
            raise RuntimeError("manual phone control path is missing")
        self.control_dir = Path(control_path).expanduser().resolve()
        self.control_dir.mkdir(parents=True, exist_ok=True)
        self.phone_path = self.control_dir / "phone.json"
        self.code_path = self.control_dir / "code.json"
        self.status_path = self.control_dir / "status.json"
        self.log_fn = log_fn
        self.owner_key = str(owner_key or "").strip()
        self.current_attempt_id = int(_read_control_json(self.status_path).get("attemptId") or 0)
        self.current_phone = ""
        self.timeout_seconds = max(
            120,
            int(_get_config_value(config, "manual_phone_timeout_seconds") or 1800),
        )
        self.closed = False

    def _publish(self, phase: str, *, error: str = "", active: bool = True) -> None:
        existing = _read_control_json(self.status_path)
        payload = {
            "sessionId": str(existing.get("sessionId") or ""),
            "jobId": str(existing.get("jobId") or ""),
            "phase": str(phase or ""),
            "active": bool(active),
            "attemptId": int(self.current_attempt_id or 0),
            "phoneMasked": _mask_manual_phone(self.current_phone),
            "error": str(error or "")[:1000],
            "updatedAtEpoch": time.time(),
        }
        _write_control_json(self.status_path, payload)

    def acquire_phone(self) -> ManualPhoneEntry:
        previous_error = str(_read_control_json(self.status_path).get("error") or "")
        self._publish("waiting_phone", error=previous_error)
        deadline = time.monotonic() + self.timeout_seconds
        while time.monotonic() < deadline:
            command = _read_control_json(self.phone_path)
            attempt_id = int(command.get("attemptId") or 0)
            if attempt_id > self.current_attempt_id:
                phone = _normalize_manual_phone(command.get("phoneNumber"))
                if not phone:
                    self.current_attempt_id = attempt_id
                    self.current_phone = ""
                    self._publish("retry_phone", error="手机号格式无效，请填写 +国家码手机号。")
                    continue
                self.current_attempt_id = attempt_id
                self.current_phone = phone
                self._publish("sending_code")
                _safe_log(self.log_fn, "http_add_phone using manually entered phone number")
                return ManualPhoneEntry(attempt_id=attempt_id, phone_number=phone)
            time.sleep(0.25)
        raise ManualPhoneControlTimeoutError("manual phone input timed out")

    def wait_for_code(self, entry: ManualPhoneEntry, timeout: Optional[int] = None) -> str:
        self._publish("waiting_code")
        deadline = time.monotonic() + max(120, int(timeout or self.timeout_seconds))
        while time.monotonic() < deadline:
            phone_command = _read_control_json(self.phone_path)
            if int(phone_command.get("attemptId") or 0) > int(entry.attempt_id):
                raise ManualPhoneReplacedError("manual phone number was replaced")
            code_command = _read_control_json(self.code_path)
            if int(code_command.get("attemptId") or 0) == int(entry.attempt_id):
                code = "".join(ch for ch in str(code_command.get("code") or "") if ch.isdigit())
                if code:
                    try:
                        self.code_path.unlink(missing_ok=True)
                    except OSError:
                        pass
                    self._publish("verifying")
                    return code
            time.sleep(0.25)
        raise ManualPhoneControlTimeoutError("manual phone verification code timed out")

    def report_failure(self, error: str) -> None:
        self._publish("retry_phone", error=str(error or "手机号验证失败，请更换号码后重试。"))

    def mark_order_completed(self, _entry: Any) -> None:
        self.closed = True
        self._publish("completed", active=False)
        for path in (self.phone_path, self.code_path):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass

    def cancel_order(self, _entry: Any) -> None:
        return None

    def mark_blacklisted(self, _phone: str) -> None:
        return None

    def mark_cooldown(self, _phone: str, _seconds: Optional[int] = None) -> None:
        return None


def _get_or_create_manual_phone_service(
    config: dict[str, Any],
    *,
    log_fn: Optional[Callable[[str], None]] = None,
    owner_key: str = "",
) -> ManualPhoneService:
    control_key = str(Path(_manual_phone_control_path(config)).expanduser().resolve())
    with _MANUAL_PHONE_LOCK:
        service = _MANUAL_PHONE_SERVICES.get(control_key)
        if service is None or service.closed:
            service = ManualPhoneService(config, log_fn=log_fn, owner_key=owner_key)
            _MANUAL_PHONE_SERVICES[control_key] = service
        return service


class SmsActivationPhoneService:
    def __init__(
        self,
        config: dict[str, Any],
        *,
        log_fn: Optional[Callable[[str], None]] = None,
        owner_key: str = "",
    ) -> None:
        sms_config = _sms_provider_config(config)
        provider_key = str(sms_config.get("sms_provider") or "").strip().lower()
        if create_sms_provider is None:
            raise RuntimeError("SMS provider module is unavailable")
        self.config = sms_config
        self.provider_key = provider_key
        self.provider: BaseSmsProvider = create_sms_provider(provider_key, sms_config)
        self.log_fn = log_fn
        self.owner_key = str(owner_key or "").strip()
        self.activation: Any = None
        self.closed = False

    def acquire_phone(self) -> Any:
        service = str(self.config.get("sms_service") or "dr").strip() or "dr"
        country = str(self.config.get("sms_country") or "52").strip() or "52"
        allowed_raw = str(self.config.get("sms_allowed_countries") or "").strip()
        candidates = [
            value.strip()
            for value in allowed_raw.replace(";", ",").split(",")
            if value.strip()
        ]
        if _config_bool(self.config.get("sms_auto_select_country")) and hasattr(self.provider, "get_best_country"):
            try:
                selected = self.provider.get_best_country(
                    service=service,
                    allowed_countries=candidates or None,
                    strict_whitelist=_config_bool(self.config.get("sms_strict_whitelist")),
                )
                if selected:
                    country = str(selected)
                    candidates = [country]
            except Exception:
                pass
        self.activation = self.provider.get_number(
            service=service,
            country=country,
            country_candidates=candidates or None,
        )
        try:
            self._write_activation_journal()
        except Exception as error:
            activation_id = str(getattr(self.activation, "activation_id", "") or "").strip()
            try:
                cancelled = bool(activation_id and self.provider.cancel(activation_id))
            except Exception:
                cancelled = False
            if cancelled:
                self.closed = True
                self._clear_activation_journal()
            outcome = "rental was cancelled" if cancelled else "rental cancellation was not confirmed"
            raise RuntimeError(f"SMS activation recovery journal could not be saved; {outcome}") from error
        _safe_log(self.log_fn, f"http_add_phone using {self.provider_key} SMS provider")
        return self.activation

    def wait_for_code(self, entry: Any, timeout: Optional[int] = None) -> str:
        activation = entry or self.activation
        activation_id = str(getattr(activation, "activation_id", "") or "").strip()
        if not activation_id:
            raise SmsPhoneUnusableNumberError("SMS provider activation is missing")
        self.provider.mark_send_succeeded(activation_id)
        code = str(self.provider.get_code(activation_id, timeout=int(timeout or 180)) or "").strip()
        if not code:
            raise SmsPhoneTimeoutError("SMS verification code timed out")
        return code

    def mark_order_completed(self, entry: Any) -> None:
        if self.closed:
            return
        activation_id = str(getattr(entry or self.activation, "activation_id", "") or "").strip()
        settled = bool(activation_id and self.provider.report_success(activation_id))
        if settled:
            self.closed = True
            self._clear_activation_journal()
            self._remove_pending()
            return
        _safe_log(self.log_fn, "SMS provider did not confirm settlement; attempting cancellation")
        cancelled = bool(activation_id and self.provider.cancel(activation_id))
        if cancelled:
            self.closed = True
            self._clear_activation_journal()
            self._remove_pending()
            return
        raise RuntimeError("SMS provider did not confirm settlement or cancellation")

    def cancel_order(self, entry: Any) -> None:
        if self.closed:
            return
        activation_id = str(getattr(entry or self.activation, "activation_id", "") or "").strip()
        cancelled = bool(activation_id and self.provider.cancel(activation_id))
        if not cancelled:
            raise RuntimeError("SMS provider did not confirm cancellation")
        self.closed = True
        self._clear_activation_journal()
        self._remove_pending()

    def mark_blacklisted(self, _phone: str) -> None:
        self.cancel_order(self.activation)

    def mark_cooldown(self, _phone: str, _seconds: Optional[int] = None) -> None:
        self.cancel_order(self.activation)

    def _remove_pending(self) -> None:
        if not self.owner_key:
            return
        with _SMS_PENDING_LOCK:
            current = _SMS_PENDING_BY_OWNER.get(self.owner_key)
            if current is not None and current.service is self:
                _SMS_PENDING_BY_OWNER.pop(self.owner_key, None)

    def _activation_journal_path(self) -> Optional[Path]:
        raw = str(os.environ.get("REG_2FA_SMS_ACTIVATION_PATH") or "").strip()
        return Path(raw).expanduser() if raw else None

    def _write_activation_journal(self) -> None:
        path = self._activation_journal_path()
        activation_id = str(getattr(self.activation, "activation_id", "") or "").strip()
        if path is None or not activation_id:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
        temp_path.write_text(
            json.dumps(
                {
                    "provider": self.provider_key,
                    "activationId": activation_id,
                    "country": str(getattr(self.activation, "country", "") or ""),
                    "service": str(self.config.get("sms_service") or "dr"),
                    "proxy": str(self.config.get("sms_proxy") or self.config.get("proxy") or ""),
                },
                ensure_ascii=True,
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        try:
            temp_path.chmod(0o600)
        except OSError:
            pass
        temp_path.replace(path)

    def _clear_activation_journal(self) -> None:
        path = self._activation_journal_path()
        if path is None:
            return
        artifacts = [path]
        try:
            artifacts.extend(path.parent.glob(f"{path.name}.*.tmp"))
        except OSError:
            pass
        for artifact in artifacts:
            try:
                artifact.unlink(missing_ok=True)
            except OSError:
                pass


def _get_configured_phone_number(config: dict[str, Any]) -> str:
    raw = _get_config_value(
        config,
        "chatgpt_add_phone_number",
        "openai_add_phone_number",
        "chatgpt_phone_number",
        "openai_phone_number",
    )
    if not raw:
        return ""
    normalized = "".join(ch for ch in raw if ch.isdigit() or ch == "+")
    if normalized.startswith("+"):
        return normalized
    country = _get_config_value(
        config,
        "chatgpt_add_phone_country_code",
        "openai_add_phone_country_code",
        "chatgpt_phone_country_code",
        "openai_phone_country_code",
    )
    country_digits = "".join(ch for ch in country if ch.isdigit())
    return f"+{country_digits}{normalized}" if country_digits else normalized


def _get_configured_phone_codes(config: dict[str, Any]) -> list[str]:
    raw = _get_config_value(
        config,
        "chatgpt_add_phone_otp_codes",
        "chatgpt_add_phone_otp_code",
        "openai_add_phone_otp_codes",
        "openai_add_phone_otp_code",
        "chatgpt_phone_otp_codes",
        "chatgpt_phone_otp_code",
        "openai_phone_otp_codes",
        "openai_phone_otp_code",
    )
    if not raw:
        return []
    codes: list[str] = []
    for chunk in raw.replace("\n", ",").replace(";", ",").split(","):
        code = "".join(ch for ch in str(chunk or "") if ch.isdigit()).strip()
        if code:
            codes.append(code)
    return codes


def acquire_http_phone_candidate(
    config: dict[str, Any],
    *,
    log_fn: Optional[Callable[[str], None]] = None,
    local_phone_usage_mode: str = LOCAL_PHONE_USAGE_MODE_SINGLE_USE,
    owner_key: str = "",
) -> HttpPhoneCandidate:
    cfg = dict(config or {})
    if _manual_phone_enabled(cfg):
        service = _get_or_create_manual_phone_service(
            cfg,
            log_fn=log_fn,
            owner_key=owner_key,
        )
        entry = service.acquire_phone()
        return HttpPhoneCandidate(
            phone=str(entry.phone_number or "").strip(),
            source="manual",
            service=service,
            entry=entry,
            owner_key=str(owner_key or "").strip(),
        )

    configured_phone = _get_configured_phone_number(cfg)
    if configured_phone:
        _safe_log(log_fn, "http_add_phone using configured phone number")
        return HttpPhoneCandidate(
            phone=configured_phone,
            source="configured",
            codes=_get_configured_phone_codes(cfg),
            owner_key=str(owner_key or "").strip(),
        )

    if _sms_provider_enabled(cfg):
        service = SmsActivationPhoneService(cfg, log_fn=log_fn, owner_key=owner_key)
        entry = service.acquire_phone()
        phone = str(getattr(entry, "phone_number", "") or "").strip()
        if not phone:
            service.cancel_order(entry)
            raise SmsPhoneUnusableNumberError("SMS provider returned an empty phone number")
        candidate = HttpPhoneCandidate(
            phone=phone,
            source=service.provider_key,
            service=service,
            entry=entry,
            owner_key=str(owner_key or "").strip(),
        )
        if candidate.owner_key:
            with _SMS_PENDING_LOCK:
                _SMS_PENDING_BY_OWNER[candidate.owner_key] = candidate
        return candidate

    if uses_local_phone_api_file(cfg):
        if LocalPhoneApiPhoneService is None:
            raise RuntimeError("local_phone_api provider is unavailable")
        service = LocalPhoneApiPhoneService(
            cfg,
            log_fn=log_fn,
            usage_mode=str(local_phone_usage_mode or LOCAL_PHONE_USAGE_MODE_SINGLE_USE).strip()
            or LOCAL_PHONE_USAGE_MODE_SINGLE_USE,
        )
        entry = service.acquire_phone(owner_key=str(owner_key or "").strip())
        if entry is None:
            raise RuntimeError("local phone provider did not return a phone number")
        return HttpPhoneCandidate(
            phone=str(getattr(entry, "phone", "") or "").strip(),
            source="local_api_file",
            service=service,
            entry=entry,
            owner_key=str(owner_key or "").strip(),
        )

    raise RuntimeError(
        "add-phone requires a phone provider. Configure chatgpt_add_phone_number/openai_add_phone_number "
        "or register.phone.provider=local_api_file."
    )


def acquire_pending_http_phone_candidate(
    config: dict[str, Any],
    *,
    log_fn: Optional[Callable[[str], None]] = None,
    local_phone_usage_mode: str = LOCAL_PHONE_USAGE_MODE_SINGLE_USE,
    owner_key: str = "",
) -> Optional[HttpPhoneCandidate]:
    cfg = dict(config or {})
    if owner_key and _manual_phone_enabled(cfg):
        service = _get_or_create_manual_phone_service(
            cfg,
            log_fn=log_fn,
            owner_key=owner_key,
        )
        if service.current_phone and service.current_attempt_id > 0:
            entry = ManualPhoneEntry(
                attempt_id=int(service.current_attempt_id),
                phone_number=str(service.current_phone),
            )
        else:
            entry = service.acquire_phone()
        return HttpPhoneCandidate(
            phone=str(entry.phone_number or "").strip(),
            source="manual",
            service=service,
            entry=entry,
            owner_key=str(owner_key or "").strip(),
        )
    if owner_key and _sms_provider_enabled(cfg):
        with _SMS_PENDING_LOCK:
            candidate = _SMS_PENDING_BY_OWNER.get(str(owner_key or "").strip())
        if candidate is not None:
            return candidate
    if not owner_key or not uses_local_phone_api_file(cfg) or LocalPhoneApiPhoneService is None:
        return None
    service = LocalPhoneApiPhoneService(
        cfg,
        log_fn=log_fn,
        usage_mode=str(local_phone_usage_mode or LOCAL_PHONE_USAGE_MODE_SINGLE_USE).strip()
        or LOCAL_PHONE_USAGE_MODE_SINGLE_USE,
    )
    getter = getattr(service, "get_pending_owner_phone", None)
    if not callable(getter):
        return None
    entry = getter(str(owner_key or "").strip())
    if entry is None:
        return None
    return HttpPhoneCandidate(
        phone=str(getattr(entry, "phone", "") or "").strip(),
        source="local_api_file_pending",
        service=service,
        entry=entry,
        owner_key=str(owner_key or "").strip(),
    )


def wait_for_http_phone_code(
    candidate: HttpPhoneCandidate,
    *,
    timeout: Optional[int] = None,
) -> str:
    if candidate.codes:
        return str(candidate.codes.pop(0) or "").strip()
    service = candidate.service
    entry = candidate.entry
    if service is not None and entry is not None:
        return str(service.wait_for_code(entry, timeout=timeout) or "").strip()
    return ""


def mark_http_phone_completed(candidate: HttpPhoneCandidate) -> None:
    service = candidate.service
    entry = candidate.entry
    if service is not None and entry is not None:
        service.mark_order_completed(entry)


def mark_http_phone_completed_for_owner(
    config: dict[str, Any],
    *,
    owner_key: str,
    log_fn: Optional[Callable[[str], None]] = None,
    local_phone_usage_mode: str = LOCAL_PHONE_USAGE_MODE_SINGLE_USE,
) -> bool:
    cfg = dict(config or {})
    if not owner_key or not uses_local_phone_api_file(cfg) or LocalPhoneApiPhoneService is None:
        return False
    service = LocalPhoneApiPhoneService(
        cfg,
        log_fn=log_fn,
        usage_mode=str(local_phone_usage_mode or LOCAL_PHONE_USAGE_MODE_SINGLE_USE).strip()
        or LOCAL_PHONE_USAGE_MODE_SINGLE_USE,
    )
    marker = getattr(service, "mark_pending_owner_completed", None)
    if not callable(marker):
        return False
    return bool(marker(owner_key))


def cancel_http_phone(candidate: HttpPhoneCandidate) -> None:
    service = candidate.service
    entry = candidate.entry
    if service is not None and entry is not None:
        service.cancel_order(entry)


def is_local_phone_one_shot_mode() -> bool:
    """单次尝试模式：每号失败即永久拉黑，不走冷却、不释放回号池复用。"""
    return str(os.environ.get("LOCAL_PHONE_ONE_SHOT", "") or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def blacklist_http_phone(candidate: HttpPhoneCandidate) -> None:
    service = candidate.service
    if service is not None and candidate.phone:
        service.mark_blacklisted(candidate.phone)


def cooldown_http_phone(candidate: HttpPhoneCandidate, seconds: Optional[int] = None) -> None:
    """将候选号标记为冷却（临时不可用，到期自动恢复），区别于永久拉黑。

    用于号收到验证码但 OpenAI validate 返回 recently used、或发码被临时限频等
    可恢复场景：号本身没坏，等冷却到期可再用，避免误当坏号永久拉黑。
    LOCAL_PHONE_ONE_SHOT=1 时改为永久拉黑（本轮任务每号只试一次）。
    """
    if is_local_phone_one_shot_mode():
        blacklist_http_phone(candidate)
        return
    service = candidate.service
    if service is not None and candidate.phone:
        marker = getattr(service, "mark_cooldown", None)
        if callable(marker):
            marker(candidate.phone, seconds)
        else:
            # 旧版 service 无 mark_cooldown，退化为拉黑以保持原行为
            service.mark_blacklisted(candidate.phone)


def dispose_http_phone_after_failure(candidate: HttpPhoneCandidate) -> None:
    """auth/add-phone 失败后处置号码：默认释放回号池；单次尝试模式则永久拉黑。"""
    if is_local_phone_one_shot_mode():
        blacklist_http_phone(candidate)
    else:
        cancel_http_phone(candidate)


def is_manual_http_phone(candidate: HttpPhoneCandidate) -> bool:
    return str(getattr(candidate, "source", "") or "").strip().lower() == "manual"


def report_http_phone_failure(candidate: HttpPhoneCandidate, error: str) -> None:
    service = getattr(candidate, "service", None)
    reporter = getattr(service, "report_failure", None)
    if callable(reporter):
        reporter(str(error or ""))


def is_phone_provider_timeout(error: BaseException) -> bool:
    return isinstance(error, (LocalPhoneApiTimeoutError, SmsPhoneTimeoutError))


def is_phone_provider_unusable(error: BaseException) -> bool:
    return isinstance(error, (LocalPhoneApiUnusableNumberError, SmsPhoneUnusableNumberError))
