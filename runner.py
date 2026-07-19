from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parent
X9_ROOT = ROOT / "X9-Free"
TOOLCORE = X9_ROOT / "_credential_toolcore"
for candidate in (str(X9_ROOT), str(TOOLCORE)):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

from desktop_auth_common import (  # noqa: E402
    run_bind_phone_flow,
    run_login_flow,
    run_register_flow,
    run_set_password_flow,
)


RESULT_PREFIX = "__ISOLATED_JOB_RESULT__="


def _namespace(payload: dict) -> SimpleNamespace:
    provider = payload.get("provider") if isinstance(payload.get("provider"), dict) else {}
    phone_verification = (
        dict(payload.get("phone_verification"))
        if isinstance(payload.get("phone_verification"), dict)
        else {}
    )
    mode = str(provider.get("mode") or "api").strip().lower()
    use_imap = mode in {"imap", "outlook_oauth"}
    return SimpleNamespace(
        email=str(payload.get("email") or "").strip().lower(),
        password=str(payload.get("accountPassword") or ""),
        full_name=str(payload.get("fullName") or "").strip(),
        birth_date=str(payload.get("birthDate") or "").strip(),
        proxy_url=str(payload.get("proxy") or "").strip(),
        trace=bool(payload.get("trace")),
        timeout_seconds=float(payload.get("registerTimeoutSeconds") or 360),
        otp_timeout_seconds=float(payload.get("otpTimeoutSeconds") or 180),
        otp_interval_seconds=float(payload.get("otpIntervalSeconds") or 2),
        disable_managed_mail_otp=True,
        managed_mail_provider="",
        managed_mail_jwt="",
        managed_mail_api_base="",
        managed_mail_frontend_base="",
        managed_mail_latest_n=20,
        otp_api_url=str(provider.get("apiUrl") or "").strip() if mode == "api" else "",
        use_imap_otp=use_imap,
        imap_host=str(provider.get("host") or ("outlook.office365.com" if mode == "outlook_oauth" else "")).strip(),
        imap_port=int(provider.get("port") or 993),
        imap_user=str(provider.get("username") or payload.get("email") or "").strip(),
        imap_pass=str(provider.get("password") or ""),
        imap_folder=str(provider.get("folder") or ("INBOX" if mode == "outlook_oauth" else "Inbox")).strip(),
        imap_latest_n=int(provider.get("latestN") or 80),
        imap_auth_type="oauth2" if mode == "outlook_oauth" else "password",
        imap_oauth_client_id=str(provider.get("clientId") or "").strip(),
        imap_oauth_refresh_token=str(provider.get("refreshToken") or "").strip(),
        imap_password_fallback=bool(provider.get("passwordFallback")),
        imap_pop3_fallback=bool(provider.get("pop3Fallback")),
        imap_profiles_file="",
        imap_profiles_json="",
        mfa_totp_secret="",
        disable_domain_mail_otp=True,
        domain_mail_api_base="",
        domain_mail_domain="",
        domain_mail_token="",
        domain_mail_latest_n=20,
        phone_verification=phone_verification,
        storage_state=str(payload.get("storageStatePath") or "").strip(),
    )


def _result_payload(result) -> dict:
    return {
        "success": bool(getattr(result, "success", False)),
        "email": str(getattr(result, "email", "") or ""),
        "message": str(getattr(result, "message", "") or ""),
        "storageStatePath": str(getattr(result, "storage_state_path", "") or ""),
        "atPath": str(getattr(result, "at_txt_path", "") or ""),
        "tracePath": str(getattr(result, "trace_path", "") or ""),
        "sessionSnapshotPath": str(getattr(result, "session_snapshot_path", "") or ""),
        "successCredentialPath": str(getattr(result, "success_credential_path", "") or ""),
        "boundPhone": str(getattr(result, "bound_phone", "") or ""),
        "stage": str(getattr(result, "stage", "") or ""),
        "errorCode": str(getattr(result, "error_code", "") or ""),
        "remotePasswordSet": bool(getattr(result, "remote_password_set", False)),
        "remotePasswordMode": str(getattr(result, "remote_password_mode", "") or ""),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run one isolated registration or login job")
    parser.add_argument("input_path")
    args = parser.parse_args(argv)
    path = Path(args.input_path).expanduser().resolve()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("job input must be a JSON object")
        operation = str(payload.get("operation") or "register").strip().lower()
        namespace = _namespace(payload)
        namespace.mfa_totp_secret = str(payload.get("mfaTotpSecret") or "").strip()
        if operation == "login":
            result = asyncio.run(run_login_flow(namespace))
        elif operation == "register":
            result = asyncio.run(run_register_flow(namespace))
        elif operation == "bind_phone":
            result = asyncio.run(run_bind_phone_flow(namespace))
        elif operation == "set_password":
            result = asyncio.run(run_set_password_flow(namespace))
        else:
            raise ValueError(f"unsupported operation: {operation}")
        output = _result_payload(result)
    except Exception as error:
        output = {
            "success": False,
            "message": str(error),
            "stage": "runner_exception",
            "errorCode": type(error).__name__,
        }
    print(RESULT_PREFIX + json.dumps(output, ensure_ascii=False, separators=(",", ":")), flush=True)
    return 0 if bool(output.get("success")) else 1


if __name__ == "__main__":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    raise SystemExit(main())
