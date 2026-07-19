from __future__ import annotations

import asyncio
import inspect
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TOOLCORE = ROOT / "X9-Free" / "_credential_toolcore"
for candidate in (str(ROOT), str(TOOLCORE)):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

import chatgpt_register_http as register_http  # noqa: E402
import chatgpt_login_http as login_http  # noqa: E402
import codex_oauth  # noqa: E402
import desktop_auth_common as auth_common  # noqa: E402
import http_phone_verification as phone_verification  # noqa: E402
import runner as isolated_runner  # noqa: E402
import sms_provider  # noqa: E402


class FakeSmsProvider:
    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def get_number(self, **kwargs):
        self.calls.append(("get_number", kwargs))
        return sms_provider.SmsActivation("activation-1", "+66812345678", "52")

    def mark_send_succeeded(self, activation_id: str) -> None:
        self.calls.append(("mark_send_succeeded", activation_id))

    def get_code(self, activation_id: str, *, timeout: int = 180) -> str:
        self.calls.append(("get_code", activation_id, timeout))
        return "123456"

    def report_success(self, activation_id: str) -> bool:
        self.calls.append(("report_success", activation_id))
        return True

    def cancel(self, activation_id: str) -> bool:
        self.calls.append(("cancel", activation_id))
        return True

    def mark_send_failed(self, activation_id: str, reason: str = "") -> None:
        self.calls.append(("mark_send_failed", activation_id, reason))


class SmsIntegrationTests(unittest.TestCase):
    def test_codex_phone_channel_helpers_prefer_options_without_treating_whatsapp_as_selected(self):
        payload = {
            "page": {"type": "phone_otp_select_channel"},
            "available_channels": ["whatsapp", "sms"],
            "continue_url": "https://auth.openai.com/phone-otp/select-channel",
        }

        self.assertTrue(
            codex_oauth._auth_phone_channel_selection_required(
                payload,
                url=payload["continue_url"],
            )
        )
        self.assertEqual(
            codex_oauth._auth_phone_channel_options(payload),
            ["whatsapp", "sms"],
        )
        self.assertEqual(
            codex_oauth._choose_auth_phone_channel(
                ["whatsapp", "sms"],
                allow_whatsapp=True,
            ),
            "sms",
        )
        self.assertEqual(
            codex_oauth._choose_auth_phone_channel(
                ["whatsapp"],
                allow_whatsapp=True,
            ),
            "whatsapp",
        )
        self.assertEqual(
            codex_oauth._choose_auth_phone_channel(
                ["whatsapp"],
                allow_whatsapp=False,
            ),
            "",
        )
        self.assertFalse(codex_oauth._auth_phone_forced_whatsapp(payload))
        self.assertTrue(
            codex_oauth._auth_phone_forced_whatsapp(
                {"channel": "whatsapp"},
            )
        )

    def test_phone_bind_success_requires_leaving_phone_verification_step(self):
        self.assertTrue(
            codex_oauth._auth_phone_step_still_active(
                {"page": {"type": "phone_otp_verification"}},
                url="https://auth.openai.com/phone-verification",
            )
        )
        self.assertFalse(
            codex_oauth._auth_phone_step_still_active(
                {"continue_url": "https://chatgpt.com/"},
                url="https://chatgpt.com/",
            )
        )
        self.assertTrue(codex_oauth._auth_phone_bind_progress_url("https://chatgpt.com/"))
        self.assertFalse(
            codex_oauth._auth_phone_bind_progress_url(
                "https://auth.openai.com/phone-verification"
            )
        )

    def test_manual_phone_retry_classifier_rejects_broken_authorization_state(self):
        self.assertTrue(
            codex_oauth._is_retryable_manual_phone_error(
                RuntimeError(
                    "http_auth_add_phone_failed: phone-otp/validate failed: wrong phone otp code"
                )
            )
        )
        self.assertFalse(
            codex_oauth._is_retryable_manual_phone_error(
                RuntimeError(
                    "http_auth_add_phone_failed: phone verification send failed: Invalid authorization step."
                )
            )
        )
        self.assertFalse(
            codex_oauth._is_retryable_manual_phone_error(
                RuntimeError(
                    "http_auth_add_phone_failed: phone verification send failed: too many phone verification requests"
                )
            )
        )

    def test_pending_select_channel_recovers_manual_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            control_dir = Path(directory)
            (control_dir / "status.json").write_text(
                '{"attemptId":0,"phase":"starting","active":true}',
                encoding="utf-8",
            )
            (control_dir / "phone.json").write_text(
                '{"attemptId":1,"phoneNumber":"+66812345678"}',
                encoding="utf-8",
            )
            candidate = phone_verification.acquire_pending_http_phone_candidate(
                {"manual_phone_control_path": str(control_dir)},
                owner_key="user@example.com",
            )

        self.assertIsNotNone(candidate)
        self.assertEqual(candidate.phone, "+66812345678")
        self.assertEqual(candidate.source, "manual")

    def test_manual_phone_retry_uses_loop_instead_of_recursive_await(self):
        source = inspect.getsource(codex_oauth.run_codex_oauth_http_flow)
        retry_wrapper = source.split(
            "async def _complete_http_add_phone_if_required",
            1,
        )[1].split(
            "async def _complete_http_codex_consent_via_browser",
            1,
        )[0]
        self.assertIn("while True:", retry_wrapper)
        self.assertNotIn("return await _complete_http_add_phone_if_required", source)

    def test_post_registration_bind_reuses_state_and_preserves_local_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "state.json"
            state_path.write_text(
                '{"cookies":[{"name":"session","value":"old"}],'
                '"accessToken":"existing-token",'
                '"mfa_summary":{"status":"enabled","secret":"JBSWY3DPEHPK3PXP"}}',
                encoding="utf-8",
            )
            args = isolated_runner._namespace(
                {
                    "operation": "bind_phone",
                    "email": "user@example.com",
                    "accountPassword": "account-password",
                    "storageStatePath": str(state_path),
                    "provider": {
                        "mode": "api",
                        "apiUrl": "https://mail.test/latest?token=email-secret",
                    },
                    "phone_verification": {
                        "sms_provider": "herosms",
                        "sms_api_key": "hero-secret",
                        "sms_country": "52",
                        "sms_service": "dr",
                    },
                }
            )
            args.mfa_totp_secret = "JBSWY3DPEHPK3PXP"
            oauth_result = {
                "success": True,
                "bound_phone": "+66812345678",
                "trace_path": "trace.jsonl",
                "storage_state": {
                    "cookies": [{"name": "session", "value": "new"}],
                    "origins": [],
                },
            }
            with mock.patch.object(
                auth_common,
                "run_codex_oauth_flow",
                new=mock.AsyncMock(return_value=oauth_result),
            ) as oauth:
                result = asyncio.run(auth_common.run_bind_phone_flow(args))

            self.assertTrue(result.success)
            self.assertEqual(result.bound_phone, "+66812345678")
            self.assertTrue(oauth.call_args.kwargs["require_phone_bind"])
            self.assertEqual(
                oauth.call_args.kwargs["otp_api_url"],
                "https://mail.test/latest?token=email-secret",
            )
            self.assertEqual(oauth.call_args.kwargs["mfa_totp_secret"], "JBSWY3DPEHPK3PXP")
            self.assertEqual(
                oauth.call_args.kwargs["phone_verification"]["sms_provider"],
                "herosms",
            )
            saved = auth_common.load_json(state_path)
            self.assertEqual(saved["cookies"][0]["value"], "new")
            self.assertEqual(saved["accessToken"], "existing-token")
            self.assertEqual(saved["mfa_summary"]["secret"], "JBSWY3DPEHPK3PXP")

    def test_post_registration_bind_fails_without_a_real_add_phone_transaction(self):
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "state.json"
            state_path.write_text('{"cookies":[{"name":"session","value":"old"}]}', encoding="utf-8")
            args = isolated_runner._namespace(
                {
                    "operation": "bind_phone",
                    "email": "user@example.com",
                    "storageStatePath": str(state_path),
                    "phone_verification": {
                        "sms_provider": "smsbower",
                        "sms_api_key": "secret",
                    },
                }
            )
            with mock.patch.object(
                auth_common,
                "run_codex_oauth_flow",
                new=mock.AsyncMock(return_value={"success": True, "trace_path": "trace.jsonl"}),
            ):
                result = asyncio.run(auth_common.run_bind_phone_flow(args))

        self.assertFalse(result.success)
        self.assertEqual(result.error_code, "phone_bind_not_offered")

    def test_normal_registration_never_forwards_sms_configuration(self):
        args = isolated_runner._namespace(
            {
                "operation": "register",
                "email": "user@example.com",
                "accountPassword": "account-password",
                "fullName": "Example User",
                "phone_verification": {
                    "sms_provider": "smsbower",
                    "sms_api_key": "must-not-be-forwarded",
                },
            }
        )
        failure = SimpleNamespace(
            success=False,
            message="mock registration stopped",
            details={},
            stage="mock",
            errorCode="mock",
        )
        with mock.patch.object(
            auth_common,
            "run_chatgpt_http_register",
            new=mock.AsyncMock(return_value=failure),
        ) as register:
            result = asyncio.run(auth_common.run_register_flow(args))

        self.assertFalse(result.success)
        self.assertEqual(register.call_args.kwargs["config"].phoneVerification, {})

    def test_registration_session_failure_is_structured_instead_of_runner_exception(self):
        args = isolated_runner._namespace(
            {
                "operation": "register",
                "email": "user@example.com",
                "accountPassword": "account-password",
                "provider": {"mode": "api", "apiUrl": "https://mail.test/code"},
            }
        )
        registered = SimpleNamespace(
            success=True,
            message="registered",
            details={
                "storageStatePath": "state.json",
                "accessTokenPresent": True,
                "remotePasswordSet": True,
                "remotePasswordMode": "signup_password_step",
            },
            stage="registration_authenticated",
            errorCode="",
        )
        with (
            mock.patch.object(
                auth_common,
                "run_chatgpt_http_register",
                new=mock.AsyncMock(return_value=registered),
            ),
            mock.patch.object(
                auth_common,
                "extract_at_from_storage_state",
                new=mock.AsyncMock(side_effect=RuntimeError("session 响应缺少 accessToken（可能未登录）")),
            ),
        ):
            result = asyncio.run(auth_common.run_register_flow(args))

        self.assertFalse(result.success)
        self.assertEqual(result.stage, "registration_session_pending")
        self.assertEqual(result.error_code, "session_missing")
        self.assertEqual(result.storage_state_path, "state.json")
        self.assertIn("Session", result.message)

    def test_login_session_failure_is_structured_instead_of_runner_exception(self):
        args = isolated_runner._namespace(
            {
                "operation": "login",
                "email": "user@example.com",
                "accountPassword": "account-password",
                "provider": {"mode": "api", "apiUrl": "https://mail.test/code"},
            }
        )
        logged_in = SimpleNamespace(
            success=True,
            message="logged in",
            details={"storageStatePath": "state.json", "accessTokenPresent": True},
            stage="done",
            errorCode="",
        )
        with (
            mock.patch.object(
                auth_common,
                "run_chatgpt_http_login",
                new=mock.AsyncMock(return_value=logged_in),
            ),
            mock.patch.object(
                auth_common,
                "extract_at_from_storage_state",
                new=mock.AsyncMock(side_effect=RuntimeError("session 响应缺少 accessToken（可能未登录）")),
            ),
        ):
            result = asyncio.run(auth_common.run_login_flow(args))

        self.assertFalse(result.success)
        self.assertEqual(result.stage, "login_session_missing")
        self.assertEqual(result.error_code, "session_missing")
        self.assertEqual(result.storage_state_path, "state.json")

    def test_phone_required_detection_does_not_rent_during_registration_or_login(self):
        register_payload = {"page": {"type": "add_phone"}}
        login_payload = {"continue_url": "https://auth.openai.com/phone-otp/select-channel"}

        self.assertEqual(
            register_http._registration_phone_step(register_payload, ""),
            "add_phone",
        )
        self.assertEqual(
            auth_common.run_chatgpt_http_login.__module__,
            "chatgpt_login_http",
        )
        import chatgpt_login_http as login_http  # noqa: PLC0415

        self.assertEqual(login_http._login_phone_step(login_payload, ""), "select_channel")

    def test_codex_oauth_can_poll_the_jobs_api_email_source(self):
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _size):
                return b'{"verificationCode":"654321"}'

        with mock.patch.object(codex_oauth.urllib.request, "urlopen", return_value=FakeResponse()):
            code = codex_oauth._poll_otp_api_url_verification_code_sync(
                otp_api_url="https://mail.test/latest?token=secret",
                otp_timeout_sec=3,
                otp_interval_sec=1,
            )

        self.assertEqual(code, "654321")

    def test_http_login_pre_password_otp_uses_email_code_even_with_totp_secret(self):
        request = mock.AsyncMock(
            return_value={"status": 200, "text": "", "payload": {}}
        )
        with (
            mock.patch.object(login_http, "generate_totp_code") as generate_totp,
            mock.patch.object(
                login_http,
                "poll_otp_api_url_verification_code_sync",
                return_value="654321",
            ),
            mock.patch.object(login_http, "_request_auth_api_with_context", new=request),
        ):
            result = asyncio.run(
                login_http._submit_http_otp_if_required(
                    request_ctx=object(),
                    payload={"page": {"type": "email_otp_verification"}},
                    safe_email="user@example.com",
                    trace=SimpleNamespace(write=mock.Mock()),
                    log=SimpleNamespace(info=mock.Mock(), warn=mock.Mock()),
                    timeout_sec=60,
                    otp_timeout_sec=30,
                    otp_interval_sec=1,
                    normalized_totp_secret="JBSWY3DPEHPK3PXP",
                    allow_totp=False,
                    use_managed_mail_otp=False,
                    managed_mail_provider="",
                    managed_mail_jwt="",
                    managed_mail_api_base="",
                    managed_mail_frontend_base="",
                    managed_mail_latest_n=20,
                    otp_api_url="https://mail.test/latest",
                    use_domain_mail_otp=False,
                    domain_mail_api_base="",
                    domain_mail_domain="",
                    domain_mail_token="",
                    domain_mail_latest_n=20,
                    use_imap_otp=False,
                    imap_host="",
                    imap_port=993,
                    imap_user="",
                    imap_pass="",
                    imap_folder="Inbox",
                    imap_latest_n=10,
                )
            )

        self.assertTrue(result["handled"])
        generate_totp.assert_not_called()
        self.assertEqual(request.call_args.kwargs["json_body"], {"code": "654321"})
        self.assertEqual(request.call_args.kwargs["trace_json_body"], {"code": "***"})

    def test_http_login_password_totp_stops_immediately_on_remote_cooldown(self):
        request = mock.AsyncMock(
            return_value={
                "status": 429,
                "text": "max_check_attempts",
                "payload": {"error": {"code": "max_check_attempts"}},
            }
        )
        with (
            mock.patch.object(login_http, "totp_seconds_remaining", return_value=20),
            mock.patch.object(login_http, "generate_totp_code", return_value="123456"),
            mock.patch.object(login_http, "_request_auth_api_with_context", new=request),
        ):
            with self.assertRaisesRegex(RuntimeError, "http_auth_totp_cooldown"):
                asyncio.run(
                    login_http._submit_http_otp_if_required(
                        request_ctx=object(),
                        payload={"page": {"type": "email_otp_verification"}},
                        safe_email="user@example.com",
                        trace=SimpleNamespace(write=mock.Mock()),
                        log=SimpleNamespace(info=mock.Mock(), warn=mock.Mock()),
                        timeout_sec=60,
                        otp_timeout_sec=30,
                        otp_interval_sec=1,
                        normalized_totp_secret="JBSWY3DPEHPK3PXP",
                        allow_totp=True,
                        use_managed_mail_otp=False,
                        managed_mail_provider="",
                        managed_mail_jwt="",
                        managed_mail_api_base="",
                        managed_mail_frontend_base="",
                        managed_mail_latest_n=20,
                        use_domain_mail_otp=False,
                        domain_mail_api_base="",
                        domain_mail_domain="",
                        domain_mail_token="",
                        domain_mail_latest_n=20,
                        use_imap_otp=False,
                        imap_host="",
                        imap_port=993,
                        imap_user="",
                        imap_pass="",
                        imap_folder="Inbox",
                        imap_latest_n=10,
                    )
                )

        self.assertEqual(request.call_count, 1)
        self.assertEqual(request.call_args.kwargs["trace_json_body"], {"code": "***"})

    def test_http_login_uses_email_recovery_when_remote_mfa_has_no_local_totp(self):
        requests = mock.AsyncMock(
            side_effect=[
                {"status": 200, "text": "", "payload": {}},
                {"status": 200, "text": "", "payload": {"page": {"type": "workspace"}}},
            ]
        )
        mfa_payload = {
            "continue_url": "https://auth.openai.com/mfa-challenge/totp-factor",
            "page": {
                "type": "mfa_challenge",
                "payload": {
                    "factors": [
                        {"id": "totp-factor", "factor_type": "totp"},
                        {
                            "id": "email-otp",
                            "factor_type": "email",
                            "metadata": {"email": "user@example.com"},
                        },
                    ]
                },
            },
        }
        with (
            mock.patch.object(login_http, "_request_auth_api_with_context", new=requests),
            mock.patch.object(
                login_http,
                "poll_otp_api_url_verification_code_sync",
                return_value="222222",
            ) as poll_code,
            mock.patch.object(login_http, "generate_totp_code") as generate_totp,
        ):
            result = asyncio.run(
                login_http._submit_http_mfa_challenge_if_required(
                    request_ctx=object(),
                    payload=mfa_payload,
                    continue_url=mfa_payload["continue_url"],
                    safe_email="user@example.com",
                    trace=SimpleNamespace(write=mock.Mock()),
                    log=SimpleNamespace(info=mock.Mock(), warn=mock.Mock()),
                    timeout_sec=60,
                    config=login_http.ChatGptHttpLoginConfig(
                        useManagedMailOtp=False,
                        useDomainMailOtp=False,
                        otpApiUrl="https://mail.test/latest",
                    ),
                    normalized_totp_secret="",
                    imap_profiles_json="",
                    previously_submitted_codes={"111111"},
                )
            )

        self.assertTrue(result["handled"])
        generate_totp.assert_not_called()
        self.assertEqual(
            [call.kwargs["path"] for call in requests.call_args_list],
            ["/mfa/issue_challenge", "/mfa/verify"],
        )
        self.assertEqual(requests.call_args_list[0].kwargs["json_body"]["type"], "email")
        self.assertEqual(requests.call_args_list[1].kwargs["json_body"]["code"], "222222")
        self.assertEqual(requests.call_args_list[1].kwargs["trace_json_body"]["code"], "***")
        self.assertIn("111111", poll_code.call_args.kwargs["blocked_codes"])

    def test_http_login_keeps_email_otp_and_mfa_totp_as_separate_steps(self):
        source = inspect.getsource(login_http.run_chatgpt_http_login)
        login_hint_call = source.split("login_hint_otp_result =", 1)[1].split(
            "if bool(login_hint_otp_result.get", 1
        )[0]
        final_call = source.split("final_otp_result =", 1)[1].split(
            "if bool(final_otp_result.get", 1
        )[0]

        self.assertIn("allow_totp=False", login_hint_call)
        self.assertIn("allow_totp=False", final_call)
        self.assertIn("_submit_http_mfa_challenge_if_required", source)
        self.assertIn("login_hint_otp_completed = True", source)
        password_submit_guard = source.split(
            'stage="submit_password",\n                step_name="提交密码"', 1
        )[0].rsplit("\n        if ", 1)[1]
        self.assertIn("not login_hint_otp_completed", password_submit_guard)

    def test_http_login_passes_job_proxy_to_sentinel_playwright_helper(self):
        proxy_url = "http://proxy-user:proxy-pass@proxy.test:8080"
        request_ctx = SimpleNamespace(dispose=mock.AsyncMock())
        collect_sentinel = mock.AsyncMock(side_effect=RuntimeError("stop after sentinel probe"))

        with (
            tempfile.TemporaryDirectory() as temp_dir,
            mock.patch.object(
                login_http,
                "_TraceWriter",
                return_value=SimpleNamespace(write=mock.Mock(), path=""),
            ),
            mock.patch.object(
                login_http,
                "activate_http_stage_feature_session",
                return_value=None,
            ),
            mock.patch.object(
                login_http,
                "_build_http_provider_request_context",
                return_value=request_ctx,
            ) as build_context,
            mock.patch.object(
                login_http,
                "_bootstrap_http_login_session",
                new=mock.AsyncMock(
                    return_value={
                        "loginUrl": "https://auth.openai.com/log-in",
                        "authorizeUrl": "",
                        "hasAuthSessionCookie": True,
                    }
                ),
            ),
            mock.patch.object(
                login_http,
                "_collect_http_sentinel_header_candidates_for_flows",
                new=collect_sentinel,
            ),
        ):
            result = asyncio.run(
                login_http.run_chatgpt_http_login(
                    profile=login_http.ChatGptHttpLoginProfile(
                        email="user@example.com",
                        password="account-password",
                    ),
                    config=login_http.ChatGptHttpLoginConfig(
                        proxyUrl=proxy_url,
                        storageStatePath=str(Path(temp_dir) / "state.json"),
                        timeoutSeconds=60,
                    ),
                )
            )

        self.assertFalse(result.success)
        self.assertEqual(build_context.call_args.kwargs["proxy_url"], proxy_url)
        self.assertEqual(
            collect_sentinel.await_args.kwargs["proxy_opt"],
            {
                "server": "http://proxy.test:8080",
                "username": "proxy-user",
                "password": "proxy-pass",
            },
        )
        request_ctx.dispose.assert_awaited_once_with()

    def test_registration_and_login_traces_mask_proxy_credentials(self):
        login_source = inspect.getsource(login_http.run_chatgpt_http_login)
        register_source = inspect.getsource(register_http.run_chatgpt_http_register)
        self.assertIn('"proxy": _mask_proxy_url_for_log(resolved_proxy_url)', login_source)
        self.assertIn('"proxy": _mask_proxy_url_for_log(resolved_proxy_url)', register_source)
        self.assertNotIn('"proxy": resolved_proxy_url or ""', login_source)
        self.assertNotIn('"proxy": resolved_proxy_url or ""', register_source)

    def test_provider_errors_do_not_expose_api_key(self):
        provider = sms_provider.SmsBowerProvider(
            "top-secret-api-key",
            proxy="http://proxy-user:proxy-secret@proxy.test:8080",
        )
        error = sms_provider.requests.ConnectionError(
            "GET https://sms.test/handler?api_key=top-secret-api-key&action=getBalance "
            "via http://proxy-user:proxy-secret@proxy.test:8080 failed"
        )
        with mock.patch.object(sms_provider.requests, "get", side_effect=error):
            with self.assertRaises(RuntimeError) as raised:
                provider.get_balance()

        message = str(raised.exception)
        self.assertNotIn("top-secret-api-key", message)
        self.assertNotIn("proxy-secret", message)
        self.assertIn("api_key=***", message)

    def test_provider_does_not_accept_unconfirmed_success_response(self):
        provider = sms_provider.SmsBowerProvider("secret")
        response = SimpleNamespace(status_code=200, text="BAD_STATUS")
        with (
            mock.patch.object(sms_provider, "_SMS_CACHE", None),
            mock.patch.object(provider, "_request", return_value=response) as request,
        ):
            self.assertFalse(provider.report_success("activation-1"))
        self.assertEqual(request.call_count, 2)

    def test_sms_adapter_runs_rent_wait_and_success_lifecycle(self):
        fake = FakeSmsProvider()
        config = {
            "phone_verification": {
                "sms_provider": "smsbower",
                "sms_api_key": "secret",
                "sms_country": "52",
                "sms_service": "dr",
                "proxy": "http://proxy.test:8080",
            }
        }
        with mock.patch.object(phone_verification, "create_sms_provider", return_value=fake) as create:
            candidate = phone_verification.acquire_http_phone_candidate(
                config,
                owner_key="user@example.com",
            )
            code = phone_verification.wait_for_http_phone_code(candidate, timeout=45)
            phone_verification.mark_http_phone_completed(candidate)

        self.assertEqual(candidate.phone, "+66812345678")
        self.assertEqual(candidate.source, "smsbower")
        self.assertEqual(code, "123456")
        self.assertEqual(create.call_args.args[1]["proxy"], "http://proxy.test:8080")
        self.assertIn(("mark_send_succeeded", "activation-1"), fake.calls)
        self.assertIn(("get_code", "activation-1", 45), fake.calls)
        self.assertIn(("report_success", "activation-1"), fake.calls)

    def test_sms_adapter_journals_activation_until_provider_confirms(self):
        fake = FakeSmsProvider()
        config = {
            "phone_verification": {
                "sms_provider": "smsbower",
                "sms_api_key": "secret",
                "sms_country": "52",
                "sms_service": "dr",
                "proxy": "http://proxy.test:8080",
            }
        }
        with tempfile.TemporaryDirectory() as directory:
            journal = Path(directory) / "activation.json"
            with (
                mock.patch.dict(os.environ, {"REG_2FA_SMS_ACTIVATION_PATH": str(journal)}),
                mock.patch.object(phone_verification, "create_sms_provider", return_value=fake),
            ):
                candidate = phone_verification.acquire_http_phone_candidate(config)
                self.assertTrue(journal.exists())
                phone_verification.mark_http_phone_completed(candidate)
                self.assertFalse(journal.exists())

    def test_sms_adapter_cancels_when_success_is_not_confirmed(self):
        fake = FakeSmsProvider()
        fake.report_success = mock.Mock(return_value=False)
        config = {
            "phone_verification": {
                "sms_provider": "smsbower",
                "sms_api_key": "secret",
            }
        }
        with mock.patch.object(phone_verification, "create_sms_provider", return_value=fake):
            candidate = phone_verification.acquire_http_phone_candidate(config)
            phone_verification.mark_http_phone_completed(candidate)

        fake.report_success.assert_called_once_with("activation-1")
        self.assertIn(("cancel", "activation-1"), fake.calls)

    def test_sms_adapter_cancels_rental_when_journal_write_fails(self):
        fake = FakeSmsProvider()
        config = {"sms_provider": "smsbower", "sms_api_key": "secret"}
        with mock.patch.object(phone_verification, "create_sms_provider", return_value=fake):
            service = phone_verification.SmsActivationPhoneService(config)
        with mock.patch.object(
            service,
            "_write_activation_journal",
            side_effect=OSError("journal unavailable"),
        ):
            with self.assertRaisesRegex(RuntimeError, "rental was cancelled"):
                service.acquire_phone()

        self.assertIn(("cancel", "activation-1"), fake.calls)

    def test_registration_phone_step_sends_waits_validates_and_completes(self):
        candidate = SimpleNamespace(phone="+66812345678", source="smsbower")
        requests_seen: list[str] = []

        async def request(_request_ctx, **kwargs):
            requests_seen.append(kwargs["path"])
            if kwargs["path"] == "/add-phone/send":
                self.assertEqual(kwargs["json_body"], {"phone_number": "+66812345678"})
                self.assertEqual(kwargs["trace_json_body"], {"phone_number": "***"})
                return {
                    "status": 200,
                    "payload": {"continue_url": "https://auth.openai.com/phone-otp"},
                    "text": "",
                }
            self.assertEqual(kwargs["json_body"], {"code": "123456"})
            self.assertEqual(kwargs["trace_json_body"], {"code": "***"})
            return {
                "status": 200,
                "payload": {"continue_url": "https://chatgpt.com/"},
                "text": "",
            }

        trace = SimpleNamespace(write=mock.Mock())
        log = SimpleNamespace(info=mock.Mock())
        with (
            mock.patch.object(register_http, "acquire_http_phone_candidate", return_value=candidate),
            mock.patch.object(register_http, "wait_for_http_phone_code", return_value="123456"),
            mock.patch.object(register_http, "mark_http_phone_completed") as completed,
            mock.patch.object(register_http, "dispose_http_phone_after_failure") as disposed,
            mock.patch.object(register_http, "_request_auth_api_with_context", side_effect=request),
            mock.patch.object(
                register_http,
                "_open_continue_url",
                new=mock.AsyncMock(return_value=("https://chatgpt.com/", "")),
            ),
        ):
            result = asyncio.run(
                register_http._submit_register_phone_if_required(
                    request_ctx=object(),
                    payload={"continue_url": "https://auth.openai.com/add-phone"},
                    continue_url="https://auth.openai.com/add-phone",
                    phone_config={"sms_provider": "smsbower", "sms_api_key": "secret"},
                    safe_email="user@example.com",
                    trace=trace,
                    log=log,
                    timeout_sec=360,
                    otp_timeout_sec=180,
                )
            )

        self.assertTrue(result["handled"])
        self.assertEqual(result["continue_url"], "https://chatgpt.com/")
        self.assertEqual(requests_seen, ["/add-phone/send", "/phone-otp/validate"])
        completed.assert_called_once_with(candidate)
        disposed.assert_not_called()

    def test_registration_phone_step_rejects_validate_that_stays_on_phone_page(self):
        candidate = SimpleNamespace(phone="+66812345678", source="smsbower")

        async def request(_request_ctx, **kwargs):
            if kwargs["path"] == "/add-phone/send":
                return {
                    "status": 200,
                    "payload": {"continue_url": "https://auth.openai.com/phone-otp"},
                    "text": "",
                }
            return {
                "status": 200,
                "payload": {
                    "page": {"type": "phone_otp_verification"},
                    "continue_url": "https://auth.openai.com/phone-verification",
                },
                "text": "Enter the code we sent",
            }

        with (
            mock.patch.object(register_http, "acquire_http_phone_candidate", return_value=candidate),
            mock.patch.object(register_http, "wait_for_http_phone_code", return_value="123456"),
            mock.patch.object(register_http, "mark_http_phone_completed") as completed,
            mock.patch.object(register_http, "dispose_http_phone_after_failure") as disposed,
            mock.patch.object(register_http, "_request_auth_api_with_context", side_effect=request),
            mock.patch.object(
                register_http,
                "_open_continue_url",
                new=mock.AsyncMock(
                    return_value=(
                        "https://auth.openai.com/phone-verification",
                        "Enter the code we sent",
                    )
                ),
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "did not leave the phone verification step"):
                asyncio.run(
                    register_http._submit_register_phone_if_required(
                        request_ctx=object(),
                        payload={"continue_url": "https://auth.openai.com/add-phone"},
                        continue_url="https://auth.openai.com/add-phone",
                        phone_config={"sms_provider": "smsbower", "sms_api_key": "secret"},
                        safe_email="user@example.com",
                        trace=SimpleNamespace(write=mock.Mock()),
                        log=SimpleNamespace(info=mock.Mock()),
                        timeout_sec=360,
                        otp_timeout_sec=180,
                    )
                )

        completed.assert_not_called()
        disposed.assert_called_once_with(candidate)

    def test_registration_phone_step_recognizes_structured_page_types(self):
        self.assertEqual(
            register_http._registration_phone_step({"page": {"type": "add_phone"}}, ""),
            "add_phone",
        )
        self.assertEqual(
            register_http._registration_phone_step(
                {"page": {"type": "phone_otp_select_channel"}},
                "",
            ),
            "select_channel",
        )

    def test_registration_phone_step_explicitly_selects_sms_channel(self):
        candidate = SimpleNamespace(phone="+66812345678", source="smsbower")
        requests_seen: list[tuple[str, dict]] = []

        async def request(_request_ctx, **kwargs):
            requests_seen.append((kwargs["path"], kwargs["json_body"]))
            if kwargs["path"] == "/add-phone/send":
                return {
                    "status": 200,
                    "payload": {
                        "continue_url": "https://auth.openai.com/phone-otp/select-channel",
                        "available_channels": ["sms", "whatsapp"],
                    },
                    "text": "",
                }
            if kwargs["path"] == "/phone-otp/select-channel":
                return {
                    "status": 200,
                    "payload": {"continue_url": "https://auth.openai.com/phone-otp"},
                    "text": "",
                }
            return {
                "status": 200,
                "payload": {"continue_url": "https://chatgpt.com/"},
                "text": "",
            }

        with (
            mock.patch.object(register_http, "acquire_http_phone_candidate", return_value=candidate),
            mock.patch.object(register_http, "wait_for_http_phone_code", return_value="123456"),
            mock.patch.object(register_http, "mark_http_phone_completed") as completed,
            mock.patch.object(register_http, "dispose_http_phone_after_failure") as disposed,
            mock.patch.object(register_http, "_request_auth_api_with_context", side_effect=request),
            mock.patch.object(
                register_http,
                "_open_continue_url",
                new=mock.AsyncMock(return_value=("https://chatgpt.com/", "")),
            ),
        ):
            result = asyncio.run(
                register_http._submit_register_phone_if_required(
                    request_ctx=object(),
                    payload={"continue_url": "https://auth.openai.com/add-phone"},
                    continue_url="https://auth.openai.com/add-phone",
                    phone_config={"sms_provider": "smsbower", "sms_api_key": "secret"},
                    safe_email="user@example.com",
                    trace=SimpleNamespace(write=mock.Mock()),
                    log=SimpleNamespace(info=mock.Mock()),
                    timeout_sec=360,
                    otp_timeout_sec=180,
                )
            )

        self.assertTrue(result["handled"])
        self.assertEqual(
            requests_seen,
            [
                ("/add-phone/send", {"phone_number": "+66812345678"}),
                ("/phone-otp/select-channel", {"channel": "sms"}),
                ("/phone-otp/validate", {"code": "123456"}),
            ],
        )
        completed.assert_called_once_with(candidate)
        disposed.assert_not_called()

    def test_registration_phone_step_selects_sms_after_continue_redirect(self):
        candidate = SimpleNamespace(phone="+66812345678", source="smsbower")
        requests_seen: list[str] = []

        async def request(_request_ctx, **kwargs):
            requests_seen.append(kwargs["path"])
            if kwargs["path"] == "/add-phone/send":
                return {
                    "status": 200,
                    "payload": {"continue_url": "https://auth.openai.com/phone-otp"},
                    "text": "",
                }
            if kwargs["path"] == "/phone-otp/select-channel":
                return {
                    "status": 200,
                    "payload": {"continue_url": "https://auth.openai.com/phone-otp"},
                    "text": "",
                }
            return {
                "status": 200,
                "payload": {"continue_url": "https://chatgpt.com/"},
                "text": "",
            }

        open_continue = mock.AsyncMock(
            side_effect=[
                (
                    "https://auth.openai.com/phone-otp/select-channel",
                    "<button>SMS</button><button>WhatsApp</button>",
                ),
                ("https://auth.openai.com/phone-otp", "<html></html>"),
                ("https://chatgpt.com/", "<html></html>"),
            ]
        )
        with (
            mock.patch.object(register_http, "acquire_http_phone_candidate", return_value=candidate),
            mock.patch.object(register_http, "wait_for_http_phone_code", return_value="123456"),
            mock.patch.object(register_http, "mark_http_phone_completed") as completed,
            mock.patch.object(register_http, "dispose_http_phone_after_failure") as disposed,
            mock.patch.object(register_http, "_request_auth_api_with_context", side_effect=request),
            mock.patch.object(register_http, "_open_continue_url", new=open_continue),
        ):
            result = asyncio.run(
                register_http._submit_register_phone_if_required(
                    request_ctx=object(),
                    payload={"continue_url": "https://auth.openai.com/add-phone"},
                    continue_url="https://auth.openai.com/add-phone",
                    phone_config={"sms_provider": "smsbower", "sms_api_key": "secret"},
                    safe_email="user@example.com",
                    trace=SimpleNamespace(write=mock.Mock()),
                    log=SimpleNamespace(info=mock.Mock()),
                    timeout_sec=360,
                    otp_timeout_sec=180,
                )
            )

        self.assertTrue(result["handled"])
        self.assertEqual(
            requests_seen,
            ["/add-phone/send", "/phone-otp/select-channel", "/phone-otp/validate"],
        )
        self.assertEqual(open_continue.await_count, 3)
        completed.assert_called_once_with(candidate)
        disposed.assert_not_called()

    def test_registration_without_phone_step_does_not_rent_number(self):
        with mock.patch.object(register_http, "acquire_http_phone_candidate") as acquire:
            result = asyncio.run(
                register_http._submit_register_phone_if_required(
                    request_ctx=object(),
                    payload={"continue_url": "https://chatgpt.com/"},
                    continue_url="https://chatgpt.com/",
                    phone_config={},
                    safe_email="user@example.com",
                    trace=SimpleNamespace(write=mock.Mock()),
                    log=SimpleNamespace(info=mock.Mock()),
                    timeout_sec=360,
                    otp_timeout_sec=180,
                )
            )

        self.assertFalse(result["handled"])
        acquire.assert_not_called()

    def test_whatsapp_response_cancels_number_without_waiting_for_sms(self):
        candidate = SimpleNamespace(phone="+66812345678", source="smsbower")

        async def request(_request_ctx, **_kwargs):
            return {
                "status": 200,
                "payload": {"channel": "whatsapp", "continue_url": "https://auth.openai.com/phone-otp"},
                "text": "",
            }

        with (
            mock.patch.object(register_http, "acquire_http_phone_candidate", return_value=candidate),
            mock.patch.object(register_http, "blacklist_http_phone") as cancelled,
            mock.patch.object(register_http, "wait_for_http_phone_code") as wait_code,
            mock.patch.object(register_http, "dispose_http_phone_after_failure") as disposed,
            mock.patch.object(register_http, "_request_auth_api_with_context", side_effect=request),
        ):
            with self.assertRaisesRegex(RuntimeError, "WhatsApp"):
                asyncio.run(
                    register_http._submit_register_phone_if_required(
                        request_ctx=object(),
                        payload={"continue_url": "https://auth.openai.com/add-phone"},
                        continue_url="https://auth.openai.com/add-phone",
                        phone_config={"sms_provider": "smsbower", "sms_api_key": "secret"},
                        safe_email="user@example.com",
                        trace=SimpleNamespace(write=mock.Mock()),
                        log=SimpleNamespace(info=mock.Mock()),
                        timeout_sec=360,
                        otp_timeout_sec=180,
                    )
                )

        cancelled.assert_called_once_with(candidate)
        wait_code.assert_not_called()
        disposed.assert_not_called()

    def test_whatsapp_continue_page_cancels_number_without_waiting_for_sms(self):
        candidate = SimpleNamespace(phone="+66812345678", source="smsbower")

        async def request(_request_ctx, **_kwargs):
            return {
                "status": 200,
                "payload": {"continue_url": "https://auth.openai.com/phone-otp"},
                "text": "",
            }

        with (
            mock.patch.object(register_http, "acquire_http_phone_candidate", return_value=candidate),
            mock.patch.object(register_http, "blacklist_http_phone") as cancelled,
            mock.patch.object(register_http, "wait_for_http_phone_code") as wait_code,
            mock.patch.object(register_http, "dispose_http_phone_after_failure") as disposed,
            mock.patch.object(register_http, "_request_auth_api_with_context", side_effect=request),
            mock.patch.object(
                register_http,
                "_open_continue_url",
                new=mock.AsyncMock(
                    return_value=(
                        "https://auth.openai.com/phone-otp",
                        "<p>Your verification code was sent to WhatsApp. Check your WhatsApp.</p>",
                    )
                ),
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "WhatsApp"):
                asyncio.run(
                    register_http._submit_register_phone_if_required(
                        request_ctx=object(),
                        payload={"continue_url": "https://auth.openai.com/add-phone"},
                        continue_url="https://auth.openai.com/add-phone",
                        phone_config={"sms_provider": "smsbower", "sms_api_key": "secret"},
                        safe_email="user@example.com",
                        trace=SimpleNamespace(write=mock.Mock()),
                        log=SimpleNamespace(info=mock.Mock()),
                        timeout_sec=360,
                        otp_timeout_sec=180,
                    )
                )

        cancelled.assert_called_once_with(candidate)
        wait_code.assert_not_called()
        disposed.assert_not_called()


if __name__ == "__main__":
    unittest.main()
