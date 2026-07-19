from __future__ import annotations

import asyncio
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TOOLCORE = ROOT / "X9-Free" / "_credential_toolcore"
for candidate in (str(ROOT), str(TOOLCORE)):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

import chatgpt_register_http as register_http  # noqa: E402
import runner as isolated_runner  # noqa: E402


class RemotePasswordTests(unittest.TestCase):
    def test_post_registration_password_reset_uses_json_otp_and_masks_secrets(self):
        request_ctx = SimpleNamespace(dispose=mock.AsyncMock())
        pages = [
            {
                "status": 200,
                "url": "https://auth.openai.com/email-verification",
                "text": (
                    '<form action="/api/accounts/federated/google" method="post"></form>'
                    '<form action="/api/accounts/federated/apple" method="post"></form>'
                    '<form action="/email-verification" method="post"><input name="code">'
                    '<button name="intent" value="validate" type="submit">Continue</button>'
                    '<button name="intent" value="resend" type="submit">Resend</button></form>'
                ),
            }
        ]
        request_html = mock.AsyncMock(side_effect=pages)

        async def request_api(_request_ctx, **kwargs):
            path = str(kwargs.get("path") or "")
            if path == "/email-otp/validate":
                return {
                    "status": 200,
                    "payload": {
                        "continue_url": "https://auth.openai.com/reset-password/new-password",
                        "page": {"type": "reset_password_new_password"},
                    },
                    "text": "",
                }
            if path == "/password/add":
                return {
                    "status": 200,
                    "payload": {
                        "continue_url": "https://chatgpt.com/api/auth/callback/openai?code=abc&state=xyz",
                    },
                    "text": "",
                }
            return {"status": 400, "payload": {}, "text": "unexpected"}

        request_api_mock = mock.AsyncMock(side_effect=request_api)
        open_continue = mock.AsyncMock(
            side_effect=[
                (
                    "https://auth.openai.com/reset-password/new-password",
                    "<html><title>Add your password</title></html>",
                ),
                (
                    "https://chatgpt.com/",
                    "ok",
                ),
            ]
        )

        with tempfile.TemporaryDirectory() as temp_dir, ExitStack() as stack:
            state_path = Path(temp_dir) / "state.json"
            state_path.write_text('{"cookies":[]}', encoding="utf-8")
            stack.enter_context(
                mock.patch.object(register_http, "_build_http_provider_request_context", return_value=request_ctx)
            )
            bootstrap = stack.enter_context(
                mock.patch.object(
                    register_http,
                    "_bootstrap_http_login_session",
                    new=mock.AsyncMock(
                        return_value={"loginUrl": "https://auth.openai.com/email-verification"}
                    ),
                )
            )
            stack.enter_context(mock.patch.object(register_http, "_request_html_page", new=request_html))
            stack.enter_context(
                mock.patch.object(register_http, "_request_auth_api_with_context", new=request_api_mock)
            )
            stack.enter_context(
                mock.patch.object(register_http, "_open_continue_url", new=open_continue)
            )
            stack.enter_context(
                mock.patch.object(
                    register_http,
                    "_read_password_reset_otp_code",
                    new=mock.AsyncMock(side_effect=["654321", "123456"]),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    register_http,
                    "_read_request_context_storage_state",
                    new=mock.AsyncMock(return_value={"cookies": []}),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    register_http,
                    "_fetch_session_after_login",
                    new=mock.AsyncMock(return_value={"status": 200, "payload": {}, "error": ""}),
                )
            )
            result = asyncio.run(
                register_http.set_chatgpt_password_via_reset_flow(
                    profile=register_http.ChatGptHttpRegisterProfile(
                        email="user@example.com",
                        password="account-password",
                    ),
                    config=register_http.ChatGptHttpRegisterConfig(storageStatePath=str(state_path)),
                )
            )

        self.assertTrue(result["ok"])
        self.assertTrue(result["remotePasswordSet"])
        self.assertEqual(result["remotePasswordMode"], "post_registration_password_reset")
        self.assertEqual(request_html.await_count, 1)
        self.assertEqual(
            bootstrap.await_args.kwargs["authorization_params"],
            {"post_login_add_password": "true", "login_hint": "user@example.com"},
        )
        otp_submit = request_api_mock.await_args_list[0].kwargs
        self.assertEqual(otp_submit["path"], "/email-otp/validate")
        self.assertEqual(otp_submit["json_body"], {"code": "123456"})
        self.assertEqual(otp_submit["trace_json_body"], {"code": "***"})
        password_submit = request_api_mock.await_args_list[1].kwargs
        self.assertEqual(password_submit["path"], "/password/add")
        self.assertEqual(password_submit["json_body"], {"password": "account-password"})
        self.assertEqual(password_submit["trace_json_body"], {"password": "***"})
        self.assertEqual(open_continue.await_count, 2)
        request_ctx.dispose.assert_awaited_once_with()

    def test_html_form_body_prefers_non_resend_submitter(self):
        form = register_http._HtmlFormSnapshot(
            action="/email-verification",
            method="POST",
            inputs=(register_http._HtmlInputField(name="code", value="", input_type="text", checked=False),),
            submitters=(
                register_http._HtmlInputField(name="intent", value="validate", input_type="submit", checked=False),
                register_http._HtmlInputField(name="intent", value="resend", input_type="submit", checked=False),
            ),
        )
        body = register_http._build_html_form_body(
            form=form,
            overrides={"code": "123456"},
            preferred_submit_values={"validate"},
        )
        self.assertIn("code=123456", body)
        self.assertIn("intent=validate", body)
        self.assertNotIn("Continue=", body)

    def test_password_submission_mode_recovers_after_otp_about_you(self):
        payload = {
            "page": {"type": "about_you"},
            "continue_url": "https://auth.openai.com/about-you",
        }

        self.assertEqual(
            register_http._register_password_submission_mode(payload),
            "post_otp_about_you_recovery",
        )
        self.assertEqual(
            register_http._register_password_submission_mode(
                {"page": {"type": "signup_password"}}
            ),
            "signup_password_step",
        )
        self.assertEqual(
            register_http._register_password_submission_mode(
                {
                    "page": {
                        "type": "email_otp_verification",
                        "payload": {"email_verification_mode": "passwordless_login"},
                    }
                }
            ),
            "",
        )

    def test_password_response_requires_success_without_embedded_error(self):
        self.assertTrue(register_http._register_password_response_accepted({"status": 200}))
        self.assertFalse(
            register_http._register_password_response_accepted(
                {"status": 200, "errorCode": "invalid_authorization_step"}
            )
        )
        self.assertFalse(register_http._register_password_response_accepted({"status": 400}))

    def _run_about_you_registration(self, password_response: dict, *, password_first: bool = False):
        request_ctx = SimpleNamespace(dispose=mock.AsyncMock())
        submit_password = mock.AsyncMock(return_value=password_response)
        about_you_payload = {
            "page": {"type": "about_you"},
            "continue_url": "https://auth.openai.com/about-you",
        }
        email_response = {
            "status": 200,
            "payload": {
                "page": {
                    "type": "email_otp_verification",
                    "payload": {"email_verification_mode": "signup"},
                },
                "continue_url": "https://auth.openai.com/email-verification",
            },
            "continueUrl": "https://auth.openai.com/email-verification",
            "errorCode": "",
            "errorMessage": "",
        }
        if password_first:
            email_response = {
                "status": 200,
                "payload": {
                    "page": {"type": "signup_password"},
                    "continue_url": "https://auth.openai.com/create-account/password",
                },
                "continueUrl": "https://auth.openai.com/create-account/password",
                "errorCode": "",
                "errorMessage": "",
            }

        with tempfile.TemporaryDirectory() as temp_dir, ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(
                    register_http,
                    "_TraceWriter",
                    return_value=SimpleNamespace(write=mock.Mock(), path="trace.jsonl"),
                )
            )
            stack.enter_context(
                mock.patch.object(register_http, "activate_http_stage_feature_session", return_value=None)
            )
            stack.enter_context(
                mock.patch.object(
                    register_http,
                    "_build_http_provider_request_context",
                    return_value=request_ctx,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    register_http,
                    "_bootstrap_http_register_session",
                    new=mock.AsyncMock(
                        return_value={
                            "registerUrl": "https://auth.openai.com/create-account",
                            "authorizeUrl": "https://auth.openai.com/authorize",
                            "hasAuthSessionCookie": True,
                        }
                    ),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    register_http,
                    "_collect_http_sentinel_header_candidates_for_flows",
                    new=mock.AsyncMock(return_value={}),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    register_http,
                    "_request_with_sentinel_candidates",
                    new=mock.AsyncMock(return_value=email_response),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    register_http,
                    "_submit_http_otp_if_required",
                    new=mock.AsyncMock(
                        return_value={
                            "handled": True,
                            "payload": about_you_payload,
                            "continue_url": "https://auth.openai.com/about-you",
                        }
                    ),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    register_http,
                    "_refresh_register_sentinel_header_candidates",
                    new=mock.AsyncMock(return_value={}),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    register_http,
                    "_submit_register_password_http",
                    new=submit_password,
                )
            )
            stack.enter_context(
                mock.patch.object(register_http, "_prefer_direct_create_account", return_value=True)
            )
            stack.enter_context(
                mock.patch.object(
                    register_http,
                    "_submit_register_profile_http",
                    new=mock.AsyncMock(
                        return_value={
                            "ok": False,
                            "status": 400,
                            "errorCode": "profile_fixture_stop",
                            "errorMessage": "stop after password assertion",
                            "payload": {},
                            "continueUrl": "",
                        }
                    ),
                )
            )
            result = asyncio.run(
                register_http.run_chatgpt_http_register(
                    profile=register_http.ChatGptHttpRegisterProfile(
                        email="user@example.com",
                        password="account-password",
                    ),
                    config=register_http.ChatGptHttpRegisterConfig(
                        storageStatePath=str(Path(temp_dir) / "state.json"),
                        timeoutSeconds=60,
                    ),
                )
            )

        request_ctx.dispose.assert_awaited_once_with()
        if password_first:
            submit_password.assert_awaited_once()
            self.assertEqual(
                submit_password.await_args.kwargs["referer_url"],
                "https://auth.openai.com/create-account/password",
            )
        else:
            submit_password.assert_not_awaited()
        return result

    def test_password_first_rejects_unconfirmed_remote_password(self):
        result = self._run_about_you_registration(
            {
                "status": 400,
                "errorCode": "invalid_authorization_step",
                "errorMessage": "step rejected",
                "payload": {},
                "continueUrl": "",
            },
            password_first=True,
        )

        self.assertFalse(result.success)
        self.assertEqual(result.stage, "submit_password")
        self.assertEqual(result.errorCode, "remote_password_not_set")
        self.assertFalse(result.details["remotePasswordSet"])
        self.assertEqual(result.details["remotePasswordMode"], "signup_password_step")

    def test_password_first_records_remote_acceptance(self):
        result = self._run_about_you_registration(
            {
                "status": 200,
                "errorCode": "",
                "errorMessage": "",
                "payload": {},
                "continueUrl": "",
            },
            password_first=True,
        )

        self.assertFalse(result.success)
        self.assertEqual(result.stage, "submit_profile")
        self.assertTrue(result.details["remotePasswordSet"])
        self.assertEqual(result.details["remotePasswordMode"], "signup_password_step")

    def test_about_you_after_otp_does_not_retry_password_registration(self):
        result = self._run_about_you_registration(
            {
                "status": 400,
                "errorCode": "invalid_authorization_step",
                "errorMessage": "must not be submitted",
                "payload": {},
                "continueUrl": "",
            }
        )

        self.assertFalse(result.success)
        self.assertEqual(result.stage, "submit_profile")
        self.assertFalse(result.details["remotePasswordSet"])
        self.assertEqual(result.details["remotePasswordMode"], "not_attempted")

    def test_runner_preserves_remote_password_evidence(self):
        payload = isolated_runner._result_payload(
            SimpleNamespace(
                success=True,
                remote_password_set=True,
                remote_password_mode="signup_password_step",
            )
        )

        self.assertTrue(payload["remotePasswordSet"])
        self.assertEqual(payload["remotePasswordMode"], "signup_password_step")


if __name__ == "__main__":
    unittest.main()
