from __future__ import annotations

import unittest
from unittest import mock

from enable_totp_mfa import module


class MfaTransactionTests(unittest.TestCase):
    def test_full_auth_session_helper_returns_complete_payload(self):
        session = {
            "accessToken": "session-at",
            "user": {"email": "user@example.com"},
            "account": {"id": "account-1"},
        }
        with mock.patch.object(module, "_request_chatgpt_mfa_json", return_value=session) as request:
            result = module.read_auth_session_via_cookie_header(
                cookie_header="session=cookie",
                oai_device_id="device-id",
                proxy="http://proxy.test:8080",
            )

        self.assertEqual(result, session)
        self.assertEqual(request.call_args.kwargs["url"], module.AUTH_SESSION_URL)
        self.assertEqual(request.call_args.kwargs["headers"]["cookie"], "session=cookie")
        self.assertEqual(request.call_args.kwargs["headers"]["oai-device-id"], "device-id")
        self.assertEqual(request.call_args.kwargs["proxy"], "http://proxy.test:8080")

    def test_access_token_helper_still_extracts_token_from_full_session(self):
        with mock.patch.object(
            module,
            "read_auth_session_via_cookie_header",
            return_value={"accessToken": "session-at", "user": {"id": "user-1"}},
        ):
            self.assertEqual(
                module.read_access_token_via_cookie_header(cookie_header="session=cookie"),
                "session-at",
            )

    def test_enrollment_is_persisted_before_activate(self):
        events = []

        def request(**kwargs):
            stage = kwargs["stage"]
            events.append(stage)
            if stage == "mfa_info_before":
                return {"mfa_enabled": False, "factors": {"totp": []}}
            if stage == "mfa_enroll":
                return {
                    "secret": "JBSWY3DPEHPK3PXP",
                    "session_id": "session-1",
                    "factor": {"id": "factor-1"},
                }
            if stage == "mfa_activate":
                return {"success": True}
            return {"mfa_enabled": True, "factors": {"totp": [{"id": "factor-1"}]}}

        def persist(enrollment):
            self.assertEqual(enrollment["secret"], "JBSWY3DPEHPK3PXP")
            events.append("persisted")

        with (
            mock.patch.object(module, "_request_chatgpt_mfa_json", side_effect=request),
            mock.patch.object(module.time, "time", return_value=100),
        ):
            result = module.enable_totp_mfa_with_credentials(
                access_token="access-token",
                cookie_header="session=cookie",
                before_activate=persist,
            )

        self.assertTrue(result["mfaEnabled"])
        self.assertLess(events.index("persisted"), events.index("mfa_activate"))

    def test_persistence_failure_prevents_activate(self):
        stages = []

        def request(**kwargs):
            stage = kwargs["stage"]
            stages.append(stage)
            if stage == "mfa_info_before":
                return {"mfa_enabled": False, "factors": {"totp": []}}
            if stage == "mfa_enroll":
                return {"secret": "JBSWY3DPEHPK3PXP", "session_id": "session-1"}
            raise AssertionError("activate must not be called")

        with mock.patch.object(module, "_request_chatgpt_mfa_json", side_effect=request):
            with self.assertRaisesRegex(RuntimeError, "disk full"):
                module.enable_totp_mfa_with_credentials(
                    access_token="access-token",
                    cookie_header="session=cookie",
                    before_activate=lambda _payload: (_ for _ in ()).throw(RuntimeError("disk full")),
                )

        self.assertEqual(stages, ["mfa_info_before", "mfa_enroll"])


if __name__ == "__main__":
    unittest.main()
