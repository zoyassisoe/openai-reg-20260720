from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import runner
import server
import chatgpt_api_health
import enable_totp_mfa.module as mfa_module


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.paths = {
            "DATA_DIR": root,
            "JOBS_PATH": root / "jobs.json",
            "SETTINGS_PATH": root / "settings.json",
            "SECRETS_PATH": root / "secrets.json",
            "RUN_DIR": root / "runs",
            "AUDIT_PATH": root / "audit.jsonl",
            "SMS_ACTIVATIONS_DIR": root / "sms-activations",
            "MANUAL_PHONE_DIR": root / "manual-phone",
            "X9_RUNTIME_ROOT": root / "x9",
        }
        self.patchers = [mock.patch.object(server, name, value) for name, value in self.paths.items()]
        for patcher in self.patchers:
            patcher.start()
        server.write_json_atomic(server.JOBS_PATH, [])
        server.write_json_atomic(server.SETTINGS_PATH, server.SETTINGS_DEFAULTS)
        server.save_secret_store({})
        server.STOP_EVENT.clear()
        server.SMS_RECOVERY_COMPLETE.set()
        with server.RUNTIME_LOCK:
            server.RUNTIME.update(
                {
                    "running": False,
                    "startedAt": "",
                    "finishedAt": "",
                    "active": {},
                    "logs": [],
                    "worker": None,
                    "operation": "idle",
                    "activeJobIds": [],
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
            )

    def tearDown(self):
        server.STOP_EVENT.clear()
        server.SMS_RECOVERY_COMPLETE.set()
        with server.RUNTIME_LOCK:
            server.RUNTIME["running"] = False
            server.RUNTIME["active"] = {}
            server.RUNTIME["worker"] = None
            server.RUNTIME["operation"] = "idle"
            server.RUNTIME["activeJobIds"] = []
            server.RUNTIME["manualPhoneJobId"] = ""
            server.RUNTIME["manualPhoneSessionId"] = ""
        for patcher in reversed(self.patchers):
            patcher.stop()
        self.temp_dir.cleanup()

    def test_api_import_keeps_full_url_out_of_jobs_file(self):
        secret_url = "https://mail.test/latest?token=very-secret-token"
        result = server.import_jobs(
            {"mode": "api", "text": f"user@example.com----{secret_url}", "defaults": {}}
        )

        self.assertEqual(result["added"], 1)
        raw_job = server.load_jobs()[0]
        self.assertNotIn("apiUrl", raw_job["provider"])
        self.assertEqual(raw_job["provider"]["apiEndpoint"], "https://mail.test/latest")
        self.assertNotIn("very-secret-token", server.JOBS_PATH.read_text(encoding="utf-8"))
        self.assertEqual(server.get_job(raw_job["id"])["provider"]["apiUrl"], secret_url)
        self.assertNotIn("very-secret-token", str(server.public_job(raw_job)))

    def test_imap_mode_maps_to_password_imap_only(self):
        result = server.import_jobs(
            {
                "mode": "imap",
                "text": "alias@example.com----mailbox@example.com----mail-secret",
                "defaults": {"host": "imap.example.com", "port": 993, "folder": "INBOX"},
            }
        )
        self.assertEqual(result["added"], 1)
        job = server.get_job(server.load_jobs()[0]["id"])
        payload = server._runner_input(job, server.load_settings())
        args = runner._namespace(payload)

        self.assertTrue(args.use_imap_otp)
        self.assertEqual(args.imap_auth_type, "password")
        self.assertEqual(args.imap_host, "imap.example.com")
        self.assertEqual(args.imap_user, "mailbox@example.com")
        self.assertEqual(args.imap_pass, "mail-secret")
        self.assertEqual(args.otp_api_url, "")
        self.assertTrue(args.disable_managed_mail_otp)

    def test_outlook_mode_maps_refresh_token_to_xoauth2(self):
        result = server.import_jobs(
            {
                "mode": "outlook_oauth",
                "text": "user@outlook.com----user@outlook.com----client-id----refresh-secret",
                "defaults": {"pop3Fallback": True},
            }
        )
        self.assertEqual(result["added"], 1)
        raw_job = server.load_jobs()[0]
        self.assertNotIn("refreshToken", raw_job["provider"])
        job = server.get_job(raw_job["id"])
        args = runner._namespace(server._runner_input(job, server.load_settings()))

        self.assertTrue(args.use_imap_otp)
        self.assertEqual(args.imap_auth_type, "oauth2")
        self.assertEqual(args.imap_host, "outlook.office365.com")
        self.assertEqual(args.imap_oauth_client_id, "client-id")
        self.assertEqual(args.imap_oauth_refresh_token, "refresh-secret")
        self.assertTrue(args.imap_pop3_fallback)

    def test_csv_can_mix_all_three_modes(self):
        csv_text = """email,otp_mode,otp_api_url,imap_host,imap_user,imap_password,outlook_client_id,outlook_refresh_token
api@example.com,api,https://mail.test/a,,,,,
imap@example.com,imap,,imap.test,box@example.com,mail-pass,,
oauth@outlook.com,outlook_oauth,,,oauth@outlook.com,,client-id,refresh-token
"""
        result = server.import_jobs({"mode": "api", "text": csv_text, "defaults": {}})
        self.assertEqual(result["added"], 3)
        self.assertEqual({job["provider"]["mode"] for job in server.load_jobs()}, {"api", "imap", "outlook_oauth"})

    def test_duplicate_email_is_rejected(self):
        first = server.import_jobs({"mode": "api", "text": "user@example.com----https://mail.test/a"})
        second = server.import_jobs({"mode": "api", "text": "USER@example.com----https://mail.test/b"})
        self.assertEqual(first["added"], 1)
        self.assertEqual(second["added"], 0)
        self.assertEqual(second["skipped"], 1)

    def test_batch_import_allocates_unique_registration_names(self):
        result = server.import_jobs(
            {
                "mode": "api",
                "text": "one@example.com\ntwo@example.com\nthree@example.com",
                "defaults": {"apiUrl": "https://mail.test/latest?email={email}"},
                "accountDefaults": {"fullName": "Same Name"},
            }
        )

        self.assertEqual(result["added"], 3)
        names = [str(job.get("fullName") or "") for job in server.load_jobs()]
        self.assertTrue(all(names))
        self.assertEqual(len(set(names)), 3)
        self.assertNotIn("Same Name", names)

    def test_legacy_seven_field_api_format_uses_third_field(self):
        line = (
            "legacy@example.com----mail-password----https://mail.test/latest?token=secret----"
            "mailbox@example.com----another-password----client-id----refresh-token"
        )
        result = server.import_jobs({"mode": "api", "text": line})
        self.assertEqual(result["added"], 1)
        job = server.get_job(server.load_jobs()[0]["id"])
        self.assertEqual(job["provider"]["apiUrl"], "https://mail.test/latest?token=secret")

    def test_unknown_csv_mode_is_rejected_instead_of_becoming_outlook(self):
        csv_text = "email,otp_mode,outlook_client_id,outlook_refresh_token\nuser@example.com,outlok,client,refresh\n"
        result = server.import_jobs({"mode": "api", "text": csv_text})
        self.assertEqual(result["added"], 0)
        self.assertIn("不支持的取码模式", result["errors"][0]["errors"])

    def test_multi_account_api_default_requires_email_template(self):
        rejected = server.import_jobs(
            {
                "mode": "api",
                "text": "one@example.com\ntwo@example.com",
                "defaults": {"apiUrl": "https://mail.test/latest"},
            }
        )
        self.assertEqual(rejected["added"], 0)

        accepted = server.import_jobs(
            {
                "mode": "api",
                "text": "one@example.com\ntwo@example.com",
                "defaults": {"apiUrl": "https://mail.test/latest?email={email}"},
            }
        )
        self.assertEqual(accepted["added"], 2)
        urls = [server.get_job(job["id"])["provider"]["apiUrl"] for job in server.load_jobs()]
        self.assertTrue(any("one%40example.com" in url for url in urls))

    def test_mfa_summary_is_atomically_retained_from_pending_to_enabled(self):
        server.import_jobs({"mode": "api", "text": "user@example.com----https://mail.test/a"})
        raw_job = server.load_jobs()[0]
        state_path = Path(self.temp_dir.name) / "state.json"
        server.write_json_atomic(state_path, {"cookies": [], "accessToken": "token"})
        server.update_job(raw_job["id"], storageStatePath=str(state_path), registrationStatus="registered")
        job = server.get_job(raw_job["id"])

        pending = server.persist_mfa_summary(
            job,
            status="pending_activation",
            secret="JBSWY3DPEHPK3PXP",
            session_id="session-1",
            factor_id="factor-1",
        )
        enabled = server.persist_mfa_summary(job, status="enabled", factor_id="factor-1")

        self.assertEqual(pending["status"], "pending_activation")
        self.assertEqual(enabled["status"], "enabled")
        self.assertEqual(enabled["secret"], "JBSWY3DPEHPK3PXP")
        self.assertEqual(enabled["sessionId"], "")
        self.assertTrue(server.credential_payload(server.get_job(raw_job["id"]))["totpCode"].isdigit())

    def test_credentials_return_at_without_exposing_it_in_public_job(self):
        server.import_jobs({"mode": "api", "text": "user@example.com----https://mail.test/a"})
        raw_job = server.load_jobs()[0]
        payload = base64.urlsafe_b64encode(json.dumps({"exp": 4102444800}).encode()).decode().rstrip("=")
        token = f"header.{payload}.signature"
        state_path = server.X9_RUNTIME_ROOT / "登录态" / "user@example.com.json"
        server.write_json_atomic(state_path, {"cookies": [], "accessToken": token})
        server.update_job(
            raw_job["id"],
            storageStatePath=str(state_path),
            registrationStatus="registered",
            remotePasswordSet=True,
            remotePasswordMode="signup_password_step",
            remotePasswordStatus="set",
        )
        job = server.get_job(raw_job["id"])
        server.persist_access_token(job, token, source="registration")

        credentials = server.credential_payload(server.get_job(raw_job["id"]))
        public = server.public_job(server.load_jobs()[0])

        self.assertEqual(credentials["accessToken"], token)
        self.assertEqual(credentials["atStatus"], "available")
        self.assertTrue(credentials["remotePasswordSet"])
        self.assertEqual(credentials["remotePasswordStatus"], "set")
        self.assertNotIn(token, str(public))

    def test_delete_jobs_removes_records_but_preserves_account_artifacts(self):
        server.import_jobs({"mode": "api", "text": "user@example.com----https://mail.test/a"})
        raw_job = server.load_jobs()[0]
        state_path = server.X9_RUNTIME_ROOT / "登录态" / "user@example.com.json"
        server.write_json_atomic(state_path, {"cookies": [{"name": "session", "value": "value"}]})

        result = server.delete_jobs([raw_job["id"]])

        self.assertEqual(result["removed"], 1)
        self.assertEqual(server.load_jobs(), [])
        self.assertNotIn(raw_job["id"], server.load_secret_store())
        self.assertTrue(state_path.exists())

    def test_at_refresh_falls_back_to_full_login_and_persists_latest_token(self):
        server.import_jobs({"mode": "api", "text": "user@example.com----https://mail.test/a"})
        raw_job = server.load_jobs()[0]
        state_path = server.X9_RUNTIME_ROOT / "登录态" / "user@example.com.json"
        server.write_json_atomic(
            state_path,
            {
                "cookies": [{"name": "session", "value": "old"}],
                "accessToken": "old-token",
                "mfa_summary": {"status": "enabled", "secret": "JBSWY3DPEHPK3PXP"},
            },
        )
        server.update_job(
            raw_job["id"],
            status="ready",
            stage="ready",
            registrationStatus="registered",
            mfaStatus="enabled",
            storageStatePath=str(state_path),
        )
        replacement = {
            "cookies": [{"name": "session", "value": "new"}],
            "accessToken": "new-token",
        }

        with (
            mock.patch.object(server, "refresh_access_token_from_session", side_effect=RuntimeError("expired")),
            mock.patch.object(
                server,
                "run_registration",
                return_value=(True, {"_storageStatePayload": replacement, "_accessToken": "new-token"}),
            ) as login,
        ):
            server.run_at_refresh_one(raw_job["id"], server.load_settings())

        self.assertEqual(login.call_args.kwargs["operation"], "login")
        self.assertEqual(login.call_args.kwargs["mfa_totp_secret"], "JBSWY3DPEHPK3PXP")
        saved = server.read_json(state_path, {})
        self.assertEqual(saved["accessToken"], "new-token")
        self.assertEqual(saved["mfa_summary"]["secret"], "JBSWY3DPEHPK3PXP")
        job = server.get_job(raw_job["id"])
        self.assertEqual(job["atStatus"], "available")
        self.assertEqual(job["atSource"], "full_login")
        self.assertEqual(job["status"], "ready")

    def test_at_refresh_without_totp_falls_back_to_email_login(self):
        server.import_jobs({"mode": "api", "text": "user@example.com----https://mail.test/a"})
        raw_job = server.load_jobs()[0]
        state_path = server.X9_RUNTIME_ROOT / "登录态" / "user@example.com.json"
        server.write_json_atomic(
            state_path,
            {
                "cookies": [{"name": "session", "value": "old"}],
                "accessToken": "old-token",
            },
        )
        server.update_job(
            raw_job["id"],
            status="registered",
            stage="registered",
            registrationStatus="registered",
            mfaStatus="pending",
            storageStatePath=str(state_path),
        )
        replacement = {
            "cookies": [{"name": "session", "value": "new"}],
            "accessToken": "new-token",
        }

        with (
            mock.patch.object(server, "refresh_access_token_from_session", side_effect=RuntimeError("expired")),
            mock.patch.object(
                server,
                "run_registration",
                return_value=(True, {"_storageStatePayload": replacement, "_accessToken": "new-token"}),
            ) as login,
            mock.patch.object(server, "persist_mfa_summary") as persist_summary,
        ):
            server.run_at_refresh_one(raw_job["id"], server.load_settings())

        self.assertEqual(login.call_args.kwargs["operation"], "login")
        self.assertEqual(login.call_args.kwargs["mfa_totp_secret"], "")
        persist_summary.assert_not_called()
        saved = server.read_json(state_path, {})
        self.assertEqual(saved["accessToken"], "new-token")
        self.assertNotIn("mfa_summary", saved)
        job = server.get_job(raw_job["id"])
        self.assertEqual(job["atStatus"], "available")
        self.assertEqual(job["atSource"], "full_login")
        self.assertEqual(job["status"], "registered")
        self.assertEqual(job["stage"], "registered")

    def test_basic_auth(self):
        encoded = server.base64.b64encode(b"admin:secret").decode("ascii")
        with (
            mock.patch.object(server, "ACCESS_USERNAME", "admin"),
            mock.patch.object(server, "ACCESS_PASSWORD", "secret"),
        ):
            self.assertTrue(server.basic_auth_valid(f"Basic {encoded}"))
            self.assertFalse(server.basic_auth_valid("Bearer secret"))

    def test_public_settings_never_returns_proxy_credentials(self):
        server.save_settings(
            {
                "proxy": "http://user:pass@proxy.test:8080",
                "proxyPool": [
                    "http://pool-user:pool-secret@one.test:8001",
                    "two.test:8002:second-user:second-secret",
                ],
                "proxyStrategy": "random",
            }
        )
        payload = server.public_settings()
        self.assertEqual(payload["proxy"], "")
        self.assertTrue(payload["proxyConfigured"])
        self.assertEqual(payload["proxyPool"], [])
        self.assertEqual(payload["proxyPoolCount"], 2)
        self.assertEqual(payload["proxyStrategy"], "random")
        self.assertNotIn("pool-secret", str(payload))
        self.assertNotIn("second-secret", str(payload))

    def test_sms_settings_are_masked_and_only_forwarded_to_phone_binding(self):
        server.save_settings(
            {
                "smsProvider": "smsbower",
                "smsApiKey": "sms-secret-key",
                "smsCountry": "52",
                "smsService": "dr",
                "smsMaxPrice": 1.25,
            }
        )
        public = server.public_settings()
        self.assertEqual(public["smsApiKey"], "")
        self.assertTrue(public["smsApiKeyConfigured"])
        self.assertNotIn("sms-secret-key", str(public))

        server.import_jobs({"mode": "api", "text": "user@example.com----https://mail.test/a"})
        job = server.get_job(server.load_jobs()[0]["id"])
        register_payload = server._runner_input(job, server.load_settings())
        self.assertEqual(register_payload["phone_verification"], {})

        payload = server._runner_input(job, server.load_settings(), operation="bind_phone")
        phone = payload["phone_verification"]
        self.assertEqual(phone["sms_provider"], "smsbower")
        self.assertEqual(phone["sms_api_key"], "sms-secret-key")
        self.assertEqual(phone["sms_country"], "52")
        self.assertEqual(phone["sms_service"], "dr")
        self.assertFalse(phone["sms_reuse_phone"])

    def test_blank_sms_key_can_preserve_existing_secret(self):
        server.save_settings({"smsProvider": "smsbower", "smsApiKey": "sms-secret-key"})
        saved = server.save_settings({"smsCountry": "52"})
        self.assertEqual(saved["smsApiKey"], "sms-secret-key")

        disabled = server.save_settings({"smsProvider": ""})
        server.import_jobs({"mode": "api", "text": "user@example.com----https://mail.test/a"})
        job = server.get_job(server.load_jobs()[0]["id"])
        self.assertEqual(server._runner_input(job, disabled)["phone_verification"], {})

    def test_sms_activation_cleanup_cancels_and_removes_journal(self):
        journal = server.sms_activation_journal_path("job-1")
        server.write_json_atomic(
            journal,
            {
                "provider": "smsbower",
                "activationId": "activation-1",
                "country": "52",
                "service": "dr",
                "proxy": "http://proxy.test:8080",
            },
        )
        provider = mock.Mock()
        provider.cancel.return_value = True
        settings = {
            "smsApiKey": "secret",
            "smsCountry": "52",
            "smsService": "dr",
            "smsMaxPrice": -1,
            "proxy": "",
        }

        with mock.patch.object(server, "create_sms_provider", return_value=provider) as create:
            cleaned = server.cleanup_sms_activation_journal(journal, settings)

        self.assertTrue(cleaned)
        self.assertFalse(journal.exists())
        provider.cancel.assert_called_once_with("activation-1")
        self.assertEqual(create.call_args.args[1]["proxy"], "http://proxy.test:8080")

    def test_sms_activation_cleanup_keeps_journal_when_cancel_is_unconfirmed(self):
        journal = server.sms_activation_journal_path("job-2")
        server.write_json_atomic(
            journal,
            {"provider": "smsbower", "activationId": "activation-2"},
        )
        provider = mock.Mock()
        provider.cancel.return_value = False
        with mock.patch.object(server, "create_sms_provider", return_value=provider):
            cleaned = server.cleanup_sms_activation_journal(
                journal,
                {"smsApiKey": "secret", "proxy": ""},
            )

        self.assertFalse(cleaned)
        self.assertTrue(journal.exists())

    def test_sms_activation_recovery_includes_interrupted_temp_journal(self):
        primary = server.sms_activation_journal_path("job-temp")
        temp_journal = primary.with_suffix(primary.suffix + ".999.tmp")
        server.write_json_atomic(
            temp_journal,
            {"provider": "smsbower", "activationId": "activation-temp"},
        )
        provider = mock.Mock()
        provider.cancel.return_value = True
        with mock.patch.object(server, "create_sms_provider", return_value=provider):
            server.recover_pending_sms_activations({"smsApiKey": "secret", "proxy": ""})

        provider.cancel.assert_called_once_with("activation-temp")
        self.assertFalse(temp_journal.exists())

    def test_startup_sms_recovery_only_processes_its_initial_snapshot(self):
        old_journal = server.sms_activation_journal_path("old-job")
        server.write_json_atomic(
            old_journal,
            {"provider": "smsbower", "activationId": "activation-old"},
        )
        startup_snapshot = server.list_pending_sms_activation_journals()
        new_journal = server.sms_activation_journal_path("new-job")
        server.write_json_atomic(
            new_journal,
            {"provider": "smsbower", "activationId": "activation-new"},
        )
        provider = mock.Mock()
        provider.cancel.return_value = True
        with mock.patch.object(server, "create_sms_provider", return_value=provider):
            server.recover_pending_sms_activations(
                {"smsApiKey": "secret", "proxy": ""},
                paths=startup_snapshot,
            )

        provider.cancel.assert_called_once_with("activation-old")
        self.assertFalse(old_journal.exists())
        self.assertTrue(new_journal.exists())

    def test_phone_binding_does_not_overwrite_uncancelled_sms_activation(self):
        job = {"id": "job-3", "email": "user@example.com"}
        journal = server.sms_activation_journal_path(job["id"])
        server.write_json_atomic(
            journal,
            {"provider": "smsbower", "activationId": "activation-3"},
        )
        with (
            mock.patch.object(server, "cleanup_sms_activation_journal", return_value=False),
            mock.patch.object(server.subprocess, "Popen") as popen,
        ):
            with self.assertRaisesRegex(RuntimeError, "仍未确认取消"):
                server.run_registration(
                    job,
                    {
                        "registerTimeoutSeconds": 60,
                        "smsProvider": "smsbower",
                        "smsApiKey": "secret",
                    },
                    operation="bind_phone",
                )

        popen.assert_not_called()

    def test_phone_binding_waits_for_startup_sms_recovery_barrier(self):
        job = {"id": "job-barrier", "email": "user@example.com"}
        with (
            mock.patch.object(server.SMS_RECOVERY_COMPLETE, "wait", return_value=False) as wait,
            mock.patch.object(server.subprocess, "Popen") as popen,
        ):
            with self.assertRaisesRegex(RuntimeError, "启动恢复仍在进行"):
                server.run_registration(
                    job,
                    {
                        "registerTimeoutSeconds": 60,
                        "smsProvider": "smsbower",
                        "smsApiKey": "secret",
                    },
                    operation="bind_phone",
                )

        wait.assert_called_once_with(timeout=120)
        popen.assert_not_called()

    def test_runner_process_termination_escalates_after_grace_period(self):
        process = mock.Mock()
        process.poll.return_value = None
        process.wait.side_effect = [server.subprocess.TimeoutExpired("runner", 0.1), 0]

        server._terminate_runner_process(process, grace_seconds=0.1)

        process.terminate.assert_called_once_with()
        process.kill.assert_called_once_with()
        self.assertEqual(process.wait.call_count, 2)

    def test_login_runner_does_not_receive_sms_provider_secret(self):
        payload = server._runner_input(
            {"id": "job-login", "email": "user@example.com"},
            {"smsProvider": "smsbower", "smsApiKey": "secret"},
            operation="login",
        )

        self.assertEqual(payload["phone_verification"], {})

    def test_start_phone_binding_accepts_only_explicit_eligible_unique_jobs(self):
        server.import_jobs(
            {
                "mode": "api",
                "text": "one@example.com\ntwo@example.com\nthree@example.com",
                "defaults": {"apiUrl": "https://mail.test/latest?email={email}"},
            }
        )
        first, second, third = server.load_jobs()
        for raw_job in (first, second):
            state_path = server.job_state_path(raw_job)
            server.write_json_atomic(
                state_path,
                {"cookies": [{"name": "session", "value": raw_job["id"], "domain": ".chatgpt.com"}]},
            )
            server.update_job(
                raw_job["id"],
                status="ready",
                registrationStatus="registered",
                mfaStatus="enabled",
                storageStatePath=str(state_path),
            )
        server.update_job(second["id"], phoneStatus="phone_bound", phoneMasked="+66***999")
        server.save_settings({"smsProvider": "herosms", "smsApiKey": "hero-secret", "concurrency": 2})

        with mock.patch.object(server.threading, "Thread") as thread_type:
            status, payload = server.start_phone_binding(
                [first["id"], first["id"], second["id"], third["id"], "missing-job"]
            )

        self.assertEqual(status, 202)
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["skipped"], 4)
        self.assertEqual(
            {item["reason"] for item in payload["skippedItems"]},
            {"duplicate", "already_bound", "account_not_registered", "not_found"},
        )
        self.assertEqual(server.get_job(first["id"])["phoneStatus"], "phone_queued")
        self.assertEqual(server.get_job(second["id"])["phoneStatus"], "phone_bound")
        with server.RUNTIME_LOCK:
            self.assertTrue(server.RUNTIME["running"])
            self.assertEqual(server.RUNTIME["totalCount"], 1)
            self.assertEqual(server.RUNTIME["activeJobIds"], [first["id"]])
        thread_type.assert_called_once()
        thread_type.return_value.start.assert_called_once_with()
        self.assertNotIn("hero-secret", server.JOBS_PATH.read_text(encoding="utf-8"))
        self.assertNotIn("hero-secret", str(server.state_payload()))

    def test_manual_phone_session_accepts_new_number_and_code_without_storing_them_in_job(self):
        server.import_jobs({"mode": "api", "text": "user@example.com----https://mail.test/a"})
        raw_job = server.load_jobs()[0]
        state_path = server.job_state_path(raw_job)
        server.write_json_atomic(
            state_path,
            {"cookies": [{"name": "session", "value": "old", "domain": ".chatgpt.com"}]},
        )
        server.update_job(
            raw_job["id"],
            status="ready",
            registrationStatus="registered",
            mfaStatus="enabled",
            storageStatePath=str(state_path),
        )

        with mock.patch.object(server.threading, "Thread") as thread_type:
            status, payload = server.send_manual_phone(raw_job["id"], "+66812345678")

        self.assertEqual(status, 202)
        self.assertTrue(payload["active"])
        thread_type.return_value.start.assert_called_once_with()
        control_dir = server.manual_phone_control_dir(raw_job["id"])
        first_command = server.read_json(control_dir / "phone.json", {})
        self.assertEqual(first_command["attemptId"], 1)
        self.assertEqual(first_command["phoneNumber"], "+66812345678")
        self.assertNotIn("+66812345678", server.JOBS_PATH.read_text(encoding="utf-8"))

        server.update_manual_phone_status(
            raw_job["id"],
            phase="waiting_code",
            active=True,
            attemptId=1,
            phoneMasked="+66***5678",
        )
        code_status, _code_payload = server.submit_manual_phone_code(raw_job["id"], "123456")
        self.assertEqual(code_status, 202)
        self.assertEqual(server.read_json(control_dir / "code.json", {})["code"], "123456")
        duplicate_status, _duplicate_payload = server.submit_manual_phone_code(raw_job["id"], "654321")
        self.assertEqual(duplicate_status, 409)
        self.assertEqual(server.read_json(control_dir / "code.json", {})["code"], "123456")

        server.update_manual_phone_status(raw_job["id"], phase="verifying")
        verifying_status, _verifying_payload = server.submit_manual_phone_code(raw_job["id"], "654321")
        self.assertEqual(verifying_status, 409)

        replace_status, replacement = server.send_manual_phone(raw_job["id"], "+66987654321")
        self.assertEqual(replace_status, 202)
        self.assertEqual(replacement["queuedAttemptId"], 2)
        second_command = server.read_json(control_dir / "phone.json", {})
        self.assertEqual(second_command["attemptId"], 2)
        self.assertEqual(second_command["phoneNumber"], "+66987654321")
        self.assertEqual(server.manual_phone_status(raw_job["id"])["attemptId"], 1)
        self.assertEqual(server.manual_phone_status(raw_job["id"])["phase"], "verifying")
        jobs_text = server.JOBS_PATH.read_text(encoding="utf-8")
        self.assertNotIn("+66812345678", jobs_text)
        self.assertNotIn("+66987654321", jobs_text)
        self.assertNotIn("123456", jobs_text)

    def test_manual_phone_start_claims_runtime_and_rolls_back_when_thread_start_fails(self):
        server.import_jobs({"mode": "api", "text": "user@example.com----https://mail.test/a"})
        raw_job = server.load_jobs()[0]
        state_path = server.job_state_path(raw_job)
        server.write_json_atomic(
            state_path,
            {"cookies": [{"name": "session", "value": "old", "domain": ".chatgpt.com"}]},
        )
        server.update_job(
            raw_job["id"],
            status="ready",
            registrationStatus="registered",
            mfaStatus="enabled",
            storageStatePath=str(state_path),
        )

        fake_thread = mock.Mock()
        fake_thread.start.side_effect = RuntimeError("thread start failed")

        def create_thread(*_args, **_kwargs):
            with server.RUNTIME_LOCK:
                self.assertTrue(server.RUNTIME["running"])
                self.assertEqual(server.RUNTIME["operation"], "manual_phone_binding")
                self.assertEqual(server.RUNTIME["manualPhoneJobId"], raw_job["id"])
                self.assertTrue(server.RUNTIME["manualPhoneSessionId"])
            return fake_thread

        with mock.patch.object(server.threading, "Thread", side_effect=create_thread):
            with self.assertRaisesRegex(RuntimeError, "thread start failed"):
                server.send_manual_phone(raw_job["id"], "+66812345678")

        with server.RUNTIME_LOCK:
            self.assertFalse(server.RUNTIME["running"])
            self.assertEqual(server.RUNTIME["operation"], "idle")
            self.assertEqual(server.RUNTIME["manualPhoneJobId"], "")
            self.assertEqual(server.RUNTIME["manualPhoneSessionId"], "")
        self.assertEqual(server.get_job(raw_job["id"])["phoneStatus"], "phone_unknown")
        control_dir = server.manual_phone_control_dir(raw_job["id"])
        self.assertFalse((control_dir / "phone.json").exists())
        self.assertFalse((control_dir / "code.json").exists())
        self.assertFalse(server.manual_phone_status(raw_job["id"])["active"])

    def test_old_manual_phone_worker_cannot_clear_new_session(self):
        server.import_jobs({"mode": "api", "text": "user@example.com----https://mail.test/a"})
        raw_job = server.load_jobs()[0]
        control_dir = server.manual_phone_control_dir(raw_job["id"])
        server.write_json_atomic(
            control_dir / "status.json",
            {
                "sessionId": "new-session",
                "jobId": raw_job["id"],
                "phase": "waiting_phone",
                "active": True,
                "attemptId": 1,
            },
        )
        server.write_json_atomic(control_dir / "phone.json", {"attemptId": 2, "phoneNumber": "+66812345678"})
        with server.RUNTIME_LOCK:
            server.RUNTIME.update(
                {
                    "running": True,
                    "operation": "manual_phone_binding",
                    "manualPhoneJobId": raw_job["id"],
                    "manualPhoneSessionId": "new-session",
                }
            )

        with mock.patch.object(server, "run_phone_binding_one", return_value=False):
            server._manual_phone_worker(raw_job["id"], server.load_settings(), control_dir, "old-session")

        with server.RUNTIME_LOCK:
            self.assertTrue(server.RUNTIME["running"])
            self.assertEqual(server.RUNTIME["manualPhoneSessionId"], "new-session")
        self.assertEqual(server.manual_phone_status(raw_job["id"])["phase"], "waiting_phone")
        self.assertTrue((control_dir / "phone.json").exists())

    def test_manual_phone_recovery_removes_plaintext_commands(self):
        control_dir = server.MANUAL_PHONE_DIR / "control"
        server.write_json_atomic(
            control_dir / "status.json",
            {"sessionId": "old", "phase": "waiting_code", "active": True, "attemptId": 1},
        )
        server.write_json_atomic(control_dir / "phone.json", {"phoneNumber": "+66812345678"})
        server.write_json_atomic(control_dir / "code.json", {"code": "123456"})
        server.write_json_atomic(control_dir / "code-submission.json", {"attemptId": 1})
        temp_command = control_dir / ".code.json.crashed.tmp"
        temp_command.write_text('{"code":"654321"}', encoding="utf-8")

        server.recover_interrupted_manual_phone_controls()

        self.assertFalse((control_dir / "phone.json").exists())
        self.assertFalse((control_dir / "code.json").exists())
        self.assertFalse((control_dir / "code-submission.json").exists())
        self.assertFalse(temp_command.exists())
        recovered = server.read_json(control_dir / "status.json", {})
        self.assertFalse(recovered["active"])
        self.assertEqual(recovered["phase"], "stopped")

    def test_phone_binding_success_preserves_primary_state_and_only_saves_masked_phone(self):
        server.import_jobs({"mode": "api", "text": "user@example.com----https://mail.test/a"})
        raw_job = server.load_jobs()[0]
        state_path = server.job_state_path(raw_job)
        original_state = {
            "cookies": [{"name": "session", "value": "old", "domain": ".chatgpt.com"}],
            "accessToken": "existing-token",
            "mfa_summary": {"status": "enabled", "secret": "JBSWY3DPEHPK3PXP"},
        }
        server.write_json_atomic(state_path, original_state)
        server.update_job(
            raw_job["id"],
            status="ready",
            stage="ready",
            registrationStatus="registered",
            mfaStatus="enabled",
            storageStatePath=str(state_path),
        )
        server.save_settings({"smsProvider": "herosms", "smsApiKey": "hero-secret"})
        replacement_state = {
            "cookies": [{"name": "session", "value": "new", "domain": ".chatgpt.com"}],
            "accessToken": "existing-token",
        }

        with mock.patch.object(
            server,
            "run_registration",
            return_value=(
                True,
                {
                    "success": True,
                    "boundPhone": "+66812345678",
                    "_storageStatePayload": replacement_state,
                },
            ),
        ) as run:
            success = server.run_phone_binding_one(raw_job["id"], server.load_settings())

        self.assertTrue(success)
        self.assertEqual(run.call_args.kwargs["operation"], "bind_phone")
        self.assertEqual(run.call_args.kwargs["mfa_totp_secret"], "JBSWY3DPEHPK3PXP")
        job = server.get_job(raw_job["id"])
        self.assertEqual(job["status"], "ready")
        self.assertEqual(job["mfaStatus"], "enabled")
        self.assertEqual(job["phoneStatus"], "phone_bound")
        self.assertEqual(job["phoneMasked"], "+66***678")
        saved_state = server.read_json(state_path, {})
        self.assertEqual(saved_state["cookies"][0]["value"], "new")
        self.assertEqual(saved_state["mfa_summary"]["secret"], "JBSWY3DPEHPK3PXP")
        self.assertNotIn("+66812345678", server.JOBS_PATH.read_text(encoding="utf-8"))
        self.assertNotIn("+66812345678", str(server.public_job(server.load_jobs()[0])))

    def test_phone_binding_reuses_selected_proxy_for_openai_and_sms_requests(self):
        server.import_jobs({"mode": "api", "text": "user@example.com----https://mail.test/a"})
        raw_job = server.load_jobs()[0]
        state_path = server.job_state_path(raw_job)
        server.write_json_atomic(
            state_path,
            {"cookies": [{"name": "session", "value": "old", "domain": ".chatgpt.com"}]},
        )
        server.update_job(
            raw_job["id"],
            status="ready",
            registrationStatus="registered",
            storageStatePath=str(state_path),
        )
        server.save_settings(
            {
                "smsProvider": "herosms",
                "smsApiKey": "hero-secret",
                "proxyPool": ["socks5://user:password@proxy.test:1080"],
                "proxyStrategy": "single",
            }
        )
        settings = server.load_settings()
        selected = server.settings_for_job(settings, raw_job["id"])
        self.assertEqual(selected["proxy"], "socks5h://user:password@proxy.test:1080")

        runner_payload = server._runner_input(raw_job, selected, operation="bind_phone")
        self.assertEqual(runner_payload["proxy"], selected["proxy"])
        self.assertEqual(runner_payload["phone_verification"]["proxy"], selected["proxy"])

        with mock.patch.object(
            server,
            "run_registration",
            return_value=(False, {"message": "expected test stop"}),
        ) as run:
            server.run_phone_binding_one(
                raw_job["id"],
                settings,
                manual_control_path=str(server.MANUAL_PHONE_DIR / "manual-phone-control"),
            )

        self.assertEqual(run.call_args.args[1]["proxy"], selected["proxy"])
        self.assertEqual(
            run.call_args.kwargs["phone_verification_override"]["proxy"],
            selected["proxy"],
        )

    def test_browser_page_mfa_reuses_explicit_proxy(self):
        proxy = "socks5h://user:password@proxy.test:1080"
        with (
            mock.patch.object(
                mfa_module,
                "extract_runtime_auth_from_browser_page",
                return_value={
                    "accessToken": "token",
                    "cookieHeader": "session=value",
                    "oaiDeviceId": "device",
                    "referer": "https://chatgpt.com/",
                    "clientHeaders": {},
                    "pageUrl": "https://chatgpt.com/",
                },
            ),
            mock.patch.object(
                mfa_module,
                "enable_totp_mfa_with_credentials",
                return_value={"success": True},
            ) as enable,
        ):
            result = mfa_module.enable_totp_mfa_via_browser_page(
                cdp_url="http://127.0.0.1:9222",
                proxy=proxy,
            )

        self.assertTrue(result["success"])
        self.assertEqual(enable.call_args.kwargs["proxy"], proxy)

    def test_phone_binding_state_write_warning_does_not_rent_another_number(self):
        server.import_jobs({"mode": "api", "text": "user@example.com----https://mail.test/a"})
        raw_job = server.load_jobs()[0]
        state_path = server.job_state_path(raw_job)
        server.write_json_atomic(
            state_path,
            {"cookies": [{"name": "session", "value": "old", "domain": ".chatgpt.com"}]},
        )
        server.update_job(
            raw_job["id"],
            status="ready",
            registrationStatus="registered",
            storageStatePath=str(state_path),
        )
        settings = {**server.load_settings(), "smsProvider": "smsbower", "smsApiKey": "secret"}
        with (
            mock.patch.object(
                server,
                "run_registration",
                return_value=(True, {"success": True, "boundPhone": "+66812345678", "_storageStatePayload": {"cookies": []}}),
            ),
            mock.patch.object(
                server,
                "persist_phone_binding_storage_state",
                side_effect=OSError("disk unavailable"),
            ),
        ):
            success = server.run_phone_binding_one(raw_job["id"], settings)

        self.assertTrue(success)
        job = server.get_job(raw_job["id"])
        self.assertEqual(job["phoneStatus"], "phone_bound")
        self.assertEqual(job["phoneMasked"], "+66***678")
        self.assertIn("本地登录态更新失败", job["phoneError"])

    def test_phone_binding_errors_redact_provider_secret_and_full_phone(self):
        server.import_jobs({"mode": "api", "text": "user@example.com----https://mail.test/a"})
        raw_job = server.load_jobs()[0]
        state_path = server.job_state_path(raw_job)
        server.write_json_atomic(
            state_path,
            {"cookies": [{"name": "session", "value": "old", "domain": ".chatgpt.com"}]},
        )
        server.update_job(raw_job["id"], registrationStatus="registered", storageStatePath=str(state_path))
        server.save_settings({"smsProvider": "smsbower", "smsApiKey": "top-secret"})

        with mock.patch.object(
            server,
            "run_registration",
            return_value=(False, {"message": "top-secret failed for +66812345678"}),
        ):
            success = server.run_phone_binding_one(raw_job["id"], server.load_settings())

        self.assertFalse(success)
        error = server.get_job(raw_job["id"])["phoneError"]
        self.assertNotIn("top-secret", error)
        self.assertNotIn("+66812345678", error)
        self.assertIn("+66***678", error)

    def test_recovery_stops_phone_binding_without_changing_ready_status(self):
        server.import_jobs({"mode": "api", "text": "user@example.com----https://mail.test/a"})
        raw_job = server.load_jobs()[0]
        server.update_job(
            raw_job["id"],
            status="ready",
            stage="ready",
            registrationStatus="registered",
            mfaStatus="enabled",
            phoneStatus="phone_binding",
        )

        server.recover_interrupted_jobs()

        job = server.get_job(raw_job["id"])
        self.assertEqual(job["status"], "ready")
        self.assertEqual(job["stage"], "ready")
        self.assertEqual(job["phoneStatus"], "phone_stopped")

    def test_restart_keeps_intentionally_registered_account_available_for_optional_mfa(self):
        server.import_jobs({"mode": "api", "text": "user@example.com----https://mail.test/a"})
        raw_job = server.load_jobs()[0]
        server.update_job(
            raw_job["id"],
            status="registered",
            stage="registered",
            registrationStatus="registered",
            mfaStatus="pending",
        )

        server.recover_interrupted_jobs()

        job = server.get_job(raw_job["id"])
        self.assertEqual(job["status"], "registered")
        self.assertEqual(job["stage"], "registered")
        self.assertEqual(job["mfaStatus"], "pending")

    def test_fetch_full_session_uses_cookies_and_persists_latest_at(self):
        server.import_jobs({"mode": "api", "text": "user@example.com----https://mail.test/a"})
        raw_job = server.load_jobs()[0]
        state_path = server.job_state_path(raw_job)
        server.write_json_atomic(
            state_path,
            {
                "cookies": [
                    {"name": "session", "value": "cookie-value", "domain": ".chatgpt.com"},
                    {"name": "oai-did", "value": "device-id", "domain": ".chatgpt.com"},
                ],
                "mfa_summary": {"status": "enabled", "secret": "JBSWY3DPEHPK3PXP"},
            },
        )
        server.update_job(raw_job["id"], storageStatePath=str(state_path), registrationStatus="registered")
        job = server.get_job(raw_job["id"])
        session = {"access_token": "fresh-at", "user": {"email": "user@example.com"}}

        with mock.patch.object(server, "read_auth_session_via_cookie_header", return_value=session) as read_session:
            result = server.fetch_full_session(job, {"proxy": "http://proxy.test:8080"})

        self.assertEqual(result["session"], session)
        self.assertIn("session=cookie-value", read_session.call_args.kwargs["cookie_header"])
        self.assertEqual(read_session.call_args.kwargs["oai_device_id"], "device-id")
        self.assertEqual(read_session.call_args.kwargs["proxy"], "http://proxy.test:8080")
        saved = server.read_json(state_path, {})
        self.assertEqual(saved["accessToken"], "fresh-at")
        self.assertEqual(saved["cookies"][0]["value"], "cookie-value")
        self.assertEqual(saved["mfa_summary"]["secret"], "JBSWY3DPEHPK3PXP")
        self.assertEqual(server.get_job(raw_job["id"])["atSource"], "full_session")

    def test_fetch_full_session_rejects_non_authenticated_payload(self):
        server.import_jobs({"mode": "api", "text": "user@example.com----https://mail.test/a"})
        raw_job = server.load_jobs()[0]
        state_path = server.job_state_path(raw_job)
        server.write_json_atomic(
            state_path,
            {"cookies": [{"name": "session", "value": "cookie-value", "domain": ".chatgpt.com"}]},
        )
        server.update_job(raw_job["id"], storageStatePath=str(state_path), registrationStatus="registered")
        job = server.get_job(raw_job["id"])

        with (
            mock.patch.object(
                server,
                "read_auth_session_via_cookie_header",
                return_value={"text": "challenge page"},
            ),
            mock.patch.object(
                server,
                "run_registration",
                return_value=(False, {"message": "重新登录失败"}),
            ) as relogin,
        ):
            with self.assertRaisesRegex(RuntimeError, "重新登录失败"):
                server.fetch_full_session(job, {"proxy": ""})

        self.assertEqual(relogin.call_args.kwargs["operation"], "login")

        self.assertFalse(server.get_job(raw_job["id"])["atPresent"])

    def test_fetch_full_session_rejects_session_for_another_account(self):
        server.import_jobs({"mode": "api", "text": "user@example.com----https://mail.test/a"})
        raw_job = server.load_jobs()[0]
        state_path = server.job_state_path(raw_job)
        server.write_json_atomic(
            state_path,
            {"cookies": [{"name": "session", "value": "cookie-value", "domain": ".chatgpt.com"}]},
        )
        server.update_job(raw_job["id"], storageStatePath=str(state_path), registrationStatus="registered")
        with mock.patch.object(
            server,
            "read_auth_session_via_cookie_header",
            return_value={"accessToken": "wrong-at", "user": {"email": "other@example.com"}},
        ):
            with self.assertRaisesRegex(RuntimeError, "账号与当前任务不匹配"):
                server.fetch_full_session(server.get_job(raw_job["id"]), {"proxy": ""})

        self.assertFalse(server.get_job(raw_job["id"])["atPresent"])

    def test_fetch_full_session_rejects_state_without_chatgpt_cookies(self):
        server.import_jobs({"mode": "api", "text": "user@example.com----https://mail.test/a"})
        raw_job = server.load_jobs()[0]
        state_path = server.job_state_path(raw_job)
        server.write_json_atomic(state_path, {"cookies": []})
        server.update_job(raw_job["id"], storageStatePath=str(state_path), registrationStatus="registered")

        with mock.patch.object(
            server,
            "run_registration",
            return_value=(False, {"message": "重新登录失败"}),
        ) as relogin:
            with self.assertRaisesRegex(RuntimeError, "重新登录失败"):
                server.fetch_full_session(server.get_job(raw_job["id"]), {"proxy": ""})

        self.assertEqual(relogin.call_args.kwargs["operation"], "login")

    def test_proxy_pool_normalization_and_round_robin(self):
        pool = server.normalize_proxy_pool(
            "proxy-one.test:8001\nproxy-two.test:8002:user:password\nsocks5://proxy-three.test:8003"
        )
        self.assertEqual(pool[0], "http://proxy-one.test:8001")
        self.assertEqual(pool[1], "http://user:password@proxy-two.test:8002")
        self.assertEqual(pool[2], "socks5h://proxy-three.test:8003")
        self.assertEqual(
            server.normalize_proxy_url("socks5://user:password@proxy.test:1080"),
            "socks5h://user:password@proxy.test:1080",
        )
        self.assertEqual(
            chatgpt_api_health._normalize_proxy_url("socks5://user:password@proxy.test:1080"),
            "socks5h://user:password@proxy.test:1080",
        )
        settings = {"proxyPool": pool, "proxyStrategy": "round_robin", "proxy": ""}
        with server.RUNTIME_LOCK:
            server.RUNTIME["proxyCursor"] = 0

        selected = [server.choose_proxy(settings, f"job-{index}") for index in range(4)]

        self.assertEqual(selected, [pool[0], pool[1], pool[2], pool[0]])

    def test_sticky_proxy_keeps_same_account_on_same_proxy(self):
        settings = {
            "proxyPool": ["http://one.test:8001", "http://two.test:8002"],
            "proxyStrategy": "sticky",
            "proxy": "",
        }
        first = server.choose_proxy(settings, "stable-job")
        self.assertEqual(first, server.choose_proxy(settings, "stable-job"))
        self.assertIn(first, settings["proxyPool"])

    def test_detect_exit_ip_uses_proxy_and_returns_latency(self):
        captured = {}

        class FakeResponse:
            text = '{"ip":"203.0.113.20"}'

            def raise_for_status(self):
                return None

            def json(self):
                return {"ip": "203.0.113.20"}

        def fake_get(url, **kwargs):
            captured["url"] = url
            captured["proxies"] = kwargs.get("proxies")
            return FakeResponse()

        with mock.patch.object(server.requests, "get", side_effect=fake_get):
            result = server.detect_exit_ip("http://user:secret@proxy.test:8080")

        self.assertTrue(result["ok"])
        self.assertEqual(result["ip"], "203.0.113.20")
        self.assertEqual(captured["proxies"]["https"], "http://user:secret@proxy.test:8080")

    def test_ip_geolocation_uses_public_api(self):
        class FakeResponse:
            def raise_for_status(self):
                return None

            def json(self):
                return {
                    "success": True,
                    "country": "Singapore",
                    "region": "Central Singapore",
                    "city": "Singapore",
                    "connection": {"isp": "Example Network"},
                    "timezone": {"id": "Asia/Singapore"},
                }

        with mock.patch.object(server.requests, "get", return_value=FakeResponse()) as request:
            result = server.lookup_ip_geolocation("203.0.113.20")

        self.assertTrue(result["ok"])
        self.assertEqual(result["location"], "Singapore · Central Singapore · Singapore")
        self.assertEqual(result["organization"], "Example Network")
        self.assertIn("203.0.113.20", request.call_args.args[0])

    def test_api_source_preflight_expands_email_without_returning_code(self):
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _size):
                return b"Your OpenAI code is 123456"

            def getcode(self):
                return 200

        captured = {}

        def open_request(request, timeout):
            captured["url"] = request.full_url
            captured["timeout"] = timeout
            return FakeResponse()

        with mock.patch.object(server.urllib.request, "urlopen", side_effect=open_request):
            result = server.test_source(
                {
                    "mode": "api",
                    "email": "user@example.com",
                    "provider": {"apiUrl": "https://mail.test/latest?email={email}"},
                }
            )

        self.assertTrue(result["codeDetected"])
        self.assertNotIn("123456", str(result))
        self.assertIn("user%40example.com", captured["url"])

    def test_email_otp_api_returns_code_from_json(self):
        class FakeHeaders:
            def get(self, _name):
                return "application/json"

        class FakeResponse:
            headers = FakeHeaders()

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _size):
                return b'{"verificationCode":"654321"}'

        server.import_jobs({"mode": "api", "text": "user@example.com----https://mail.test/latest"})
        job = server.get_job(server.load_jobs()[0]["id"])

        with mock.patch.object(server.urllib.request, "urlopen", return_value=FakeResponse()):
            result = server.fetch_email_verification_code(job)

        self.assertEqual(result["code"], "654321")
        self.assertEqual(result["mode"], "api")

    def test_email_otp_api_ignores_css_hex_colors(self):
        class FakeHeaders:
            def get(self, _name):
                return "text/html"

        class FakeResponse:
            headers = FakeHeaders()

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _size):
                return (
                    b'<html><body style="color:#000000">'
                    b'<p style="color:#202123">Hello</p>'
                    b"<p>Your temporary ChatGPT login code is 490780</p>"
                    b'<a href="https://u20216706.ct.sendgrid.net/x">Open</a>'
                    b"</body></html>"
                )

        server.import_jobs({"mode": "api", "text": "user@example.com----https://mail.test/latest"})
        job = server.get_job(server.load_jobs()[0]["id"])

        with mock.patch.object(server.urllib.request, "urlopen", return_value=FakeResponse()):
            result = server.fetch_email_verification_code(job)

        self.assertEqual(result["code"], "490780")

    def test_email_otp_api_rejects_color_only_mail_without_real_code(self):
        class FakeHeaders:
            def get(self, _name):
                return "text/html"

        class FakeResponse:
            headers = FakeHeaders()

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _size):
                return (
                    b'<html><body style="color:#000000">'
                    b'<p style="color:#202123">New sign-in to your OpenAI account</p>'
                    b"</body></html>"
                )

        server.import_jobs({"mode": "api", "text": "user@example.com----https://mail.test/latest"})
        job = server.get_job(server.load_jobs()[0]["id"])

        with mock.patch.object(server.urllib.request, "urlopen", return_value=FakeResponse()):
            with self.assertRaisesRegex(LookupError, "没有找到有效的 6 位验证码"):
                server.fetch_email_verification_code(job)

    def test_email_otp_imap_scans_newest_matching_recipient(self):
        raw_message = (
            b"To: user@example.com\r\n"
            b"Subject: OpenAI verification code 112233\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"Your verification code is 112233"
        )

        class FakeImap:
            def login(self, username, password):
                self.credentials = (username, password)

            def select(self, _folder, readonly=True):
                return "OK", [b"1"]

            def uid(self, action, *_args):
                if action == "search":
                    return "OK", [b"10 11"]
                return "OK", [(b"11 (RFC822)", raw_message)]

            def logout(self):
                return "BYE", []

        server.import_jobs(
            {
                "mode": "imap",
                "text": "user@example.com----mailbox@example.com----mail-password",
                "defaults": {"host": "imap.test", "folder": "INBOX"},
            }
        )
        job = server.get_job(server.load_jobs()[0]["id"])
        fake_imap = FakeImap()

        with mock.patch.object(server.imaplib, "IMAP4_SSL", return_value=fake_imap):
            result = server.fetch_email_verification_code(job)

        self.assertEqual(result["code"], "112233")
        self.assertEqual(fake_imap.credentials, ("mailbox@example.com", "mail-password"))

    def test_export_lines_uses_requested_field_order(self):
        server.import_jobs({"mode": "api", "text": "user@example.com----https://mail.test/latest"})
        raw_job = server.load_jobs()[0]
        state_path = server.X9_RUNTIME_ROOT / "登录态" / "user@example.com.json"
        server.write_json_atomic(
            state_path,
            {
                "accessToken": "latest-at",
                "mfa_summary": {"status": "enabled", "secret": "JBSWY3DPEHPK3PXP"},
            },
        )
        server.update_job(raw_job["id"], status="ready", storageStatePath=str(state_path))
        job = server.get_job(raw_job["id"])

        line = server.export_lines()[0]

        self.assertEqual(
            line,
            "----".join(
                [
                    "user@example.com",
                    job["accountPassword"],
                    "https://mail.test/latest",
                    "JBSWY3DPEHPK3PXP",
                    "latest-at",
                ]
            ),
        )

    def test_export_rt_defaults_to_sub2api_for_phone_bound_accounts(self):
        server.import_jobs({"mode": "api", "text": "user@example.com----https://mail.test/latest"})
        raw_job = server.load_jobs()[0]
        success_path = server.X9_RUNTIME_ROOT / "成功凭证" / "user@example.com.json"
        server.write_json_atomic(
            success_path,
            {
                "type": "codex",
                "email": "user@example.com",
                "expired": "2026-07-29T00:00:00+00:00",
                "id_token": "id-token",
                "account_id": "acct-1",
                "access_token": "access-token",
                "last_refresh": "2026-07-19T00:00:00+00:00",
                "refresh_token": "rt.1.example",
            },
        )
        server.update_job(
            raw_job["id"],
            status="ready",
            phoneStatus="phone_bound",
            phoneMasked="+60***123",
            successCredentialPath=str(success_path),
            rtStatus="available",
            rtPresent=True,
        )

        result = server.export_rt_payloads(format_name="sub2api")
        body, content_type, filename = server.export_rt_text(format_name="sub2api")

        self.assertEqual(result["count"], 1)
        self.assertEqual(result["format"], "sub2api")
        self.assertEqual(result["items"][0]["platform"], "openai")
        self.assertEqual(result["items"][0]["type"], "oauth")
        self.assertEqual(result["items"][0]["credentials"]["refresh_token"], "rt.1.example")
        self.assertIn("application/json", content_type)
        self.assertTrue(filename.startswith("sub2api-export-"))
        self.assertIn("rt.1.example", body)

    def test_phone_binding_marks_rt_available_when_success_credential_exists(self):
        server.import_jobs({"mode": "api", "text": "user@example.com----https://mail.test/a"})
        raw_job = server.load_jobs()[0]
        state_path = server.job_state_path(raw_job)
        success_path = server.X9_RUNTIME_ROOT / "成功凭证" / "user@example.com.json"
        server.write_json_atomic(
            state_path,
            {
                "cookies": [{"name": "session", "value": "old", "domain": ".chatgpt.com"}],
                "accessToken": "existing-token",
                "mfa_summary": {"status": "enabled", "secret": "JBSWY3DPEHPK3PXP"},
            },
        )
        server.write_json_atomic(
            success_path,
            {
                "type": "codex",
                "email": "user@example.com",
                "access_token": "access-token",
                "refresh_token": "rt.1.bound",
                "id_token": "id-token",
                "account_id": "acct-1",
            },
        )
        server.update_job(
            raw_job["id"],
            status="ready",
            stage="ready",
            registrationStatus="registered",
            mfaStatus="enabled",
            storageStatePath=str(state_path),
        )
        server.save_settings({"smsProvider": "herosms", "smsApiKey": "hero-secret"})

        with mock.patch.object(
            server,
            "run_registration",
            return_value=(
                True,
                {
                    "success": True,
                    "boundPhone": "+66812345678",
                    "successCredentialPath": str(success_path),
                    "message": "手机号绑定验证已完成，RT 已落库。",
                    "_storageStatePayload": {
                        "cookies": [{"name": "session", "value": "new", "domain": ".chatgpt.com"}],
                        "accessToken": "existing-token",
                    },
                },
            ),
        ):
            success = server.run_phone_binding_one(raw_job["id"], server.load_settings())

        self.assertTrue(success)
        job = server.get_job(raw_job["id"])
        self.assertEqual(job["phoneStatus"], "phone_bound")
        self.assertEqual(job["rtStatus"], "available")
        self.assertTrue(job["rtPresent"])

    def test_registration_always_completes_mfa_even_if_legacy_option_is_false(self):
        server.import_jobs({"mode": "api", "text": "user@example.com----https://mail.test/latest"})
        raw_job = server.load_jobs()[0]
        state_path = server.X9_RUNTIME_ROOT / "登录态" / "user@example.com.json"

        def register(_job, _settings, **_kwargs):
            server.write_json_atomic(
                state_path,
                {
                    "cookies": [{"name": "session", "value": "authenticated", "domain": ".chatgpt.com"}],
                    "accessToken": "registered-token",
                },
            )
            return True, {"success": True, "storageStatePath": str(state_path), "atPath": ""}

        def enable_mfa(job, _settings):
            server.update_job(
                str(job.get("id") or ""),
                status="ready",
                registrationStatus="registered",
                mfaStatus="enabled",
                stage="ready",
            )
            return True, ""

        with (
            mock.patch.object(server, "run_registration", side_effect=register) as run_registration,
            mock.patch.object(server, "run_mfa", side_effect=enable_mfa) as run_mfa,
        ):
            server.run_one(raw_job["id"], {**server.load_settings(), "autoEnableMfaAfterRegistration": False})

        self.assertEqual(run_registration.call_count, 1)
        run_mfa.assert_called_once()
        job = server.get_job(raw_job["id"])
        self.assertEqual(job["status"], "ready")
        self.assertEqual(job["registrationStatus"], "registered")
        self.assertEqual(job["mfaStatus"], "enabled")

    def test_registration_can_still_auto_enable_mfa_when_option_is_on(self):
        server.import_jobs({"mode": "api", "text": "user@example.com----https://mail.test/latest"})
        raw_job = server.load_jobs()[0]
        state_path = server.X9_RUNTIME_ROOT / "登录态" / "user@example.com.json"

        def register(_job, _settings, **_kwargs):
            server.write_json_atomic(
                state_path,
                {
                    "cookies": [{"name": "session", "value": "authenticated", "domain": ".chatgpt.com"}],
                    "accessToken": "registered-token",
                },
            )
            return True, {"success": True, "storageStatePath": str(state_path)}

        settings = server.save_settings({"autoEnableMfaAfterRegistration": True})
        with (
            mock.patch.object(server, "run_registration", side_effect=register),
            mock.patch.object(server, "run_mfa", return_value=(True, "")) as run_mfa,
        ):
            server.run_one(raw_job["id"], settings)

        run_mfa.assert_called_once()
        self.assertTrue(server.load_settings()["autoEnableMfaAfterRegistration"])
        self.assertTrue(server.public_settings()["autoEnableMfaAfterRegistration"])

    def test_session_pending_retry_uses_email_login_without_re_registering_or_mfa(self):
        server.import_jobs({"mode": "api", "text": "user@example.com----https://mail.test/latest"})
        raw_job = server.load_jobs()[0]
        state_path = server.X9_RUNTIME_ROOT / "登录态" / "user@example.com.json"
        server.write_json_atomic(
            state_path,
            {"cookies": [{"name": "__cf_bm", "value": "anonymous", "domain": ".chatgpt.com"}]},
        )
        server.update_job(
            raw_job["id"],
            status="session_pending",
            registrationStatus="session_pending",
            storageStatePath=str(state_path),
        )

        with (
            mock.patch.object(
                server,
                "run_registration",
                return_value=(
                    False,
                    {"stage": "login_session_missing", "message": "Session still missing"},
                ),
            ) as run_registration,
            mock.patch.object(server, "run_mfa") as run_mfa,
        ):
            server.run_one(raw_job["id"], {**server.load_settings(), "autoEnableMfaAfterRegistration": True})

        self.assertEqual(run_registration.call_count, 1)
        self.assertEqual(run_registration.call_args.kwargs["operation"], "login")
        run_mfa.assert_not_called()
        job = server.get_job(raw_job["id"])
        self.assertEqual(job["status"], "session_pending")
        self.assertEqual(job["registrationStatus"], "session_pending")

    def test_legacy_missing_session_failure_logs_in_before_any_new_registration(self):
        server.import_jobs({"mode": "api", "text": "user@example.com----https://mail.test/latest"})
        raw_job = server.load_jobs()[0]
        state_path = server.X9_RUNTIME_ROOT / "登录态" / "user@example.com.json"
        server.write_json_atomic(
            state_path,
            {"cookies": [{"name": "__cf_bm", "value": "anonymous", "domain": ".chatgpt.com"}]},
        )
        server.update_job(
            raw_job["id"],
            status="registration_failed",
            registrationStatus="failed",
            stage="runner_exception",
            error="session 响应缺少 accessToken（可能未登录）",
        )
        with mock.patch.object(
            server,
            "run_registration",
            return_value=(False, {"stage": "login_session_missing", "message": "still pending"}),
        ) as run_registration:
            server.run_one(raw_job["id"], server.load_settings())

        self.assertEqual(run_registration.call_count, 1)
        self.assertEqual(run_registration.call_args.kwargs["operation"], "login")
        self.assertEqual(server.get_job(raw_job["id"])["registrationStatus"], "session_pending")

    def test_start_jobs_preserves_legacy_missing_session_as_login_retry(self):
        server.import_jobs({"mode": "api", "text": "user@example.com----https://mail.test/latest"})
        raw_job = server.load_jobs()[0]
        server.update_job(
            raw_job["id"],
            status="registration_failed",
            registrationStatus="failed",
            stage="runner_exception",
            error="session 响应缺少 accessToken（可能未登录）",
        )

        with mock.patch.object(server.threading, "Thread") as thread_type:
            status, payload = server.start_jobs([raw_job["id"]])

        self.assertEqual(status, 200)
        self.assertEqual(payload["count"], 1)
        queued = server.get_job(raw_job["id"])
        self.assertEqual(queued["registrationStatus"], "session_pending")
        self.assertEqual(queued["stage"], "session_retry_queued")
        thread_type.return_value.start.assert_called_once_with()

    def test_phone_required_account_is_eligible_for_explicit_batch_binding(self):
        server.import_jobs({"mode": "api", "text": "user@example.com----https://mail.test/latest"})
        raw_job = server.load_jobs()[0]
        state_path = server.X9_RUNTIME_ROOT / "登录态" / "user@example.com.json"
        server.write_json_atomic(
            state_path,
            {"cookies": [{"name": "__cf_bm", "value": "anonymous", "domain": ".chatgpt.com"}]},
        )
        server.update_job(
            raw_job["id"],
            status="phone_required",
            registrationStatus="phone_required",
            storageStatePath=str(state_path),
        )
        server.save_settings({"smsProvider": "herosms", "smsApiKey": "hero-secret"})

        with mock.patch.object(server.threading, "Thread") as thread_type:
            status, payload = server.start_phone_binding([raw_job["id"]])

        self.assertEqual(status, 202)
        self.assertEqual(payload["count"], 1)
        self.assertEqual(server.get_job(raw_job["id"])["phoneStatus"], "phone_queued")
        thread_type.return_value.start.assert_called_once_with()

    def test_explicit_mfa_batch_only_accepts_registered_pending_accounts(self):
        server.import_jobs(
            {
                "mode": "api",
                "text": (
                    "one@example.com----https://mail.test/one\n"
                    "two@example.com----https://mail.test/two"
                ),
            }
        )
        first, second = server.load_jobs()
        server.update_job(first["id"], status="registered", registrationStatus="registered", mfaStatus="pending")
        server.update_job(second["id"], status="phone_required", registrationStatus="phone_required", mfaStatus="pending")

        with mock.patch.object(server.threading, "Thread") as thread_type:
            status, payload = server.start_mfa([first["id"], second["id"]])

        self.assertEqual(status, 202)
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["skippedItems"], [{"id": second["id"], "reason": "not_registered"}])
        self.assertEqual(server.get_job(first["id"])["stage"], "mfa_queued")
        thread_type.return_value.start.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
