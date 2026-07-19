from __future__ import annotations

import inspect
import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TOOLCORE = ROOT / "X9-Free" / "_credential_toolcore"
for candidate in (str(ROOT), str(TOOLCORE)):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

import codex_oauth  # noqa: E402


class CodexOAuthProxyTests(unittest.TestCase):
    def test_plain_token_exchange_uses_explicit_job_proxy(self):
        proxy_url = "http://proxy-user:proxy-secret@proxy.test:8080"
        response = SimpleNamespace(
            status_code=200,
            json=lambda: {"access_token": "access", "refresh_token": "refresh"},
        )
        with mock.patch.object(codex_oauth.requests, "post", return_value=response) as post:
            result = codex_oauth._exchange_code_for_tokens(
                code="oauth-code",
                pkce=codex_oauth.PKCECodes("verifier", "challenge"),
                client_id="client-id",
                redirect_uri="http://localhost/callback",
                proxy_url=proxy_url,
            )

        self.assertEqual(result["access_token"], "access")
        self.assertEqual(
            post.call_args.kwargs["proxies"],
            {"http": proxy_url, "https": proxy_url},
        )

    def test_plain_token_exchange_does_not_retry_direct_when_proxy_fails(self):
        proxy_error = codex_oauth.requests.exceptions.ProxyError("proxy unavailable")
        with mock.patch.object(codex_oauth.requests, "post", side_effect=proxy_error) as post:
            with self.assertRaises(codex_oauth.requests.exceptions.ProxyError):
                codex_oauth._exchange_code_for_tokens(
                    code="oauth-code",
                    pkce=codex_oauth.PKCECodes("verifier", "challenge"),
                    client_id="client-id",
                    redirect_uri="http://localhost/callback",
                    proxy_url="http://proxy.test:8080",
                )

        post.assert_called_once()
        self.assertEqual(
            post.call_args.kwargs["proxies"],
            {
                "http": "http://proxy.test:8080",
                "https": "http://proxy.test:8080",
            },
        )

    def test_browser_proxy_resolver_prefers_aio_api_proxy(self):
        with mock.patch.dict(
            os.environ,
            {
                "AIO_API_PROXY": "http://job-proxy.test:9000",
                "AIO_CODEX_OAUTH_PROXY_URL": "http://codex-proxy.test:9001",
                "HTTPS_PROXY": "http://environment-proxy.test:9002",
            },
            clear=True,
        ):
            self.assertEqual(
                codex_oauth._resolve_codex_proxy_url(),
                "http://job-proxy.test:9000",
            )

    def test_explicit_direct_proxy_override_does_not_fall_through(self):
        with mock.patch.dict(
            os.environ,
            {
                "AIO_API_PROXY": "direct",
                "AIO_CODEX_OAUTH_PROXY_URL": "http://codex-proxy.test:9001",
                "HTTPS_PROXY": "http://environment-proxy.test:9002",
            },
            clear=True,
        ):
            self.assertEqual(codex_oauth._resolve_codex_proxy_url(), "")

    def test_playwright_proxy_maps_socks5h_and_preserves_credentials(self):
        self.assertEqual(
            codex_oauth._build_playwright_proxy_option(
                "socks5h://proxy-user:proxy-secret@proxy.test:1080"
            ),
            {
                "server": "socks5://proxy.test:1080",
                "username": "proxy-user",
                "password": "proxy-secret",
            },
        )
        self.assertEqual(
            codex_oauth._normalize_proxy_server(
                "socks5h://proxy-user:proxy-secret@proxy.test:1080"
            ),
            "socks5://proxy-user:proxy-secret@proxy.test:1080",
        )

    def test_nonempty_invalid_browser_proxy_fails_closed(self):
        for proxy_url in (
            "http://proxy.test/config.pac",
            "ftp://proxy.test:21",
            "not a proxy",
        ):
            with self.subTest(proxy_url=proxy_url):
                with self.assertRaises(ValueError):
                    codex_oauth._build_playwright_proxy_option(proxy_url)
                with self.assertRaises(ValueError):
                    codex_oauth._normalize_proxy_server(proxy_url)

    def test_proxy_log_mask_never_exposes_credentials(self):
        masked = codex_oauth._mask_proxy_url_for_log(
            "http://proxy-user:proxy-secret@proxy.test:8080"
        )
        self.assertEqual(masked, "http://<redacted>@proxy.test:8080")
        self.assertNotIn("proxy-user", masked)
        self.assertNotIn("proxy-secret", masked)

        flow_source = inspect.getsource(codex_oauth.run_codex_oauth_http_flow)
        self.assertIn(
            "proxy={_mask_proxy_url_for_log(resolved_proxy_url)}",
            flow_source,
        )
        self.assertNotIn(
            'proxy={resolved_proxy_url or "none"}',
            flow_source,
        )

    def test_curl_session_disables_implicit_environment_proxy_fallback(self):
        session = SimpleNamespace(cookies=SimpleNamespace(set=mock.Mock()))
        fake_curl_requests = SimpleNamespace(Session=mock.Mock(return_value=session))
        with mock.patch.object(codex_oauth, "curl_cffi_requests", fake_curl_requests):
            result = codex_oauth._create_curl_cffi_session(
                storage_state={"cookies": [], "origins": []},
                proxy_url="http://job-proxy.test:8080",
                impersonate="chrome131",
            )

        self.assertIs(result, session)
        fake_curl_requests.Session.assert_called_once_with(
            default_headers=False,
            trust_env=False,
            impersonate="chrome131",
            proxy="http://job-proxy.test:8080",
        )

    def test_standalone_curl_helper_uses_fail_closed_session(self):
        response = SimpleNamespace(status_code=200)
        session = SimpleNamespace(
            request=mock.Mock(return_value=response),
            close=mock.Mock(),
        )
        fake_curl_requests = SimpleNamespace(Session=mock.Mock(return_value=session))
        with mock.patch.object(codex_oauth, "curl_cffi_requests", fake_curl_requests):
            result = codex_oauth._curl_cffi_request(
                method="POST",
                url="https://auth.openai.com/oauth/token",
                headers={"accept": "application/json"},
                json_body={"code": "oauth-code"},
                timeout_sec=30,
                proxy_url="socks5h://proxy.test:1080",
                impersonate="chrome131",
            )

        self.assertIs(result, response)
        fake_curl_requests.Session.assert_called_once_with(
            default_headers=False,
            trust_env=False,
            impersonate="chrome131",
            proxy="socks5h://proxy.test:1080",
        )
        session.request.assert_called_once()
        session.close.assert_called_once_with()

    def test_token_exchange_call_sites_forward_the_selected_proxy(self):
        http_flow_source = inspect.getsource(codex_oauth.run_codex_oauth_http_flow)
        browser_flow_source = inspect.getsource(codex_oauth.run_codex_oauth_flow)
        self.assertIn("proxy_url=resolved_proxy_url", http_flow_source)
        self.assertIn("proxy_url=_resolve_codex_proxy_url()", browser_flow_source)


if __name__ == "__main__":
    unittest.main()
