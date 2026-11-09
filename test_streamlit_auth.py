"""Tests for Clerk sign-in on the Streamlit website.

Run:  python -m unittest test_streamlit_auth -v

* Unit tests check the helper logic (address check, session expiry,
  failure classification) without starting Streamlit.
* App tests run mobile_app.py with Streamlit's AppTest, simulating a
  signed-in user (AppTest.user) and the browser address (AppTest.context).
* The real cookie-based login flow (login, refresh, logout, expired token,
  wrong address) is tested end-to-end in test_clerk_login_flow.py.

Skipped automatically if Streamlit is not installed.
"""

import importlib
import logging
import time
import unittest


def _streamlit_available():
    try:
        importlib.import_module("streamlit.testing.v1")
        return True
    except Exception:
        return False


CLERK_SECRETS = {
    "redirect_uri": "http://localhost:8501/oauth2callback",
    "cookie_secret": "test-cookie-secret-not-real",
    "clerk": {
        "client_id": "test-client-id",
        "client_secret": "test-client-secret",
        "server_metadata_url": "https://test-app.clerk.accounts.dev/.well-known/openid-configuration",
    },
}

NOW = time.time()
SIGNED_IN_USER = {"is_logged_in": True, "name": "Test Kid", "email": "kid@example.com",
                  "sub": "user_123", "iat": NOW - 60, "exp": NOW + 3600}


@unittest.skipUnless(_streamlit_available(), "Streamlit is not installed")
class TestHelpers(unittest.TestCase):

    def setUp(self):
        import streamlit_auth
        self.auth = streamlit_auth

    # ----- address check (the silent "logged out" cause) -----
    def test_same_address_is_fine(self):
        self.assertIsNone(self.auth.address_mismatch(
            "http://localhost:8501/", "http://localhost:8501/oauth2callback"))

    def test_127_0_0_1_is_flagged(self):
        self.assertEqual(self.auth.address_mismatch(
            "http://127.0.0.1:8501/", "http://localhost:8501/oauth2callback"),
            "http://localhost:8501/")

    def test_network_url_is_flagged(self):
        self.assertEqual(self.auth.address_mismatch(
            "http://192.168.1.20:8501/", "http://localhost:8501/oauth2callback"),
            "http://localhost:8501/")

    def test_wrong_port_is_flagged(self):
        self.assertEqual(self.auth.address_mismatch(
            "http://localhost:8502/", "http://localhost:8501/oauth2callback"),
            "http://localhost:8501/")

    def test_hosted_app_is_not_checked(self):
        self.assertIsNone(self.auth.address_mismatch(
            "https://other.streamlit.app/", "https://scamshield.streamlit.app/oauth2callback"))

    def test_unknown_browser_address_is_not_blocked(self):
        self.assertIsNone(self.auth.address_mismatch(None, "http://localhost:8501/oauth2callback"))

    # ----- session expiry -----
    def test_fresh_session_not_expired(self):
        self.assertFalse(self.auth.session_expired({"iat": NOW - 3600}, now=NOW))

    def test_old_session_expired(self):
        self.assertTrue(self.auth.session_expired({"iat": NOW - 8 * 24 * 3600}, now=NOW))

    def test_session_without_issue_time_not_expired(self):
        self.assertFalse(self.auth.session_expired({}, now=NOW))
        self.assertFalse(self.auth.session_expired({"iat": "garbage"}, now=NOW))

    # ----- classifying Streamlit's sign-in warnings -----
    def test_classify_real_streamlit_messages(self):
        cases = {
            "Missing provider for OAuth callback; this often indicates a stale or replayed callback": "interrupted",
            "OAuth token exchange failed for provider 'clerk'. MissingClaimError: missing_claim: Missing claim: 'nonce'": "nonce",
            "OAuth token exchange failed for provider 'clerk'. ExpiredTokenError: expired_token: The token is expired": "clock",
            "OAuth provider 'clerk' did not return user information during callback.": "no_user",
            "OAuth token exchange failed for provider 'clerk'. OAuthError: invalid_client:": "credentials",
            "Error during OAuth authorization redirect. ConnectError: [Errno 11001] getaddrinfo failed": "network",
            "Error during authentication: access_denied. Error description: None": "denied",
            "Error, misconfigured origin for `redirect_uri` in secrets.": "redirect",
            "something new and strange": "unknown",
        }
        for message, expected in cases.items():
            with self.subTest(expected=expected):
                self.assertEqual(self.auth.classify_failure(message), expected)
        for category in cases.values():
            self.assertIn(category, self.auth.FAILURE_HELP)

    def test_recorder_captures_streamlit_warning_and_expires(self):
        recorder = self.auth.failure_recorder()
        self.assertIs(recorder, self.auth.failure_recorder())  # attached only once
        logging.getLogger(self.auth.STREAMLIT_AUTH_LOGGERS[0]).warning(
            "Missing provider for OAuth callback; this often indicates a stale callback")
        self.assertEqual(recorder.recent_failure(), "interrupted")
        later = time.time() + self.auth.FAILURE_DISPLAY_SECONDS + 1
        self.assertIsNone(recorder.recent_failure(now=later))
        recorder.last = None


@unittest.skipUnless(_streamlit_available(), "Streamlit is not installed")
class TestStreamlitSignIn(unittest.TestCase):

    def run_app(self, auth=None, user=None, url="http://localhost:8501/"):
        from streamlit.testing.v1 import AppTest
        app = AppTest.from_file("mobile_app.py", default_timeout=60)
        # A non-empty secrets dict REPLACES .streamlit/secrets.toml, so these
        # tests never read your real Clerk keys.
        app.secrets["scamshield_test"] = "isolated"
        if auth is not None:
            app.secrets["auth"] = auth
        if user is not None:
            app.user = user
        if url is not None:
            app.context = {"url": url}
        app.run()
        self.assertFalse(app.exception, [e.message for e in app.exception])
        return app

    def has_sign_in_button(self, app):
        return any("SIGN IN" in b.label for b in app.button)

    def scanner_visible(self, app):
        return len(app.text_area) >= 1

    # ----- not configured -----
    def test_without_clerk_settings_app_opens_normally(self):
        app = self.run_app()
        self.assertTrue(self.scanner_visible(app))
        self.assertFalse(self.has_sign_in_button(app))

    def test_incomplete_settings_do_not_lock_users_out(self):
        incomplete = dict(CLERK_SECRETS)
        incomplete.pop("cookie_secret")
        app = self.run_app(incomplete)
        self.assertTrue(self.scanner_visible(app))

    # ----- signed out -----
    def test_signed_out_user_must_sign_in(self):
        app = self.run_app(CLERK_SECRETS, user={"is_logged_in": False})
        self.assertTrue(self.has_sign_in_button(app))
        self.assertFalse(self.scanner_visible(app))
        self.assertTrue(any("Sign in to continue" in s.value for s in app.subheader))

    def test_wrong_address_shows_link_instead_of_failing_sign_in(self):
        app = self.run_app(CLERK_SECRETS, user={"is_logged_in": False}, url="http://127.0.0.1:8501/")
        self.assertFalse(self.has_sign_in_button(app))
        self.assertFalse(self.scanner_visible(app))
        self.assertTrue(any("different address" in w.value for w in app.warning))

    def test_failed_sign_in_reason_is_shown(self):
        import streamlit_auth
        recorder = streamlit_auth.failure_recorder()
        logging.getLogger(streamlit_auth.STREAMLIT_AUTH_LOGGERS[0]).warning(
            "OAuth token exchange failed for provider 'clerk'.",
            exc_info=(ValueError, ValueError("expired_token: The token is expired"), None))
        try:
            app = self.run_app(CLERK_SECRETS, user={"is_logged_in": False})
            errors = " ".join(e.value for e in app.error)
            self.assertIn("clock", errors)
            self.assertTrue(self.has_sign_in_button(app))
        finally:
            recorder.last = None

    # ----- successful login -----
    def test_signed_in_user_sees_scanner(self):
        app = self.run_app(CLERK_SECRETS, user=SIGNED_IN_USER)
        self.assertTrue(self.scanner_visible(app))
        self.assertFalse(self.has_sign_in_button(app))
        self.assertTrue(any("Signed in as:** Test Kid" in m.value for m in app.markdown))

    def test_session_survives_rerun_and_refresh(self):
        app = self.run_app(CLERK_SECRETS, user=SIGNED_IN_USER)
        app.text_area[0].input("Meeting moved to 3pm.")
        app.button[0].click().run()          # a rerun caused by scanning
        self.assertFalse(app.exception)
        self.assertTrue(self.scanner_visible(app))
        refreshed = self.run_app(CLERK_SECRETS, user=SIGNED_IN_USER)  # a page refresh = new run
        self.assertTrue(self.scanner_visible(refreshed))

    # ----- logout -----
    def test_sign_out_returns_to_sign_in(self):
        app = self.run_app(CLERK_SECRETS, user=SIGNED_IN_USER)
        sign_out = next(b for b in app.button if "Sign out" in b.label)
        sign_out.click().run()
        self.assertFalse(app.exception)
        self.assertTrue(self.has_sign_in_button(app))
        self.assertFalse(self.scanner_visible(app))

    # ----- expired session -----
    def test_expired_session_must_sign_in_again(self):
        old = dict(SIGNED_IN_USER, iat=NOW - 8 * 24 * 3600)
        app = self.run_app(CLERK_SECRETS, user=old)
        self.assertFalse(self.scanner_visible(app))
        self.assertTrue(any("expired" in s.value for s in app.subheader))
        again = next(b for b in app.button if "SIGN IN AGAIN" in b.label)
        again.click().run()
        self.assertFalse(app.exception)
        self.assertTrue(self.has_sign_in_button(app))


if __name__ == "__main__":
    unittest.main(verbosity=2)
