"""Tests for the website edition (app.py): Home, Scanner, Sign in.

Run:  python -m unittest test_app_web -v
Uses Streamlit's AppTest with a fake secrets dict, so your real Clerk keys
are never read.
"""

import importlib
import unittest
from unittest import mock

CLERK = {
    "redirect_uri": "http://localhost:8501/oauth2callback",
    "cookie_secret": "test-cookie-secret-not-real",
    "clerk": {
        "client_id": "test-client-id",
        "client_secret": "test-client-secret",
        "server_metadata_url": "https://test-app.clerk.accounts.dev/.well-known/openid-configuration",
        "client_kwargs": {"scope": "openid profile email", "prompt": ""},
    },
}
SCAM = ("ALERT: Your bank account has been suspended. Verify your password and OTP now at "
        "secure-bank-verify.com or lose access today.")


def _streamlit_available():
    try:
        importlib.import_module("streamlit.testing.v1")
        return True
    except Exception:
        return False


@unittest.skipUnless(_streamlit_available(), "Streamlit is not installed")
class TestWebsite(unittest.TestCase):

    def setUp(self):
        import streamlit_auth
        self.user = {}
        for name, fake in (("_current_user", lambda: dict(self.user)),
                           ("_browser_url", lambda: "http://localhost:8501/")):
            patcher = mock.patch.object(streamlit_auth, name, fake)
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_app(self, auth=None, page=None):
        from streamlit.testing.v1 import AppTest
        app = AppTest.from_file("app.py", default_timeout=60)
        app.secrets["scamshield_test"] = "isolated"
        if auth:
            app.secrets["auth"] = auth
        if page:
            app.query_params["page"] = page
        app.run()
        self.assertFalse(app.exception, [e.message for e in app.exception])
        return app

    def page_text(self, app):
        return " ".join(str(e.value) for e in list(app.markdown) + list(app.subheader)
                        + list(app.caption) + list(app.warning) + list(app.error))

    def click(self, app, label):
        next(b for b in app.button if b.label == label).click().run()
        self.assertFalse(app.exception, [e.message for e in app.exception])

    def test_home_page(self):
        app = self.run_app()
        text = self.page_text(app)
        self.assertIn("Is that message a scam?", text)
        self.assertIn("How it works", text)
        self.assertEqual(len(app.text_area), 0, "the scanner lives on its own page")

    def test_try_the_scanner_opens_scanner(self):
        app = self.run_app()
        self.click(app, "Try the scanner")
        self.assertEqual(len(app.text_area), 1)
        self.assertIn("Scan a message", self.page_text(app))

    def test_scan_shows_verdict_warnings_and_next_steps(self):
        app = self.run_app(page="scanner")
        app.text_area(key="web_message").input(SCAM)
        self.click(app, "🔎 Scan message")
        text = self.page_text(app)
        self.assertIn("Verdict source", text)
        self.assertIn("What to do next", text)
        self.assertIsNotNone(app.session_state["latest_report"])

    def test_example_fills_the_message(self):
        app = self.run_app(page="scanner")
        self.click(app, "🏦 Bank alert")
        self.assertIn("bank account", app.text_area(key="web_message").value)

    def test_scan_another_clears_result(self):
        app = self.run_app(page="scanner")
        app.text_area(key="web_message").input(SCAM)
        self.click(app, "🔎 Scan message")
        self.click(app, "Scan another message")
        self.assertIsNone(app.session_state["latest_report"])
        self.assertEqual(app.text_area(key="web_message").value, "")

    def test_message_text_is_escaped_in_history(self):
        app = self.run_app(page="scanner")
        app.toggle(key="keep_history").set_value(True).run()
        app.text_area(key="web_message").input('<img src=x onerror=alert(1)> pay R50 fee now')
        self.click(app, "🔎 Scan message")
        markup = " ".join(str(m.value) for m in app.markdown)
        self.assertNotIn("<img src=x", markup)
        self.assertIn("&lt;img src=x", markup)

    def test_scanner_needs_sign_in_when_clerk_is_on(self):
        self.user = {"is_logged_in": False}
        app = self.run_app(auth=CLERK, page="scanner")
        self.assertEqual(len(app.text_area), 0)
        self.assertTrue(any("SIGN IN" in b.label for b in app.button))

    def test_signed_in_user_can_scan_and_see_account(self):
        import time
        self.user = {"is_logged_in": True, "name": "Test Kid", "sub": "user_1", "iat": time.time()}
        app = self.run_app(auth=CLERK, page="scanner")
        self.assertEqual(len(app.text_area), 1)
        self.click(app, "👤 Account")
        self.assertTrue(any("Signed in as:** Test Kid" in m.value for m in app.markdown))

    def test_sign_in_page_without_clerk(self):
        app = self.run_app(page="signin")
        self.assertIn("isn't switched on", self.page_text(app))


if __name__ == "__main__":
    unittest.main(verbosity=2)
