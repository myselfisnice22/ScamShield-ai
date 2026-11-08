"""Tests for Clerk sign-in on the Streamlit website.

Run:  python -m unittest test_streamlit_auth -v
(Skipped automatically if Streamlit is not installed.)
"""

import importlib
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


@unittest.skipUnless(_streamlit_available(), "Streamlit is not installed")
class TestStreamlitSignIn(unittest.TestCase):

    def run_app(self, auth=None):
        from streamlit.testing.v1 import AppTest
        app = AppTest.from_file("mobile_app.py", default_timeout=60)
        if auth is not None:
            app.secrets["auth"] = auth
        app.run()
        self.assertFalse(app.exception)
        return app

    def test_without_clerk_settings_app_opens_normally(self):
        app = self.run_app()
        self.assertEqual(len(app.text_area), 1)  # the message box
        self.assertFalse(any("SIGN IN" in b.label for b in app.button))

    def test_with_clerk_settings_sign_in_is_required(self):
        app = self.run_app(CLERK_SECRETS)
        self.assertTrue(any("SIGN IN" in b.label for b in app.button))
        self.assertEqual(len(app.text_area), 0)  # scanner hidden until signed in
        self.assertTrue(any("Sign in to continue" in s.value for s in app.subheader))

    def test_incomplete_settings_do_not_lock_users_out(self):
        incomplete = dict(CLERK_SECRETS)
        incomplete.pop("cookie_secret")
        app = self.run_app(incomplete)
        self.assertEqual(len(app.text_area), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
