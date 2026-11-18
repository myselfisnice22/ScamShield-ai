"""Tests for plans on the Streamlit website (mobile_app.py).

Run:  python -m unittest test_streamlit_plans -v

Uses Streamlit's AppTest, a temporary usage database and fake sign-in
details. Skipped automatically if Streamlit is not installed.
"""

import importlib
import os
import tempfile
import time
import unittest
from unittest import mock

import tiers


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


def signed_in(**extra):
    return dict({"is_logged_in": True, "name": "Test Kid", "email": "kid@example.com",
                 "sub": "user_123", "iat": NOW - 60, "exp": NOW + 3600}, **extra)


@unittest.skipUnless(_streamlit_available(), "Streamlit is not installed")
class TestWebsitePlans(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = {"SCAMSHIELD_USAGE_DB": os.path.join(self.tmp.name, "usage.sqlite3")}

    def tearDown(self):
        if tiers._store is not None:
            tiers._store._db.close()
            tiers._store = None
        self.tmp.cleanup()

    def use_env(self, env=None):
        """Settings for this test only (any SCAMSHIELD_LOCAL_TEST_PLAN in your shell is ignored)."""
        patcher = mock.patch.dict(os.environ, self.env)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("SCAMSHIELD_LOCAL_TEST_PLAN", None)
        os.environ.update(env or {})

    def run_app(self, env=None, auth=None, user=None):
        from streamlit.testing.v1 import AppTest
        self.use_env(env)
        app = AppTest.from_file("mobile_app.py", default_timeout=60)
        app.secrets["scamshield_test"] = "isolated"  # never read the real secrets.toml
        if auth:
            app.secrets["auth"] = auth
            app.context = {"url": "http://localhost:8501/"}
        if user:
            app.user = user
        app.run()
        self.assertFalse(app.exception, [e.message for e in app.exception])
        return app

    def scan_button(self, app):
        return next(b for b in app.button if "scan message" in b.label.lower())

    def upgrade_shown(self, app):
        return any("ScamShield Pro" in i.value for i in app.info)

    def plan_line(self, app):
        return " ".join(m.value for m in app.markdown if "**Plan:**" in m.value)

    def document_uploader_shown(self, app):
        return any(getattr(w, "label", "") == "Choose a document" for w in app.get("file_uploader"))

    def test_free_sees_upgrade_message_not_document_upload(self):
        app = self.run_app()
        self.assertTrue(self.upgrade_shown(app))
        self.assertFalse(self.document_uploader_shown(app))
        self.assertIn("Free (R0/month)", self.plan_line(app))

    def test_plus_sees_upgrade_message(self):
        app = self.run_app({"SCAMSHIELD_LOCAL_TEST_PLAN": "plus"})
        self.assertTrue(self.upgrade_shown(app))
        self.assertIn("Plus (R70/month)", self.plan_line(app))
        self.assertIn("0 of 100 checks used", self.plan_line(app))

    def test_pro_can_upload_documents(self):
        app = self.run_app({"SCAMSHIELD_LOCAL_TEST_PLAN": "pro"})
        self.assertFalse(self.upgrade_shown(app))
        self.assertTrue(self.document_uploader_shown(app))
        self.assertIn("Pro (R90/month)", self.plan_line(app))

    def test_plus_monthly_limit_on_website(self):
        env = {"SCAMSHIELD_LOCAL_TEST_PLAN": "plus", "SCAMSHIELD_PLUS_MONTHLY_CHECKS": "1"}
        app = self.run_app(env)
        app.text_area[0].input("Meeting moved to 3pm.")
        self.scan_button(app).click().run()
        self.assertFalse(any("used all" in e.value for e in app.error))
        app.text_area[0].input("Lunch is on Friday.")
        self.scan_button(app).click().run()
        self.assertTrue(any("used all 1 checks" in e.value for e in app.error))

    def test_free_scans_are_not_limited_or_counted(self):
        app = self.run_app({"SCAMSHIELD_PLUS_MONTHLY_CHECKS": "1"})
        for message in ("Meeting moved to 3pm.", "Lunch is on Friday."):
            app.text_area[0].input(message)
            self.scan_button(app).click().run()
        self.assertFalse(any("used all" in e.value for e in app.error))

    # ----- plan from the signed-in Clerk account -----
    def test_clerk_account_on_pro(self):
        app = self.run_app(auth=CLERK_SECRETS, user=signed_in(public_metadata={"plan": "pro"}))
        self.assertTrue(self.document_uploader_shown(app))
        self.assertIn("Pro", self.plan_line(app))

    def test_clerk_account_without_plan_is_free(self):
        app = self.run_app({"SCAMSHIELD_LOCAL_TEST_PLAN": "pro"}, auth=CLERK_SECRETS, user=signed_in())
        self.assertTrue(self.upgrade_shown(app))  # the local test plan is ignored when sign-in is on
        self.assertIn("Free", self.plan_line(app))



@unittest.skipUnless(_streamlit_available(), "Streamlit is not installed")
class TestWebsiteEditionPlans(TestWebsitePlans):
    """The same plan rules on the website edition (app.py, Scanner page)."""

    def run_app(self, env=None, auth=None, user=None):
        from streamlit.testing.v1 import AppTest
        import streamlit_auth
        self.use_env(env)
        for name, fake in (("_current_user", lambda: dict(user or {})),
                           ("_browser_url", lambda: "http://localhost:8501/")):
            patcher = mock.patch.object(streamlit_auth, name, fake)
            patcher.start()
            self.addCleanup(patcher.stop)
        app = AppTest.from_file("app.py", default_timeout=60)
        app.secrets["scamshield_test"] = "isolated"
        if auth:
            app.secrets["auth"] = auth
        app.query_params["page"] = "scanner"
        app.run()
        self.assertFalse(app.exception, [e.message for e in app.exception])
        return app

    def plan_line(self, app):
        return " ".join(str(c.value) for c in app.caption if "Plan:" in str(c.value))


if __name__ == "__main__":
    unittest.main(verbosity=2)
