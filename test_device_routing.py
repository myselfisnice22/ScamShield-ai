"""Tests for the front door (streamlit_app.py) that opens the right version.

Run:  python -m unittest test_device_routing -v
"""

import importlib
import unittest
from unittest import mock

IPHONE = ("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 "
          "(KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1")
ANDROID_PHONE = ("Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) "
                 "Chrome/130.0 Mobile Safari/537.36")
ANDROID_TABLET = ("Mozilla/5.0 (Linux; Android 15; SM-X910) AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/130.0 Safari/537.36")
IPAD = ("Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
        "Version/18.0 Safari/604.1")
WINDOWS = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
           "Chrome/130.0 Safari/537.36")


def _streamlit_available():
    try:
        importlib.import_module("streamlit.testing.v1")
        return True
    except Exception:
        return False


@unittest.skipUnless(_streamlit_available(), "Streamlit is not installed")
class TestDeviceDetection(unittest.TestCase):

    def test_phones_get_the_phone_version(self):
        import device
        for ua in (IPHONE, ANDROID_PHONE):
            self.assertEqual(device.view_for_user_agent(ua), "phone", ua)

    def test_computers_and_tablets_get_the_website(self):
        import device
        for ua in (WINDOWS, IPAD, ANDROID_TABLET, "", None):
            self.assertEqual(device.view_for_user_agent(ua), "web", ua)


@unittest.skipUnless(_streamlit_available(), "Streamlit is not installed")
class TestFrontDoor(unittest.TestCase):

    def run_front_door(self, user_agent=WINDOWS, view=None):
        import device
        from streamlit.testing.v1 import AppTest
        patcher = mock.patch.object(device, "_user_agent", lambda: user_agent)
        patcher.start()
        self.addCleanup(patcher.stop)
        app = AppTest.from_file("streamlit_app.py", default_timeout=60)
        app.secrets["scamshield_test"] = "isolated"  # never read the real secrets.toml
        if view:
            app.query_params["view"] = view
        app.run()
        self.assertFalse(app.exception, [e.message for e in app.exception])
        return app

    def is_phone_version(self, app):
        return any("Mobile Edition" in c.value for c in app.caption)

    def is_web_version(self, app):
        return any("Is that message a scam?" in str(m.value) for m in app.markdown)

    def test_computer_opens_the_website(self):
        app = self.run_front_door(WINDOWS)
        self.assertTrue(self.is_web_version(app))
        self.assertFalse(self.is_phone_version(app))

    def test_phone_opens_the_phone_app(self):
        app = self.run_front_door(IPHONE)
        self.assertTrue(self.is_phone_version(app))
        self.assertFalse(self.is_web_version(app))

    def test_view_parameter_overrides_the_device(self):
        self.assertTrue(self.is_phone_version(self.run_front_door(WINDOWS, view="phone")))
        self.assertTrue(self.is_web_version(self.run_front_door(IPHONE, view="web")))

    def test_switch_buttons_change_version_and_are_remembered(self):
        app = self.run_front_door(IPHONE)
        next(b for b in app.button if "desktop version" in b.label).click().run()
        self.assertFalse(app.exception)
        self.assertTrue(self.is_web_version(app))
        app.run()  # a later rerun keeps the visitor's choice
        self.assertTrue(self.is_web_version(app))
        next(b for b in app.button if "phone version" in b.label).click().run()
        self.assertTrue(self.is_phone_version(app))

    def test_phone_sign_in_screen_offers_desktop_version(self):
        import streamlit_auth
        from streamlit.testing.v1 import AppTest
        clerk = {
            "redirect_uri": "http://localhost:8501/oauth2callback",
            "cookie_secret": "test-cookie-secret-not-real",
            "clerk": {"client_id": "x", "client_secret": "y",
                      "server_metadata_url": "https://t.clerk.accounts.dev/.well-known/openid-configuration",
                      "client_kwargs": {"scope": "openid profile email", "prompt": ""}},
        }
        import device
        for target, fake in ((device, ("_user_agent", lambda: IPHONE)),
                             (streamlit_auth, ("_current_user", lambda: {"is_logged_in": False})),
                             (streamlit_auth, ("_browser_url", lambda: "http://localhost:8501/"))):
            patcher = mock.patch.object(target, fake[0], fake[1])
            patcher.start()
            self.addCleanup(patcher.stop)
        app = AppTest.from_file("streamlit_app.py", default_timeout=60)
        app.secrets["auth"] = clerk
        app.run()
        self.assertFalse(app.exception, [e.message for e in app.exception])
        self.assertTrue(any("SIGN IN" in b.label for b in app.button))
        self.assertTrue(any("desktop version" in b.label for b in app.button))


if __name__ == "__main__":
    unittest.main(verbosity=2)
