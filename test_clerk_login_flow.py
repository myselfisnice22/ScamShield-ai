"""End-to-end test of the REAL Clerk sign-in flow (cookies and redirects).

Starts the actual ScamShield Streamlit server and a fake Clerk server
(clerk_mock_server.py), then walks through the sign-in exactly like a
browser does, keeping cookies separately per address like a browser:

    /auth/login -> Clerk /oauth/authorize -> /oauth2callback -> signed cookie

Covers: successful login, page refresh, logout, an expired Clerk token
(wrong computer clock), a missing nonce, a replayed (interrupted) callback,
and the "127.0.0.1 instead of localhost" problem.

Uses a TEMPORARY secrets file (never your real .streamlit/secrets.toml) and
fake keys only. Run:
    python -m unittest test_clerk_login_flow -v
Takes about 10-20 seconds (it starts a real Streamlit server).
"""

import http.cookiejar
import importlib.util
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
REQUIRED = ("streamlit", "authlib", "joserfc")
AVAILABLE = all(importlib.util.find_spec(m) for m in REQUIRED)
AUTH_COOKIE = "_streamlit_user"


def free_port():
    with socket.socket() as s:
        s.bind(("localhost", 0))
        return s.getsockname()[1]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # we follow redirects ourselves, one step at a time


@unittest.skipUnless(AVAILABLE, "needs streamlit, authlib and joserfc (pip install -r requirements.txt)")
class TestClerkLoginFlow(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from clerk_mock_server import CLIENT_ID, CLIENT_SECRET, MockClerk

        cls.clerk = MockClerk().start()
        cls.port = free_port()
        cls.base = f"http://localhost:{cls.port}"
        cls.tmp = tempfile.TemporaryDirectory()
        cls.secrets_path = os.path.join(cls.tmp.name, "secrets.toml")
        with open(cls.secrets_path, "w", encoding="utf-8") as f:
            f.write(
                "[auth]\n"
                f'redirect_uri = "{cls.base}/oauth2callback"\n'
                f'cookie_secret = "{secrets.token_hex(32)}"\n'
                "[auth.clerk]\n"
                f'client_id = "{CLIENT_ID}"\n'
                f'client_secret = "{CLIENT_SECRET}"\n'
                f'server_metadata_url = "{cls.clerk.discovery_url}"\n'
                'client_kwargs = { scope = "openid profile email" }\n'
            )
        cls.log = open(os.path.join(cls.tmp.name, "streamlit.log"), "w", encoding="utf-8")
        cls.server = subprocess.Popen(
            [sys.executable, "-m", "streamlit", "run", "mobile_app.py",
             "--server.headless", "true", "--server.port", str(cls.port),
             "--server.address", "localhost", "--browser.gatherUsageStats", "false",
             "--secrets.files", cls.secrets_path],
            cwd=ROOT, stdout=cls.log, stderr=subprocess.STDOUT)
        deadline = time.time() + 90
        while time.time() < deadline:
            try:
                urllib.request.urlopen(cls.base + "/_stcore/health", timeout=2)
                break
            except Exception:
                if cls.server.poll() is not None:
                    break
                time.sleep(0.5)
        else:
            cls.tearDownClass()
            raise RuntimeError("Streamlit did not start")
        # The same signed "which provider" token that the SIGN IN button creates.
        cls.provider_token = subprocess.run(
            [sys.executable, "-c",
             "import sys, streamlit.config as c; c.set_option('secrets.files', [sys.argv[1]]);"
             "from streamlit.auth_util import encode_provider_token;"
             "print(encode_provider_token('clerk'))", cls.secrets_path],
            capture_output=True, text=True, cwd=ROOT, check=True).stdout.strip().splitlines()[-1]

    @classmethod
    def tearDownClass(cls):
        server = getattr(cls, "server", None)
        if server and server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=15)
            except subprocess.TimeoutExpired:
                server.kill()
        if getattr(cls, "log", None):
            cls.log.close()
        if getattr(cls, "clerk", None):
            cls.clerk.stop()
        if getattr(cls, "tmp", None):
            cls.tmp.cleanup()

    def setUp(self):
        self.clerk.reset()
        self.jar = http.cookiejar.CookieJar()
        self.browser = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar), NoRedirect())

    # ---------- helpers ----------
    def get(self, url):
        """GET without following redirects. Returns (status, Location header)."""
        try:
            response = self.browser.open(url, timeout=20)
            return response.status, response.headers.get("Location")
        except urllib.error.HTTPError as error:  # 3xx/4xx arrive here
            return error.code, error.headers.get("Location")

    def sign_in(self, start_host="localhost"):
        """Run the whole sign-in like a browser. Returns the callback URL used."""
        start = f"http://{start_host}:{self.port}/auth/login?provider={self.provider_token}"
        status, to_clerk = self.get(start)
        self.assertEqual(status, 302, "ScamShield should send the browser to Clerk")
        self.assertTrue(to_clerk.startswith(self.clerk.issuer + "/oauth/authorize"))
        status, callback = self.get(to_clerk)
        self.assertEqual(status, 302, "Clerk should send the browser back")
        self.assertTrue(callback.startswith(self.base + "/oauth2callback?"))
        status, _ = self.get(callback)
        self.assertIn(status, (302, 303, 307), "the callback should redirect to the app")
        return callback

    def auth_cookie(self):
        for cookie in self.jar:
            if cookie.name == AUTH_COOKIE:
                return cookie
        return None

    # ---------- tests ----------
    def test_successful_login_sets_signed_persistent_cookie(self):
        self.sign_in()
        cookie = self.auth_cookie()
        self.assertIsNotNone(cookie, "after a good sign-in the auth cookie must be set")
        self.assertTrue(cookie.has_nonstandard_attr("HttpOnly"), "JavaScript must not read it")
        self.assertIsNotNone(cookie.expires, "must be persistent, so a refresh keeps you signed in")
        self.assertGreater(cookie.expires, time.time() + 6 * 24 * 3600)

    def test_page_refresh_keeps_the_session(self):
        self.sign_in()
        status, _ = self.get(self.base + "/")
        self.assertEqual(status, 200)
        self.assertIsNotNone(self.auth_cookie(), "a refresh must not clear the cookie")

    def test_logout_clears_the_session(self):
        self.sign_in()
        self.assertIsNotNone(self.auth_cookie())
        status, _ = self.get(self.base + "/auth/logout")
        self.assertIn(status, (302, 303, 307))
        self.assertIsNone(self.auth_cookie(), "logout must delete the auth cookie")

    def test_expired_clerk_token_is_rejected(self):
        self.clerk.token_ttl = -600  # what a computer with a wrong clock sees
        self.sign_in()
        self.assertIsNone(self.auth_cookie(), "an expired token must not sign anyone in")

    def test_missing_nonce_is_rejected(self):
        self.clerk.nonce_in_token = False
        self.sign_in()
        self.assertIsNone(self.auth_cookie())

    def test_replayed_callback_is_rejected(self):
        callback = self.sign_in()
        self.get(self.base + "/auth/logout")
        self.assertIsNone(self.auth_cookie())
        before = self.clerk.token_requests
        self.get(callback)  # e.g. pressing Back after signing in
        self.assertIsNone(self.auth_cookie(), "an old callback must not sign you in again")
        self.assertEqual(self.clerk.token_requests, before, "it must not even reach Clerk")

    def test_starting_on_127_0_0_1_loses_the_sign_in(self):
        """The root cause: the browser keeps cookies per address."""
        self.sign_in(start_host="127.0.0.1")
        self.assertIsNone(self.auth_cookie(),
                          "starting on 127.0.0.1 and returning to localhost can't work - "
                          "this is why the app now shows a link to the right address")


if __name__ == "__main__":
    unittest.main(verbosity=2)
