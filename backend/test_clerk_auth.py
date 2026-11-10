"""Tests for Clerk sign-in on the backend API.

These tests make their OWN signing key and fake Clerk tokens, so they need
no internet connection and no real Clerk account.

Run from the repository root:
    python -m unittest backend.test_clerk_auth -v
"""

import time
import unittest
from unittest import mock

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from backend import api, clerk_auth

ISSUER = "https://test-app.clerk.accounts.dev"
PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)

client = TestClient(api.app)


def make_token(key=PRIVATE_KEY, **overrides):
    now = int(time.time())
    claims = {"sub": "user_123", "iss": ISSUER, "iat": now, "nbf": now, "exp": now + 60,
              "azp": "https://localhost"}
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "test-key"})


class TestClerkEnabled(unittest.TestCase):

    def setUp(self):
        api._recent_requests.clear()
        self.settings = mock.patch.object(clerk_auth, "settings", clerk_auth.ClerkSettings({
            "CLERK_ISSUER": ISSUER,
            "CLERK_AUTHORIZED_PARTIES": "https://localhost,capacitor://localhost",
        }))
        self.key = mock.patch.object(clerk_auth, "_signing_key",
                                     side_effect=lambda token: PRIVATE_KEY.public_key())
        self.settings.start()
        self.key.start()

    def tearDown(self):
        self.key.stop()
        self.settings.stop()

    def scan(self, token=None, header=None):
        headers = {}
        if header is not None:
            headers["Authorization"] = header
        elif token is not None:
            headers["Authorization"] = "Bearer " + token
        return client.post("/scan", json={"message": "Meeting moved to 3pm."}, headers=headers)

    def test_valid_token_is_accepted(self):
        response = self.scan(make_token())
        self.assertEqual(response.status_code, 200, response.text)

    def test_missing_token_is_rejected(self):
        response = self.scan()
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers.get("www-authenticate"), "Bearer")

    def test_wrong_scheme_is_rejected(self):
        self.assertEqual(self.scan(header="Basic abc").status_code, 401)

    def test_garbage_token_is_rejected(self):
        self.assertEqual(self.scan("not-a-real-token").status_code, 401)

    def test_token_signed_by_someone_else_is_rejected(self):
        self.assertEqual(self.scan(make_token(key=OTHER_KEY)).status_code, 401)

    def test_expired_token_is_rejected(self):
        old = int(time.time()) - 3600
        response = self.scan(make_token(iat=old, nbf=old, exp=old + 60))
        self.assertEqual(response.status_code, 401)
        self.assertIn("expired", response.json()["detail"])

    def test_wrong_issuer_is_rejected(self):
        self.assertEqual(self.scan(make_token(iss="https://evil.clerk.accounts.dev")).status_code, 401)

    def test_wrong_authorized_party_is_rejected(self):
        self.assertEqual(self.scan(make_token(azp="https://evil.example")).status_code, 401)

    def test_pending_session_is_rejected(self):
        self.assertEqual(self.scan(make_token(sts="pending")).status_code, 401)
        self.assertEqual(self.scan(make_token(sts="active")).status_code, 200)

    def test_token_without_user_is_rejected(self):
        self.assertEqual(self.scan(make_token(sub=None)).status_code, 401)

    def test_unsigned_token_is_rejected(self):
        now = int(time.time())
        token = jwt.encode({"sub": "user_123", "iss": ISSUER, "iat": now, "exp": now + 60},
                           key=None, algorithm="none")
        self.assertEqual(self.scan(token).status_code, 401)

    def test_image_scan_also_requires_sign_in(self):
        response = client.post("/scan-image", files={"file": ("x.png", b"123", "image/png")})
        self.assertEqual(response.status_code, 401)

    def test_health_reports_sign_in_required(self):
        self.assertTrue(client.get("/health").json()["sign_in_required"])

    def test_rate_limit_is_per_user(self):
        token = make_token()
        for _ in range(api.RATE_LIMIT_REQUESTS):
            self.assertEqual(self.scan(token).status_code, 200)
        self.assertEqual(self.scan(token).status_code, 429)
        self.assertEqual(self.scan(make_token(sub="user_456")).status_code, 200)

    def test_cors_allows_authorization_header(self):
        response = client.options("/scan", headers={
            "Origin": "https://localhost", "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "authorization,content-type"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("authorization", response.headers.get("access-control-allow-headers", "").lower())


class TestClerkDisabled(unittest.TestCase):

    def test_works_without_sign_in_when_not_configured(self):
        api._recent_requests.clear()
        with mock.patch.object(clerk_auth, "settings", clerk_auth.ClerkSettings({})):
            response = client.post("/scan", json={"message": "hello"})
            self.assertEqual(response.status_code, 200)
            self.assertFalse(client.get("/health").json()["sign_in_required"])

    def test_default_jwks_url(self):
        settings = clerk_auth.ClerkSettings({"CLERK_ISSUER": ISSUER + "/"})
        self.assertEqual(settings.jwks_url, ISSUER + "/.well-known/jwks.json")
        self.assertTrue(settings.enabled)


if __name__ == "__main__":
    unittest.main(verbosity=2)
