"""A small FAKE Clerk server, used only by the automated tests.

It behaves like a real Clerk OAuth/OpenID Connect instance, based on Clerk's
published settings (/.well-known/openid-configuration):
  * /oauth/authorize  sends the browser straight back with a code + state + iss
  * /oauth/token      checks the client ID/secret (HTTP Basic) and returns an
                      access token and a signed RS256 ID token (with the nonce)
  * /.well-known/jwks.json  publishes the public key

Test switches (attributes of MockClerk):
  nonce_in_token  - False: leave the nonce out of the ID token
  id_token        - False: don't return an ID token at all
  token_ttl       - seconds until the ID token expires (negative = already expired)

It never talks to the real Clerk and contains no real keys.
"""

import base64
import json
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

from joserfc import jwt
from joserfc.jwk import RSAKey

CLIENT_ID = "test-client-id"
CLIENT_SECRET = "test-client-secret-not-real"


class MockClerk:
    def __init__(self):
        self.key = RSAKey.generate_key(2048, parameters={"kid": "test-key", "use": "sig", "alg": "RS256"})
        self.server = ThreadingHTTPServer(("localhost", 0), self._handler())
        self.port = self.server.server_address[1]
        self.issuer = f"http://localhost:{self.port}"
        self.codes = {}
        self.token_requests = 0
        self.reset()

    def reset(self):
        self.nonce_in_token = True
        self.id_token = True
        self.token_ttl = 3600

    @property
    def discovery_url(self):
        return self.issuer + "/.well-known/openid-configuration"

    def start(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def stop(self):
        self.server.shutdown()
        self.server.server_close()

    def _discovery(self):
        i = self.issuer
        return {
            "issuer": i, "authorization_endpoint": i + "/oauth/authorize",
            "token_endpoint": i + "/oauth/token", "userinfo_endpoint": i + "/oauth/userinfo",
            "jwks_uri": i + "/.well-known/jwks.json",
            "scopes_supported": ["offline_access", "email", "profile", "openid"],
            "response_types_supported": ["code"], "response_modes_supported": ["form_post", "query"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "subject_types_supported": ["public"], "id_token_signing_alg_values_supported": ["RS256"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "none", "client_secret_post"],
            "code_challenge_methods_supported": ["S256"],
            "authorization_response_iss_parameter_supported": True,
        }

    def _issue_tokens(self, request):
        now = int(time.time())
        claims = {"iss": self.issuer, "sub": "user_test123", "aud": CLIENT_ID, "iat": now,
                  "exp": now + self.token_ttl, "email": "kid@example.com", "email_verified": True,
                  "name": "Test Kid"}
        if self.nonce_in_token and request.get("nonce"):
            claims["nonce"] = request["nonce"]
        header = {"alg": "RS256", "kid": "test-key"}
        body = {"access_token": jwt.encode(header, {"iss": self.issuer, "sub": "user_test123",
                                                    "exp": now + 3600}, self.key),
                "token_type": "bearer", "expires_in": 3600, "scope": request.get("scope", "")}
        if self.id_token:
            body["id_token"] = jwt.encode(header, claims, self.key)
        return body

    def _handler(self):
        mock = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, status, body=None, location=None):
                data = json.dumps(body).encode() if body is not None else b""
                self.send_response(status)
                if location:
                    self.send_header("Location", location)
                if body is not None:
                    self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                url = urlsplit(self.path)
                query = {k: v[0] for k, v in parse_qs(url.query).items()}
                if url.path == "/.well-known/openid-configuration":
                    return self._send(200, mock._discovery())
                if url.path == "/.well-known/jwks.json":
                    return self._send(200, {"keys": [mock.key.as_dict(private=False)]})
                if url.path == "/oauth/authorize":
                    code = secrets.token_urlsafe(16)
                    mock.codes[code] = query
                    back = query["redirect_uri"] + "?" + urlencode(
                        {"code": code, "state": query.get("state", ""), "iss": mock.issuer})
                    return self._send(302, location=back)
                if url.path == "/oauth/userinfo":
                    return self._send(200, {"sub": "user_test123", "email": "kid@example.com"})
                return self._send(404, {"error": "not_found"})

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                form = {k: v[0] for k, v in parse_qs(self.rfile.read(length).decode()).items()}
                mock.token_requests += 1
                auth = self.headers.get("Authorization", "")
                if auth.startswith("Basic "):
                    client_id, _, client_secret = base64.b64decode(auth[6:]).decode().partition(":")
                else:
                    client_id, client_secret = form.get("client_id"), form.get("client_secret")
                if (client_id, client_secret) != (CLIENT_ID, CLIENT_SECRET):
                    return self._send(401, {"error": "invalid_client"})
                request = mock.codes.pop(form.get("code"), None)
                if request is None:
                    return self._send(400, {"error": "invalid_grant"})
                return self._send(200, mock._issue_tokens(request))

        return Handler
