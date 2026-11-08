"""ScamShield AI - Clerk sign-in check for the backend API.

When the phone app's user is signed in with Clerk, the app sends a short-lived
"session token" (a JWT) with every scan:

    Authorization: Bearer <token>

This file checks that token, in Python:
  1. It was signed by YOUR Clerk instance (checked with Clerk's public keys).
  2. It has not expired.
  3. It came from one of YOUR apps (the "azp" / authorized party check).

Settings (environment variables on the server):
    CLERK_ISSUER               e.g. https://your-app.clerk.accounts.dev
                               Setting this switches sign-in checking ON.
    CLERK_JWKS_URL             optional, default: CLERK_ISSUER + /.well-known/jwks.json
    CLERK_AUTHORIZED_PARTIES   comma separated origins allowed to call the API,
                               default: "https://localhost,capacitor://localhost"

If CLERK_ISSUER is not set, the API works without sign-in (useful for local
testing), exactly as before.
"""

import os

import jwt
from fastapi import HTTPException, Request

DEFAULT_PARTIES = "https://localhost,capacitor://localhost"


class ClerkSettings:
    def __init__(self, environ=None):
        env = os.environ if environ is None else environ
        self.issuer = env.get("CLERK_ISSUER", "").strip().rstrip("/")
        self.jwks_url = env.get("CLERK_JWKS_URL", "").strip() or (
            self.issuer + "/.well-known/jwks.json" if self.issuer else "")
        self.authorized_parties = {
            p.strip() for p in env.get("CLERK_AUTHORIZED_PARTIES", DEFAULT_PARTIES).split(",") if p.strip()
        }

    @property
    def enabled(self):
        return bool(self.issuer)


settings = ClerkSettings()
_jwk_client = None


def _signing_key(token):
    global _jwk_client
    if _jwk_client is None or _jwk_client.uri != settings.jwks_url:
        _jwk_client = jwt.PyJWKClient(settings.jwks_url, cache_keys=True, lifespan=3600)
    return _jwk_client.get_signing_key_from_jwt(token).key


def verify_token(token):
    """Return the token's claims if valid, otherwise raise HTTPException(401)."""
    try:
        key = _signing_key(token)
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            issuer=settings.issuer,
            leeway=5,
            options={"require": ["exp", "iat", "sub", "iss"]},
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Your sign-in has expired. Please sign in again.")
    except (jwt.PyJWTError, jwt.PyJWKClientError, ValueError):
        raise HTTPException(status_code=401, detail="Please sign in to use ScamShield.")

    party = claims.get("azp")
    if settings.authorized_parties and party and party not in settings.authorized_parties:
        raise HTTPException(status_code=401, detail="Please sign in to use ScamShield.")
    return claims


def current_user(request: Request):
    """FastAPI dependency. Returns the Clerk user id, or None if sign-in is off."""
    if not settings.enabled:
        return None
    header = request.headers.get("Authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(status_code=401, detail="Please sign in to use ScamShield.",
                            headers={"WWW-Authenticate": "Bearer"})
    return verify_token(token.strip())["sub"]
