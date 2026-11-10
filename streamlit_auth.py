"""ScamShield AI - Clerk sign-in for the Streamlit website.

HOW IT WORKS
------------
Streamlit has built-in sign-in (st.login) that works with any "OpenID
Connect" (OIDC) login provider. Clerk acts as one: in the Clerk dashboard you
create an "OAuth application", and Clerk gives you a client ID and secret.

The sign-in journey has three steps:
  1. ScamShield -> Clerk         (st.login sends the browser to Clerk)
  2. Clerk -> /oauth2callback    (Streamlit matches the result to a
                                  "sign-in in progress" cookie)
  3. Streamlit checks Clerk's ID token, then stores a signed cookie

Step 2 fails SILENTLY if the browser started on a different address than the
registered redirect URI (e.g. 127.0.0.1 instead of localhost), because
browsers keep cookies separately per address. Step 3 fails if the computer's
clock is wrong or the Clerk app is missing the "openid" scope. In every case
Streamlit just shows the user as logged out. This module:
  * blocks sign-in from the wrong address and links to the right one;
  * shows WHY the last sign-in failed (details only when running locally);
  * ends sessions older than Clerk's session lifetime (7 days).

Sign-in is switched ON only when the Clerk settings exist in
.streamlit/secrets.toml (or Streamlit Community Cloud's "Secrets").
NEVER commit the real secrets.toml to GitHub.
"""

import ipaddress
import logging
import threading
import time
from urllib.parse import urlsplit

import streamlit as st

PROVIDER = "clerk"

# Clerk's free (Hobby) plan has a fixed 7-day session lifetime. Streamlit's own
# sign-in cookie lasts 30 days, so we enforce Clerk's limit ourselves.
MAX_SESSION_SECONDS = 7 * 24 * 60 * 60

# How long a failed sign-in reason stays visible on the sign-in page.
FAILURE_DISPLAY_SECONDS = 5 * 60

# Streamlit writes sign-in problems to these loggers (new and old servers).
STREAMLIT_AUTH_LOGGERS = (
    "streamlit.web.server.starlette.starlette_auth_routes",
    "streamlit.web.server.oauth_authlib_routes",
)

# category -> (what happened, how to fix it). No secrets or tokens included.
FAILURE_HELP = {
    "interrupted": (
        "The sign-in was interrupted before ScamShield received it.",
        "This happens if ScamShield was opened at a different address than the one registered in "
        "Clerk (for example 127.0.0.1 instead of localhost), or if you pressed Back during "
        "sign-in. Open the address shown below and sign in again.",
    ),
    "clock": (
        "Clerk's sign-in token looked expired or not valid yet.",
        "Your computer's clock is probably wrong. In Windows: Settings > Time & language > "
        "Date & time > turn on 'Set time automatically' and click 'Sync now'.",
    ),
    "nonce": (
        "Clerk's sign-in token was missing a security check value (nonce).",
        "Make sure the Clerk OAuth application includes the 'openid' scope, then sign in again.",
    ),
    "no_user": (
        "Clerk didn't send the user's details.",
        "Add the 'openid', 'profile' and 'email' scopes to the Clerk OAuth application.",
    ),
    "credentials": (
        "Clerk rejected ScamShield's Client ID or Client Secret.",
        "Run: python check_clerk_setup.py",
    ),
    "network": (
        "ScamShield couldn't reach Clerk.",
        "Check your internet connection, VPN or network filter, then run: python check_clerk_setup.py",
    ),
    "denied": (
        "Sign-in was cancelled on Clerk's page.",
        "Click SIGN IN again and choose Allow on the consent screen.",
    ),
    "redirect": (
        "The redirect_uri in secrets.toml is set up wrongly.",
        "It must be http://localhost:8501/oauth2callback for local testing.",
    ),
    "prompt": (
        "Clerk refused the sign-in request because of its 'prompt' setting.",
        "Streamlit asks for prompt=select_account, which Clerk doesn't support. In secrets.toml, "
        "under [auth.clerk], use: client_kwargs = { scope = \"openid profile email\", prompt = \"\" } "
        "and restart ScamShield.",
    ),
    "unknown": (
        "The sign-in didn't complete.",
        "Try again. If it keeps happening, copy the WARNING lines from the terminal.",
    ),
}


# ==========================================
# Configuration
# ==========================================

def clerk_configured():
    """True when [auth] and [auth.clerk] settings are present."""
    try:
        auth = st.secrets.get("auth")
    except Exception:  # no secrets file at all
        return False
    if not auth:
        return False
    try:
        clerk = auth.get(PROVIDER)
    except AttributeError:
        return False
    required = ("client_id", "client_secret", "server_metadata_url")
    return bool(clerk) and all(clerk.get(key) for key in required) and bool(
        auth.get("redirect_uri")) and bool(auth.get("cookie_secret"))


# "prompt" values Clerk accepts ("" means: don't ask for anything special).
# Streamlit 1.66+ sends prompt=select_account unless client_kwargs sets a
# prompt, and Clerk rejects that AFTER the user has typed their password.
CLERK_PROMPTS = ("", "login", "consent", "none")


def prompt_problem():
    """True when the Clerk settings would make Streamlit send a prompt Clerk rejects."""
    try:
        kwargs = st.secrets["auth"][PROVIDER].get("client_kwargs") or {}
        prompt = kwargs.get("prompt")
    except Exception:
        return False
    if prompt is None:
        return True
    return str(prompt).strip() not in CLERK_PROMPTS


def _redirect_uri():
    try:
        return str(st.secrets["auth"]["redirect_uri"])
    except Exception:
        return ""


# ==========================================
# Recording WHY a sign-in failed
# ==========================================

def classify_failure(text):
    """Turn a Streamlit sign-in warning into one of the FAILURE_HELP categories."""
    t = text.lower()
    if "prompt parameter" in t or "select_account" in t:
        return "prompt"
    if "missing provider" in t or "mismatching_state" in t or "csrf" in t:
        return "interrupted"
    if "access_denied" in t:
        return "denied"
    if "nonce" in t:
        return "nonce"
    if "expired" in t or "not valid yet" in t or "invalid_token" in t or "'iat'" in t or "'nbf'" in t:
        return "clock"
    if "did not return user information" in t:
        return "no_user"
    if "invalid_client" in t or "unauthorized_client" in t or "401" in t:
        return "credentials"
    if "getaddrinfo" in t or "connecterror" in t or "connection" in t or "timed out" in t:
        return "network"
    if "misconfigured origin" in t or "redirect_uri" in t:
        return "redirect"
    return "unknown"


class _FailureRecorder(logging.Handler):
    """Remembers the most recent sign-in failure Streamlit logged."""

    def __init__(self):
        super().__init__(level=logging.WARNING)
        self._state_lock = threading.Lock()  # NOT "self.lock": logging.Handler uses that name itself
        self.last = None  # (timestamp, category)

    def emit(self, record):
        try:
            text = record.getMessage()
            if record.exc_info and record.exc_info[1] is not None:
                error = record.exc_info[1]
                text += f" {type(error).__name__}: {error}"
            with self._state_lock:
                self.last = (time.time(), classify_failure(text))
        except Exception:  # a logging handler must never crash the app
            pass

    def recent_failure(self, now=None):
        now = time.time() if now is None else now
        with self._state_lock:
            if self.last and now - self.last[0] <= FAILURE_DISPLAY_SECONDS:
                return self.last[1]
        return None


def failure_recorder():
    """Attach (once) and return the recorder for Streamlit's sign-in warnings."""
    for name in STREAMLIT_AUTH_LOGGERS:
        logger = logging.getLogger(name)
        for handler in logger.handlers:
            if isinstance(handler, _FailureRecorder):
                return handler
    recorder = _FailureRecorder()
    for name in STREAMLIT_AUTH_LOGGERS:
        logging.getLogger(name).addHandler(recorder)
    return recorder


# ==========================================
# Address check (the most common silent failure)
# ==========================================

def _origin(url):
    parts = urlsplit(url or "")
    if not parts.scheme or not parts.hostname:
        return None
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return f"{parts.scheme}://{parts.hostname}:{port}", parts.hostname


def _is_local(host):
    if host in ("localhost",):
        return True
    try:
        address = ipaddress.ip_address(host)
        return address.is_loopback or address.is_private
    except ValueError:
        return False


def address_mismatch(browser_url, redirect_uri):
    """Return the correct address to open, or None if the browser is fine.

    Only checked for local testing (localhost / 127.0.0.1 / 192.168.x.x), where
    this mistake happens. Hosted apps are left alone.
    """
    browser = _origin(browser_url)
    expected = _origin(redirect_uri)
    if not browser or not expected:
        return None
    if not (_is_local(browser[1]) or _is_local(expected[1])):
        return None
    if browser[0] != expected[0]:
        parts = urlsplit(redirect_uri)
        return f"{parts.scheme}://{parts.netloc}/"
    return None


def _browser_url():
    try:
        return st.context.url
    except Exception:
        return None


# ==========================================
# Session lifetime
# ==========================================

def session_expired(user, now=None, max_age=MAX_SESSION_SECONDS):
    """True if the sign-in (its 'iat' = issued-at time) is older than max_age."""
    now = time.time() if now is None else now
    try:
        issued = float(user.get("iat"))
    except (TypeError, ValueError, AttributeError):
        return False  # no issue time recorded: nothing to judge
    return now - issued > max_age


# ==========================================
# What the app calls
# ==========================================

def _current_user():
    """The signed-in user's details as a plain dict (empty if unavailable)."""
    try:
        return dict(st.user)
    except Exception:
        return {}


def _sign_out():
    st.logout()


def is_signed_in():
    return bool(_current_user().get("is_logged_in"))


def _show_header():
    st.title("🛡️ ScamShield AI 😎")
    st.caption("Mobile Edition | Experiment 10")


def require_sign_in():
    """Show the sign-in screen and STOP the app until the user is signed in.

    Does nothing when Clerk is not configured.
    """
    if not clerk_configured():
        return

    recorder = failure_recorder()

    if is_signed_in():
        if not session_expired(_current_user()):
            return
        _show_header()
        st.subheader("⏰ Your session has expired")
        st.write("For your security, please sign in again (sessions last 7 days).")
        st.button("🔐 SIGN IN AGAIN", type="primary", use_container_width=True, on_click=_sign_out)
        st.stop()

    _show_header()
    st.subheader("🔐 Sign in to continue")

    redirect_uri = _redirect_uri()
    correct_address = address_mismatch(_browser_url(), redirect_uri)
    if correct_address:
        st.warning(
            "⚠️ You opened ScamShield at a different address than the one set up for sign-in. "
            "Your browser keeps sign-in cookies separately for each address, so signing in "
            "from here would fail."
        )
        st.link_button(f"➡️ Open {correct_address}", correct_address,
                       type="primary", use_container_width=True)
        st.stop()

    local = _is_local(urlsplit(redirect_uri).hostname or "")
    if prompt_problem():
        problem, fix = FAILURE_HELP["prompt" if local else "unknown"]
        st.error(f"Sign-in can't work yet: {problem}\n\n**Fix:** {fix}")
        st.stop()

    failure = recorder.recent_failure()
    if failure:
        problem, fix = FAILURE_HELP[failure if local else "unknown"]
        st.error(f"Sign-in didn't complete: {problem}\n\n**Fix:** {fix}")

    st.write(
        "ScamShield uses **Clerk** for secure sign-in. "
        "You'll be sent to the Clerk sign-in page and then back here."
    )
    st.button(
        "🔐 SIGN IN",
        type="primary",
        use_container_width=True,
        on_click=st.login,
        args=[PROVIDER],
    )
    st.caption(
        "ScamShield never sees your password. Clerk handles sign-in. "
        "We only receive your name and email address to show who is signed in."
    )
    st.stop()


# ==========================================
# Deleting an account (Clerk Backend API)
# ==========================================

CLERK_API = "https://api.clerk.com/v1"
DELETE_WORD = "DELETE"

DELETE_HELP = {
    "bad_user": "ScamShield couldn't tell which Clerk account you're signed in with. Sign out, "
                "sign in again, and try once more.",
    "key": "Clerk refused the request: the Secret key in secrets.toml ([clerk_admin] secret_key) "
           "is wrong or belongs to a different Clerk app.",
    "network": "ScamShield couldn't reach Clerk. Check your internet connection and try again.",
    "unknown": "Clerk couldn't delete the account right now. Nothing was deleted. Try again later.",
}


def _admin_secret_key():
    """Clerk's Secret key (sk_...), needed only for deleting accounts."""
    try:
        return str(st.secrets["clerk_admin"]["secret_key"]).strip()
    except Exception:
        return ""


def delete_clerk_user(user_id, secret_key, opener=None):
    """Permanently delete a Clerk user. Returns (deleted, problem_category)."""
    import re
    import urllib.error
    import urllib.request

    if not re.fullmatch(r"user_[A-Za-z0-9]+", str(user_id or "")):
        return False, "bad_user"
    request = urllib.request.Request(
        f"{CLERK_API}/users/{user_id}", method="DELETE",
        headers={"Authorization": f"Bearer {secret_key}", "User-Agent": "ScamShield"})
    try:
        with (opener or urllib.request.urlopen)(request, timeout=20):
            return True, None
    except urllib.error.HTTPError as error:
        if error.code == 404:  # already gone: treat as deleted
            return True, None
        if error.code in (401, 403):
            return False, "key"
        return False, "unknown"
    except Exception:
        return False, "network"


def account_settings(clear_app_data=None):
    """Settings tab: who is signed in, sign out, and delete account.

    clear_app_data: called after a successful delete, before signing out,
    so the app can wipe anything it keeps for this user (e.g. scan history).
    """
    st.subheader("👤 Account")
    if not clerk_configured():
        st.write("**Sign-in:** not enabled on this server.")
        return
    if not is_signed_in():
        return

    user = _current_user()
    name = user.get("name") or user.get("email") or "your account"
    st.write(f"**Signed in as:** {name}")
    if user.get("email") and user.get("email") != name:
        st.caption(user["email"])
    st.button("🚪 Sign out", on_click=_sign_out, use_container_width=True)

    st.divider()
    st.subheader("🗑️ Delete account")
    st.write(
        "This permanently deletes your ScamShield sign-in account and clears the scan "
        "history on this device. **It can't be undone.**"
    )

    secret_key = _admin_secret_key()
    if not secret_key:
        if _is_local(urlsplit(_redirect_uri()).hostname or ""):
            st.info(
                "Account deletion isn't switched on yet. In the Clerk dashboard open "
                "**Configure > API keys**, copy the **Secret key** (starts with sk_), and add "
                "to .streamlit/secrets.toml:\n\n"
                "```\n[clerk_admin]\nsecret_key = \"sk_test_...\"\n```\n\n"
                "Then restart ScamShield."
            )
        else:
            st.info("Account deletion isn't available on this server yet. "
                    "Please contact the person who runs this ScamShield site.")
        return

    understood = st.checkbox("I understand my account will be deleted permanently",
                             key="delete_account_understood")
    typed = st.text_input(f"Type {DELETE_WORD} to confirm", key="delete_account_typed")
    ready = understood and typed.strip() == DELETE_WORD
    if st.button("🗑️ DELETE MY ACCOUNT", type="primary", disabled=not ready,
                 use_container_width=True):
        deleted, problem = delete_clerk_user(user.get("sub"), secret_key)
        if not deleted:
            st.error(f"Your account was not deleted. {DELETE_HELP[problem]}")
            return
        if clear_app_data:
            clear_app_data()
        st.success("Your account has been deleted. Signing you out…")
        _sign_out()


def account_box():
    """Kept for older callers: same as the Settings tab's account section."""
    account_settings()
