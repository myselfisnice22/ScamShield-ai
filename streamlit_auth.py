"""ScamShield AI - Clerk sign-in for the Streamlit website.

HOW IT WORKS
------------
Streamlit has built-in sign-in (st.login) that works with any "OpenID
Connect" (OIDC) login provider. Clerk can act as one: in the Clerk dashboard
you create an "OAuth application", and Clerk gives you a client ID and secret.

Sign-in is switched ON only when the Clerk settings exist in
.streamlit/secrets.toml (or in Streamlit Community Cloud's "Secrets").
Without them, the app works exactly as before, so nothing breaks.

See .streamlit/secrets.toml.example for the settings to fill in.
NEVER commit the real secrets.toml to GitHub.
"""

import streamlit as st

PROVIDER = "clerk"


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


def is_signed_in():
    try:
        return bool(st.user.is_logged_in)
    except Exception:
        return False


def require_sign_in():
    """Show the sign-in screen and STOP the app until the user signs in.

    Does nothing when Clerk is not configured.
    """
    if not clerk_configured() or is_signed_in():
        return

    st.title("🛡️ ScamShield AI 😎")
    st.caption("Mobile Edition | Experiment 10")

    st.subheader("🔐 Sign in to continue")
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


def account_box():
    """Small 'signed in as ... / sign out' section for the Info tab."""
    if not clerk_configured():
        st.write("**Sign-in:** not enabled on this server.")
        return
    if not is_signed_in():
        return
    name = st.user.get("name") or st.user.get("email") or "your account"
    st.write(f"**Signed in as:** {name}")
    st.button("🚪 Sign out", on_click=st.logout, use_container_width=True)
