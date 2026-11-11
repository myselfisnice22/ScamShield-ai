"""ScamShield AI - pick the right version for the visitor's device.

streamlit_app.py (the front door) asks preferred_view() which version to
open: "phone" (mobile_app.py) or "web" (app.py). Each version shows a
switch_view_button() so visitors can change their mind; the choice is
remembered for the rest of the session.
"""

import re

import streamlit as st

VIEWS = ("phone", "web")
PAGE_FILES = {"phone": "mobile_app.py", "web": "app.py"}
ROUTER_FLAG = "_ss_router"  # set by streamlit_app.py when it is running
CHOICE_KEY = "ss_view_choice"

# Phones (not tablets: an iPad gets the wide website).
_PHONE_UA = re.compile(r"iPhone|iPod|Android.+Mobile|Windows Phone|BlackBerry|Opera Mini|"
                       r"IEMobile|Mobi", re.IGNORECASE)


def view_for_user_agent(user_agent):
    """'phone' for phone browsers, 'web' for everything else (or unknown)."""
    return "phone" if _PHONE_UA.search(user_agent or "") else "web"


def _user_agent():
    try:
        return st.context.headers.get("User-Agent", "")
    except Exception:
        return ""


def preferred_view():
    """The version to open: the visitor's own choice, else ?view=, else their device."""
    choice = st.session_state.get(CHOICE_KEY)
    if choice in VIEWS:
        return choice
    try:
        requested = st.query_params.get("view")
    except Exception:
        requested = None
    if requested in VIEWS:
        st.session_state[CHOICE_KEY] = requested
        return requested
    return view_for_user_agent(_user_agent())


def routed():
    """True when this page was opened through the front door (streamlit_app.py)."""
    return bool(st.session_state.get(ROUTER_FLAG))


def _switch(view):
    st.session_state[CHOICE_KEY] = view
    st.switch_page(PAGE_FILES[view])


def switch_view_button(current, where="footer"):
    """'Switch to desktop/phone version' button (only when opened via the front door)."""
    if not routed():
        return
    other = "web" if current == "phone" else "phone"
    label = "💻 Switch to the desktop version" if other == "web" else "📱 Switch to the phone version"
    if st.button(label, key=f"switch_to_{other}_{where}", type="tertiary"):
        _switch(other)
