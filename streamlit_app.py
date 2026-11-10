"""ScamShield AI - front door.

Opens the right version for the visitor's device:
  * phones  -> mobile_app.py  (address /phone)
  * others  -> app.py         (address /web)

After Clerk sign-in, Streamlit always returns visitors to the site's main
address, so this check also runs right after signing in. Each version has a
"Switch to ... version" button, and ?view=phone / ?view=web forces one.

Run:  python -m streamlit run streamlit_app.py
"""

import streamlit as st

import device

st.session_state[device.ROUTER_FLAG] = True

pages = {
    "phone": st.Page("mobile_app.py", title="ScamShield AI", icon="🛡️", url_path="phone"),
    "web": st.Page("app.py", title="ScamShield AI", icon="🛡️", url_path="web"),
}
first = device.preferred_view()
order = [pages[first]] + [page for view, page in pages.items() if view != first]

# The first page is the default, i.e. what the main address opens.
st.navigation(order, position="hidden").run()
