"""ScamShield AI - website edition (Home, Scanner, Sign in).

Built from the ScamShield Figma website design (black, red and white
design system in ui_theme.py). Uses the same scanner as mobile_app.py:
Experiment 10 (AI model + security rules), Tesseract OCR for screenshots,
and Clerk sign-in when it is configured in secrets.

Run:  python -m streamlit run app.py
"""

import hashlib
from io import BytesIO

import streamlit as st
from PIL import Image, UnidentifiedImageError

import device
import streamlit_auth as auth
import ui_theme as ui
from experiment_v10 import scan_message
from ocr_engine import OCRError, read_text

st.set_page_config(
    page_title="ScamShield AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)
ui.apply_theme("web")


# ==========================================
# STATE AND NAVIGATION
# ==========================================

PAGES = ("home", "scanner", "signin", "account")

EXAMPLES = {
    "📦 Parcel fee": "Your parcel is on hold. Pay the R19.99 redelivery fee within 24h: "
                    "post-redeliver.info/pay",
    "🏦 Bank alert": "ALERT: Your bank account has been suspended. Verify your password and "
                    "OTP now at secure-bank-verify.com or lose access today.",
    "💼 Job offer": "Hi! We saw your CV. Earn R3,000 a day working from home. Just pay a R250 "
                   "registration fee to start. Reply YES on WhatsApp.",
}

DEFAULTS = {
    "latest_report": None,
    "history": [],
    "keep_history": False,
    "web_message": "",
    "ocr_review_text": "",
    "ocr_source_id": None,
    "ocr_error": None,
}
for key, value in DEFAULTS.items():
    if key not in st.session_state:
        st.session_state[key] = value if not isinstance(value, list) else []

if "page" not in st.session_state:
    requested = st.query_params.get("page", "home")
    st.session_state.page = requested if requested in PAGES else "home"


def go(page):
    st.session_state.page = page
    st.query_params["page"] = page


def use_example(text):
    st.session_state.web_message = text
    go("scanner")


def changed_history_preference():
    if not st.session_state.keep_history:
        st.session_state.history = []


def clear_my_data():
    st.session_state.history = []
    st.session_state.latest_report = None


def scan_another():
    st.session_state.latest_report = None
    st.session_state.web_message = ""


# ==========================================
# SCANNING (same engine as the mobile app)
# ==========================================

def run_scan(message):
    message = (message or "").strip()
    if not message:
        st.warning("Please enter a message first.")
        return None
    try:
        with st.spinner("ScamShield is analysing..."):
            report = scan_message(message)
    except ValueError as error:
        st.error(str(error))
        return None
    except Exception:
        st.error("The scanner ran into a problem. Please try again.")
        return None

    st.session_state.latest_report = report
    if st.session_state.keep_history:
        st.session_state.history.insert(0, {
            "preview": message[:85],
            "risk": report["risk"],
            "prediction": report["ai_prediction"],
            "source": report.get("verdict_source_label", ""),
        })
        st.session_state.history = st.session_state.history[:20]
    return report


def read_screenshot(image):
    """Run Tesseract OCR. Returns (text, error_message)."""
    try:
        text = read_text(image, timeout=20)
    except OCRError as error:
        return "", str(error)
    text = text[:5000].strip()
    if not text:
        return "", "No readable text was found. Try a clearer screenshot."
    return text, None


# ==========================================
# SHARED PIECES
# ==========================================

def nav():
    signed_in = auth.is_signed_in()
    configured = auth.clerk_configured()
    with st.container(key="ss_nav"):
        brand, home, scanner, _, account, cta = st.columns(
            [2.6, 0.8, 0.9, 0.9, 1.8, 1.5], vertical_alignment="center")
        brand.markdown('<div class="ss-brand">🛡️ ScamShield AI</div>', unsafe_allow_html=True)
        home.button("Home", type="tertiary", on_click=go, args=("home",), key="nav_home")
        scanner.button("Scanner", type="tertiary", on_click=go, args=("scanner",),
                       key="nav_scanner")
        if configured and signed_in:
            hello = auth.first_name()
            account.button(f"👋 Hi, {hello}" if hello else "👤 Account", on_click=go,
                           args=("account",), key="nav_account", use_container_width=True,
                           help="Your account: sign out or delete it")
        elif configured:
            account.button("Sign in", on_click=go, args=("signin",), key="nav_signin",
                           use_container_width=True)
        cta.button("Try the scanner", type="primary", on_click=go, args=("scanner",),
                   key="nav_cta", use_container_width=True)


FOOTER_NOTE = ("ScamShield gives guidance, not guarantees. If in doubt, contact the "
               "organisation through an official channel.")


def page_footer():
    ui.html(ui.footer(FOOTER_NOTE))
    device.switch_view_button("web")


def _footer_in(container):
    with container:
        page_footer()


def sign_in_gate():
    """On pages that need an account: show the sign-in card (and stop) if needed."""
    _, middle, _ = st.columns([1, 1.3, 1])
    bottom = st.container()
    with middle:
        auth.require_sign_in(
            header=lambda: ui.html('<p class="ss-eyebrow" style="text-align:center">'
                                   "Free · Messages are never stored</p>"),
            footer=lambda: _footer_in(bottom),
        )


# ==========================================
# HOME
# ==========================================

def home_page():
    copy, preview = st.columns([1.05, 1], gap="large", vertical_alignment="center")
    with copy:
        ui.html(
            ui.badge("🛡️ Free scam checker", on=True)
            + '<div class="ss-display">Is that message a scam? Check it in seconds.</div>'
            '<p class="ss-lead">Paste a suspicious text, WhatsApp message or email — or upload '
            "a screenshot. ScamShield AI explains the warning signs in plain language.</p>"
        )
        try_it, how, _ = st.columns([1, 1, 1.2])
        try_it.button("Try the scanner", type="primary", on_click=go, args=("scanner",),
                      key="hero_cta", use_container_width=True)
        with how:
            ui.html('<a class="ss-ghost" href="#how-it-works" target="_self">How it works</a>')
        ui.html('<p class="ss-small">Free · Messages are checked, then discarded</p>')

    with preview:
        with st.container(key="ss_card_preview"):
            ui.html(
                '<div class="ss-eyebrow">Live example</div>'
                '<div class="ss-bubble">Your parcel is on hold. Pay the R19.99 redelivery fee '
                "within 24h: post-redeliver.info/pay</div>"
                + ui.verdict_card("HIGH RISK")
                + ui.warning_item("Asks for a payment through an unofficial link.", "high",
                                  "Payment request")
                + ui.warning_item("Creates urgency with a 24-hour deadline.", "medium",
                                  "Urgency pressure")
            )

    st.write("")
    with st.container(key="ss_card_alt_how"):
        ui.html('<div id="how-it-works" class="ss-section-title">How it works</div>'
                '<p class="ss-lead">Three steps, no technical knowledge needed.</p>')
        steps = st.columns(3, gap="medium")
        cards = [
            ("📋", "1. Paste or upload",
             "Paste a message or drop a screenshot. ScamShield reads the text for you."),
            ("🧠", "2. AI + rule checks",
             "An AI model and scam rules look for links, urgency, payments and impersonation."),
            ("✅", "3. Clear verdict",
             "Get High risk, Needs review or No known pattern — with the reasons why."),
        ]
        for column, (icon, title, body) in zip(steps, cards):
            column.markdown(ui.feature(icon, title, body), unsafe_allow_html=True)

    st.write("")
    privacy, phone = st.columns(2, gap="medium")
    with privacy:
        with st.container(key="ss_card_privacy"):
            st.subheader("🔒 Private by design")
            ui.html('<p class="ss-muted">Messages are checked and then discarded. Sign in only '
                    "keeps your session; scan history is off unless you switch it on.</p>")
            with st.expander("Read the privacy notes"):
                st.write("• Messages and screenshots are processed on the server running "
                         "ScamShield and are not stored.")
                st.write("• Links are analysed as text. ScamShield never opens them.")
                st.write("• Sign-in is handled by Clerk. ScamShield never sees your password "
                         "and only receives your name and email address.")
                st.write("• Don't upload passwords, one-time codes or banking details.")
    with phone:
        with st.container(key="ss_card_phone"):
            st.subheader("📱 ScamShield on your phone")
            ui.html('<p class="ss-muted">This site works in any phone browser — open it, paste '
                    "the message or upload a screenshot. A ScamShield iOS app is in "
                    "development.</p>")
            st.button("Open the scanner", type="primary", on_click=go, args=("scanner",),
                      key="phone_cta")
    page_footer()


# ==========================================
# SCANNER
# ==========================================

def scanner_input():
    text_tab, shot_tab = st.tabs(["✍️ Text", "📸 Screenshot"])

    with text_tab:
        st.markdown("#### Your message")
        with st.form("web_text_scanner", border=False):
            message = st.text_area(
                "Paste your message", key="web_message", height=190, max_chars=5000,
                placeholder="Paste a suspicious SMS, WhatsApp message or email...",
                label_visibility="collapsed")
            submitted = st.form_submit_button("🔎 Scan message", type="primary",
                                              use_container_width=True)
        if submitted:
            run_scan(message)
        st.caption("Try an example")
        for column, (label, text) in zip(st.columns(len(EXAMPLES)), EXAMPLES.items()):
            column.button(label, on_click=use_example, args=(text,), key=f"ex_{label}",
                          use_container_width=True)
        ui.html('<p class="ss-small">🔒 Messages are checked and then discarded. Links are '
                "analysed as text and never visited.</p>")

    with shot_tab:
        st.markdown("#### Scan a screenshot")
        st.caption("Crop or hide passwords, one-time codes, phone numbers and private "
                   "information before uploading.")
        uploaded = st.file_uploader("Choose a screenshot", type=["png", "jpg", "jpeg"],
                                    key="web_screenshot")
        if uploaded is None:
            return
        data = uploaded.getvalue()
        source_id = hashlib.sha256(data).hexdigest()
        image = None
        if len(data) > 5 * 1024 * 1024:
            st.error("Image is too large. Please upload a screenshot under 5 MB.")
        else:
            try:
                with Image.open(BytesIO(data)) as opened:
                    if opened.width * opened.height > 20_000_000:
                        raise ValueError("Image is too large. Please crop it first.")
                    image = opened.convert("RGB")
            except (UnidentifiedImageError, OSError, ValueError,
                    Image.DecompressionBombError) as error:
                st.error(f"Image error: {error}")
        if image is None:
            return

        # A new screenshot is read and scanned once, not on every rerun.
        if st.session_state.ocr_source_id != source_id:
            st.session_state.ocr_source_id = source_id
            with st.spinner("Reading and analysing screenshot..."):
                text, error = read_screenshot(image)
            st.session_state.ocr_review_text = text
            st.session_state.ocr_error = error
            if text:
                run_scan(text)

        if st.session_state.ocr_error:
            st.warning(st.session_state.ocr_error)
        with st.expander("🖼️ View screenshot"):
            st.image(image, use_container_width=True)
        if st.session_state.ocr_review_text:
            with st.expander("✏️ Check the text ScamShield read"):
                st.caption("OCR can misread letters. Fix any mistakes, then scan again.")
                st.text_area("Extracted message", key="ocr_review_text", height=180,
                             max_chars=5000)
                if st.button("🔁 Scan corrected text", use_container_width=True):
                    run_scan(st.session_state.ocr_review_text)


def scanner_results():
    report = st.session_state.latest_report
    st.markdown("#### 🔍 Results")
    if report is None:
        ui.html('<div class="ss-bubble">Scan a message or screenshot and the verdict, the '
                "warning signs and what to do next will appear here.</div>")
        return

    risk = str(report.get("risk", "NEEDS REVIEW"))
    ui.html(ui.verdict_card(risk) + ui.ai_row(report) + ui.verdict_source(report))

    warnings = report.get("warnings", [])
    st.markdown("#### ⚠️ Warning signs")
    if warnings:
        ui.html(ui.report_warnings(report))
    else:
        ui.html('<p class="ss-muted">No predefined warning signs detected.</p>')

    with st.expander("🧭 Why this result?"):
        for line in report.get("explanation", []):
            st.write("• " + str(line))
        st.caption("The AI judges word patterns only. The AI alone can raise a message to "
                   "NEEDS REVIEW; HIGH RISK needs evidence from the security rules.")
    if report.get("urls"):
        with st.expander("🔗 Detected links — not opened"):
            for url in report["urls"]:
                st.code(str(url), language=None)

    st.markdown("#### What to do next")
    ui.html(ui.next_steps(risk))
    st.button("Scan another message", on_click=scan_another, key="scan_another")


def scanner_page():
    sign_in_gate()
    if auth.clerk_configured() and auth.is_signed_in():
        ui.html(ui.greeting(auth.first_name(),
                            "You're signed in. Your account is under the Hi button at the top."))
    ui.html('<div class="ss-section-title">Scan a message</div>'
            '<p class="ss-lead">Paste a text, WhatsApp message or email, or upload a '
            "screenshot. ScamShield checks it with an AI model and scam rules.</p>")
    left, right = st.columns(2, gap="large")
    with left:
        with st.container(key="ss_card_input"):
            scanner_input()
    with right:
        with st.container(key="ss_card_results"):
            scanner_results()

    st.write("")
    with st.expander("🕘 Scan history"):
        st.toggle("Remember scans during this session", key="keep_history",
                  on_change=changed_history_preference)
        st.caption("History is off by default and only lasts for this browser session.")
        if st.session_state.history:
            for entry in st.session_state.history:
                ui.html(ui.history_entry(entry))
            if st.button("🗑️ Clear history"):
                st.session_state.history = []
                st.rerun()
        else:
            st.caption("No saved scans.")
    page_footer()


# ==========================================
# SIGN IN / ACCOUNT
# ==========================================

def signin_page():
    if not auth.clerk_configured():
        _, middle, _ = st.columns([1, 1.3, 1])
        with middle, st.container(key="ss_card_signin_off"):
            st.subheader("🔐 Sign-in isn't switched on")
            st.write("This copy of ScamShield runs without accounts, so you can use the "
                     "scanner straight away.")
            st.button("Open the scanner", type="primary", on_click=go, args=("scanner",),
                      use_container_width=True, key="signin_off_cta")
        page_footer()
        return
    sign_in_gate()
    _, middle, _ = st.columns([1, 1.3, 1])
    with middle, st.container(key="ss_card_signed_in"):
        st.subheader("✅ You're signed in")
        st.button("Open the scanner", type="primary", on_click=go, args=("scanner",),
                  use_container_width=True, key="signed_in_cta")
    page_footer()


def account_page():
    sign_in_gate()
    _, middle, _ = st.columns([1, 1.6, 1])
    with middle, st.container(key="ss_card_account"):
        auth.account_settings(clear_app_data=clear_my_data)
    page_footer()


# ==========================================
# PAGE
# ==========================================

nav()
{
    "home": home_page,
    "scanner": scanner_page,
    "signin": signin_page,
    "account": account_page,
}[st.session_state.page]()
