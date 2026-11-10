import hashlib
from io import BytesIO

import streamlit as st
from PIL import Image, UnidentifiedImageError

from ocr_engine import OCRError, read_text

from experiment_v10 import scan_message
from streamlit_auth import account_settings, require_sign_in
import ui_theme as ui


# ==========================================
# SCAMSHIELD AI - EXPERIMENT 10
# TEXT + SCREENSHOT SCANNER
# ==========================================

st.set_page_config(
    page_title="ScamShield AI",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed"
)

# Screenshot reading (Tesseract OCR) is loaded only when needed, by
# ocr_engine.py. It finds the Windows installation automatically and keeps
# working even if Windows blocks the optional "pandas" library.


# ==========================================
# APP DESIGN
# ==========================================

# Black, red and white ScamShield design system (same as the Figma file).
ui.apply_theme("mobile")


# ==========================================
# SIGN-IN (Clerk) - only when configured
# ==========================================

require_sign_in()


# ==========================================
# SESSION STATE
# ==========================================

defaults = {
    "latest_report": None,
    "history": [],
    "keep_history": False,
    "ocr_review_text": "",
    "ocr_source_id": None,
    "ocr_error": None,
    "screenshot_report": None
}

for key, value in defaults.items():
    if key not in st.session_state:
        st.session_state[key] = value


def changed_history_preference():
    if not st.session_state.keep_history:
        st.session_state.history = []


# ==========================================
# VERDICT BANNER (shared by Results tab and
# the instant screenshot answer)
# ==========================================

def show_verdict_banner(risk):
    ui.html(ui.verdict_card(risk))


# ==========================================
# SCAN FUNCTION
# ==========================================

def run_scan(message, announce=True):
    message = message.strip()

    if not message:
        st.warning("Please enter a message first.")
        return None

    try:
        with st.spinner("ScamShield is analyzing..."):
            report = scan_message(message)

    except ValueError as error:
        st.error(str(error))
        return None

    except Exception:
        st.error(
            "The scanner encountered an error. "
            "Check your VS Code terminal."
        )
        return None

    st.session_state.latest_report = report

    if st.session_state.keep_history:
        st.session_state.history.insert(
            0,
            {
                "preview": message[:85],
                "risk": report["risk"],
                "prediction": report["ai_prediction"],
                "source": report.get(
                    "verdict_source_label", ""
                )
            }
        )

        st.session_state.history = (
            st.session_state.history[:20]
        )

    if announce:
        st.success("Scan complete! Check Results below.")

    return report


def read_screenshot(image):
    """Run Tesseract OCR. Returns (text, error_message)."""
    try:
        text = read_text(image, timeout=20)

    except OCRError as error:
        return "", str(error)

    text = text[:5000].strip()

    if not text:
        return "", (
            "No readable text was found. "
            "Try a clearer screenshot."
        )

    return text, None


# ==========================================
# HEADER
# ==========================================

st.title("🛡️ ScamShield AI 😎")

st.caption("Mobile Edition | Experiment 10")

st.write(
    "Scan suspicious SMS messages, WhatsApp "
    "messages, emails, and screenshots."
)

ui.html(
    ui.badge("🛡️ Free scam checker", on=True)
    + ui.badge("🧠 AI + 10 scam rules")
    + '<p class="ss-small">ScamShield is an experimental security '
    "tool. A low-risk result never guarantees safety.</p>"
)

st.divider()


# ==========================================
# INPUT TABS
# ==========================================

text_tab, screenshot_tab = st.tabs([
    "✍️ Text Scanner",
    "📸 Screenshot Scanner"
])


# ==========================================
# TEXT SCANNER
# ==========================================

with text_tab:

    st.subheader("Scan a Message")

    with st.form("text_scanner"):

        message = st.text_area(
            "Paste your message",
            placeholder=(
                "Paste a suspicious SMS, "
                "WhatsApp message, or email..."
            ),
            height=175,
            max_chars=5000
        )

        scan_button = st.form_submit_button(
            "🔎 SCAN MESSAGE",
            type="primary",
            use_container_width=True
        )

    if scan_button:
        run_scan(message)


# ==========================================
# SCREENSHOT SCANNER
# ==========================================

with screenshot_tab:

    st.subheader("📸 Screenshot Scanner")

    st.write(
        "Upload a screenshot of a suspicious "
        "message. ScamShield reads the text and "
        "gives you an answer straight away."
    )

    st.caption(
        "Crop or hide passwords, OTPs, "
        "phone numbers, and private information "
        "before uploading."
    )

    uploaded_image = st.file_uploader(
        "Choose a screenshot",
        type=["png", "jpg", "jpeg"],
        key="screenshot_upload"
    )

    if uploaded_image is not None:

        image_bytes = uploaded_image.getvalue()

        source_id = hashlib.sha256(
            image_bytes
        ).hexdigest()

        image = None

        if len(image_bytes) > 5 * 1024 * 1024:

            st.error(
                "Image is too large. "
                "Please upload a screenshot under 5 MB."
            )

        else:

            try:
                with Image.open(
                    BytesIO(image_bytes)
                ) as uploaded:

                    if (
                        uploaded.width * uploaded.height
                        > 20_000_000
                    ):
                        raise ValueError(
                            "Image is too large. "
                            "Please crop it first."
                        )

                    image = uploaded.convert("RGB")

            except (
                UnidentifiedImageError,
                OSError,
                ValueError,
                Image.DecompressionBombError
            ) as error:
                st.error(f"Image error: {error}")

        # A NEW screenshot: read it and analyse it
        # automatically. This runs only once per
        # image, not every time the page refreshes.
        if (
            image is not None
            and st.session_state.ocr_source_id
            != source_id
        ):
            st.session_state.ocr_source_id = source_id
            st.session_state.screenshot_report = None

            with st.spinner(
                "Reading and analysing screenshot..."
            ):
                text, error = read_screenshot(image)

            st.session_state.ocr_review_text = text
            st.session_state.ocr_error = error

            if text:
                st.session_state.screenshot_report = (
                    run_scan(text, announce=False)
                )

        if image is not None:

            if st.session_state.ocr_error:
                st.warning(st.session_state.ocr_error)

            report = st.session_state.screenshot_report

            if report is not None:

                st.subheader("🛡️ Instant Answer")

                show_verdict_banner(report["risk"])

                st.caption(
                    "Verdict source: "
                    + str(report.get(
                        "verdict_source_label", ""
                    ))
                    + " | "
                    + f"{len(report.get('warnings', []))}"
                    + " warning sign(s)"
                )

                st.info(
                    "Open the 🔍 Results tab below for "
                    "the full explanation."
                )

            with st.expander("🖼️ View screenshot"):
                st.image(
                    image,
                    caption="Uploaded screenshot",
                    use_container_width=True
                )

            if st.session_state.ocr_review_text:

                with st.expander(
                    "✏️ Check the text ScamShield read"
                ):

                    st.caption(
                        "OCR can misread letters. Fix any "
                        "mistakes, then scan again."
                    )

                    st.text_area(
                        "Extracted message",
                        key="ocr_review_text",
                        height=200,
                        max_chars=5000
                    )

                    if st.button(
                        "🔁 SCAN CORRECTED TEXT",
                        use_container_width=True
                    ):
                        st.session_state.screenshot_report = (
                            run_scan(
                                st.session_state.ocr_review_text,
                                announce=False
                            )
                        )
                        st.rerun()


# ==========================================
# RESULTS / HISTORY / INFO TABS
# ==========================================

results_tab, history_tab, settings_tab, info_tab = st.tabs([
    "🔍 Results",
    "🕘 History",
    "⚙️ Settings",
    "ℹ️ Info"
])


# ==========================================
# RESULTS - EXPERIMENT 10
# ==========================================

with results_tab:

    report = st.session_state.latest_report

    if report is None:

        st.info(
            "Scan a message or screenshot "
            "to see the results."
        )

    else:

        risk = str(
            report.get("risk", "NEEDS REVIEW")
        )

        prediction = str(
            report.get(
                "ai_prediction", "unknown"
            )
        )

        v7_prediction = str(
            report.get(
                "v7_prediction", "unknown"
            )
        )

        source = report.get("verdict_source", "none")

        warnings = report.get("warnings", [])
        urls = report.get("urls", [])

        st.subheader("🛡️ ScamShield Verdict")

        show_verdict_banner(risk)

        st.caption(
            "Final assessment: " + risk
        )

        # ----------------------------------
        # Experiment 10: where did the
        # verdict come from?
        # ----------------------------------

        st.subheader("🧭 Where Did This Verdict Come From?")

        ai_on = source in ("ai", "ai_and_rules")
        rules_on = source in ("rules", "ai_and_rules")

        ui.html(ui.verdict_source(report))
        ui.html(ui.ai_row(report))

        for line in report.get("explanation", []):
            st.write("• " + str(line))

        st.divider()

        st.subheader("🔎 Why This Result?")

        if warnings:

            st.write(
                f"{len(warnings)} warning sign(s) found:"
            )

            ui.html(ui.report_warnings(report))

        else:

            st.info(
                "No predefined warning signs detected."
            )

        with st.expander(
            "🧠 View AI Model Details"
        ):

            probability = report.get(
                "ai_scam_probability"
            )

            st.write(
                "**V10 AI prediction:** "
                + prediction.upper()
            )

            if probability is not None:
                st.write(
                    "**Calibrated scam probability:** "
                    f"{float(probability) * 100:.0f}% "
                    f"({report.get('ai_confidence', '?')}"
                    " confidence)"
                )

            st.write(
                "**Original V7 prediction:** "
                + v7_prediction.upper()
            )

            st.caption(
                "The AI judges word patterns only. "
                "In Experiment 10 the AI alone can "
                "raise a message to NEEDS REVIEW, but "
                "HIGH RISK needs supporting evidence "
                "from the security rules."
            )

        if urls:

            with st.expander(
                "🔗 Detected Links — Not Opened"
            ):

                for url in urls:
                    st.code(
                        str(url),
                        language=None
                    )

        st.subheader("✅ What To Do Next")

        ui.html(ui.next_steps(risk))

        st.divider()

        st.warning(
            "ScamShield AI is experimental. "
            "Never share passwords, PINs, OTPs, "
            "or banking information based on "
            "an unexpected message."
        )


# ==========================================
# HISTORY
# ==========================================

with history_tab:

    st.subheader("🕘 Scan History")

    st.toggle(
        "Remember scans during this session",
        key="keep_history",
        on_change=changed_history_preference
    )

    st.caption(
        "History is disabled by default. "
        "When enabled, it stores short message "
        "previews in the current app session."
    )

    if st.session_state.history:

        if st.button(
            "🗑️ Clear History",
            use_container_width=True
        ):
            st.session_state.history = []
            st.rerun()

        for entry in st.session_state.history:
            ui.html(ui.history_entry(entry))

    else:

        st.info("No saved scans.")


# ==========================================
# SETTINGS (account: sign out / delete)
# ==========================================

def clear_my_data():
    """Wipe everything ScamShield keeps for this user in the session."""
    st.session_state.history = []
    st.session_state.latest_report = None
    st.session_state.screenshot_report = None


with settings_tab:

    account_settings(clear_app_data=clear_my_data)


# ==========================================
# INFO
# ==========================================

with info_tab:

    st.subheader("About ScamShield AI")

    st.write(
        "**Version:** Experiment 10"
    )

    st.write(
        "**Machine-learning model:** "
        "V10 Naive Bayes (V7 data + synthetic "
        "workplace examples), with calibrated "
        "probability"
    )

    st.write(
        "**Security analysis:** "
        "Experiment 8, 9 and 10 rules "
        "(Experiment 10 adds workplace-fraud checks)"
    )

    st.write(
        "**Screenshot technology:** "
        "Tesseract OCR"
    )

    st.write(
        "**Model status:** "
        "Experimental and not independently "
        "validated for real-world accuracy."
    )

    st.write(
        "**Privacy:** Messages and screenshots "
        "are processed on the server running "
        "Streamlit. Do not upload secrets "
        "or private credentials."
    )

    st.write(
        "**How verdicts work:** "
        "The AI alone can only give NEEDS REVIEW. "
        "HIGH RISK requires security-rule evidence, "
        "and every result says whether it came "
        "from the AI model, the rules, or both."
    )

    st.write(
        "**Link safety:** "
        "ScamShield analyzes link text "
        "without visiting the links."
    )


# ==========================================
# FOOTER
# ==========================================

ui.html(ui.footer(
    "Experiment 10 · A low-risk result never guarantees safety."
))