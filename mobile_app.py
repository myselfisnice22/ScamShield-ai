import hashlib
import os
from io import BytesIO

import streamlit as st
import pytesseract
from PIL import Image, UnidentifiedImageError

from experiment_v9 import scan_message


# ==========================================
# SCAMSHIELD AI - EXPERIMENT 9
# TEXT + SCREENSHOT SCANNER
# ==========================================

st.set_page_config(
    page_title="ScamShield AI",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed"
)

# Windows uses a local Tesseract installation.
# Streamlit Cloud uses the system installation.
windows_tesseract = (
    r"C:\Program Files\Tesseract-OCR\tesseract.exe"
)

if os.path.isfile(windows_tesseract):
    pytesseract.pytesseract.tesseract_cmd = (
        windows_tesseract
    )


# ==========================================
# APP DESIGN
# ==========================================

st.markdown("""
<style>
.block-container {
    max-width: 720px;
    padding-top: 1.2rem;
    padding-bottom: 3rem;
}

h1 {
    letter-spacing: -0.035em;
}

div[data-testid="stForm"] {
    border-radius: 18px;
    padding: 1rem;
}

.stButton button,
.stFormSubmitButton button {
    min-height: 3.2rem;
    border-radius: 12px;
    font-weight: bold;
}

textarea {
    font-size: 16px !important;
    line-height: 1.5 !important;
}

@media (max-width: 600px) {
    .block-container {
        padding-left: .85rem;
        padding-right: .85rem;
    }
}
</style>
""", unsafe_allow_html=True)


# ==========================================
# SESSION STATE
# ==========================================

defaults = {
    "latest_report": None,
    "history": [],
    "keep_history": False,
    "ocr_review_text": "",
    "ocr_source_id": None
}

for key, value in defaults.items():
    if key not in st.session_state:
        st.session_state[key] = value


def changed_history_preference():
    if not st.session_state.keep_history:
        st.session_state.history = []


# ==========================================
# SCAN FUNCTION
# ==========================================

def run_scan(message):
    message = message.strip()

    if not message:
        st.warning("Please enter a message first.")
        return

    try:
        with st.spinner("ScamShield is analyzing..."):
            report = scan_message(message)

    except ValueError as error:
        st.error(str(error))
        return

    except Exception:
        st.error(
            "The scanner encountered an error. "
            "Check your VS Code terminal."
        )
        return

    st.session_state.latest_report = report

    if st.session_state.keep_history:
        st.session_state.history.insert(
            0,
            {
                "preview": message[:85],
                "risk": report["risk"],
                "prediction": report["v7_prediction"]
            }
        )

        st.session_state.history = (
            st.session_state.history[:20]
        )

    st.success("Scan complete! Check Results below.")


# ==========================================
# HEADER
# ==========================================

st.title("🛡️ ScamShield AI 😎")

st.caption("Mobile Edition | Experiment 9")

st.write(
    "Scan suspicious SMS messages, WhatsApp "
    "messages, emails, and screenshots."
)

st.warning(
    "ScamShield is an experimental security tool. "
    "A low-risk result never guarantees safety."
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
        "message. ScamShield will extract the "
        "text and analyze it."
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

        if st.session_state.ocr_source_id != source_id:
            st.session_state.ocr_source_id = source_id
            st.session_state.ocr_review_text = ""

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

                st.image(
                    image,
                    caption="Uploaded screenshot",
                    use_container_width=True
                )

                if st.button(
                    "📖 EXTRACT TEXT",
                    use_container_width=True
                ):

                    try:
                        with st.spinner(
                            "Reading screenshot..."
                        ):

                            extracted_text = (
                                pytesseract.image_to_string(
                                    image,
                                    timeout=20
                                )
                            )

                        st.session_state.ocr_review_text = (
                            extracted_text[:5000].strip()
                        )

                        if not extracted_text.strip():
                            st.warning(
                                "No readable text was found. "
                                "Try a clearer screenshot."
                            )

                    except (
                        pytesseract.TesseractNotFoundError
                    ):
                        st.error(
                            "Tesseract OCR was not found. "
                            "Check its installation."
                        )

                    except RuntimeError:
                        st.error(
                            "Text extraction timed out. "
                            "Try a smaller screenshot."
                        )

                    except Exception:
                        st.error(
                            "Could not read the screenshot."
                        )

            except (
                UnidentifiedImageError,
                OSError,
                ValueError,
                Image.DecompressionBombError
            ) as error:
                st.error(f"Image error: {error}")

        if st.session_state.ocr_review_text:

            st.success("Text extracted successfully!")

            st.info(
                "Review the text and correct any "
                "OCR mistakes before scanning."
            )

            st.text_area(
                "Extracted message",
                key="ocr_review_text",
                height=200,
                max_chars=5000
            )

            if st.button(
                "🛡️ SCAN SCREENSHOT TEXT",
                type="primary",
                use_container_width=True
            ):
                run_scan(
                    st.session_state.ocr_review_text
                )


# ==========================================
# RESULTS / HISTORY / INFO TABS
# ==========================================

results_tab, history_tab, info_tab = st.tabs([
    "🔍 Results",
    "🕘 History",
    "ℹ️ Info"
])


# ==========================================
# RESULTS - EXPERIMENT 9
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
                "v7_prediction", "unknown"
            )
        )

        warnings = report.get("warnings", [])
        urls = report.get("urls", [])

        st.subheader("🛡️ ScamShield Verdict")

        if risk.upper().startswith("HIGH"):

            st.error(
                "🚨 HIGH RISK — POSSIBLE SCAM\n\n"
                "Strong scam indicators were detected. "
                "Do not reply, click suspicious links, "
                "or share personal information."
            )

        elif risk.upper().startswith("NEEDS"):

            st.warning(
                "⚠️ NEEDS REVIEW\n\n"
                "ScamShield found warning signs. "
                "Verify the message through an "
                "official channel."
            )

        else:

            st.info(
                "ℹ️ NO KNOWN SCAM PATTERN DETECTED\n\n"
                "No strong pattern was detected. "
                "This does not prove the message "
                "is legitimate."
            )

        st.caption(
            "Final assessment: " + risk
        )

        st.divider()

        st.subheader("🔎 Why This Result?")

        if warnings:

            st.write(
                f"{len(warnings)} warning sign(s) found:"
            )

            for finding in warnings:

                description = finding.get(
                    "description",
                    "Unspecified warning"
                )

                severity = finding.get(
                    "severity", "low"
                )

                if severity == "high":
                    st.error(
                        "🚨 " + description
                    )

                elif severity == "medium":
                    st.warning(
                        "⚠️ " + description
                    )

                else:
                    st.write(
                        "⚠️ " + description
                    )

        else:

            st.info(
                "No predefined warning signs detected."
            )

        with st.expander(
            "🧠 View Original AI Prediction"
        ):

            st.write(
                "**V7 AI prediction:** "
                + prediction.upper()
            )

            st.caption(
                "The original AI prediction can differ "
                "from the final verdict. Experiments "
                "8 and 9 add security checks to "
                "the AI prediction."
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

            with st.container(border=True):

                st.write(
                    "**" + entry["risk"] + "**"
                )

                st.caption(
                    "Original AI: "
                    + entry["prediction"].upper()
                )

                st.write(entry["preview"])

    else:

        st.info("No saved scans.")


# ==========================================
# INFO
# ==========================================

with info_tab:

    st.subheader("About ScamShield AI")

    st.write(
        "**Version:** Experiment 9"
    )

    st.write(
        "**Machine-learning model:** "
        "Frozen V7 Naive Bayes"
    )

    st.write(
        "**Security analysis:** "
        "Experiment 8 + Experiment 9 rules"
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
        "**Link safety:** "
        "ScamShield analyzes link text "
        "without visiting the links."
    )


# ==========================================
# FOOTER
# ==========================================

st.divider()

st.caption(
    "🛡️ ScamShield AI 😎 | Experiment 9"
)