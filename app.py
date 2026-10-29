import streamlit as st
from PIL import Image, UnidentifiedImageError
import pytesseract
pytesseract.pytesseract.tesseract_cmd = r"C:/program files/tesseract-OCR/tesseract.exe"
from experiment_v9 import scan_message


# ==========================================
# SCAMSHIELD AI - MOBILE EDITION V8
# TEXT + SCREENSHOT SCANNER
# ==========================================

st.set_page_config(
    page_title="ScamShield AI",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed"
)

st.markdown("""
<style>
.block-container {
    max-width: 720px;
    padding-top: 1.1rem;
    padding-bottom: 3rem;
}

div[data-testid="stForm"] {
    border-radius: 18px;
    padding: 1rem;
}

.stButton button,
.stFormSubmitButton button {
    min-height: 3.25rem;
    border-radius: 12px;
    font-weight: bold;
}

textarea {
    font-size: 16px !important;
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
# SESSION MEMORY
# ==========================================

if "latest_report" not in st.session_state:
    st.session_state.latest_report = None

if "history" not in st.session_state:
    st.session_state.history = []

if "keep_history" not in st.session_state:
    st.session_state.keep_history = False

if "ocr_review_text" not in st.session_state:
    st.session_state.ocr_review_text = ""

if "ocr_source_id" not in st.session_state:
    st.session_state.ocr_source_id = None


def changed_history_preference():
    if not st.session_state.keep_history:
        st.session_state.history = []


# ==========================================
# SCANNING ENGINE
# ==========================================

def run_scan(message):
    if not message.strip():
        st.warning("Please enter a message first.")
        return

    try:
        with st.spinner("Analyzing message..."):
            report = scan_message(message)

    except ValueError as error:
        st.error(str(error))
        return

    except Exception:
        st.error("Scanner error. Please try again.")
        return

    st.session_state.latest_report = report

    if st.session_state.keep_history:
        st.session_state.history.insert(0, {
            "preview": message[:85],
            "risk": report["risk"],
            "prediction": report["v7_prediction"]
        })

        st.session_state.history = (
            st.session_state.history[:20]
        )

    st.success("Scan complete! Check Results below.")


# ==========================================
# APP HEADER
# ==========================================

st.title("🛡️ ScamShield AI 😎")

st.caption("Mobile Edition | Experiment 8")

st.write(
    "Detect suspicious messages using "
    "AI and cybersecurity warning signs."
)

st.warning(
    "ScamShield is experimental. "
    "Never rely on it alone to decide "
    "whether a message is safe."
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
            placeholder="Paste a suspicious SMS here...",
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

    st.subheader("📸 Scan a Screenshot")

    st.write(
        "Upload a screenshot of a suspicious "
        "SMS, WhatsApp message, or email."
    )

    st.caption(
        "Crop out personal information, "
        "passwords, OTPs, and phone numbers "
        "before uploading."
    )

    uploaded_image = st.file_uploader(
        "Choose screenshot",
        type=["png", "jpg", "jpeg"],
        key="screenshot_upload"
    )

    if uploaded_image is not None:

        st.image(
            uploaded_image,
            caption="Uploaded screenshot",
            use_container_width=True
        )

        source_id = (
            uploaded_image.name,
            uploaded_image.size,
            uploaded_image.file_id
        )

        if st.session_state.ocr_source_id != source_id:
            st.session_state.ocr_source_id = source_id
            st.session_state.ocr_review_text = ""

        if uploaded_image.size > 5 * 1024 * 1024:

            st.error(
                "Screenshot is too large. "
                "Please use an image under 5 MB."
            )

        elif st.button(
            "📖 EXTRACT TEXT",
            use_container_width=True
        ):

            try:
                uploaded_image.seek(0)

                with Image.open(uploaded_image) as img:
                    img.load()

                    if img.width * img.height > 20_000_000:
                        raise ValueError(
                            "Image is too large. "
                            "Crop it and try again."
                        )

                    image = img.convert("RGB")

                with st.spinner(
                    "Reading screenshot..."
                ):
                    extracted_text = (
                        pytesseract.image_to_string(image)
                    )

                st.session_state.ocr_review_text = (
                    extracted_text[:5000].strip()
                )

                if not st.session_state.ocr_review_text:
                    st.warning(
                        "No readable text found. "
                        "Try a clearer screenshot."
                    )

            except pytesseract.TesseractNotFoundError:
                st.error(
                    "Tesseract OCR is not installed. "
                    "Install it before using screenshots."
                )

            except (
                UnidentifiedImageError,
                OSError,
                ValueError,
                Image.DecompressionBombError
            ) as error:
                st.error(f"Image error: {error}")

            except Exception:
                st.error(
                    "Could not extract text "
                    "from this screenshot."
                )

        if st.session_state.ocr_review_text:

            st.success("Text extracted!")

            st.info(
                "Review and correct the extracted "
                "text before scanning."
            )

            st.text_area(
                "Extracted text",
                key="ocr_review_text",
                height=175,
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
# RESULTS / HISTORY / INFO
# ==========================================

results_tab, history_tab, info_tab = st.tabs([
    "🔍 Results",
    "🕘 History",
    "ℹ️ Info"
])


# ==========================================
# RESULTS
# ==========================================

with results_tab:

    report = st.session_state.latest_report

    if report is None:

        st.info(
            "Your scan results will appear here."
        )

    else:

        st.subheader("🧠 AI Prediction")

        prediction = report["v7_prediction"]

        st.write(
            "**" + prediction.upper() + "**"
        )

        st.subheader("🛡️ Risk Assessment")

        risk = report["risk"]

        if risk.startswith("HIGH"):
            st.error("🚨 " + risk)

        elif risk.startswith("NEEDS"):
            st.warning("⚠️ " + risk)

        else:
            st.info("ℹ️ " + risk)

        st.divider()

        st.subheader("⚠️ Warning Signs")

        if report["warnings"]:

            for finding in report["warnings"]:
                st.write(
                    "⚠️ " + finding["description"]
                )

        else:
            st.write(
                "No predefined warning signs detected."
            )

        if report["urls"]:

            with st.expander(
                "🔗 Detected Links - Not Opened"
            ):

                for url in report["urls"]:
                    st.code(url, language=None)

        st.divider()

        st.warning(
            "A low-risk prediction does not "
            "guarantee safety. Never share "
            "your PIN, OTP, password, "
            "or banking details."
        )


# ==========================================
# SCAN HISTORY
# ==========================================

with history_tab:

    st.subheader("🕘 Scan History")

    st.toggle(
        "Remember scans during this session",
        key="keep_history",
        on_change=changed_history_preference
    )

    st.caption(
        "History is off by default "
        "and stays in this app session."
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
                    "AI: " + entry["prediction"].upper()
                )

                st.write(entry["preview"])

    else:

        st.info("No saved scans.")


# ==========================================
# ABOUT
# ==========================================

with info_tab:

    st.subheader("About ScamShield AI")

    st.write(
        "**AI model:** ScamShield Version 7"
    )

    st.write(
        "**Security analysis:** Experiment 8"
    )

    st.write(
        "**Machine learning:** Naive Bayes"
    )

    st.write(
        "**Screenshot technology:** "
        "Tesseract OCR"
    )

    st.write(
        "**Development accuracy:** "
        "95% on 60 synthetic messages. "
        "This is not independently "
        "verified real-world accuracy."
    )

    st.write(
        "**Privacy:** Uploaded messages "
        "and screenshots are processed "
        "on the Streamlit hosting server. "
        "Avoid sharing sensitive information."
    )

    st.write(
        "**Research status:** "
        "Experimental cybersecurity project."
    )


# ==========================================
# FOOTER
# ==========================================

st.divider()

st.caption(
    "🛡️ ScamShield AI 😎 | Experiment 8"
)