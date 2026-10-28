
import streamlit as st
from experiment_v8 import scan_message

# ==========================================
# SCAMSHIELD AI - MOBILE EDITION
# Version 8 | iPhone + Windows
# ==========================================

st.set_page_config(
    page_title="ScamShield Mobile",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed"
)

# MOBILE-FRIENDLY DESIGN

st.markdown("""
<style>
.block-container {
    max-width: 720px;
    padding-top: 1.1rem;
    padding-bottom: 3rem;
}

h1 {
    letter-spacing: -0.035em;
}

div[data-testid="stForm"] {
    border: 1px solid rgba(140,150,170,.26);
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
    line-height: 1.6 !important;
}

@media (max-width: 600px) {
    .block-container {
        padding-left: .85rem;
        padding-right: .85rem;
    }

    h1 {
        font-size: 2rem !important;
    }

    button {
        font-size: 1rem !important;
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


def changed_history_preference():
    if not st.session_state.keep_history:
        st.session_state.history = []


# ==========================================
# APP HEADER
# ==========================================

st.title("🛡️ ScamShield AI")

st.caption(
    "Mobile Edition | Version 8.0"
)

st.write(
    "Your intelligent scam detection assistant."
)

st.write(
    "Paste a fictional or anonymized SMS, "
    "email, or WhatsApp message below."
)

st.divider()


# ==========================================
# MESSAGE SCANNER
# ==========================================

with st.form("mobile_scanner"):

    message = st.text_area(
        "Message to scan",
        height=175,
        max_chars=5000,
        placeholder="Paste a suspicious message here..."
    )

    scanned = st.form_submit_button(
        "🔎 SCAN MESSAGE",
        type="primary",
        use_container_width=True
    )


# ==========================================
# RUN SCAMSHIELD
# ==========================================

if scanned:

    if not message.strip():

        st.warning(
            "Please enter a message first."
        )

    else:

        try:

            with st.spinner("Analysing message..."):
                report = scan_message(message)

        except ValueError as error:

            st.error(str(error))

        except Exception:

            st.error(
                "The scanner encountered an error. "
                "Check your VS Code terminal."
            )

        else:

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


# ==========================================
# APPLICATION TABS
# ==========================================

results_tab, history_tab, info_tab = st.tabs(
    [
        "🔍 Results",
        "🕘 History",
        "ℹ️ Info"
    ]
)


# ==========================================
# RESULTS TAB
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

            st.error(
                "🚨 " + risk
            )

        elif risk.startswith("NEEDS"):

            st.warning(
                "⚠️ " + risk
            )

        else:

            st.info(
                "ℹ️ " + risk
            )

        st.divider()

        # WARNING ANALYSIS

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

        # URL ANALYSIS

        if report["urls"]:

            with st.expander(
                "🔗 Links detected - Not opened"
            ):

                for url in report["urls"]:

                    st.code(
                        url,
                        language=None
                    )

        st.divider()

        st.warning(
            "ScamShield is experimental. "
            "A low-risk prediction does not "
            "guarantee a message is safe. "
            "Never share your PIN, OTP, "
            "password, or banking details."
        )


# ==========================================
# HISTORY TAB
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
        "Saved previews remain only in your "
        "current Streamlit session."
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

                st.write(
                    entry["preview"]
                )

    else:

        st.info(
            "No saved scans in this session."
        )


# ==========================================
# INFORMATION TAB
# ==========================================

with info_tab:

    st.subheader("About ScamShield AI")

    st.write(
        "**Model:** ScamShield Version 7"
    )

    st.write(
        "**Security analysis:** Version 8"
    )

    st.write(
        "**Machine learning:** Naive Bayes "
        "using words and two-word phrases"
    )

    st.write(
        "**Development accuracy:** 95% "
        "on 60 synthetic development messages"
    )

    st.write(
        "**Privacy:** No external AI APIs "
        "are used. Messages are processed "
        "on the laptop running this app."
    )

    st.write(
        "**Research:** The development "
        "accuracy is not a verified measure "
        "of real-world scam detection."
    )

    st.write(
        "**Mobile:** Your laptop must remain "
        "running for your iPhone to use ScamShield."
    )

    st.caption(
        "ScamShield AI | Cybersecurity Research Project"
    )


# ==========================================
# FOOTER
# ==========================================

st.divider()

st.caption(
    "🛡️ ScamShield AI Mobile Edition | "
    "Experimental Security Prototype"
)
