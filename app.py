import streamlit as st

from experiment_v4 import predict_v4
from experiment_v5 import predict_v5

# SCAMSHIELD AI - DUAL AI APP V6.0

st.set_page_config(
    page_title="ScamShield AI",
    page_icon="🛡️",
    layout="centered"
)

st.title("🛡️ ScamShield AI")
st.caption("Version 6.0 | Dual-AI Cybersecurity")

st.divider()

st.subheader("Message Scanner")

message = st.text_area(
    "Enter a suspicious message",
    placeholder="Paste an SMS or WhatsApp message...",
    height=160
)

if st.button("SCAN MESSAGE", use_container_width=True):

    if not message.strip():
        st.warning("Please enter a message.")

    else:
        with st.spinner("Both AI models are analysing..."):
            result_v4 = predict_v4(message)
            result_v5 = predict_v5(message)

        st.subheader("AI Model Predictions")

        col1, col2 = st.columns(2)

        with col1:
            st.metric("AI Model 1 (V4)", result_v4.upper())

        with col2:
            st.metric("AI Model 2 (V5)", result_v5.upper())

        st.divider()
        st.subheader("Final Assessment")

        if result_v4 == "scam" and result_v5 == "scam":
            st.error("🚨 HIGH RISK - POSSIBLE SCAM")
            st.write("Both models detected scam patterns.")

        elif result_v4 == "scam" or result_v5 == "scam":
            st.warning("⚠️ CAUTION - REVIEW REQUIRED")
            st.write("The AI models disagree.")
            st.write("At least one model detected scam patterns.")

        else:
            st.info("No known scam pattern detected.")
            st.warning(
                "This does not mean the message is safe."
            )

        st.info(
            "Never share passwords or OTPs. "
            "Verify suspicious requests using "
            "official contact details."
        )

st.divider()

with st.expander("About the AI Models"):
    st.write("Model 1: Naive Bayes with bigrams")
    st.write("Model 2: TF-IDF with logistic regression")
    st.write("Both models run locally.")
    st.write("Gemini is not connected.")
    st.write(
        "Experimental research prototype. "
        "Accuracy of the combined system "
        "has not yet been established."
    )

st.caption("ScamShield AI | Research Prototype")

