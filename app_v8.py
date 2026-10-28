"""Run: py -m streamlit run app_v8.py
Requires streamlit plus the existing ScamShield project files.
"""

import streamlit as st
from experiment_v8 import scan_message

st.set_page_config(page_title='ScamShield AI V8', page_icon='🛡️', layout='centered')
st.title('🛡️ ScamShield AI')
st.caption('Version 8 • V7 machine learning + transparent warning checks')
st.write('Paste a fictional or anonymized suspicious SMS, email, or WhatsApp message.')

with st.form('scanner'):
    message = st.text_area('Message to scan', height=160, max_chars=5000,
                           placeholder='Example: Your account will be blocked in 2hrs...')
    submitted = st.form_submit_button('Scan message', use_container_width=True)

if submitted:
    if not message.strip():
        st.warning('Please enter a message.')
    else:
        report = scan_message(message)
        st.subheader('Results')
        st.write('**Machine learning (frozen V7):**', report['v7_prediction'].upper())
        risk = report['risk']
        if risk.startswith('HIGH'):
            st.error(risk)
        elif risk.startswith('NEEDS'):
            st.warning(risk)
        else:
            st.info(risk)
        st.subheader('Warning signs')
        if report['warnings']:
            for finding in report['warnings']:
                st.write('• ' + finding['description'])
        else:
            st.write('No predefined warning signs detected.')
        if report['urls']:
            st.caption('URLs found (not opened):')
            for url in report['urls']:
                st.code(url, language=None)
        st.warning('Neither model output nor warning signs can prove that a message is safe. '
                   'Never enter OTPs, passwords, or private banking information into this prototype.')

with st.expander('Research notes'):
    st.write('The V7 prediction comes from a Naive Bayes classifier trained on synthetic examples.')
    st.write('V8 adds hand-written warning checks. They are **not explanations** of the classifier.')
    st.write('The previously reported 95% accuracy was measured on reused synthetic development data; '
             'real-world accuracy is unknown.')
    st.write('No Gemini or other external AI API is connected.')
