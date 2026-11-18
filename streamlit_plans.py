"""ScamShield AI - plans, monthly limits and the Pro document scanner for the
Streamlit pages (app.py = website, mobile_app.py = phone version).

The rules themselves live in tiers.py (plans, limits) and document_check.py
(reading and checking documents), shared with the backend API. Everything
here runs in Python on the server, so a Free or Plus visitor can't reach the
document checker or a report by changing the page in their browser.
"""

import hashlib
from datetime import datetime, timezone

import streamlit as st

import document_check
import tiers
import ui_theme as ui
from experiment_v10 import scan_message
from streamlit_auth import current_account


def account():
    """(account id, plan) for this visitor. See streamlit_auth.current_account."""
    return current_account()


# ==========================================
# Monthly check limit (Plus and Pro only; Free has
# no monthly limit, as before)
# ==========================================

def use_check():
    """Use one monthly check. Returns False (and explains) if none are left."""
    user_id, plan = account()
    limit = tiers.monthly_limit(plan)
    if limit is None or user_id is None:
        return True
    try:
        tiers.usage_store().reserve(user_id, limit)
    except tiers.CheckLimitReached as error:
        st.error("🚫 " + str(error))
        return False
    return True


def give_back_check():
    """The check didn't complete, so it doesn't count."""
    user_id, plan = account()
    if tiers.monthly_limit(plan) is not None and user_id is not None:
        tiers.usage_store().release(user_id)


def plan_line():
    """e.g. 'Plan: Plus (R70/month) — 3 of 100 checks used this month (resets on ...)'."""
    user_id, plan = account()
    info = tiers.PLANS[plan]
    line = f"**Plan:** {info.name} ({info.price})"
    limit = tiers.monthly_limit(plan)
    if limit is not None and user_id is not None:
        used = tiers.usage_store().used(user_id)
        line += (f" — {min(used, limit)} of {limit} checks used this month "
                 f"(resets on {tiers.next_reset()})")
    return line


def show_plan():
    st.subheader("⭐ Plan")
    st.write(plan_line())
    if not tiers.PLANS[account()[1]].documents:
        st.caption(tiers.UPGRADE_MESSAGE)


# ==========================================
# Pro: document scanner
# ==========================================

def _check(name, data):
    """Check a document once and keep the result for this session."""
    if not use_check():
        return
    try:
        with st.spinner("Reading and checking document... Scanned pages can take up to a minute."):
            result = document_check.check_document(name, data, scan_message)
    except document_check.DocumentError as error:
        give_back_check()
        st.session_state.document_error = str(error)
        return
    except Exception:
        give_back_check()
        st.session_state.document_error = "ScamShield couldn't analyse this document. Please try again."
        return

    scanned_at = datetime.now(timezone.utc)
    st.session_state.document_result = result
    st.session_state.document_report = document_check.build_report(result, scanned_at)

    if st.session_state.get("keep_history"):
        st.session_state.history.insert(0, {
            "preview": "📄 " + result["document"]["file_name"],
            "risk": result["risk"],
            "prediction": str(result.get("ai_prediction", "")),
            "source": result.get("verdict_source_label", ""),
        })
        st.session_state.history = st.session_state.history[:20]


def _show_result(result, key):
    document = result["document"]
    st.markdown("#### 🛡️ Document result")
    ui.html(ui.verdict_card(result["risk"]) + ui.verdict_source(result))
    st.caption(f"📄 {document['file_name']} · Final assessment: {result['risk']}")
    for note in document_check.coverage_notes(document):
        st.caption("ℹ️ " + note)

    st.markdown("#### ⚠️ Warning signs")
    if result["warnings"]:
        ui.html(ui.report_warnings(result))
    else:
        ui.html('<p class="ss-muted">No predefined warning signs detected.</p>')

    with st.expander("🧭 Why this result?"):
        for line in result.get("explanation", []):
            st.write("• " + str(line))
    if result.get("flagged_sections"):
        with st.expander("📍 Where to look in the document"):
            for section in result["flagged_sections"]:
                st.write(f"**{section['location'].capitalize()}** — {section['risk']}")
                st.code(section["excerpt"], language=None, wrap_lines=True)
    if result.get("urls"):
        with st.expander("🔗 Detected links — not opened"):
            for url in result["urls"]:
                st.code(str(url), language=None)

    # Reports are Pro-only, checked again here on the server.
    if tiers.PLANS[account()[1]].reports and st.session_state.document_report:
        st.download_button(
            "⬇️ Download report", data=st.session_state.document_report,
            file_name=document_check.report_file_name(document["file_name"]),
            mime="text/plain", type="primary", use_container_width=True,
            key=f"{key}_report")
    st.caption("ScamShield is experimental. A low-risk result never proves a document is safe.")


def document_scanner(key="document"):
    """The whole 📄 Document tab: upgrade message for Free/Plus, scanner for Pro."""
    for name in ("document_source_id", "document_result", "document_error", "document_report"):
        st.session_state.setdefault(name, None)

    st.markdown("#### 📄 Check a document")
    st.write("Check a PDF, Word (.docx) or text file, such as an invoice, job offer or letter, "
             "for scam warning signs.")

    if not tiers.PLANS[account()[1]].documents:
        # Free and Plus never reach the document checker.
        st.info("⭐ " + tiers.UPGRADE_MESSAGE)
        return

    limits = document_check.limits()
    st.caption(f"Up to {limits['max_bytes'] // (1024 * 1024)} MB and {limits['max_pages']} pages. "
               "The document is checked in memory and not saved. Remove passwords and private "
               "details first.")
    uploaded = st.file_uploader("Choose a document", type=["pdf", "docx", "txt"], key=f"{key}_upload")
    if uploaded is None:
        st.session_state.document_source_id = None
        return

    data = uploaded.getvalue()
    document_id = hashlib.sha256(uploaded.name.encode("utf-8", "replace") + b"\0" + data).hexdigest()
    if st.session_state.document_source_id != document_id:  # a NEW document: check it once
        st.session_state.document_source_id = document_id
        st.session_state.document_result = None
        st.session_state.document_report = None
        st.session_state.document_error = None
        _check(uploaded.name, data)

    if st.session_state.document_error:
        st.error("📄 " + st.session_state.document_error)
    if st.session_state.document_result is not None:
        _show_result(st.session_state.document_result, key)


def clear_document():
    for name in ("document_source_id", "document_result", "document_error", "document_report"):
        st.session_state[name] = None
