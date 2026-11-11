"""ScamShield AI - shared look for the Streamlit apps.

The same design system as the ScamShield Figma file (black, red and white):
colour tokens, Source Sans 3 type, cards, verdict cards, warning items,
badges and segmented tabs.

    apply_theme("mobile")   phone-first layout (mobile_app.py)
    apply_theme("web")      wide website layout (app.py)

Every helper that puts text into HTML escapes it first, because scan
results contain text copied from untrusted messages.
"""

from html import escape

import streamlit as st

# Colour tokens - identical to the Figma "ScamShield" variables.
TOKENS = {
    "bg": "#0E1117",
    "surface": "#1A1D26",
    "surface-2": "#262730",
    "border": "#3A3D4A",
    "text": "#FFFFFF",
    "text-muted": "#B8BCC8",
    "red": "#FF4B4B",
    "red-text": "#FF9C9C",
    "red-dark": "#3D1A1E",
    "amber": "#FFC857",
    "amber-dark": "#3A3118",
    "blue": "#7CB7FF",
    "blue-dark": "#172338",
}

_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Source+Sans+3:wght@400;600;700;900&display=swap');

:root {
__VARS__
  --ss-radius-sm: 12px;
  --ss-radius-md: 16px;
  --ss-radius-lg: 24px;
}

html, body, .stApp, .stMarkdown, button, input, textarea {
  font-family: "Source Sans 3", "Source Sans Pro", system-ui, sans-serif;
}
.stApp { background: var(--ss-bg); color: var(--ss-text); }
.block-container { max-width: __MAX_WIDTH__; padding-top: __TOP__; padding-bottom: 3rem; }
h1 { font-weight: 700; letter-spacing: -0.02em; }
h2, h3 { font-weight: 700; }

/* ---------- buttons ---------- */
.stButton button, .stFormSubmitButton button, .stLinkButton a {
  min-height: 3rem; border-radius: var(--ss-radius-sm); font-weight: 700;
}
[data-testid="stBaseButton-primary"], [data-testid="stBaseButton-primaryFormSubmit"] {
  background: var(--ss-red); border-color: var(--ss-red); color: #fff;
}
[data-testid="stBaseButton-secondary"], [data-testid="stBaseButton-secondaryFormSubmit"] {
  background: transparent; border: 1px solid var(--ss-border); color: var(--ss-text);
}
[data-testid="stBaseButton-secondary"]:hover { border-color: var(--ss-red); color: var(--ss-text); }
[data-testid="stBaseButton-tertiary"] { min-height: 2.5rem; color: var(--ss-text-muted); font-weight: 600; }
[data-testid="stBaseButton-tertiary"]:hover { color: var(--ss-text); }

/* ---------- segmented tabs ---------- */
/* Streamlit 1.66+ (react-aria) and older (baseweb) tab markup */
[data-testid="stTabs"] [role="tablist"], [data-baseweb="tab-list"] {
  gap: 8px; background: var(--ss-surface-2); border-radius: var(--ss-radius-md); padding: 6px;
  border: none; box-shadow: none; width: fit-content; max-width: 100%;
}
[data-testid="stTab"], [data-baseweb="tab"] {
  border-radius: var(--ss-radius-sm); padding: 8px 16px; height: auto; color: var(--ss-text-muted);
  border: none; margin: 0;
}
[data-testid="stTab"] p, [data-baseweb="tab"] p { font-weight: 700; }
[data-testid="stTab"][aria-selected="true"], [data-baseweb="tab"][aria-selected="true"] {
  background: var(--ss-bg); color: var(--ss-text);
}
[data-testid="stTabs"] .react-aria-SelectionIndicator,
[data-baseweb="tab-highlight"], [data-baseweb="tab-border"] { display: none; }

/* ---------- inputs ---------- */
.stTextArea textarea {
  background: var(--ss-surface-2); border-radius: var(--ss-radius-md);
  font-size: 16px !important; line-height: 1.5 !important;
}
[data-testid="stFileUploaderDropzone"] {
  background: var(--ss-surface-2); border: 1px dashed var(--ss-border); border-radius: var(--ss-radius-md);
}
div[data-testid="stForm"] { border: none; padding: 0; }

/* ---------- cards (st.container(key="ss_card_...")) ---------- */
[class*="st-key-ss_card"] {
  background: var(--ss-surface); border: 1px solid var(--ss-border);
  border-radius: var(--ss-radius-lg); padding: 24px;
}
[class*="st-key-ss_card_alt"] { background: var(--ss-surface-2); border: none; }
[class*="st-key-ss_nav"] {
  border-bottom: 1px solid var(--ss-border); padding-bottom: 12px; margin-bottom: 8px;
}

/* ---------- HTML components ---------- */
.ss-brand { font-size: 1.25rem; font-weight: 700; color: var(--ss-text); padding-top: .45rem; }
.ss-eyebrow { color: var(--ss-text-muted); font-weight: 600; font-size: .95rem; margin-bottom: .25rem; }
.ss-display { font-size: clamp(2.3rem, 5vw, 4rem); font-weight: 900; line-height: 1.05; margin: .6rem 0 1rem; }
.ss-lead { color: var(--ss-text-muted); font-size: 1.125rem; line-height: 1.55; max-width: 34rem; }
.ss-muted { color: var(--ss-text-muted); }
.ss-small { font-size: .875rem; color: var(--ss-text-muted); }

.ss-badge {
  display: inline-block; border-radius: 999px; padding: .2rem .75rem; margin: .15rem .35rem .15rem 0;
  font-size: .85rem; font-weight: 700; border: 1px solid var(--ss-red); color: var(--ss-text);
  background: var(--ss-surface-2);
}
.ss-badge.on { background: var(--ss-red); }

.ss-verdict { border-radius: var(--ss-radius-md); padding: 16px 18px; margin: .5rem 0 .9rem; border: 1px solid transparent; }
.ss-verdict .t { font-weight: 900; font-size: 1.25rem; letter-spacing: .01em; }
.ss-verdict .b { font-size: .95rem; line-height: 1.5; margin-top: .3rem; }
.ss-verdict.high { background: var(--ss-red-dark); border-color: var(--ss-red); color: var(--ss-red-text); }
.ss-verdict.review { background: var(--ss-amber-dark); color: var(--ss-amber); }
.ss-verdict.none { background: var(--ss-blue-dark); color: var(--ss-blue); }

.ss-warn {
  border-radius: var(--ss-radius-sm); padding: 12px 14px; margin: .45rem 0;
  border-left: 3px solid var(--ss-text-muted); background: var(--ss-surface-2); color: var(--ss-text);
}
.ss-warn.high { border-left-color: var(--ss-red); background: var(--ss-red-dark); }
.ss-warn.medium { border-left-color: var(--ss-amber); background: var(--ss-amber-dark); }
.ss-warn .r { font-size: .8rem; color: var(--ss-text-muted); margin-top: .2rem; }

.ss-source {
  border: 1px solid var(--ss-border); border-radius: var(--ss-radius-md);
  padding: .8rem 1rem; margin: .4rem 0 .8rem; background: var(--ss-surface-2);
}
.ss-row {
  display: flex; justify-content: space-between; align-items: center; gap: 12px;
  background: var(--ss-surface-2); border-radius: var(--ss-radius-sm); padding: 14px 16px; margin: .5rem 0;
}
.ss-row b { white-space: nowrap; }
.ss-row .v { font-weight: 700; color: var(--ss-red-text); text-align: right; }

.ss-feature {
  background: var(--ss-surface); border: 1px solid var(--ss-border); border-radius: var(--ss-radius-lg); padding: 28px; height: 100%;
}
.ss-feature .i { font-size: 1.75rem; }
.ss-feature .t { font-weight: 700; font-size: 1.25rem; margin: .6rem 0 .4rem; }
.ss-feature .b { color: var(--ss-text-muted); line-height: 1.5; }

.ss-bubble {
  background: var(--ss-surface-2); border-radius: var(--ss-radius-md); padding: 14px 16px;
  color: var(--ss-text-muted); line-height: 1.5;
}
.ss-history { border: 1px solid var(--ss-border); border-radius: var(--ss-radius-md); padding: 14px 16px; margin: .5rem 0; background: var(--ss-surface); }
.ss-history .p { color: var(--ss-text-muted); margin-top: .35rem; }
.ss-pill { display: inline-block; border-radius: 999px; padding: .1rem .6rem; font-size: .8rem; font-weight: 700; }
.ss-pill.high { background: var(--ss-red-dark); color: var(--ss-red-text); }
.ss-pill.review { background: var(--ss-amber-dark); color: var(--ss-amber); }
.ss-pill.none { background: var(--ss-blue-dark); color: var(--ss-blue); }

.ss-footer {
  border-top: 1px solid var(--ss-border); margin-top: 2.5rem; padding-top: 1.25rem;
  display: flex; justify-content: space-between; gap: 1rem; flex-wrap: wrap;
  color: var(--ss-text-muted); font-size: .875rem;
}
.ss-footer b { color: var(--ss-text); }
a.ss-ghost {
  display: inline-flex; align-items: center; justify-content: center; width: 100%; min-height: 3rem;
  padding: 0 1.2rem; border: 1px solid var(--ss-border); border-radius: var(--ss-radius-sm);
  color: var(--ss-text) !important; text-decoration: none; font-weight: 700;
}
a.ss-ghost:hover { border-color: var(--ss-red); }
.ss-section-title { font-size: 2.5rem; font-weight: 700; margin: 0 0 .25rem; }
.ss-hello {
  background: var(--ss-surface); border: 1px solid var(--ss-border); border-left: 3px solid var(--ss-red);
  border-radius: var(--ss-radius-md); padding: 12px 16px; margin: .25rem 0 1rem;
}
.ss-hello .t { font-weight: 700; font-size: 1.15rem; }
.ss-steps { padding-left: 1.2rem; color: var(--ss-text-muted); line-height: 1.7; margin: .3rem 0 .6rem; }

@media (max-width: 640px) {
  .block-container { padding-left: 1rem; padding-right: 1rem; }
  /* nav bar: brand on its own line, links + buttons in one wrapped row */
  [class*="st-key-ss_nav"] [data-testid="stHorizontalBlock"] {
    flex-direction: row !important; flex-wrap: wrap !important; gap: 4px 10px !important;
    align-items: center !important;
  }
  [class*="st-key-ss_nav"] [data-testid="stColumn"] {
    width: auto !important; min-width: 0 !important; flex: 0 1 auto !important;
  }
  [class*="st-key-ss_nav"] [data-testid="stColumn"]:first-child { flex-basis: 100% !important; }
  [class*="st-key-ss_nav"] [data-testid="stColumn"]:nth-child(4) { display: none !important; }
  [class*="st-key-ss_nav"] [data-testid="stColumn"]:last-child { flex: 1 1 auto !important; }
  [class*="st-key-ss_card"] { padding: 18px; border-radius: var(--ss-radius-md); }
  .ss-feature { padding: 20px; }
}
</style>
"""


def apply_theme(mode="mobile"):
    """Inject the ScamShield design system. mode: 'mobile' or 'web'."""
    variables = "\n".join(f"  --ss-{name}: {value};" for name, value in TOKENS.items())
    web = mode == "web"
    css = (_CSS.replace("__VARS__", variables)
           .replace("__MAX_WIDTH__", "1200px" if web else "720px")
           .replace("__TOP__", "3.5rem"))
    st.markdown(css, unsafe_allow_html=True)


def html(markup):
    """Render trusted HTML built with the helpers below."""
    st.markdown(markup, unsafe_allow_html=True)


# ==========================================
# Verdicts
# ==========================================

VERDICTS = {
    "high": ("🚨 HIGH RISK — POSSIBLE SCAM",
             "Strong scam indicators were detected. Do not reply, click suspicious links, "
             "or share personal information."),
    "ai_only": ("⚠️ NEEDS REVIEW — AI MODEL ONLY",
                "Only the AI model flagged this message. No security rule found scam behaviour "
                "(such as password requests, fees, or changed bank details). Check who sent it "
                "before acting."),
    "review": ("⚠️ NEEDS REVIEW",
               "ScamShield found warning signs. Verify the message through an official channel."),
    "none": ("ℹ️ NO KNOWN SCAM PATTERN DETECTED",
             "No strong pattern was detected. This does not prove the message is legitimate."),
}

NEXT_STEPS = {
    "high": ["Don’t reply, click links, pay, or share codes.",
             "Contact the person or company using a number or website you already trust.",
             "Report the message, then delete it."],
    "review": ["Check who really sent it, using an official channel.",
               "Never share passwords, PINs or one-time codes.",
               "If you’re unsure, ask someone you trust before acting."],
    "none": ["Still be careful with unexpected requests.",
             "Never share passwords, PINs or one-time codes.",
             "If anything feels off, check with the sender another way."],
}


def risk_level(risk):
    """'high', 'review' or 'none' for a ScamShield risk string."""
    text = str(risk).upper()
    if text.startswith("HIGH"):
        return "high"
    if text.startswith("NEEDS"):
        return "review"
    return "none"


def verdict_card(risk):
    text = str(risk).upper()
    level = risk_level(risk)
    key = "ai_only" if text.startswith("NEEDS REVIEW - AI MODEL ONLY") else level
    title, body = VERDICTS[key]
    return (f'<div class="ss-verdict {level}"><div class="t">{escape(title)}</div>'
            f'<div class="b">{escape(body)}</div></div>')


def warning_item(description, severity="low", rule=""):
    severity = severity if severity in ("high", "medium") else "low"
    icon = {"high": "🚨", "medium": "⚠️"}.get(severity, "⚠️")
    rule_html = f'<div class="r">{escape(rule)}</div>' if rule else ""
    return f'<div class="ss-warn {severity}">{icon} {escape(str(description))}{rule_html}</div>'


def badge(label, on=False):
    return f'<span class="ss-badge{" on" if on else ""}">{escape(label)}</span>'


def pill(label, level):
    return f'<span class="ss-pill {level}">{escape(label)}</span>'


def verdict_source(report):
    source = report.get("verdict_source", "none")
    label = str(report.get("verdict_source_label", "Unknown"))
    return ('<div class="ss-source"><b>Verdict source: ' + escape(label) + "</b><br>"
            + badge("🧠 AI model", source in ("ai", "ai_and_rules"))
            + badge("🛡️ Security rules", source in ("rules", "ai_and_rules")) + "</div>")


def ai_row(report):
    prediction = str(report.get("ai_prediction", "unknown")).upper()
    probability = report.get("ai_scam_probability")
    value = prediction
    if probability is not None:
        value += f" · {float(probability) * 100:.0f}% scam probability"
    return f'<div class="ss-row"><b>🧠 AI prediction</b><span class="v">{escape(value)}</span></div>'


def next_steps(risk):
    items = "".join(f"<li>{escape(s)}</li>" for s in NEXT_STEPS[risk_level(risk)])
    return f'<ol class="ss-steps">{items}</ol>'


def report_warnings(report):
    """Warning items for every finding in a scan report."""
    parts = []
    for finding in report.get("warnings", []):
        rule = str(finding.get("source", "")).upper()
        parts.append(warning_item(finding.get("description", "Unspecified warning"),
                                  finding.get("severity", "low"),
                                  f"{rule} rule" if rule else ""))
    return "".join(parts)


def history_entry(entry):
    level = risk_level(entry.get("risk", ""))
    meta = "AI: " + str(entry.get("prediction", "")).upper()
    if entry.get("source"):
        meta += " · " + str(entry["source"])
    return (f'<div class="ss-history">{pill(str(entry.get("risk", "")), level)} '
            f'<span class="ss-small">{escape(meta)}</span>'
            f'<div class="p">{escape(str(entry.get("preview", "")))}</div></div>')


def greeting(first_name, detail):
    """'👋 Hi, Name' card shown after sign-in."""
    hello = f"👋 Hi, {escape(first_name)}!" if first_name else "👋 Hi!"
    return (f'<div class="ss-hello"><div class="t">{hello}</div>'
            f'<div class="ss-small">{escape(detail)}</div></div>')


def feature(icon, title, body):
    return (f'<div class="ss-feature"><div class="i">{escape(icon)}</div>'
            f'<div class="t">{escape(title)}</div><div class="b">{escape(body)}</div></div>')


def footer(note):
    return (f'<div class="ss-footer"><b>🛡️ ScamShield AI</b>'
            f'<span>{escape(note)}</span></div>')
