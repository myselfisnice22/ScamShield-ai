"""SCAMSHIELD AI - EXPERIMENT 10
Reducing false positives without weakening scam detection.

WHAT CHANGED SINCE EXPERIMENT 9
-------------------------------
1. Root-cause fix in the decision logic.
   In V8/V9 the rule was:  "if the AI says scam -> HIGH RISK", even with zero
   warning signs. Now an AI-only scam prediction becomes
   "NEEDS REVIEW - AI MODEL ONLY". HIGH RISK requires evidence from the
   security rules (alone or together with the AI).

2. Retrained model with less biased data.
   The V10 Naive Bayes model uses exactly the same algorithm as V7, but is
   trained on V7's data PLUS 600 synthetic workplace examples
   (experiment_v10_data.py) in which legitimate and scam messages share the
   same workplace vocabulary.

3. Probability calibration.
   Naive Bayes is famously over-confident. V10 converts its score into a
   probability with "temperature scaling", fitted on templates the model did
   not see during training.

4. New workplace-phishing rules (fake HR portals, payroll diversion, gift-card
   CEO fraud, invoice bank-detail changes, fake job fees, look-alike links...).

5. Every verdict explains whether it came from the AI model, the security
   rules, or both.

The frozen V7 prediction is still reported (as "v7_prediction") so results
can be compared with earlier experiments.

Usage:
    python experiment_v10.py                 # interactive scanner
    python experiment_v10.py --self-test     # quick functional checks
    python experiment_v10.py --model-report  # investigate the AI model
    python -m unittest test_experiment_v10   # full automated test suite
"""

import argparse
import ipaddress
import re
from collections import Counter
from math import exp, log

from experiment_v7 import BigramNaiveBayes, extract_features, predict_v7, v7_training
from experiment_v8 import hostname_for, warning_signs as warning_signs_v8
from experiment_v9 import warning_signs_v9
from experiment_v10_data import generate_workplace_examples, workplace_examples

VERSION = "Experiment 10"


# ==========================================
# PART 1 - THE AI MODEL (retrained + calibrated)
# ==========================================

class ScoredNaiveBayes(BigramNaiveBayes):
    """Same Naive Bayes as V7, but it can also report HOW strongly it leans.

    log_odds > 0 means "leans scam", < 0 means "leans safe".
    """

    def log_odds(self, message):
        scores = {}
        for label in self.labels:
            score = log(self.doc_counts[label] / self.n)
            denominator = self.totals[label] + len(self.vocabulary) + 1
            for feature in extract_features(message):
                if feature in self.vocabulary:
                    score += log((self.feature_counts[label][feature] + 1) / denominator)
            scores[label] = score
        return scores["scam"] - scores["safe"]


def sigmoid(value):
    if value >= 0:
        return 1 / (1 + exp(-value))
    z = exp(value)
    return z / (1 + z)


def out_of_fold_scores(folds=5):
    """Train on some workplace TEMPLATES, score the templates left out.

    Holding out whole templates is stricter than holding out single messages,
    because the model never sees that sentence pattern at all.
    Returns a list of (log_odds, true_label, message).
    """
    tagged = generate_workplace_examples(with_template_id=True)
    template_ids = sorted({tid for _, _, tid in tagged})
    fold_of = {tid: i % folds for i, tid in enumerate(template_ids)}
    results = []
    for fold in range(folds):
        train = list(v7_training) + [(m, l) for m, l, t in tagged if fold_of[t] != fold]
        model = ScoredNaiveBayes(train)
        for message, label, tid in tagged:
            if fold_of[tid] == fold:
                results.append((model.log_odds(message), label, message))
    return results


def _known_features(message):
    return max(1, sum(f in v10_model.vocabulary for f in extract_features(message)))


def _log_loss(probabilities_and_labels):
    total = 0.0
    for p, label in probabilities_and_labels:
        p = min(max(p, 1e-6), 1 - 1e-6)
        total -= log(p) if label == "scam" else log(1 - p)
    return total / len(probabilities_and_labels)


def fit_temperature(scored):
    """Classic temperature scaling: p = sigmoid(log_odds / T).

    Fitted on held-out SYNTHETIC templates. Kept for the model report, because
    it taught us something: the synthetic data is so easy that T comes out
    below 1 ("be even MORE confident"), which is wrong for real messages.
    """
    def loss(temperature):
        return _log_loss([(sigmoid(score / temperature), label) for score, label, _ in scored])
    grid = [0.5 + 0.5 * i for i in range(200)]
    best = min(grid, key=loss)
    return best, loss(1.0), loss(best)


def fit_length_calibration(messages):
    """Length-normalised calibration: p = sigmoid(A * log_odds / sqrt(known words)).

    WHY: Naive Bayes treats every word as independent evidence. A long, formal
    email therefore piles up evidence and becomes extremely (over-)confident.
    Dividing by the square root of the number of known features stops long
    messages from looking more certain just because they are long.

    A is fitted on the 60 development messages (never used for training).
    """
    def loss(a):
        return _log_loss([(sigmoid(a * v10_model.log_odds(m) / _known_features(m) ** 0.5), label)
                          for m, label in messages])
    grid = [0.05 * i for i in range(1, 400)]
    return min(grid, key=loss)


v10_training = list(v7_training) + list(workplace_examples)
v10_model = ScoredNaiveBayes(v10_training)
_calibration_scores = out_of_fold_scores()
SYNTHETIC_TEMPERATURE, _LOSS_RAW, _LOSS_TEMPERATURE = fit_temperature(_calibration_scores)

from evaluate_scams import tests as _calibration_messages  # noqa: E402  (V2 dev set)
CALIBRATION_A = fit_length_calibration(_calibration_messages)


def calibrated_probability(message):
    score = v10_model.log_odds(message)
    return sigmoid(CALIBRATION_A * score / _known_features(message) ** 0.5), score


def ai_assessment(message):
    """Return the V10 AI's prediction, calibrated probability and confidence.

    Calibration never changes the label (scam if log_odds > 0); it only makes
    the probability, and therefore the confidence, more realistic.
    """
    probability, score = calibrated_probability(message)
    prediction = "scam" if score > 0 else "safe"
    distance = abs(probability - 0.5)
    confidence = "high" if distance >= 0.35 else "medium" if distance >= 0.15 else "low"
    return {
        "prediction": prediction,
        "scam_probability": round(probability, 3),
        "confidence": confidence,
        "log_odds": round(score, 2),
    }


# ==========================================
# PART 2 - EXPERIMENT 10 SECURITY RULES
# ==========================================

CREDENTIAL = (
    r"(?:password|passcode|pin|otp|one[- ]time (?:pin|password|code)|login (?:code|details)|"
    r"credentials|cvv|card (?:number|details)|banking details|bank details|account details|"
    r"security code|access code)"
)
LINK_ACTION = r"(?:log ?in|sign ?in|sign-in|verify|validate|confirm|update|enter|re-?enter|keep|reset|type|provide|submit|use)"
SEND_ACTION = r"(?:send|share|provide|reply with|give|forward|enter|type|tell|reveal|submit|read out)"
NEGATION = re.compile(r"\b(?:never|not|don't|dont|do not|no one|nobody|avoid|won't|will never)\b")
HYPOTHETICAL = re.compile(r"\b(?:if you (?:receive|get)|if (?:someone|anyone)|asking you to|asks you to|report)\b")
URGENCY = re.compile(
    r"\b(?:urgent\w*|immediately|asap|right now|now|today|within \d+ (?:minutes?|hours?)|"
    r"before (?:the end of the day|midnight)|overdue|will not be paid)\b"
)
PAYROLL = re.compile(r"\b(?:salary|salaries|payroll|payslip|wages?|bonus|severance)\b")
INVOICE = re.compile(r"\b(?:invoices?|supplier|accounts payable|outstanding payment|make payment)\b")

# Official domains for brands that are often impersonated.
OFFICIAL_DOMAINS = {
    "microsoft": ("microsoft.com", "office.com", "live.com", "microsoftonline.com", "sharepoint.com", "outlook.com"),
    "office365": ("microsoft.com", "office.com", "microsoftonline.com"),
    "outlook": ("outlook.com", "office.com", "live.com", "microsoft.com"),
    "sharepoint": ("sharepoint.com", "microsoft.com"),
    "docusign": ("docusign.com", "docusign.net"),
    "paypal": ("paypal.com",),
    "google": ("google.com",),
    "apple": ("apple.com", "icloud.com"),
    "sars": ("sars.gov.za",),
    "fnb": ("fnb.co.za",),
    "absa": ("absa.co.za",),
    "capitec": ("capitecbank.co.za",),
    "nedbank": ("nedbank.co.za",),
    "standardbank": ("standardbank.co.za",),
}
ALL_OFFICIAL = {d for domains in OFFICIAL_DOMAINS.values() for d in domains}
DOMAIN_BAIT_WORDS = ("login", "signin", "verify", "verification", "secure", "update", "password",
                     "payroll", "wallet", "kyc", "banking", "account")
DIGIT_SWAP = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s"})


def _normalise(message):
    """Lower-case and collapse spaces/new lines (helps with OCR text)."""
    return " ".join(message.lower().split())


def _unnegated(pattern, text):
    """True if the pattern appears WITHOUT a nearby 'never/do not' before it.

    V8 ignored a credential request whenever the message contained safety
    advice ANYWHERE, so a scammer could add "Never share your PIN" to hide.
    V10 only looks at the same sentence, just before the match.
    """
    for match in re.finditer(pattern, text, re.DOTALL):
        before = text[max(0, match.start() - 40):match.start()]
        before = re.split(r"[.!?\n]", before)[-1]
        if not NEGATION.search(before):
            return True
    return False


def _bank_detail_change(text):
    patterns = [
        r"\b(?:changed|change|new|updated|update|re-?enter|amended)\b.{0,40}"
        r"\b(?:bank(?:ing)? (?:account|details)|account (?:number|details)|new account|beneficiary|supplier account)\b",
        r"\b(?:bank(?:ing)? (?:account|details)|account details)\b.{0,30}\b(?:have|has) (?:been )?changed\b",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, text):
            before = re.split(r"[.!?]", text[max(0, match.start() - 60):match.start()])[-1]
            if not NEGATION.search(before) and not HYPOTHETICAL.search(before):
                return True
    return False


def _domain_findings(urls):
    found = []
    for url in urls:
        host = hostname_for(url)
        if not host:
            continue
        if host.startswith("xn--") or ".xn--" in host:
            found.append(("punycode_domain", "Link uses an encoded international domain that can imitate a real one.", "medium"))
        is_official = any(host == d or host.endswith("." + d) for d in ALL_OFFICIAL)
        if is_official:
            continue
        try:
            ipaddress.ip_address(host)
            continue  # V8 already reports IP-address links
        except ValueError:
            pass
        plain = host.translate(DIGIT_SWAP)
        brand = next((b for b in OFFICIAL_DOMAINS if b in plain.replace("-", "").replace(".", "")), None)
        if brand or re.search(r"[a-z][0135][a-z]", host):
            label = f"'{brand}'" if brand else "a familiar name"
            found.append(("lookalike_domain",
                          f"Link address imitates {label} but is not an official domain ({host}).", "medium"))
        elif any(word in host for word in DOMAIN_BAIT_WORDS):
            found.append(("bait_domain",
                          f"Link address uses bait words such as 'login' or 'update' ({host}).", "medium"))
    return found


def warning_signs_v10(message, urls):
    """New Experiment 10 rules, focused on workplace fraud. Returns (findings, flags)."""
    text = _normalise(message)
    findings = []

    def add(code, description, severity):
        findings.append({"code": code, "description": description, "severity": severity, "source": "v10"})

    flags = {}
    flags["credential_link"] = bool(urls) and _unnegated(rf"\b{LINK_ACTION}\b.{{0,70}}\b{CREDENTIAL}\b", text)
    flags["credential_request"] = _unnegated(rf"\b{SEND_ACTION}\b.{{0,60}}\b{CREDENTIAL}\b", text)
    flags["payment_credential"] = _unnegated(r"\b(?:pay|paying|payment|purchase|buy)\b.{0,50}\b(?:pin|otp|cvv|password)\b", text)
    flags["bank_change"] = _bank_detail_change(text)
    flags["gift_cards"] = _unnegated(r"\b(?:buy|purchase|get|send|pick up)\b.{0,40}\bgift ?cards?\b", text)
    flags["secrecy"] = bool(re.search(
        r"\b(?:keep (?:this|it) (?:between us|secret|quiet|to yourself)|don'?t tell|do not tell|"
        r"do not discuss (?:this )?with|don'?t discuss|don'?t call me|do not call me|can'?t talk|cannot talk|"
        r"i'?m (?:stuck )?in a (?:board )?meeting|i am (?:stuck )?in a (?:board )?meeting)", text))
    confidential = bool(re.search(r"\bkeep (?:this|it) (?:confidential|private)\b", text))
    flags["money_request"] = _unnegated(
        r"\b(?:pay|transfer|purchase|buy|send)\b.{0,50}(?:\br\s?\d|\$|€|£|\bmoney\b|\bfunds\b|\bgift ?cards?\b|\bpayment\b|\bamount\b|\bsettlement\b)",
        text)
    flags["job_fee"] = bool(re.search(
        r"\b(?:job|position|vacancy|interview|hired|recruit\w*|shortlisted|job offer|work(?:ing)? from home|start date)\b", text
    )) and bool(re.search(
        r"\b(?:registration|training|processing|application|admin(?:istration)?|placement|uniform|starter[- ]kit|"
        r"equipment|once-off|joining|onboarding)\s+(?:fee|payment|charge|cost|costs|deposit|materials)\b"
        r"|\bpay\b.{0,40}\bbefore\b.{0,40}\b(?:start|interview|position|job|confirm)", text))
    flags["pay_to_avoid"] = bool(re.search(
        r"\b(?:pay|transfer|send|deposit|settle)\b.{0,60}\b(?:to avoid|or face|to stop|to cancel|to prevent)\b.{0,40}"
        r"\b(?:dismissal|disciplinary|termination|suspension|arrest|legal action|fine|being fired|prosecution)"
        r"|\b(?:to avoid|to stop|to cancel|to prevent)\b.{0,40}\b(?:dismissal|disciplinary|termination|suspension|arrest|"
        r"legal action|being fired|prosecution)\b.{0,60}\b(?:pay|transfer|send|deposit|settle)\b", text))
    flags["exec_impersonation"] = bool(re.search(
        r"\b(?:this is|it'?s|i am|i'm)\s+(?:your|the)\s+(?:ceo|md|managing director|director|boss|manager|hr director|"
        r"finance director|cfo|company owner|supervisor)\b", text
    )) and bool(re.search(
        r"\b(?:new number|personal number|personal (?:email|phone)|whatsapp|in a (?:board )?meeting|can'?t talk|"
        r"cannot talk|urgent\w*|quick favou?r|asap|right now|immediately)\b", text))
    flags["release_fee"] = bool(re.search(
        r"\b(?:prize|bonus|refund|grant|inheritance|winnings|reward|payout|free|won)\b", text
    )) and bool(re.search(
        r"\b(?:processing|release|admin|activation|clearance|insurance|shipping|handling)\s+(?:fee|charge|cost)s?\b"
        r"\s*.{0,40}\b(?:paid|pay|required|must)\b|\bto (?:release|claim)\b.{0,40}\b(?:processing|release|admin|activation|"
        r"clearance|insurance|shipping|handling)\s+(?:fee|charge)", text))
    flags["prize_payment"] = bool(re.search(r"\b(?:free|bonus|giveaway|voucher|won|prize|reward)\b", text)) and bool(
        re.search(r"\bafter paying\b|\bto (?:claim|release)\b.{0,60}\bpay\b|\bpay\b.{0,40}\bto (?:claim|release|receive)\b", text))
    flags["hr_lure_link"] = bool(urls) and bool(re.search(
        r"\b(?:dismissal|disciplinary|termination|salary review|salary increase|payslip|bonus|severance|hr notice|"
        r"hr document|employment contract|performance review|policy)\b", text
    )) and bool(re.search(r"\b(?:view|download|open|read|access|sign|review)\b", text))
    flags["delivery_fee_link"] = bool(urls) and bool(re.search(r"\b(?:parcel|package|delivery|courier)\b", text)) and bool(
        re.search(r"\b(?:redelivery|delivery|handling|customs|release|clearance)\s+(?:fee|charge)\b", text))
    flags["urgency"] = bool(URGENCY.search(text))
    flags["payroll"] = bool(PAYROLL.search(text))
    flags["invoice"] = bool(INVOICE.search(text))

    # ---- individual warning signs ----
    if flags["credential_link"]:
        add("credential_link", "Asks you to sign in or enter a password, PIN or banking details through a link.", "high")
    if flags["credential_request"]:
        add("credential_request", "Appears to request a password, PIN, OTP, or other sensitive details.", "high")
    if flags["payment_credential"]:
        add("payment_credential", "Connects a payment with your PIN, OTP, CVV or password. Real payments never need these to be shared.", "high")
    if flags["bank_change"]:
        add("bank_detail_change", "Mentions changed or new bank details for a payment. Confirm by phone using a number you already trust.", "high")
    if flags["gift_cards"]:
        add("gift_card_request", "Asks you to buy gift cards. Employers and suppliers do not pay with gift-card codes.", "high")
    if flags["job_fee"]:
        add("job_fee", "Asks for a fee to get a job or interview. Genuine employers do not charge applicants.", "high")
    if flags["pay_to_avoid"]:
        add("pay_to_avoid_action", "Demands payment to avoid dismissal, arrest or legal action.", "high")
    if flags["release_fee"]:
        add("release_fee", "A prize, bonus or refund can only be 'released' after paying a fee.", "high")
    if flags["prize_payment"]:
        add("advance_fee", "Connects a prize, refund, or grant with an upfront payment.", "high")
    if flags["exec_impersonation"]:
        add("executive_impersonation", "Claims to be a manager or executive and uses pressure or an unusual contact channel.", "medium")
    if flags["hr_lure_link"]:
        add("hr_lure_link", "Uses an HR topic (dismissal, payslip, bonus...) to get you to open a link.", "medium")
    if flags["delivery_fee_link"]:
        add("delivery_fee_link", "Asks for a delivery or customs fee through a link.", "medium")
    if flags["secrecy"]:
        add("secrecy", "Asks you to keep it secret or not to call. Scammers avoid verification.", "low")
    for code, description, severity in _domain_findings(urls):
        add(code, description, severity)

    # ---- strong combined patterns (enough for HIGH RISK on their own) ----
    domain_codes = {"lookalike_domain", "bait_domain", "punycode_domain"}
    has_bad_domain = any(f["code"] in domain_codes for f in findings)
    if flags["credential_link"] and has_bad_domain:
        add("phishing_link_pattern", "Strong phishing pattern: a sign-in/password request through a suspicious link.", "high")
    if flags["payroll"] and (flags["credential_link"] or flags["credential_request"]
                             or (flags["bank_change"] and (urls or flags["urgency"]))):
        add("payroll_diversion_pattern", "Strong payroll-fraud pattern: salary or payslip combined with a request for login or bank details.", "high")
    if flags["bank_change"] and flags["invoice"] and flags["urgency"]:
        add("invoice_fraud_pattern", "Strong invoice-fraud pattern: new bank details plus pressure to pay quickly.", "high")
    if (flags["secrecy"] or confidential) and flags["money_request"]:
        add("secret_payment_pattern", "Strong fraud pattern: a money request combined with secrecy or 'don't call me'.", "high")
    if flags["gift_cards"] and (flags["exec_impersonation"] or flags["secrecy"]):
        add("ceo_fraud_pattern", "Strong 'CEO fraud' pattern: a boss asking for gift cards under pressure.", "high")
    return findings


# Codes that are strong enough to give HIGH RISK on their own.
STRONG_CODES = {
    "fake_donation_pattern", "money_for_details",                    # Experiment 9
    "phishing_link_pattern", "payroll_diversion_pattern", "invoice_fraud_pattern",
    "secret_payment_pattern", "ceo_fraud_pattern", "job_fee", "pay_to_avoid_action",
    "release_fee",                                                     # Experiment 10
}


def all_warning_signs(message):
    """Combine V8 + V9 + V10 rules, removing duplicate codes."""
    v8_findings, urls = warning_signs_v8(message)
    combined, seen = [], set()
    for source, group in (("v8", v8_findings), ("v9", warning_signs_v9(message)),
                          ("v10", warning_signs_v10(message, urls))):
        for finding in group:
            if finding["code"] in seen:
                continue
            seen.add(finding["code"])
            entry = dict(finding)
            entry.setdefault("source", source)
            combined.append(entry)
    return combined, urls


# ==========================================
# PART 3 - COMBINING THE AI AND THE RULES
# ==========================================

HIGH = "HIGH RISK - POSSIBLE SCAM"
REVIEW_STRONG = "NEEDS REVIEW - STRONG WARNING SIGNS"
REVIEW_AI = "NEEDS REVIEW - AI MODEL ONLY"
REVIEW_CONTEXT = "NEEDS REVIEW - CHECK CONTEXT"
NO_PATTERN = "NO KNOWN PATTERN - NOT PROOF OF SAFETY"


def decide(ai, findings):
    """Return (risk, verdict_source, explanation_lines).

    Key principle: the AI model ALONE can raise a message to NEEDS REVIEW,
    but never to HIGH RISK. HIGH RISK needs supporting rule evidence.
    """
    ai_scam = ai["prediction"] == "scam"
    strong = [f for f in findings if f["code"] in STRONG_CODES]
    highs = [f for f in findings if f["severity"] == "high"]
    mediums = [f for f in findings if f["severity"] == "medium"]
    pct = f"{ai['scam_probability'] * 100:.0f}%"

    if strong:
        risk, reason = HIGH, f"A strong fraud pattern was found: {strong[0]['description']}"
    elif len(highs) >= 2:
        risk, reason = HIGH, "Two or more serious warning signs were found."
    elif highs and mediums:
        risk, reason = HIGH, "A serious warning sign was found together with a supporting sign."
    elif ai_scam and highs:
        risk, reason = HIGH, "The AI model and a serious security rule both point to a scam."
    elif ai_scam and len(mediums) >= 2:
        risk, reason = HIGH, "The AI model and several medium warning signs point to a scam."
    elif highs:
        risk, reason = REVIEW_STRONG, "One serious warning sign was found. Verify before acting."
    elif ai_scam and mediums:
        risk, reason = REVIEW_STRONG, "The AI model leans scam and one supporting warning sign was found."
    elif ai_scam:
        risk, reason = REVIEW_AI, ("Only the AI model flagged this message. No security rule found a "
                                   "scam behaviour, so this is NOT treated as high risk.")
    elif findings:
        risk, reason = REVIEW_CONTEXT, "Some minor or context-dependent signs were found."
    else:
        risk, reason = NO_PATTERN, "Neither the AI model nor the security rules found a known scam pattern."

    rule_driven = bool(highs or mediums or (findings and not ai_scam))
    if risk == NO_PATTERN:
        source = "none"
    elif risk == REVIEW_AI:
        source = "ai"
    elif ai_scam and rule_driven:
        source = "ai_and_rules"
    else:
        source = "rules"

    lines = [reason]
    if ai_scam:
        lines.append(f"AI model: leans SCAM ({pct} scam probability, {ai['confidence']} confidence).")
    else:
        lines.append(f"AI model: leans SAFE ({pct} scam probability, {ai['confidence']} confidence).")
    if findings:
        lines.append(f"Security rules: {len(findings)} warning sign(s) found "
                     f"({len(highs)} serious, {len(mediums)} medium).")
    else:
        lines.append("Security rules: no warning signs found.")
    if source == "ai":
        lines.append("Tip: the AI judges word patterns only. Formal letters (HR, legal, finance) "
                     "can look unusual to it. Check the sender and any requests yourself.")
    return risk, source, lines


SOURCE_LABELS = {
    "ai": "AI model only",
    "rules": "Security rules",
    "ai_and_rules": "AI model + security rules",
    "none": "Nothing detected",
}


def scan_message(message):
    """Scan a message. Never claims a message is definitely safe."""
    if not isinstance(message, str) or not message.strip():
        raise ValueError("Please enter a nonempty message.")
    if len(message) > 5000:
        raise ValueError("Please scan messages under 5,000 characters.")

    ai = ai_assessment(message)
    findings, urls = all_warning_signs(message)
    risk, source, lines = decide(ai, findings)

    return {
        "version": VERSION,
        "risk": risk,
        "warnings": findings,
        "urls": urls,
        "ai_prediction": ai["prediction"],
        "ai_scam_probability": ai["scam_probability"],
        "ai_confidence": ai["confidence"],
        "v7_prediction": predict_v7(message),   # original frozen model, for comparison
        "verdict_source": source,
        "verdict_source_label": SOURCE_LABELS[source],
        "explanation": lines,
        "v10_screening_label": ("scam" if risk.startswith("HIGH")
                                else "review" if risk.startswith("NEEDS")
                                else "no_known_pattern"),
    }


# ==========================================
# PART 4 - MODEL INVESTIGATION REPORT
# ==========================================

def _exclusive_words(model, words_to_check):
    rows = []
    for word in words_to_check:
        feature = "W:" + word
        rows.append((word, model.feature_counts["scam"][feature], model.feature_counts["safe"][feature]))
    return rows


def _binary_metrics(pairs):
    """pairs = [(actual, predicted)] with labels scam/safe."""
    tp = sum(a == "scam" and p == "scam" for a, p in pairs)
    tn = sum(a == "safe" and p == "safe" for a, p in pairs)
    fp = sum(a == "safe" and p == "scam" for a, p in pairs)
    fn = sum(a == "scam" and p == "safe" for a, p in pairs)
    return tp, tn, fp, fn


def _print_metrics(name, pairs):
    tp, tn, fp, fn = _binary_metrics(pairs)
    n = len(pairs)
    print(f"  {name:38} correct {tp + tn:3}/{n:<3} | scams caught {tp}/{tp + fn} | "
          f"false alarms {fp}/{fp + tn}")


def model_report():
    from evaluate_scams import tests as dev_tests
    from experiment_v7 import v7_model
    from experiment_v9 import scan_message as scan_v9
    from test_data_v10 import CASES

    print("=" * 72)
    print("SCAMSHIELD AI - EXPERIMENT 10 MODEL INVESTIGATION")
    print("All numbers below are computed now from synthetic or hand-written data.")
    print("They are NOT real-world accuracy figures.")
    print("=" * 72)

    print("\n1) TRAINING-DATA BIAS: how often each word appears per class")
    print("   (word, scam count, safe count). V7 vs V10 training data.")
    check = ["of", "this", "within", "pay", "salary", "payroll", "company", "terminated",
             "payment", "account", "confirm", "employment"]
    v7_rows = _exclusive_words(v7_model, check)
    v10_rows = _exclusive_words(v10_model, check)
    for (word, s7, f7), (_, s10, f10) in zip(v7_rows, v10_rows):
        print(f"   {word:12} V7: scam {s7:4} safe {f7:4}   |   V10: scam {s10:4} safe {f10:4}")

    print("\n2) GENERALISATION TO UNSEEN WORKPLACE TEMPLATES (5-fold, by template)")
    v7_pairs = [(label, "scam" if v7_model.predict(m) == "scam" else "safe")
                for _, label, m in _calibration_scores]
    oof_pairs = [(label, "scam" if score > 0 else "safe") for score, label, _ in _calibration_scores]
    _print_metrics("V7 model (no workplace training)", v7_pairs)
    _print_metrics("V10 model (held-out templates)", oof_pairs)

    print("\n3) PROBABILITY CALIBRATION")
    print("   a) Temperature scaling fitted on held-out SYNTHETIC templates:")
    print(f"      T = {SYNTHETIC_TEMPERATURE} (log loss {_LOSS_RAW:.3f} -> {_LOSS_TEMPERATURE:.3f})")
    print("      T below 1 means 'be MORE confident' - the synthetic data is too easy")
    print("      to calibrate on, so V10 does NOT use this.")
    print(f"   b) Length-normalised calibration fitted on the 60 dev messages: A = {CALIBRATION_A:.2f}")
    held = [(m, "scam" if e in ("HIGH", "FLAGGED") else "safe") for _, _, m, e in CASES]
    for name, fn in (("raw Naive Bayes", lambda m: sigmoid(v10_model.log_odds(m))),
                     ("length-normalised (used)", lambda m: calibrated_probability(m)[0])):
        dev_loss = _log_loss([(fn(m), a) for m, a in dev_tests])
        held_loss = _log_loss([(fn(m), a) for m, a in held])
        print(f"      {name:26} log loss: dev {dev_loss:.3f} | held-out {held_loss:.3f} (lower is better)")
    print("      Note: the method was chosen after also looking at held-out log loss,")
    print("      so that held-out number is slightly optimistic.")
    print("   Reliability on held-out set (calibrated probability vs reality):")
    print("   predicted scam prob   messages   actually should-flag")
    bins, hits = Counter(), Counter()
    for m, label in held:
        b = min(int(calibrated_probability(m)[0] * 5), 4)
        bins[b] += 1
        hits[b] += label == "scam"
    for b in range(5):
        if bins[b]:
            print(f"   {b * 20:3}% - {b * 20 + 20:3}%          {bins[b]:5}      {hits[b] / bins[b] * 100:5.1f}%")

    print("\n4) HELD-OUT EVALUATION SET (test_data_v10.py, never used for training)")
    labelled = [(m, "scam" if e in ("HIGH", "FLAGGED") else "safe") for _, _, m, e in CASES]
    _print_metrics("V7 AI model alone", [(a, predict_v7(m)) for m, a in labelled])
    _print_metrics("V10 AI model alone", [(a, ai_assessment(m)["prediction"]) for m, a in labelled])
    v9_high = [(a, "scam" if scan_v9(m)["risk"].startswith("HIGH") else "safe") for m, a in labelled]
    v10_high = [(a, "scam" if scan_message(m)["risk"].startswith("HIGH") else "safe") for m, a in labelled]
    v9_flag = [(a, "safe" if scan_v9(m)["risk"].startswith("NO KNOWN") else "scam") for m, a in labelled]
    v10_flag = [(a, "safe" if scan_message(m)["risk"].startswith("NO KNOWN") else "scam") for m, a in labelled]
    _print_metrics("V9 full system (HIGH RISK only)", v9_high)
    _print_metrics("V10 full system (HIGH RISK only)", v10_high)
    _print_metrics("V9 full system (HIGH or REVIEW)", v9_flag)
    _print_metrics("V10 full system (HIGH or REVIEW)", v10_flag)

    print("\n5) REUSED 60-MESSAGE DEVELOPMENT SET (seen many times - NOT independent)")
    _print_metrics("V7 AI model alone", [(a, predict_v7(m)) for m, a in dev_tests])
    _print_metrics("V10 AI model alone", [(a, ai_assessment(m)["prediction"]) for m, a in dev_tests])
    _print_metrics("V9 full system (HIGH or REVIEW)",
                   [(a, "safe" if scan_v9(m)["risk"].startswith("NO KNOWN") else "scam") for m, a in dev_tests])
    _print_metrics("V10 full system (HIGH or REVIEW)",
                   [(a, "safe" if scan_message(m)["risk"].startswith("NO KNOWN") else "scam") for m, a in dev_tests])
    print("\nReminder: synthetic and self-written tests cannot prove real-world accuracy.")


# ==========================================
# PART 5 - COMMAND LINE
# ==========================================

def self_test():
    checks = [
        ("Notice of termination of employment. Your employment with the company is terminated with "
         "immediate effect. Your final payment will be transferred to your bank account.", False),
        ("Your salary is on hold. Update your banking details at http://payroll-fix.example.com today.", True),
        ("Hi, it's your CEO. Buy five gift cards now and keep this between us.", True),
        ("The budget meeting moved to Thursday at 10:00 in the boardroom.", False),
    ]
    for message, should_be_high in checks:
        report = scan_message(message)
        is_high = report["risk"].startswith("HIGH")
        assert is_high == should_be_high, (message, report["risk"])
        print(f"OK  [{report['risk']}] via {report['verdict_source_label']}: {message[:55]}...")
    print("All self-test checks passed. (Functional checks only, not accuracy.)")


def main():
    parser = argparse.ArgumentParser(description="ScamShield AI Experiment 10")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--model-report", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if args.model_report:
        model_report()
        return
    print(f"\nSCAMSHIELD AI - {VERSION.upper()}  (type exit to quit)")
    while True:
        try:
            message = input("\nMessage: ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if message.lower() == "exit":
            break
        if not message:
            continue
        report = scan_message(message)
        print("Final assessment:", report["risk"])
        print("Verdict source:  ", report["verdict_source_label"])
        for line in report["explanation"]:
            print(" *", line)
        for finding in report["warnings"]:
            print(f"   - [{finding['severity']}] {finding['description']}")


if __name__ == "__main__":
    main()
