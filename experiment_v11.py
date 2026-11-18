"""SCAMSHIELD AI - EXPERIMENT 11
Fewer false alarms on stories, scripts, school texts and South African languages.

THE PROBLEM
-----------
A school play script of a traditional folktale was checked as a PDF and got
"NEEDS REVIEW - AI MODEL ONLY" (92% scam probability) plus one warning sign.
Two causes were found:

1. RULE TOO LOOSE (Experiment 8's "account_threat" rule).
   It fired on the words blocked / suspended / frozen / terminated /
   deactivated / locked / closed / disconnected ANYWHERE, so "the closed door"
   in a story counted as "your account is being closed". Combined with a
   time phrase ("in 2 hours") it even became a SERIOUS warning.
   FIX: the word must be about an account, card, number, SIM, service... in
   the same sentence (within 40 characters), e.g. "your account will be
   closed" or "blocked card".

2. AI MODEL NEVER SAW THIS KIND OF TEXT.
   It was trained on English SMS, emails and workplace messages. Sesotho or
   isiZulu words, story dialogue and commands ("Come here!") looked unusual.
   FIX: retrain the same Naive Bayes on Experiment 10's data PLUS 300 new
   synthetic examples (experiment_v11_data.py): 150 safe stories / scripts /
   school texts and 150 local scams that use THE SAME greetings and words.

Everything else (Experiment 8-10 rules, the "AI alone can never give HIGH
RISK" decision logic, the report format) is unchanged from Experiment 10,
which stays frozen in experiment_v10.py for comparison.

Usage:
    python experiment_v11.py --self-test
    python experiment_v11.py --model-report
    python -m unittest test_experiment_v11 -v
"""

import argparse
import re

import experiment_v10 as v10
from experiment_v10 import ScoredNaiveBayes, sigmoid
from experiment_v11_data import local_examples
from experiment_v7 import extract_features, predict_v7

VERSION = "Experiment 11"


# ==========================================
# PART 1 - THE AI MODEL (retrained + recalibrated)
# ==========================================

v11_training = list(v10.v10_training) + list(local_examples)
v11_model = ScoredNaiveBayes(v11_training)


def _known_features(message):
    return max(1, sum(f in v11_model.vocabulary for f in extract_features(message)))


def _fit_length_calibration(messages):
    """Same method as Experiment 10: p = sigmoid(A * log_odds / sqrt(known words)),
    with A fitted on the 60 development messages (never used for training)."""
    def loss(a):
        return v10._log_loss([(sigmoid(a * v11_model.log_odds(m) / _known_features(m) ** 0.5), label)
                              for m, label in messages])
    grid = [0.05 * i for i in range(1, 400)]
    return min(grid, key=loss)


from evaluate_scams import tests as _calibration_messages  # noqa: E402  (V2 dev set)
CALIBRATION_A = _fit_length_calibration(_calibration_messages)


def calibrated_probability(message):
    score = v11_model.log_odds(message)
    return sigmoid(CALIBRATION_A * score / _known_features(message) ** 0.5), score


def ai_assessment(message):
    probability, score = calibrated_probability(message)
    distance = abs(probability - 0.5)
    return {
        "prediction": "scam" if score > 0 else "safe",
        "scam_probability": round(probability, 3),
        "confidence": "high" if distance >= 0.35 else "medium" if distance >= 0.15 else "low",
        "log_odds": round(score, 2),
    }


# ==========================================
# PART 2 - RULES (Experiment 10 + stricter account-threat rule)
# ==========================================

THREAT = (r"(?:blocked|suspended|frozen|terminated|deactivated|disabled|locked|closed|"
          r"disconnected|restricted|cut off|cancelled|canceled)")
# Kept specific on purpose: words like "water", "power" or "line" are left out
# because stories use them ("the water was frozen", "the line was closed").
ACCOUNT = (r"(?:accounts?|acc|cards?|sim|sim card|numbers?|services?|subscriptions?|"
           r"mailbox|e-?mail|profile|wallet|access|membership|debit order|electricity|"
           r"internet|airtime|banking|bank|app|login|password|benefits?|grant|sassa|"
           r"office ?365|outlook|whatsapp|facebook|instagram|online banking)")
_ACCOUNT_THREAT = re.compile(
    rf"\b{ACCOUNT}\b[^.!?\n]{{0,40}}\b{THREAT}\b|\b{THREAT}\b[^.!?\n]{{0,40}}\b{ACCOUNT}\b")
# Experiment 8's time-pressure pattern, unchanged.
_URGENCY = re.compile(
    r"\b(?:urgent|immediately|right now|act now|within\s+\d+\s*"
    r"(?:minutes?|mins?|hours?|hrs?)|\bin\s+\d+\s*(?:hours?|hrs?|minutes?|mins?)|"
    r"\d+\s*(?:hrs?|hours?|mins?|minutes?)|today only)\b")
_REPLACED_CODES = {"account_threat", "deadline_threat", "urgency"}


def account_threat(message):
    """True only when an ACCOUNT/SERVICE is threatened, not any closed door."""
    return bool(_ACCOUNT_THREAT.search(" ".join(message.lower().split())))


def _time_rules(message):
    """Experiment 8's urgency / account-threat findings, with the stricter check."""
    text = " ".join(message.lower().split())
    urgent, threat = bool(_URGENCY.search(text)), account_threat(message)
    if urgent and threat:
        return [{"code": "deadline_threat", "severity": "high", "source": "v11",
                 "description": "A short deadline is combined with a threatened account/service interruption."}]
    if urgent:
        return [{"code": "urgency", "severity": "low", "source": "v8",
                 "description": "Uses urgent or time-limited language. Context matters."}]
    if threat:
        return [{"code": "account_threat", "severity": "low", "source": "v11",
                 "description": "Says an account, card, number or service will be blocked, closed or suspended."}]
    return []


def all_warning_signs(message):
    """Experiment 8 + 9 + 10 rules, with Experiment 8's time/threat rule replaced."""
    findings, urls = v10.all_warning_signs(message)
    kept = [f for f in findings if f["code"] not in _REPLACED_CODES]
    return _time_rules(message) + kept, urls


# ==========================================
# PART 3 - SCAN
# ==========================================

AI_ONLY_TIP = ("Tip: the AI judges word patterns only. Formal letters, stories, scripts and messages "
               "in other languages can look unusual to it. Check the sender and any requests yourself.")


def scan_message(message):
    """Scan a message. Never claims a message is definitely safe."""
    if not isinstance(message, str) or not message.strip():
        raise ValueError("Please enter a nonempty message.")
    if len(message) > 5000:
        raise ValueError("Please scan messages under 5,000 characters.")

    ai = ai_assessment(message)
    findings, urls = all_warning_signs(message)
    risk, source, lines = v10.decide(ai, findings)
    lines = [AI_ONLY_TIP if line.startswith("Tip: the AI judges") else line for line in lines]

    return {
        "version": VERSION,
        "risk": risk,
        "warnings": findings,
        "urls": urls,
        "ai_prediction": ai["prediction"],
        "ai_scam_probability": ai["scam_probability"],
        "ai_confidence": ai["confidence"],
        "v7_prediction": predict_v7(message),
        "verdict_source": source,
        "verdict_source_label": v10.SOURCE_LABELS[source],
        "explanation": lines,
        # Same key name as Experiment 10, so the apps and API need no changes.
        "v10_screening_label": ("scam" if risk.startswith("HIGH")
                                else "review" if risk.startswith("NEEDS")
                                else "no_known_pattern"),
    }


# ==========================================
# PART 4 - MODEL REPORT (V10 vs V11)
# ==========================================

def _flagged(report):
    return not report["risk"].startswith("NO KNOWN")


def model_report():
    from test_data_v10 import CASES as V10_CASES
    from test_data_v11 import CASES as V11_CASES

    print("=" * 72)
    print("SCAMSHIELD AI - EXPERIMENT 11 vs EXPERIMENT 10")
    print("All numbers come from synthetic or hand-written messages.")
    print("They are NOT real-world accuracy figures.")
    print("=" * 72)
    print(f"Training examples: V10 {len(v10.v10_training)}  ->  V11 {len(v11_training)}")
    print(f"Calibration A:     V10 {v10.CALIBRATION_A:.2f}  ->  V11 {CALIBRATION_A:.2f}")

    for title, cases in (("NEW held-out set (test_data_v11.py)", V11_CASES),
                         ("Experiment 10 held-out set (test_data_v10.py)", V10_CASES)):
        print(f"\n{title}: {len(cases)} messages")
        for name, scan, ai in (("V10", v10.scan_message, v10.ai_assessment),
                               ("V11", scan_message, ai_assessment)):
            legit = [m for _, _, m, e in cases if e == "NOT_HIGH"]
            scams = [m for _, _, m, e in cases if e != "NOT_HIGH"]
            ai_false = sum(ai(m)["prediction"] == "scam" for m in legit)
            high_false = sum(scan(m)["risk"].startswith("HIGH") for m in legit)
            any_false = sum(_flagged(scan(m)) for m in legit)
            caught = sum(_flagged(scan(m)) for m in scams)
            high_caught = sum(scan(m)["risk"].startswith("HIGH") for m in scams)
            print(f"  {name}: legit messages -> AI says scam {ai_false}/{len(legit)}, any flag "
                  f"{any_false}/{len(legit)}, HIGH {high_false}/{len(legit)} | scams -> flagged "
                  f"{caught}/{len(scams)}, HIGH {high_caught}/{len(scams)}")
    print("\nReminder: synthetic and self-written tests cannot prove real-world accuracy.")


def self_test():
    checks = [
        ("Mother: Come inside quickly, my child! Narrator: She closes the door and the jackal waits "
         "outside in the dark for two hours.", "not high"),
        ("Dumela mme! Your Vodacom number will be blocked in 2 hours. Send the OTP to 072 555 0100 now.",
         "high"),
        ("The school hall is closed on Friday, so drama practice moves to the library.", "not high"),
    ]
    for message, expected in checks:
        report = scan_message(message)
        assert report["risk"].startswith("HIGH") == (expected == "high"), (message, report["risk"])
        print(f"OK  [{report['risk']}] {message[:60]}...")
    print("All self-test checks passed. (Functional checks only, not accuracy.)")


def main():
    parser = argparse.ArgumentParser(description="ScamShield AI Experiment 11")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--model-report", action="store_true")
    args = parser.parse_args()
    if args.model_report:
        model_report()
    else:
        self_test()


if __name__ == "__main__":
    main()
