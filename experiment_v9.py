"""""
SCAMSHIELD AI - EXPERIMENT 9

Extends Experiment 8 with additional
fraud-detection rules.

The original V7 AI model remains unchanged.
"""

import re
from experiment_v8 import scan_message as scan_v8


# ==========================================
# EXPERIMENT 9 WARNING DETECTION
# ==========================================

def warning_signs_v9(message):

    text = message.lower()
    findings = []

    def add(code, description, severity):
        findings.append({
            "code": code,
            "description": description,
            "severity": severity
        })

    # Detect money amounts
    money = bool(re.search(
        r"(?:€|£|\$|r\s*)\s*[\d,.]+"
        r"\s*(?:million|thousand)?"
        r"|\b\d[\d,.]*\s*"
        r"(?:euros?|dollars?|pounds?|rand)\b",
        text
    ))

    # Detect gifts, donations, and prizes
    gift = bool(re.search(
        r"\b(?:donat(?:e|ion)|give|giving|gift|"
        r"beneficiary|inheritance|philanthropist|"
        r"financial assistance|cash prize)\b",
        text
    ))

    # Detect random selection claims
    random_selection = bool(re.search(
        r"\b(?:randomly selected|selected at random|"
        r"chosen at random|lucky individual|"
        r"your email address was chosen|"
        r"you have been selected|"
        r"you were selected)\b",
        text
    ))

    # Detect requests for private details
    personal_details = bool(re.search(
        r"\b(?:send|share|provide|reply with|"
        r"get back to me with|forward|submit|give)"
        r"\b.{0,100}\b(?:full address|home address|"
        r"residential address|bank details|"
        r"bank account|identity number|id number|"
        r"passport number)\b",
        text,
        re.DOTALL
    ))

    # Detect unverified identity claims
    identity_claim = bool(re.search(
        r"\b(?:i am|my name is|i'm)\b.{0,100}"
        r"\b(?:ceo|chairman|billionaire|"
        r"philanthropist|foundation|director)\b",
        text,
        re.DOTALL
    ))

    # ======================================
    # INDIVIDUAL WARNING SIGNS
    # ======================================

    if money and gift:
        add(
            "unsolicited_money",
            "Offers money as a gift, donation, "
            "or inheritance. Verify independently.",
            "medium"
        )

    if random_selection:
        add(
            "random_selection",
            "Claims the recipient was randomly "
            "selected or specially chosen.",
            "medium"
        )

    if personal_details:
        add(
            "personal_information",
            "Requests personal or banking "
            "information.",
            "high"
        )

    if identity_claim:
        add(
            "identity_claim",
            "Claims an important identity or "
            "position. The identity has not "
            "been verified.",
            "medium"
        )

    # ======================================
    # STRONG COMBINED SCAM PATTERNS
    # ======================================

    if money and gift and random_selection:
        add(
            "fake_donation_pattern",
            "Strong fake-donation pattern: "
            "a money offer is combined with "
            "random selection.",
            "high"
        )

    if money and gift and personal_details:
        add(
            "money_for_details",
            "A money offer is combined with "
            "a request for personal details.",
            "high"
        )

    return findings


# ==========================================
# EXPERIMENT 9 SCANNER
# ==========================================

def scan_message(message):

    # Run the original V8 engine first
    report = scan_v8(message)

    # Find additional Experiment 9 warnings
    new_findings = warning_signs_v9(message)

    # Avoid duplicate warning codes
    existing_codes = {
        warning.get("code")
        for warning in report["warnings"]
    }

    for finding in new_findings:

        if finding["code"] not in existing_codes:

            report["warnings"].append(finding)
            existing_codes.add(finding["code"])

    # Serious combinations can override
    # a SAFE original AI prediction.
    strong_patterns = {
        "fake_donation_pattern",
        "money_for_details"
    }

    strong_pattern_detected = any(
        finding["code"] in strong_patterns
        for finding in new_findings
    )

    if strong_pattern_detected:

        report["risk"] = (
            "HIGH RISK - POSSIBLE SCAM"
        )

    elif any(
        finding["severity"] == "high"
        for finding in new_findings
    ):

        if not report["risk"].startswith("HIGH"):

            report["risk"] = (
                "NEEDS REVIEW - "
                "STRONG WARNING SIGNS"
            )

    elif new_findings:

        if report["risk"].startswith(
            "NO KNOWN PATTERN"
        ):

            report["risk"] = (
                "NEEDS REVIEW - CHECK CONTEXT"
            )

    # Keep original AI prediction untouched
    report["v9_screening_label"] = (
        "scam"
        if report["risk"].startswith("HIGH")
        else "review"
        if report["risk"].startswith("NEEDS")
        else "no_known_pattern"
    )

    return report


# ==========================================
# DIRECT TEST
# ==========================================

if __name__ == "__main__":

    example = """
    My name is Carlos Slim Helu.
    I am a philanthropist and CEO.

    You have been randomly selected
    to receive a donation of €800,000.

    Please reply with your full address.
    """

    result = scan_message(example)

    print("\nSCAMSHIELD AI - EXPERIMENT 9")
    print("=" * 45)

    print(
        "Original AI prediction:",
        result["v7_prediction"].upper()
    )

    print(
        "Final risk assessment:",
        result["risk"]
    )

    print("\nWarning signs:")

    for warning in result["warnings"]:
        print("-", warning["description"])

    assert result["risk"].startswith("HIGH")

    print("\nExample test passed!")
