"""ScamShield AI - Experiment 10 automated test suite.

Uses only Python's built-in unittest (no extra dependencies).

Run all tests:
    python -m unittest test_experiment_v10 -v

The OCR and Streamlit app tests are skipped automatically if Tesseract or
Streamlit are not installed on the computer running the tests.
"""

import contextlib
import importlib
import importlib.util
import io
import os
import re
import shutil
import unittest

with contextlib.redirect_stdout(io.StringIO()):  # hide "model loaded" prints
    import experiment_v10 as v10
    from evaluate_scams import tests as dev_tests
    from experiment_v7 import synthetic_examples, v7_model
    from experiment_v10_data import (LEGIT_WORKPLACE_TEMPLATES, SCAM_WORKPLACE_TEMPLATES,
                                     generate_workplace_examples, workplace_examples)
    from test_data_v10 import CASES


def is_high(report):
    return report["risk"].startswith("HIGH")


def is_flagged(report):
    return report["risk"].startswith(("HIGH", "NEEDS"))


def words(text):
    return set(re.findall(r"[a-z]+", text.lower()))


def fake_ai(prediction, probability=None):
    probability = probability if probability is not None else (0.99 if prediction == "scam" else 0.01)
    return {"prediction": prediction, "scam_probability": probability, "confidence": "high", "log_odds": 0}


def finding(code, severity):
    return {"code": code, "description": code, "severity": severity}


# ==========================================================
# 1. The original bug: AI-only SCAM with zero warning signs
# ==========================================================

class TestRootCauseFix(unittest.TestCase):

    def test_ai_only_scam_is_needs_review_not_high(self):
        risk, source, lines = v10.decide(fake_ai("scam"), [])
        self.assertEqual(risk, v10.REVIEW_AI)
        self.assertEqual(source, "ai")
        self.assertTrue(any("Only the AI model" in line for line in lines))

    def test_ai_only_scam_with_minor_sign_is_still_not_high(self):
        risk, source, _ = v10.decide(fake_ai("scam"), [finding("account_threat", "low")])
        self.assertEqual(risk, v10.REVIEW_AI)
        self.assertEqual(source, "ai")

    def test_v9_had_the_bug(self):
        """Documents the original behaviour so the improvement is visible."""
        with contextlib.redirect_stdout(io.StringIO()):
            from experiment_v9 import scan_message as scan_v9
        letter = ("Notice of termination of employment. Your employment with the company is "
                  "terminated with immediate effect. Your final payment will be transferred to "
                  "your bank account. Please return your access card and laptop.")
        self.assertTrue(scan_v9(letter)["risk"].startswith("HIGH"))
        self.assertFalse(is_high(v10.scan_message(letter)))


# ==========================================================
# 2. Decision logic: every path, and who is responsible
# ==========================================================

class TestDecisionLogic(unittest.TestCase):

    def test_nothing_found(self):
        risk, source, _ = v10.decide(fake_ai("safe"), [])
        self.assertEqual((risk, source), (v10.NO_PATTERN, "none"))

    def test_strong_pattern_alone_is_high_even_if_ai_says_safe(self):
        risk, source, _ = v10.decide(fake_ai("safe"), [finding("ceo_fraud_pattern", "high")])
        self.assertEqual((risk, source), (v10.HIGH, "rules"))

    def test_ai_plus_serious_rule_is_high_from_both(self):
        risk, source, _ = v10.decide(fake_ai("scam"), [finding("credential_request", "high")])
        self.assertEqual((risk, source), (v10.HIGH, "ai_and_rules"))

    def test_two_serious_rules_are_high(self):
        risk, _, _ = v10.decide(fake_ai("safe"), [finding("a", "high"), finding("b", "high")])
        self.assertEqual(risk, v10.HIGH)

    def test_serious_plus_medium_rule_is_high(self):
        risk, _, _ = v10.decide(fake_ai("safe"), [finding("a", "high"), finding("b", "medium")])
        self.assertEqual(risk, v10.HIGH)

    def test_one_serious_rule_is_strong_review(self):
        risk, source, _ = v10.decide(fake_ai("safe"), [finding("bank_detail_change", "high")])
        self.assertEqual((risk, source), (v10.REVIEW_STRONG, "rules"))

    def test_ai_plus_one_medium_is_strong_review(self):
        risk, source, _ = v10.decide(fake_ai("scam"), [finding("shortener", "medium")])
        self.assertEqual((risk, source), (v10.REVIEW_STRONG, "ai_and_rules"))

    def test_minor_rules_only(self):
        risk, source, _ = v10.decide(fake_ai("safe"), [finding("urgency", "low")])
        self.assertEqual((risk, source), (v10.REVIEW_CONTEXT, "rules"))

    def test_explanation_always_mentions_ai_and_rules(self):
        for ai in (fake_ai("scam"), fake_ai("safe")):
            for findings in ([], [finding("x", "high")]):
                _, _, lines = v10.decide(ai, findings)
                text = " ".join(lines)
                self.assertIn("AI model", text)
                self.assertIn("Security rules", text)


# ==========================================================
# 3. Held-out evaluation set (legitimate + scams + edge cases)
# ==========================================================

class TestHeldOutCases(unittest.TestCase):

    def test_every_case(self):
        for category, name, message, expected in CASES:
            with self.subTest(category=category, name=name):
                report = v10.scan_message(message)
                if expected == "HIGH":
                    self.assertTrue(is_high(report), report["risk"])
                elif expected == "FLAGGED":
                    self.assertTrue(is_flagged(report), report["risk"])
                elif expected == "NOT_HIGH":
                    self.assertFalse(is_high(report), (report["risk"], report["warnings"]))
                else:
                    self.fail(f"Unknown expectation {expected}")

    def test_dataset_is_balanced_and_covers_required_topics(self):
        categories = {c for c, _, _, _ in CASES}
        self.assertTrue({"legit_workplace", "scam_workplace", "legit_general",
                         "scam_general", "edge"} <= categories)
        text = " ".join(m.lower() for c, _, m, _ in CASES if c == "legit_workplace")
        for topic in ("disciplinary", "dismissal", "meeting", "invoice", "payroll", "hr",
                      "operations manager"):
            self.assertIn(topic, text)
        legit = sum(e == "NOT_HIGH" for *_, e in CASES)
        scams = sum(e != "NOT_HIGH" for *_, e in CASES)
        self.assertGreaterEqual(legit, 15)
        self.assertGreaterEqual(scams, 15)

    def test_workplace_emails_are_not_automatically_safe(self):
        """Workplace scams must still be flagged; work vocabulary is no free pass."""
        for category, name, message, _ in CASES:
            if category == "scam_workplace":
                with self.subTest(name=name):
                    self.assertTrue(is_flagged(v10.scan_message(message)))


# ==========================================================
# 4. Rule details and difficult edge cases
# ==========================================================

class TestRules(unittest.TestCase):

    def codes(self, message):
        return {w["code"] for w in v10.scan_message(message)["warnings"]}

    def test_negated_credential_request_is_ignored(self):
        codes = self.codes("Do not enter your password at https://login-check.example.net.")
        self.assertNotIn("credential_link", codes)

    def test_safety_advice_cannot_hide_a_real_request(self):
        codes = self.codes("Never share your PIN. Now enter your PIN at https://pay.example.net to get paid.")
        self.assertIn("credential_link", codes)

    def test_hypothetical_bank_change_warning_is_not_flagged(self):
        codes = self.codes("If you receive an email asking you to change banking details, report it to HR.")
        self.assertNotIn("bank_detail_change", codes)

    def test_unchanged_bank_details_not_flagged(self):
        self.assertNotIn("bank_detail_change", self.codes("Our banking details are unchanged."))

    def test_lookalike_and_official_domains(self):
        self.assertIn("lookalike_domain", self.codes("See https://micros0ft-support.example.net"))
        self.assertNotIn("lookalike_domain", self.codes("Join on https://teams.microsoft.com/meet/123"))

    def test_gift_card_ceo_fraud(self):
        codes = self.codes("This is your boss, I'm in a meeting. Buy three iTunes gift cards urgently.")
        self.assertIn("gift_card_request", codes)
        self.assertIn("ceo_fraud_pattern", codes)

    def test_job_fee(self):
        self.assertIn("job_fee", self.codes("You got the job! Pay the R500 uniform fee before you start."))
        self.assertNotIn("job_fee", self.codes("Your job interview is on Monday at 10:00."))

    def test_previous_v8_signals_still_work(self):
        examples = [
            ("Standard Bank: Your Account will be blocked in 2hrs due to a failed FICA update. "
             "TAP-> https://stdbankkyc.z13.web.core.windows.net/ & update", {"deadline_threat", "shared_host"}),
            ("Guaranteed cryptocurrency profits if you invest R500 today.", {"guaranteed_profit"}),
            ("I am your aunt using a new number. Transfer R850 to me now.", {"impersonation"}),
        ]
        for message, expected in examples:
            with self.subTest(message=message[:40]):
                self.assertTrue(expected <= self.codes(message))

    def test_previous_v9_expectations_still_hold(self):
        cases = [
            ("I am a billionaire philanthropist. You were randomly selected to receive €800,000 "
             "as a gift. Reply with your full address.", "HIGH"),
            ("Our school is collecting donations for charity on Friday. Bring R20 to your class "
             "teacher.", "NOT_HIGH"),
            ("Your bank account will be suspended within 30 minutes. Verify your identity at "
             "https://secure-bank-verification.example.com", "HIGH"),
            ("You have been selected to receive $2 million as an inheritance gift. Provide your "
             "bank details to claim it.", "HIGH"),
            ("Urgent! Send your OTP immediately to prevent your account being blocked.", "FLAGGED"),
            ("Never share your OTP or PIN with anyone, including bank staff.", "NOT_HIGH"),
            ("Swimming practice starts tomorrow at 16:00. Bring your goggles.", "NOT_HIGH"),
        ]
        for message, expected in cases:
            with self.subTest(message=message[:40]):
                report = v10.scan_message(message)
                if expected == "HIGH":
                    self.assertTrue(is_high(report))
                elif expected == "FLAGGED":
                    self.assertTrue(is_flagged(report))
                else:
                    self.assertFalse(is_high(report))

    def test_no_scam_on_dev_set_is_missed_compared_with_v9(self):
        """Detection must not get weaker on the reused development set."""
        with contextlib.redirect_stdout(io.StringIO()):
            from experiment_v9 import scan_message as scan_v9
        for message, actual in dev_tests:
            if actual == "scam" and is_flagged(scan_v9(message)):
                with self.subTest(message=message):
                    self.assertTrue(is_flagged(v10.scan_message(message)))


# ==========================================================
# 5. The AI model, training data and calibration
# ==========================================================

class TestModelAndData(unittest.TestCase):

    def test_workplace_training_data_is_balanced_and_unique(self):
        self.assertEqual(len(workplace_examples), 600)
        labels = [label for _, label in workplace_examples]
        self.assertEqual(labels.count("scam"), 300)
        self.assertEqual(labels.count("safe"), 300)
        self.assertEqual(len({m.lower() for m, _ in workplace_examples}), 600)
        self.assertEqual(len(LEGIT_WORKPLACE_TEMPLATES), len(SCAM_WORKPLACE_TEMPLATES))

    def test_training_data_is_deterministic(self):
        self.assertEqual(generate_workplace_examples(), workplace_examples)

    def test_no_training_example_is_used_for_evaluation(self):
        training = {" ".join(m.lower().split()) for m, _ in v10.v10_training}
        for _, name, message, _ in CASES:
            with self.subTest(name=name):
                self.assertNotIn(" ".join(message.lower().split()), training)
        for message, _ in dev_tests:
            self.assertNotIn(" ".join(message.lower().split()), training)

    def test_no_near_duplicates_between_training_and_held_out_set(self):
        training_sets = [words(m) for m, _ in v10.v10_training]
        for _, name, message, _ in CASES:
            case_words = words(message)
            best = max(len(case_words & t) / len(case_words | t) for t in training_sets)
            with self.subTest(name=name):
                self.assertLess(best, 0.6, "Held-out message is too similar to a training example")

    def test_bias_of_function_words_is_reduced(self):
        """In V7, 'of' appeared only in scam examples. V10 must be more balanced."""
        def ratio(model, word):
            scam = model.feature_counts["scam"]["W:" + word] + 1
            safe = model.feature_counts["safe"]["W:" + word] + 1
            return max(scam, safe) / min(scam, safe)
        for word in ("of", "salary", "terminated", "confirm"):
            with self.subTest(word=word):
                self.assertLess(ratio(v10.v10_model, word), ratio(v7_model, word))

    def test_calibrated_probability_is_valid_and_agrees_with_label(self):
        for message, _ in dev_tests[:20]:
            ai = v10.ai_assessment(message)
            self.assertGreaterEqual(ai["scam_probability"], 0)
            self.assertLessEqual(ai["scam_probability"], 1)
            self.assertEqual(ai["prediction"] == "scam", ai["log_odds"] > 0)
            self.assertIn(ai["confidence"], {"low", "medium", "high"})

    def test_calibration_parameter_is_reasonable(self):
        self.assertGreater(v10.CALIBRATION_A, 0)

    def test_v7_synthetic_data_untouched(self):
        self.assertEqual(len(synthetic_examples), 600)


# ==========================================================
# 6. Privacy and safety of the test data
# ==========================================================

class TestPrivacy(unittest.TestCase):

    def test_no_email_addresses_in_test_data(self):
        for _, name, message, _ in CASES:
            with self.subTest(name=name):
                self.assertIsNone(re.search(r"[\w.+-]+@[\w-]+\.[\w.]+", message))

    def test_links_use_fictional_or_well_known_domains(self):
        allowed_suffix = (".example", ".example.com", ".example.net", ".example.org",
                          "example.com", "example.net", "example.org", "bit.ly", "tinyurl.com",
                          "teams.microsoft.com")
        for _, name, message, _ in CASES:
            for url in v10.scan_message(message)["urls"]:
                host = v10.hostname_for(url)
                with self.subTest(name=name, host=host):
                    self.assertTrue(host.endswith(allowed_suffix) or ".example-" in host
                                    or host.split(".")[-2].startswith("example"), host)


# ==========================================================
# 7. Report format (keeps the Streamlit app compatible)
# ==========================================================

class TestReportFormat(unittest.TestCase):

    def test_report_has_all_keys(self):
        report = v10.scan_message("Your parcel is waiting at reception.")
        for key in ("risk", "warnings", "urls", "v7_prediction", "ai_prediction",
                    "ai_scam_probability", "ai_confidence", "verdict_source",
                    "verdict_source_label", "explanation", "v10_screening_label"):
            self.assertIn(key, report)
        self.assertIn(report["verdict_source"], v10.SOURCE_LABELS)

    def test_rejects_empty_and_huge_messages(self):
        with self.assertRaises(ValueError):
            v10.scan_message("   ")
        with self.assertRaises(ValueError):
            v10.scan_message("a" * 5001)

    def test_never_says_definitely_safe(self):
        report = v10.scan_message("See you at dinner.")
        self.assertIn("NOT PROOF OF SAFETY", report["risk"])


# ==========================================================
# 8. Screenshot (OCR) pipeline and Streamlit app
# ==========================================================

# Same Windows location that mobile_app.py uses.
WINDOWS_TESSERACT = r"C:\Program Files\Tesseract-OCR\tesseract.exe"


def _tesseract_path():
    if os.path.isfile(WINDOWS_TESSERACT):
        return WINDOWS_TESSERACT
    return shutil.which("tesseract")


@unittest.skipUnless(_tesseract_path(), "Tesseract OCR is not installed")
class TestScreenshotPipeline(unittest.TestCase):

    def test_ocr_text_is_scanned(self):
        from ocr_engine import read_text
        from PIL import Image, ImageDraw, ImageFont
        lines = ["Your Outlook password expires today.",
                 "Keep the same password at",
                 "https://outlook-keep.example.net"]
        image = Image.new("RGB", (900, 200), "white")
        draw = ImageDraw.Draw(image)
        try:
            font = ImageFont.load_default(size=32)
        except TypeError:  # older Pillow
            font = ImageFont.load_default()
        for i, line in enumerate(lines):
            draw.text((20, 20 + i * 55), line, fill="black", font=font)
        text = read_text(image, timeout=20)
        self.assertIn("password", text.lower())
        self.assertTrue(is_flagged(v10.scan_message(text)))


BLOCKED_PANDAS_SCRIPT = r"""
import sys, importlib.abc

class BlockPandas(importlib.abc.MetaPathFinder):
    # Pretend Windows Smart App Control blocks pandas, like on a real laptop.
    def find_spec(self, name, path=None, target=None):
        if name == "pandas" or name.startswith("pandas."):
            raise ImportError("DLL load failed while importing reshape: "
                              "An Application Control policy has blocked this file.")
        return None

sys.meta_path.insert(0, BlockPandas())
MODE = sys.argv[1]

if MODE == "app":
    from streamlit.testing.v1 import AppTest
    app = AppTest.from_file("mobile_app.py", default_timeout=60)
    app.secrets["scamshield_test"] = "no sign-in"  # never read the real secrets.toml
    app.run()
    print("APP_ERRORS", len(app.exception))
else:
    from PIL import Image, ImageDraw, ImageFont
    from ocr_engine import read_text
    image = Image.new("RGB", (700, 90), "white")
    try:
        font = ImageFont.load_default(size=32)
    except TypeError:
        font = ImageFont.load_default()
    ImageDraw.Draw(image).text((20, 20), "Verify your password", fill="black", font=font)
    print("OCR_TEXT", read_text(image).strip().lower())
"""


class TestBlockedPandas(unittest.TestCase):
    """Windows can BLOCK the optional pandas library. ScamShield must still work."""

    def run_script(self, mode):
        import subprocess
        import sys
        result = subprocess.run([sys.executable, "-c", BLOCKED_PANDAS_SCRIPT, mode],
                                capture_output=True, text=True, timeout=180,
                                cwd=os.path.dirname(os.path.abspath(__file__)))
        return result.stdout + result.stderr

    @unittest.skipUnless(importlib.util.find_spec("streamlit"), "Streamlit is not installed")
    def test_app_opens_when_pandas_is_blocked(self):
        output = self.run_script("app")
        self.assertIn("APP_ERRORS 0", output, output[-1500:])

    @unittest.skipUnless(_tesseract_path(), "Tesseract OCR is not installed")
    def test_ocr_works_when_pandas_is_blocked(self):
        output = self.run_script("ocr")
        self.assertIn("password", output, output[-1500:])


def _streamlit_available():
    try:
        importlib.import_module("streamlit.testing.v1")
        return True
    except Exception:
        return False


@unittest.skipUnless(_streamlit_available(), "Streamlit is not installed")
class TestStreamlitApp(unittest.TestCase):

    def run_app(self):
        from streamlit.testing.v1 import AppTest
        app = AppTest.from_file("mobile_app.py", default_timeout=60)
        # A non-empty secrets dict REPLACES .streamlit/secrets.toml, so these
        # tests never read your real Clerk keys and never require sign-in.
        app.secrets["scamshield_test"] = "no sign-in"
        app.run()
        self.assertFalse(app.exception)
        return app

    def test_app_loads(self):
        app = self.run_app()
        self.assertTrue(any("Experiment 10" in c.value for c in app.caption))

    def test_text_scan_shows_verdict_source(self):
        app = self.run_app()
        app.text_area[0].input(
            "Notice of termination of employment. Your employment with the company is "
            "terminated with immediate effect. Your final payment will be transferred to your "
            "bank account.")
        app.button[0].click().run()
        self.assertFalse(app.exception)
        page = " ".join(str(e.value) for e in list(app.markdown) + list(app.warning)
                        + list(app.error) + list(app.info) + list(app.caption))
        self.assertIn("Verdict source", page)
        self.assertNotIn("HIGH RISK — POSSIBLE SCAM", page)

    def test_history_is_off_by_default(self):
        app = self.run_app()
        self.assertFalse(app.session_state["keep_history"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
