"""Tests for PDF / document checks and reports (document_check.py).

Run:  python -m unittest test_document_check -v
All documents are SYNTHETIC (test_documents_helpers.py).
"""

import contextlib
import importlib.util
import io
import os
import shutil
import unittest
from datetime import datetime, timezone
from unittest import mock

with contextlib.redirect_stdout(io.StringIO()):
    from experiment_v11 import scan_message

import document_check as dc
from ocr_engine import OCRError
from test_documents_helpers import (HARMLESS, PHISHING, make_docx, make_encrypted_pdf,
                                    make_scanned_pdf, make_text_pdf)

HAS_DOCUMENT_LIBS = all(importlib.util.find_spec(m) for m in ("pypdf", "docx", "pypdfium2"))
HAS_TESSERACT = bool(shutil.which("tesseract")) or os.path.isfile(r"C:\Program Files\Tesseract-OCR\tesseract.exe")


def check(name, data):
    return dc.check_document(name, data, scan_message)


@unittest.skipUnless(HAS_DOCUMENT_LIBS, "pip install -r requirements.txt (pypdf, python-docx, pypdfium2)")
class TestReadingDocuments(unittest.TestCase):

    def test_pdf_warning_signs_point_to_the_right_page(self):
        result = check("letter.pdf", make_text_pdf([HARMLESS, PHISHING]))
        self.assertEqual(result["level"], "high")
        self.assertEqual(result["document"]["pages_checked"], 2)
        codes = {w["code"]: w["locations"] for w in result["warnings"]}
        self.assertEqual(codes["credential_link"], ["page 2"])
        self.assertEqual(result["flagged_sections"][0]["location"], "page 2")
        self.assertIn("micros0ft-hr", result["flagged_sections"][0]["excerpt"])
        self.assertIn("https://micros0ft-hr.example-login.net", result["urls"])

    def test_same_verdict_as_the_message_scanner(self):
        result = check("one.pdf", make_text_pdf([PHISHING]))
        self.assertEqual(result["risk"], scan_message(PHISHING)["risk"])

    def test_harmless_pdf_is_not_high(self):
        result = check("lunch.pdf", make_text_pdf([HARMLESS]))
        self.assertNotEqual(result["level"], "high")

    def test_word_document_with_table(self):
        result = check("offer.docx", make_docx([HARMLESS, PHISHING], [("Item", "Fee")]))
        self.assertEqual(result["level"], "high")
        self.assertEqual(result["document"]["file_type"], "Word document")
        self.assertTrue(result["warnings"][0]["locations"][0].startswith("paragraph"))

    def test_text_file_line_references(self):
        result = check("note.txt", (HARMLESS + "\n\n" + PHISHING).encode("utf-8"))
        self.assertEqual(result["level"], "high")
        self.assertIn("line", result["warnings"][0]["locations"][0])

    def test_long_document_is_split_into_sections(self):
        lines = [HARMLESS] * 150 + [PHISHING]
        result = check("long.txt", "\n".join(lines).encode())
        self.assertGreater(result["document"]["sections_checked"], 1)
        self.assertEqual(result["level"], "high")

    def test_page_and_length_limits_are_reported(self):
        with mock.patch.dict(os.environ, {"SCAMSHIELD_MAX_DOCUMENT_PAGES": "1"}):
            result = check("two.pdf", make_text_pdf([HARMLESS, PHISHING]))
        self.assertEqual(result["document"]["pages_checked"], 1)
        self.assertTrue(any("not checked" in n for n in dc.coverage_notes(result["document"])))
        with mock.patch.dict(os.environ, {"SCAMSHIELD_MAX_DOCUMENT_CHARS": "100"}):
            result = check("long.txt", ("word " * 500).encode())
        self.assertTrue(result["document"]["truncated"])

    @unittest.skipUnless(HAS_TESSERACT, "Tesseract OCR is not installed")
    def test_scanned_pdf_is_read_with_ocr(self):
        pdf = make_scanned_pdf(["Your Outlook password expires today.",
                                "Keep the same password at", "https://outlook-keep.example.net"])
        result = check("scan.pdf", pdf)
        self.assertEqual(result["document"]["ocr_pages"], 1)
        self.assertIn(result["level"], {"high", "review"})


@unittest.skipUnless(HAS_DOCUMENT_LIBS, "pip install -r requirements.txt (pypdf, python-docx, pypdfium2)")
class TestProblemFiles(unittest.TestCase):

    def assertKind(self, kind, name, data):
        with self.assertRaises(dc.DocumentError) as caught:
            check(name, data)
        self.assertEqual(caught.exception.kind, kind, str(caught.exception))
        return str(caught.exception)

    def test_unsupported_types(self):
        for name in ("virus.exe", "old.doc", "sheet.xlsx", "photo.png", "no_extension"):
            with self.subTest(name=name):
                self.assertKind("unsupported", name, b"hello")

    def test_renamed_files_are_rejected(self):
        self.assertKind("unsupported", "fake.pdf", b"MZ\x90\x00 this is really a program")
        self.assertKind("unsupported", "fake.docx", b"%PDF-1.4")
        self.assertKind("unsupported", "binary.txt", b"\x00\x01\x02 binary")

    def test_oversized_file(self):
        with mock.patch.dict(os.environ, {"SCAMSHIELD_MAX_DOCUMENT_MB": "1"}):
            message = self.assertKind("too_large", "big.pdf", b"%PDF-" + b"0" * (1024 * 1024))
        self.assertIn("1 MB", message)

    def test_empty_file(self):
        self.assertKind("empty", "empty.pdf", b"")

    def test_damaged_pdf(self):
        self.assertKind("unreadable", "damaged.pdf", b"%PDF-1.4 this is not really a pdf")

    def test_damaged_docx(self):
        self.assertKind("unreadable", "damaged.docx", b"PK\x03\x04 broken zip")

    def test_password_protected_pdf(self):
        self.assertKind("encrypted", "locked.pdf", make_encrypted_pdf([PHISHING]))

    def test_scanned_pdf_without_ocr_gives_clear_message(self):
        pdf = make_scanned_pdf(["Pay the release fee today"])
        unavailable = OCRError("not installed", "unavailable")
        with mock.patch.object(dc, "read_text", side_effect=unavailable):
            message = self.assertKind("ocr_unavailable", "scan.pdf", pdf)
        self.assertIn("scanned", message)
        self.assertIn("Screenshot Scanner", message)

    def test_document_without_text(self):
        with mock.patch.object(dc, "read_text", return_value=""):
            self.assertKind("no_text", "blank.pdf", make_scanned_pdf([]))
        self.assertKind("no_text", "blank.txt", b"   \n\n  ")

    def test_analysis_error(self):
        with self.assertRaises(dc.DocumentError) as caught:
            dc.check_document("x.txt", b"hello there", mock.Mock(side_effect=RuntimeError("boom")))
        self.assertEqual(caught.exception.kind, "analysis")
        self.assertNotIn("boom", str(caught.exception))  # internal details are not shown


@unittest.skipUnless(HAS_DOCUMENT_LIBS, "pip install -r requirements.txt (pypdf, python-docx, pypdfium2)")
class TestReport(unittest.TestCase):

    def setUp(self):
        self.result = check("Job offer.pdf", make_text_pdf(["PRIVATE-MARKER " + HARMLESS, PHISHING]))
        self.when = datetime(2026, 11, 17, 14, 5, tzinfo=timezone.utc)
        self.report = dc.build_report(self.result, self.when)

    def test_report_has_the_required_parts(self):
        for part in ("Job offer.pdf", "2026-11-17 14:05 UTC", "HIGH RISK - POSSIBLE SCAM",
                     "Warning signs (", "found in page 2", "Analysis", "Where to look",
                     "never proves a document is safe"):
            with self.subTest(part=part):
                self.assertIn(part, self.report)

    def test_report_leaves_out_unflagged_text_and_internals(self):
        self.assertNotIn("PRIVATE-MARKER", self.report)  # page 1 had no warning signs
        for internal in ("log_odds", "v10_screening_label", "user_", "@"):
            self.assertNotIn(internal, self.report)

    def test_safe_file_names(self):
        self.assertEqual(dc.safe_file_name("C:\\Users\\kid\\letter.pdf"), "letter.pdf")
        self.assertEqual(dc.safe_file_name("../../etc/passwd.txt"), "passwd.txt")
        self.assertEqual(dc.safe_file_name("bad\x00\nname.pdf"), "badname.pdf")
        self.assertLessEqual(len(dc.safe_file_name("a" * 500 + ".pdf")), 120)
        self.assertEqual(dc.report_file_name('my "offer"; x.pdf'), "ScamShield-report-my_offer_x.txt")


if __name__ == "__main__":
    unittest.main(verbosity=2)
