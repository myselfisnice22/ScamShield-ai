"""Tests for plans, monthly limits, Pro document checks and reports in the API.

Run from the repository root:
    python -m unittest backend.test_plans_api -v

Accounts are simulated by replacing the current_account dependency, so these
tests need no Clerk keys. Uses a temporary usage database.
"""

import os
import tempfile
import unittest
from unittest import mock

from fastapi.testclient import TestClient

import tiers
from backend import api
from test_documents_helpers import HARMLESS, PHISHING, make_text_pdf

client = TestClient(api.app)


class PlanTestCase(unittest.TestCase):

    def setUp(self):
        api._recent_requests.clear()
        api._reports.clear()
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {
            "SCAMSHIELD_USAGE_DB": os.path.join(self.tmp.name, "usage.sqlite3"),
            "SCAMSHIELD_PLUS_MONTHLY_CHECKS": "2",
            "SCAMSHIELD_PRO_MONTHLY_CHECKS": "3",
        })
        self.env.start()

    def tearDown(self):
        api.app.dependency_overrides.clear()
        self.env.stop()
        if tiers._store is not None:
            tiers._store._db.close()
            tiers._store = None
        self.tmp.cleanup()

    def login(self, user_id, plan):
        api.app.dependency_overrides[api.current_account] = lambda: api.Account(user_id, plan)

    def scan(self, message="Meeting moved to 3pm."):
        return client.post("/scan", json={"message": message})

    def upload(self, name="letter.pdf", data=None, content_type="application/pdf"):
        data = make_text_pdf([HARMLESS, PHISHING]) if data is None else data
        return client.post("/scan-document", files={"file": (name, data, content_type)})


class TestMonthlyLimits(PlanTestCase):

    def test_free_has_no_monthly_limit(self):
        self.login("user_free", "free")
        for _ in range(5):
            self.assertEqual(self.scan().status_code, 200)
        self.assertIsNone(client.get("/account").json()["checks_used"])

    def test_plus_limit_is_enforced(self):
        self.login("user_plus", "plus")
        self.assertEqual(self.scan().status_code, 200)
        self.assertEqual(self.scan().status_code, 200)
        response = self.scan()
        self.assertEqual(response.status_code, 429)
        self.assertIn("all 2 checks", response.json()["detail"])
        account = client.get("/account").json()
        self.assertEqual((account["plan"], account["checks_used"], account["checks_left"]), ("plus", 2, 0))

    def test_failed_checks_do_not_count(self):
        self.login("user_plus", "plus")
        self.assertEqual(self.scan("   ").status_code, 400)
        self.assertEqual(client.post("/scan-image", files={"file": ("x.png", b"nope", "image/png")}).status_code, 400)
        self.assertEqual(client.get("/account").json()["checks_used"], 0)

    def test_screenshots_count_towards_the_limit(self):
        self.login("user_plus", "plus")
        with mock.patch.object(api, "read_text", return_value=PHISHING):
            from io import BytesIO
            from PIL import Image
            buffer = BytesIO()
            Image.new("RGB", (40, 40), "white").save(buffer, format="PNG")
            for expected in (200, 200, 429):
                response = client.post("/scan-image", files={"file": ("s.png", buffer.getvalue(), "image/png")})
                self.assertEqual(response.status_code, expected)

    def test_each_account_has_its_own_count(self):
        self.login("user_a", "plus")
        self.scan(), self.scan()
        self.assertEqual(self.scan().status_code, 429)
        self.login("user_b", "plus")
        self.assertEqual(self.scan().status_code, 200)

    def test_documents_count_towards_the_pro_limit(self):
        self.login("user_pro", "pro")
        self.assertEqual(self.upload().status_code, 200)
        self.assertEqual(self.scan().status_code, 200)
        self.assertEqual(self.scan().status_code, 200)
        self.assertEqual(self.upload().status_code, 429)


class TestProGating(PlanTestCase):

    def test_free_and_plus_cannot_scan_documents(self):
        for plan in ("free", "plus"):
            with self.subTest(plan=plan):
                self.login("user_" + plan, plan)
                response = self.upload()
                self.assertEqual(response.status_code, 403)
                self.assertIn("Pro", response.json()["detail"])

    def test_free_and_plus_cannot_download_reports(self):
        self.login("user_pro", "pro")
        report_id = self.upload().json()["report_id"]
        for plan in ("free", "plus"):
            with self.subTest(plan=plan):
                self.login("user_pro", plan)  # e.g. the account was moved off Pro
                self.assertEqual(client.get(f"/reports/{report_id}").status_code, 403)

    def test_account_shows_what_the_plan_includes(self):
        self.login("user_plus", "plus")
        account = client.get("/account").json()
        self.assertFalse(account["documents"])
        self.assertIn("Pro", account["upgrade_message"])
        self.login("user_pro", "pro")
        account = client.get("/account").json()
        self.assertTrue(account["documents"] and account["reports"])
        self.assertEqual(account["monthly_limit"], 3)


class TestProDocuments(PlanTestCase):

    def setUp(self):
        super().setUp()
        self.login("user_pro", "pro")

    def test_document_check_result(self):
        response = self.upload()
        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        self.assertEqual(data["level"], "high")
        self.assertEqual(data["document"]["file_name"], "letter.pdf")
        self.assertIn("page 2", data["warnings"][0]["locations"])
        self.assertEqual(data["flagged_sections"][0]["location"], "page 2")
        self.assertTrue(data["coverage_notes"])
        self.assertNotIn("log_odds", data)

    def test_report_download(self):
        report_id = self.upload().json()["report_id"]
        response = client.get(f"/reports/{report_id}")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.headers["content-type"].startswith("text/plain"))
        self.assertIn('attachment; filename="ScamShield-report-letter.txt"',
                      response.headers["content-disposition"])
        self.assertEqual(response.headers["cache-control"], "no-store")
        text = response.text
        for part in ("letter.pdf", "Scan date:", "HIGH RISK", "Warning signs", "Analysis"):
            self.assertIn(part, text)
        self.assertNotIn("user_pro", text)

    def test_other_users_cannot_download_my_report(self):
        report_id = self.upload().json()["report_id"]
        self.login("user_other", "pro")
        self.assertEqual(client.get(f"/reports/{report_id}").status_code, 404)

    def test_expired_or_unknown_reports(self):
        self.assertEqual(client.get("/reports/does-not-exist").status_code, 404)
        report_id = self.upload().json()["report_id"]
        with mock.patch.object(api, "REPORT_TTL_SECONDS", -1):
            self.assertEqual(client.get(f"/reports/{report_id}").status_code, 404)

    def test_problem_files(self):
        cases = [
            (("virus.exe", b"MZ", "application/octet-stream"), 415),
            (("fake.pdf", b"not a pdf", "application/pdf"), 415),
            (("empty.pdf", b"", "application/pdf"), 400),
            (("damaged.pdf", b"%PDF-1.4 broken", "application/pdf"), 422),
            (("blank.txt", b"   ", "text/plain"), 422),
        ]
        for (name, data, content_type), status in cases:
            with self.subTest(name=name):
                response = self.upload(name, data, content_type)
                self.assertEqual(response.status_code, status, response.text)
                self.assertTrue(response.json()["detail"])
        self.assertEqual(client.get("/account").json()["checks_used"], 0)  # none of these count

    def test_oversized_document(self):
        with mock.patch.dict(os.environ, {"SCAMSHIELD_MAX_DOCUMENT_MB": "1"}):
            response = self.upload("big.pdf", b"%PDF-" + b"0" * (1024 * 1024 + 10))
        self.assertEqual(response.status_code, 413)


if __name__ == "__main__":
    unittest.main(verbosity=2)
