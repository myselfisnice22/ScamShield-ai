"""Tests for the ScamShield backend API.

Run from the repository root:
    python -m unittest backend.test_api -v
"""

import shutil
import unittest
from io import BytesIO

from fastapi.testclient import TestClient

from backend import api

client = TestClient(api.app)

LEGIT_LETTER = ("Notice of termination of employment. Your employment with the company is "
                "terminated with immediate effect. Your final payment will be transferred to your "
                "bank account. Please return your access card and laptop.")
PHISHING = ("HR Department: your dismissal letter is ready. Sign in with your email and password "
            "at https://micros0ft-hr.example-login.net within 12 hours.")


class TestTextScanning(unittest.TestCase):

    def setUp(self):
        api._recent_requests.clear()

    def test_health(self):
        response = client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")

    def test_scan_phishing_is_high(self):
        data = client.post("/scan", json={"message": PHISHING}).json()
        self.assertEqual(data["level"], "high")
        self.assertTrue(data["risk"].startswith("HIGH"))
        self.assertIn(data["verdict_source"], {"rules", "ai_and_rules"})
        self.assertTrue(data["warnings"])

    def test_scan_legit_letter_is_not_high(self):
        data = client.post("/scan", json={"message": LEGIT_LETTER}).json()
        self.assertNotEqual(data["level"], "high")

    def test_same_result_as_python_scanner(self):
        """The API must not change the scanner's answer."""
        expected = api.scan_message(PHISHING)
        data = client.post("/scan", json={"message": PHISHING}).json()
        self.assertEqual(data["risk"], expected["risk"])
        self.assertEqual([w["code"] for w in data["warnings"]],
                         [w["code"] for w in expected["warnings"]])

    def test_rejects_empty_and_too_long(self):
        self.assertEqual(client.post("/scan", json={"message": ""}).status_code, 422)
        self.assertEqual(client.post("/scan", json={"message": "a" * 5001}).status_code, 422)
        self.assertEqual(client.post("/scan", json={"message": "   "}).status_code, 400)
        self.assertEqual(client.post("/scan", json={}).status_code, 422)

    def test_rate_limit(self):
        for _ in range(api.RATE_LIMIT_REQUESTS):
            self.assertEqual(client.post("/scan", json={"message": "hello"}).status_code, 200)
        self.assertEqual(client.post("/scan", json={"message": "hello"}).status_code, 429)

    def test_cors_allows_capacitor_apps_only(self):
        for origin in ("https://localhost", "capacitor://localhost"):
            response = client.options("/scan", headers={
                "Origin": origin, "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type"})
            self.assertEqual(response.headers.get("access-control-allow-origin"), origin)
        response = client.options("/scan", headers={
            "Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
        self.assertNotIn("access-control-allow-origin", response.headers)

    def test_private_fields_not_exposed(self):
        data = client.post("/scan", json={"message": "hello there"}).json()
        self.assertNotIn("log_odds", data)


@unittest.skipUnless(shutil.which("tesseract"), "Tesseract OCR is not installed")
class TestImageScanning(unittest.TestCase):

    def setUp(self):
        api._recent_requests.clear()

    def make_png(self, lines):
        from PIL import Image, ImageDraw, ImageFont
        image = Image.new("RGB", (1000, 80 + 70 * len(lines)), "white")
        draw = ImageDraw.Draw(image)
        try:
            font = ImageFont.load_default(size=34)
        except TypeError:
            font = ImageFont.load_default()
        for i, line in enumerate(lines):
            draw.text((24, 24 + i * 70), line, fill="black", font=font)
        buffer = BytesIO()
        image.save(buffer, format="PNG")
        return buffer.getvalue()

    def test_screenshot_is_read_and_scanned(self):
        png = self.make_png(["Your Outlook password expires today.",
                             "Keep the same password at",
                             "https://outlook-keep.example.net"])
        response = client.post("/scan-image", files={"file": ("shot.png", png, "image/png")})
        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        self.assertIn("password", data["extracted_text"].lower())
        self.assertIn(data["level"], {"high", "review"})

    def test_blank_image(self):
        png = self.make_png([])
        response = client.post("/scan-image", files={"file": ("blank.png", png, "image/png")})
        self.assertEqual(response.status_code, 422)

    def test_not_an_image(self):
        response = client.post("/scan-image", files={"file": ("x.png", b"not an image", "image/png")})
        self.assertEqual(response.status_code, 400)

    def test_too_large(self):
        big = b"0" * (api.MAX_IMAGE_BYTES + 10)
        response = client.post("/scan-image", files={"file": ("big.png", big, "image/png")})
        self.assertEqual(response.status_code, 413)


if __name__ == "__main__":
    unittest.main(verbosity=2)
