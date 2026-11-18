"""ScamShield AI - Backend API.

The phone app sends messages (or screenshots) here, and this server checks
them with the SAME Python scanner used by the Streamlit website
(experiment_v10.scan_message). Nothing about the scanner is changed.

Run locally (from the repository root):
    python -m uvicorn backend.api:app --reload --port 8000

Then open http://localhost:8000/docs to try the API in your browser.

PRIVACY
-------
* Messages and screenshots are processed in memory and NEVER saved.
* The server does not log message text (only that a request happened).
* History is kept on the phone, not on the server.
* Documents (Pro) are checked in memory. Only the finished REPORT (no
  document text, except short excerpts of flagged sections) is kept in
  memory for SCAMSHIELD_REPORT_TTL_MINUTES (default 60) so it can be downloaded.
* Monthly usage stores only a Clerk user id and a number per month (tiers.py).

PLANS
-----
Free / Plus / Pro and their monthly limits are defined in tiers.py.
Document scanning and reports (Pro) are checked HERE on the server, not just
hidden in the app.

SIGN-IN
-------
Set CLERK_ISSUER to require Clerk sign-in (see backend/clerk_auth.py).
"""

import os
import secrets
import sys
import threading
import time
from collections import OrderedDict, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

# Make the scanner in the repository root importable.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import contextlib  # noqa: E402
import io  # noqa: E402

with contextlib.redirect_stdout(io.StringIO()):  # hide "model loaded" prints
    from experiment_v10 import VERSION, scan_message  # noqa: E402

import document_check  # noqa: E402
import tiers  # noqa: E402
from backend import clerk_auth  # noqa: E402
from ocr_engine import OCRError, read_text  # noqa: E402

MAX_MESSAGE_CHARS = 5000
MAX_IMAGE_BYTES = 5 * 1024 * 1024
MAX_IMAGE_PIXELS = 20_000_000
OCR_TIMEOUT_SECONDS = 20
RATE_LIMIT_REQUESTS = int(os.environ.get("SCAMSHIELD_RATE_LIMIT", "30"))  # per minute per IP
REPORT_TTL_SECONDS = int(os.environ.get("SCAMSHIELD_REPORT_TTL_MINUTES", "60")) * 60
MAX_STORED_REPORTS = 500

# Capacitor apps load from these origins:
#   Android: https://localhost     iPhone: capacitor://localhost
# Add more (comma separated) with the SCAMSHIELD_ALLOWED_ORIGINS variable,
# e.g. "http://localhost:5173" while developing in a desktop browser.
DEFAULT_ORIGINS = ["https://localhost", "capacitor://localhost", "http://localhost"]
EXTRA_ORIGINS = [o.strip() for o in os.environ.get("SCAMSHIELD_ALLOWED_ORIGINS", "").split(",") if o.strip()]

app = FastAPI(
    title="ScamShield AI API",
    version=VERSION,
    description="Checks messages and screenshots for scam warning signs. "
                "Experimental: a low-risk result never proves a message is safe.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=DEFAULT_ORIGINS + EXTRA_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
    expose_headers=["Content-Disposition"],
)


# ==========================================
# Accounts, plans and monthly limits (see tiers.py)
# ==========================================

@dataclass(frozen=True)
class Account:
    user_id: str | None  # Clerk user id, or None when sign-in is off
    plan: str

    @property
    def usage_id(self):
        return self.user_id or tiers.LOCAL_USER


def current_account(request: Request):
    """FastAPI dependency: who is calling, and on which plan."""
    claims = clerk_auth.current_claims(request)
    if claims is None:  # sign-in is off: local testing only
        return Account(None, tiers.local_test_plan())
    return Account(claims["sub"], tiers.plan_from_claims(claims))


def require_feature(account, feature):
    if not getattr(tiers.PLANS[account.plan], feature):
        raise HTTPException(status_code=403, detail=tiers.UPGRADE_MESSAGE)


class monthly_check:
    """Use one of the account's monthly checks; give it back if the check fails."""

    def __init__(self, account):
        self.account = account
        self.limit = tiers.monthly_limit(account.plan)

    def __enter__(self):
        if self.limit is not None:
            try:
                tiers.usage_store().reserve(self.account.usage_id, self.limit)
            except tiers.CheckLimitReached as error:
                raise HTTPException(status_code=429, detail=str(error))
        return self

    def __exit__(self, error_type, error, traceback):
        if error_type is not None and self.limit is not None:
            tiers.usage_store().release(self.account.usage_id)
        return False


# ==========================================
# Finished document reports (kept in memory for a short time)
# ==========================================

_reports = OrderedDict()  # report id -> (owner, created, file name, text)
_reports_lock = threading.Lock()


def save_report(owner, file_name, text):
    now = time.monotonic()
    report_id = secrets.token_urlsafe(18)
    with _reports_lock:
        for key in [k for k, v in _reports.items() if now - v[1] > REPORT_TTL_SECONDS]:
            del _reports[key]
        while len(_reports) >= MAX_STORED_REPORTS:
            _reports.popitem(last=False)
        _reports[report_id] = (owner, now, file_name, text)
    return report_id


def load_report(owner, report_id):
    with _reports_lock:
        entry = _reports.get(report_id)
    if (not entry or not secrets.compare_digest(entry[0], owner)
            or time.monotonic() - entry[1] > REPORT_TTL_SECONDS):
        return None
    return entry


# ==========================================
# Simple rate limit (stops one phone/script flooding the server)
# ==========================================

_recent_requests = defaultdict(deque)


def check_rate_limit(request: Request, user_id=None):
    # Signed-in users are limited per account, others per IP address.
    client = ("user:" + user_id) if user_id else (request.client.host if request.client else "unknown")
    now = time.monotonic()
    window = _recent_requests[client]
    while window and now - window[0] > 60:
        window.popleft()
    if len(window) >= RATE_LIMIT_REQUESTS:
        raise HTTPException(status_code=429, detail="Too many scans. Please wait a minute.")
    window.append(now)


# ==========================================
# Response format
# ==========================================

PUBLIC_FIELDS = (
    "version", "risk", "verdict_source", "verdict_source_label", "explanation",
    "warnings", "urls", "ai_prediction", "ai_scam_probability", "ai_confidence",
    "v7_prediction", "v10_screening_label",
)


def public_report(report):
    result = {key: report[key] for key in PUBLIC_FIELDS if key in report}
    result["level"] = (
        "high" if report["risk"].startswith("HIGH")
        else "review" if report["risk"].startswith("NEEDS")
        else "none"
    )
    return result


class ScanRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=MAX_MESSAGE_CHARS)


# ==========================================
# Endpoints
# ==========================================

@app.get("/health")
def health():
    return {"status": "ok", "version": VERSION, "sign_in_required": clerk_auth.settings.enabled}


@app.get("/account")
def account_info(account=Depends(current_account)):
    """The caller's plan, monthly limit and checks used this month."""
    return tiers.account_summary(account.usage_id, account.plan)


@app.post("/scan")
def scan_text(body: ScanRequest, request: Request, account=Depends(current_account)):
    check_rate_limit(request, account.user_id)
    with monthly_check(account):
        try:
            report = scan_message(body.message)
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error))
    return public_report(report)


@app.post("/scan-image")
async def scan_image(request: Request, file: UploadFile = File(...),
                     account=Depends(current_account)):
    check_rate_limit(request, account.user_id)
    with monthly_check(account):
        return await _scan_image(file)


async def _scan_image(file):
    from PIL import Image, UnidentifiedImageError

    data = await file.read(MAX_IMAGE_BYTES + 1)
    if len(data) > MAX_IMAGE_BYTES:
        raise HTTPException(status_code=413, detail="Image is too large. Please upload a screenshot under 5 MB.")
    if not data:
        raise HTTPException(status_code=400, detail="The image is empty.")

    try:
        with Image.open(BytesIO(data)) as uploaded:
            if uploaded.width * uploaded.height > MAX_IMAGE_PIXELS:
                raise HTTPException(status_code=413, detail="Image is too large. Please crop it first.")
            image = uploaded.convert("RGB")
    except HTTPException:
        raise
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError):
        raise HTTPException(status_code=400, detail="That file is not a readable image.")

    # ocr_engine loads Tesseract safely (see ocr_engine.py).
    try:
        text = read_text(image, timeout=OCR_TIMEOUT_SECONDS)
    except OCRError as error:
        status = {"unavailable": 503, "timeout": 504}.get(error.kind, 500)
        raise HTTPException(status_code=status, detail=str(error))

    text = text[:MAX_MESSAGE_CHARS].strip()
    if not text:
        raise HTTPException(status_code=422, detail="No readable text was found. Try a clearer screenshot.")

    result = public_report(scan_message(text))
    result["extracted_text"] = text
    return result


# ==========================================
# Pro: PDF and document checks + reports
# ==========================================

DOCUMENT_ERROR_STATUS = {
    "unsupported": 415, "too_large": 413, "empty": 400, "encrypted": 422,
    "unreadable": 422, "no_text": 422, "ocr_unavailable": 422, "analysis": 500,
}


@app.post("/scan-document")
async def scan_document(request: Request, file: UploadFile = File(...),
                        account=Depends(current_account)):
    require_feature(account, "documents")
    check_rate_limit(request, account.user_id)

    try:
        document_check.file_kind(file.filename)
        data = await file.read(document_check.limits()["max_bytes"] + 1)
        with monthly_check(account):
            result = await run_in_threadpool(
                document_check.check_document, file.filename, data, scan_message)
    except document_check.DocumentError as error:
        raise HTTPException(status_code=DOCUMENT_ERROR_STATUS.get(error.kind, 422), detail=str(error))

    scanned_at = datetime.now(timezone.utc)
    report_text = document_check.build_report(result, scanned_at)
    file_name = document_check.report_file_name(result["document"]["file_name"])
    result["report_id"] = save_report(account.usage_id, file_name, report_text)
    result["scanned_at"] = scanned_at.isoformat(timespec="seconds")
    result["coverage_notes"] = document_check.coverage_notes(result["document"])
    return result


@app.get("/reports/{report_id}")
def download_report(report_id: str, account=Depends(current_account)):
    require_feature(account, "reports")
    entry = load_report(account.usage_id, report_id)
    if entry is None:
        raise HTTPException(status_code=404,
                            detail="This report has expired or doesn't exist. Check the document again.")
    _, _, file_name, text = entry
    return PlainTextResponse(text, headers={
        "Content-Disposition": f'attachment; filename="{file_name}"',
        "Cache-Control": "no-store",
    })
