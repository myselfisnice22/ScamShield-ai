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

SIGN-IN
-------
Set CLERK_ISSUER to require Clerk sign-in (see backend/clerk_auth.py).
"""

import os
import sys
import time
from collections import defaultdict, deque
from io import BytesIO
from pathlib import Path

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Make the scanner in the repository root importable.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import contextlib  # noqa: E402
import io  # noqa: E402

with contextlib.redirect_stdout(io.StringIO()):  # hide "model loaded" prints
    from experiment_v10 import VERSION, scan_message  # noqa: E402

from backend import clerk_auth  # noqa: E402
from ocr_engine import OCRError, read_text  # noqa: E402

MAX_MESSAGE_CHARS = 5000
MAX_IMAGE_BYTES = 5 * 1024 * 1024
MAX_IMAGE_PIXELS = 20_000_000
OCR_TIMEOUT_SECONDS = 20
RATE_LIMIT_REQUESTS = int(os.environ.get("SCAMSHIELD_RATE_LIMIT", "30"))  # per minute per IP

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
)


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


@app.post("/scan")
def scan_text(body: ScanRequest, request: Request, user_id=Depends(clerk_auth.current_user)):
    check_rate_limit(request, user_id)
    try:
        report = scan_message(body.message)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    return public_report(report)


@app.post("/scan-image")
async def scan_image(request: Request, file: UploadFile = File(...),
                     user_id=Depends(clerk_auth.current_user)):
    check_rate_limit(request, user_id)

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
