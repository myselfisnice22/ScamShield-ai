"""ScamShield AI - PDF and document checks (Pro).

Reads the text out of a PDF, Word (.docx) or plain-text (.txt) file and sends
it through the SAME scanner as messages (experiment_v10.scan_message). Used by
both the Streamlit website and the backend API.

HOW A DOCUMENT IS CHECKED
-------------------------
1. Validate: allowed type, size limit, and the file's first bytes must match
   its type (a renamed .exe is rejected).
2. Extract text page by page (PDF), paragraph by paragraph (.docx) or line by
   line (.txt). A PDF page with no text layer (a scanned page) is read with
   Tesseract OCR, if it's installed.
3. Split the text into sections of up to 4,800 characters (the scanner reads
   up to 5,000), keeping page/paragraph/line numbers, and scan each section.
   Each PDF page is scanned on its own, so results point to the exact page.
4. Combine: the overall result is the most serious section result. Warning
   signs are merged and list WHERE they were found.

One document = one check towards the monthly limit, however many sections it has.

The file is processed in memory and never saved. The report contains the file
name, scan date, result, warning signs and analysis, plus short excerpts of
flagged sections, but no account details.

Limits (environment variables, all optional):
  SCAMSHIELD_MAX_DOCUMENT_MB      default 10
  SCAMSHIELD_MAX_DOCUMENT_PAGES   default 50   (later pages are not checked)
  SCAMSHIELD_MAX_OCR_PAGES        default 10   (scanned pages read with OCR)
  SCAMSHIELD_MAX_DOCUMENT_CHARS   default 60000
"""

import contextlib
import io
import os
import re
import zipfile
from datetime import datetime, timezone

from ocr_engine import OCRError, read_text

SECTION_CHARS = 4800
OCR_TIMEOUT_SECONDS = 20
OCR_RENDER_SCALE = 2.0          # 144 dpi: enough for Tesseract, small enough to be quick
MIN_PAGE_TEXT = 20              # fewer characters than this = probably a scanned page
MAX_DOCX_UNCOMPRESSED = 50 * 1024 * 1024
MAX_EXCERPT_CHARS = 300
MAX_FLAGGED_SECTIONS = 5
MAX_URLS = 20

SUPPORTED = {".pdf": "PDF", ".docx": "Word document", ".txt": "Text file"}
SUPPORTED_LABEL = "PDF, Word (.docx) or text (.txt)"

HIGH = "HIGH RISK - POSSIBLE SCAM"
RISK_ORDER = [  # most serious first (same strings as experiment_v10)
    HIGH,
    "NEEDS REVIEW - STRONG WARNING SIGNS",
    "NEEDS REVIEW - CHECK CONTEXT",
    "NEEDS REVIEW - AI MODEL ONLY",
    "NO KNOWN PATTERN - NOT PROOF OF SAFETY",
]
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def _int_setting(name, default):
    try:
        return max(1, int(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return default


def limits():
    return {
        "max_bytes": _int_setting("SCAMSHIELD_MAX_DOCUMENT_MB", 10) * 1024 * 1024,
        "max_pages": _int_setting("SCAMSHIELD_MAX_DOCUMENT_PAGES", 50),
        "max_ocr_pages": _int_setting("SCAMSHIELD_MAX_OCR_PAGES", 10),
        "max_chars": _int_setting("SCAMSHIELD_MAX_DOCUMENT_CHARS", 60000),
    }


class DocumentError(Exception):
    """kind: unsupported, too_large, empty, encrypted, unreadable, no_text,
    ocr_unavailable, analysis."""

    def __init__(self, message, kind):
        super().__init__(message)
        self.kind = kind


# ==========================================
# File names and validation
# ==========================================

def safe_file_name(name):
    """Just the file's own name: no folders or control characters, at most 120 characters."""
    name = re.split(r"[\\/]", str(name or ""))[-1]
    name = re.sub(r"[\x00-\x1f\x7f]", "", name).strip() or "document"
    if len(name) > 120:
        stem, dot, ext = name.rpartition(".")
        name = (stem[:110] + dot + ext[:8]) if dot else name[:120]
    return name


def file_kind(name):
    ext = os.path.splitext(str(name or "").lower())[1]
    if ext not in SUPPORTED:
        raise DocumentError(f"That file type isn't supported. Please upload a {SUPPORTED_LABEL} file.",
                            "unsupported")
    return ext


def validate(name, data):
    ext = file_kind(name)
    max_bytes = limits()["max_bytes"]
    if len(data) > max_bytes:
        raise DocumentError(f"The file is too large. Please upload a document under "
                            f"{max_bytes // (1024 * 1024)} MB.", "too_large")
    if not data:
        raise DocumentError("The file is empty.", "empty")
    if ext == ".pdf" and not data[:1024].lstrip().startswith(b"%PDF-"):
        raise DocumentError("That file isn't a real PDF. Please upload the original document.",
                            "unsupported")
    if ext == ".docx" and not data.startswith(b"PK\x03\x04"):
        raise DocumentError("That file isn't a real Word (.docx) document. Old .doc files aren't "
                            "supported. Save it as .docx or PDF first.", "unsupported")
    return ext


# ==========================================
# Text extraction -> [(location label, text)]
# ==========================================

def _pdf_units(data, info):
    try:
        from pypdf import PdfReader
        from pypdf.errors import PdfReadError
    except ImportError:
        raise DocumentError("PDF reading isn't installed on this server (pypdf).", "unreadable")

    try:
        with contextlib.redirect_stderr(io.StringIO()):
            reader = PdfReader(io.BytesIO(data))
            if reader.is_encrypted and not reader.decrypt(""):
                raise DocumentError("This PDF is password-protected. Remove the password and try again.",
                                    "encrypted")
            total = len(reader.pages)
    except DocumentError:
        raise
    except (PdfReadError, Exception):
        raise DocumentError("This PDF couldn't be opened. It may be damaged.", "unreadable")

    lim = limits()
    info["total_pages"] = total
    info["pages_checked"] = min(total, lim["max_pages"])
    units, scanned = [], []
    for number in range(info["pages_checked"]):
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                text = reader.pages[number].extract_text() or ""
        except Exception:
            text = ""
        if len(text.strip()) < MIN_PAGE_TEXT:
            scanned.append(number)
        units.append([f"page {number + 1}", text])

    if scanned:
        _ocr_pages(data, units, scanned, info, lim["max_ocr_pages"])
    return units


def _ocr_pages(data, units, scanned, info, max_ocr_pages):
    """Read scanned PDF pages (no text layer) with Tesseract."""
    to_read = scanned[:max_ocr_pages]
    info["ocr_skipped"] = len(scanned) - len(to_read)
    try:
        import pypdfium2 as pdfium
    except ImportError:
        info["ocr_problem"] = ("Scanned pages can't be read on this server "
                               "(pypdfium2 isn't installed).")
        return
    try:
        pdf = pdfium.PdfDocument(data)
    except Exception:
        info["ocr_problem"] = "Scanned pages in this PDF couldn't be opened for reading."
        return
    try:
        for number in to_read:
            try:
                page = pdf[number]
                image = page.render(scale=OCR_RENDER_SCALE).to_pil().convert("RGB")
                page.close()
            except Exception:
                continue
            try:
                text = read_text(image, timeout=OCR_TIMEOUT_SECONDS)
            except OCRError as error:
                if error.kind == "unavailable":
                    info["ocr_problem"] = ("This PDF contains scanned pages, but OCR (Tesseract) "
                                           "isn't available on this server to read them.")
                    return
                continue
            if text.strip():
                units[number][1] = text
                info["ocr_pages"] += 1
    finally:
        pdf.close()


def _docx_units(data, info):
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            if (len(entries) > 2000
                    or sum(e.file_size for e in entries) > MAX_DOCX_UNCOMPRESSED
                    or "word/document.xml" not in {e.filename for e in entries}):
                raise DocumentError("This Word document couldn't be read safely.", "unreadable")
    except zipfile.BadZipFile:
        raise DocumentError("This Word document is damaged.", "unreadable")

    try:
        import docx
    except ImportError:
        raise DocumentError("Word document reading isn't installed on this server (python-docx).",
                            "unreadable")
    try:
        document = docx.Document(io.BytesIO(data))
        paragraphs = [p.text for p in document.paragraphs]
        for table in document.tables:
            for row in table.rows:
                paragraphs.append(" | ".join(cell.text for cell in row.cells))
    except Exception:
        raise DocumentError("This Word document couldn't be read. It may be damaged.", "unreadable")
    return [[f"paragraph {i}", text] for i, text in enumerate(paragraphs, start=1) if text.strip()]


def _txt_units(data, info):
    if b"\x00" in data[:8192]:
        raise DocumentError("That doesn't look like a text file.", "unsupported")
    for encoding in ("utf-8-sig", "cp1252"):
        try:
            text = data.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    else:
        text = data.decode("latin-1")
    return [[f"line {i}", line] for i, line in enumerate(text.splitlines(), start=1) if line.strip()]


def extract(name, data):
    """Return (units, info). units = [[location label, text], ...]."""
    ext = validate(name, data)
    info = {"file_type": SUPPORTED[ext], "total_pages": None, "pages_checked": None,
            "ocr_pages": 0, "ocr_skipped": 0, "ocr_problem": None, "truncated": False}
    reader = {".pdf": _pdf_units, ".docx": _docx_units, ".txt": _txt_units}[ext]
    units = [[label, _clean(text)] for label, text in reader(data, info)]
    units = [u for u in units if u[1]]
    if not units:
        if info["ocr_problem"]:
            raise DocumentError(info["ocr_problem"] + " Try a PDF with selectable text, or upload "
                                "screenshots of the pages in the Screenshot Scanner.",
                                "ocr_unavailable")
        raise DocumentError("No readable text was found in this document. If it's a scanned or "
                            "photographed document, try a clearer copy.", "no_text")
    return units, info


def _clean(text):
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", " ", text or "")
    text = re.sub(r"[ \t]+", " ", text)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


# ==========================================
# Sections and analysis
# ==========================================

def _range_label(first, last):
    if first == last:
        return first
    kind, a = first.split(" ", 1)
    _, b = last.split(" ", 1)
    return f"{kind}s {a}–{b}"


def make_sections(units, max_chars, merge=True):
    """Group units into sections of up to SECTION_CHARS characters.

    merge=False keeps every unit (a PDF page) in its own section(s), so
    warning signs point to the exact page.
    """
    sections, current, labels, used = [], [], [], 0
    truncated = False

    def flush():
        if "".join(current).strip():
            sections.append({"location": _range_label(labels[0], labels[-1]),
                             "text": "\n".join(current)})
        current.clear()
        labels.clear()

    for label, text in units:
        if not merge:
            flush()
        if used + len(text) > max_chars:
            text = text[:max(0, max_chars - used)]
            truncated = True
        while text:
            room = SECTION_CHARS - sum(len(t) + 1 for t in current)
            if room < min(len(text), 200):
                flush()
                room = SECTION_CHARS
            piece, text = text[:room], text[room:]
            current.append(piece)
            used += len(piece)
            if not labels or labels[-1] != label:
                labels.append(label)
        if truncated:
            break
    flush()
    return sections, truncated


def _risk_rank(risk):
    """0 = most serious."""
    risk = str(risk)
    if risk in RISK_ORDER:
        return RISK_ORDER.index(risk)
    if risk.startswith("HIGH"):
        return 0
    return 1 if risk.startswith("NEEDS") else len(RISK_ORDER)


def _excerpt(text):
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= MAX_EXCERPT_CHARS else text[:MAX_EXCERPT_CHARS - 1].rstrip() + "…"


def check_document(name, data, scan):
    """Extract, scan and combine. `scan` is experiment_v10.scan_message.

    Returns a result with the same main fields as a message scan, plus
    "document" (file details) and "flagged_sections" (where problems are).
    """
    file_name = safe_file_name(name)
    units, info = extract(file_name, data)
    sections, truncated = make_sections(units, limits()["max_chars"],
                                        merge=info["file_type"] != "PDF")
    info["truncated"] = truncated

    scanned = []
    try:
        for section in sections:
            scanned.append((section, scan(section["text"])))
    except Exception:
        raise DocumentError("ScamShield couldn't analyse this document. Please try again.", "analysis")

    worst_section, worst = min(scanned, key=lambda pair: _risk_rank(pair[1]["risk"]))

    merged = {}
    for section, report in scanned:
        for warning in report.get("warnings", []):
            entry = merged.setdefault(warning["code"], dict(warning, locations=[]))
            if section["location"] not in entry["locations"]:
                entry["locations"].append(section["location"])
    warnings = sorted(merged.values(), key=lambda w: SEVERITY_ORDER.get(w.get("severity"), 3))

    urls = []
    for _, report in scanned:
        urls += [u for u in report.get("urls", []) if u not in urls]

    flagged = [{"location": section["location"], "risk": report["risk"],
                "warning_count": len(report.get("warnings", [])), "excerpt": _excerpt(section["text"])}
               for section, report in scanned
               if not report["risk"].startswith("NO KNOWN") or report.get("warnings")]
    flagged.sort(key=lambda f: (_risk_rank(f["risk"]), -f["warning_count"]))

    explanation = list(worst.get("explanation", []))
    if len(sections) > 1:
        explanation.insert(0, f"ScamShield checked this document in {len(sections)} sections. The "
                              f"result below is the most serious one, found in {worst_section['location']}.")

    risk = worst["risk"]
    return {
        "version": worst.get("version"),
        "risk": risk,
        "level": "high" if risk.startswith("HIGH") else "review" if risk.startswith("NEEDS") else "none",
        "verdict_source": worst.get("verdict_source"),
        "verdict_source_label": worst.get("verdict_source_label"),
        "explanation": explanation,
        "warnings": warnings,
        "urls": urls[:MAX_URLS],
        "ai_prediction": worst.get("ai_prediction"),
        "ai_scam_probability": worst.get("ai_scam_probability"),
        "ai_confidence": worst.get("ai_confidence"),
        "v7_prediction": worst.get("v7_prediction"),
        "flagged_sections": flagged[:MAX_FLAGGED_SECTIONS],
        "document": dict(info, file_name=file_name, sections_checked=len(sections)),
    }


# ==========================================
# Messages and the downloadable report
# ==========================================

def coverage_notes(document):
    """Plain sentences about what was (and wasn't) checked."""
    notes = []
    total, checked = document.get("total_pages"), document.get("pages_checked")
    if total:
        notes.append(f"Checked {checked} of {total} page(s).")
    if document.get("ocr_pages"):
        notes.append(f"{document['ocr_pages']} scanned page(s) were read with OCR. "
                     "OCR can misread letters.")
    if document.get("ocr_problem"):
        notes.append(document["ocr_problem"] + " Those pages were not checked.")
    if document.get("ocr_skipped"):
        notes.append(f"{document['ocr_skipped']} more scanned page(s) were not read (OCR limit).")
    if total and checked and checked < total:
        notes.append(f"Pages after page {checked} were not checked (page limit).")
    if document.get("truncated"):
        notes.append("The document is very long, so only the first part was checked.")
    return notes


def report_file_name(file_name):
    stem = os.path.splitext(safe_file_name(file_name))[0]
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("._") or "document"
    return f"ScamShield-report-{stem[:60]}.txt"


def build_report(result, scanned_at=None):
    """A readable plain-text report of a completed document check."""
    scanned_at = (scanned_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    document = result.get("document", {})
    lines = [
        "ScamShield AI - Document check report",
        "=" * 38,
        f"File:            {document.get('file_name', 'document')}",
        f"File type:       {document.get('file_type', '')}",
        f"Scan date:       {scanned_at.strftime('%Y-%m-%d %H:%M UTC')}",
        f"Scanner:         {result.get('version') or 'ScamShield'}",
        "",
        f"RESULT:          {result.get('risk', '')}",
        f"Verdict source:  {result.get('verdict_source_label') or 'Unknown'}",
        "",
    ]
    notes = coverage_notes(document)
    if notes:
        lines += ["What was checked", "-" * 16] + [f"- {n}" for n in notes] + [""]

    warnings = result.get("warnings", [])
    lines += [f"Warning signs ({len(warnings)})", "-" * 16]
    if warnings:
        for w in warnings:
            where = ", ".join(w.get("locations", []))
            lines.append(f"- [{str(w.get('severity', 'low')).upper()}] {w.get('description', '')}"
                         + (f"  (found in {where})" if where else ""))
    else:
        lines.append("- No predefined warning signs detected.")
    lines.append("")

    lines += ["Analysis", "-" * 8] + [f"- {line}" for line in result.get("explanation", [])]
    probability = result.get("ai_scam_probability")
    if probability is not None:
        lines.append(f"- AI scam probability in the most serious section: {float(probability) * 100:.0f}% "
                     f"({result.get('ai_confidence', '?')} confidence).")
    lines.append("")

    flagged = result.get("flagged_sections", [])
    if flagged:
        lines += ["Where to look", "-" * 13]
        for f in flagged:
            lines.append(f"- {f['location']}: {f['risk']}")
            lines.append(f'    "{f["excerpt"]}"')
        lines.append("")

    urls = result.get("urls", [])
    if urls:
        lines += ["Links found (not opened)", "-" * 24] + [f"- {u}" for u in urls] + [""]

    lines += [
        "Important",
        "-" * 9,
        "ScamShield is experimental. A low-risk result never proves a document is safe.",
        "Never share passwords, PINs, OTPs or banking details because of a document you",
        "didn't expect. Check with the sender through an official channel.",
        "",
    ]
    return "\n".join(lines)
