"""ScamShield AI - safe loading of Tesseract OCR (screenshot reading).

WHY THIS FILE EXISTS
--------------------
pytesseract automatically tries to load "pandas" (a big data library that
ScamShield does not need). pytesseract copes if pandas is NOT INSTALLED, but
it crashes if pandas is installed and Windows BLOCKS it, e.g. with
"DLL load failed ... An Application Control policy has blocked this file"
(Windows Smart App Control).

That crash used to take the whole app down, even the text scanner. Now:
  * pytesseract is only loaded when a screenshot is actually scanned;
  * if pandas is blocked, pytesseract is loaded WITHOUT pandas (it supports
    that), so screenshot reading still works;
  * if OCR still can't run, a clear message is shown instead of a crash.
"""

import os
import sys

WINDOWS_TESSERACT = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

_pytesseract = None


class OCRError(Exception):
    """kind is one of: 'unavailable', 'timeout', 'failed'."""

    def __init__(self, message, kind):
        super().__init__(message)
        self.kind = kind


def _forget(prefix):
    for name in [n for n in sys.modules if n == prefix or n.startswith(prefix + ".")]:
        del sys.modules[name]


def load_pytesseract():
    """Import pytesseract safely. Raises OCRError('unavailable') on failure."""
    global _pytesseract
    if _pytesseract is not None:
        return _pytesseract

    if "pandas" not in sys.modules:
        try:
            import pandas  # noqa: F401  (only to see whether Windows allows it)
        except ModuleNotFoundError:
            pass  # not installed: pytesseract handles this itself
        except Exception:
            # Installed but blocked/broken. Make "import pandas" cleanly report
            # "not available", which pytesseract knows how to handle.
            _forget("pandas")
            sys.modules["pandas"] = None

    try:
        import pytesseract
    except Exception as error:
        _forget("pytesseract")
        raise OCRError(
            "Screenshot reading is not available on this computer "
            f"({type(error).__name__}). Text scanning still works.", "unavailable")

    if os.path.isfile(WINDOWS_TESSERACT):
        pytesseract.pytesseract.tesseract_cmd = WINDOWS_TESSERACT
    _pytesseract = pytesseract
    return pytesseract


def read_text(image, timeout=20):
    """Return the text in a PIL image. Raises OCRError with a friendly message."""
    pytesseract = load_pytesseract()
    try:
        return pytesseract.image_to_string(image, timeout=timeout)
    except pytesseract.TesseractNotFoundError:
        raise OCRError("Tesseract OCR was not found. Check its installation.", "unavailable")
    except RuntimeError:
        raise OCRError("Reading the screenshot took too long. Try a smaller screenshot.", "timeout")
    except Exception:
        raise OCRError("Could not read the screenshot.", "failed")
