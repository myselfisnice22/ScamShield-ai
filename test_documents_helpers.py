"""Builds small SYNTHETIC test documents (PDF, scanned PDF, .docx) in memory.

No real documents or personal data are used. The PDF writer is hand-made, so
the tests don't need an extra PDF-writing library.
"""

from io import BytesIO

PHISHING = ("HR Department: your dismissal letter is ready. Sign in with your email and password "
            "at https://micros0ft-hr.example-login.net within 12 hours.")
HARMLESS = "Team lunch is moved to Friday at 1pm in the main boardroom. See you there."


def _escape(text):
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _wrap(text, width=80):
    words, lines, line = text.split(), [], ""
    for word in words:
        if len(line) + len(word) + 1 > width:
            lines.append(line)
            line = word
        else:
            line = (line + " " + word).strip()
    return lines + ([line] if line else [])


def make_text_pdf(pages):
    """pages: a list of strings, one per page. Returns PDF bytes with real text."""
    objects = {1: b"<< /Type /Catalog /Pages 2 0 R >>",
               3: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"}
    kids, number = [], 4
    for page_text in pages:
        lines = " ".join(f"({_escape(line)}) Tj T*" for line in _wrap(page_text))
        stream = f"BT /F1 11 Tf 50 750 Td 14 TL {lines} ET".encode("latin-1")
        objects[number + 1] = b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream"
        objects[number] = (b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                           b"/Resources << /Font << /F1 3 0 R >> >> /Contents %d 0 R >>" % (number + 1))
        kids.append(number)
        number += 2
    objects[2] = (b"<< /Type /Pages /Kids [" + " ".join(f"{k} 0 R" for k in kids).encode()
                  + b"] /Count %d >>" % len(kids))

    out = b"%PDF-1.4\n"
    offsets = {}
    for i in sorted(objects):
        offsets[i] = len(out)
        out += b"%d 0 obj\n" % i + objects[i] + b"\nendobj\n"
    xref, size = len(out), max(objects) + 1
    out += b"xref\n0 %d\n0000000000 65535 f \n" % size
    out += b"".join(b"%010d 00000 n \n" % offsets[i] for i in range(1, size))
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (size, xref)
    return out


def make_scanned_pdf(lines):
    """A PDF that is just a picture of text (like a scanned letter): no text layer."""
    from PIL import Image, ImageDraw, ImageFont
    image = Image.new("RGB", (1240, 200 + 70 * len(lines)), "white")
    draw = ImageDraw.Draw(image)
    try:
        font = ImageFont.load_default(size=36)
    except TypeError:
        font = ImageFont.load_default()
    for i, line in enumerate(lines):
        draw.text((60, 80 + i * 70), line, fill="black", font=font)
    buffer = BytesIO()
    image.save(buffer, format="PDF", resolution=150)
    return buffer.getvalue()


def make_docx(paragraphs, table_rows=()):
    import docx
    document = docx.Document()
    for text in paragraphs:
        document.add_paragraph(text)
    if table_rows:
        table = document.add_table(rows=0, cols=len(table_rows[0]))
        for row in table_rows:
            cells = table.add_row().cells
            for cell, value in zip(cells, row):
                cell.text = value
    buffer = BytesIO()
    document.save(buffer)
    return buffer.getvalue()


def make_encrypted_pdf(pages, password="test-password"):
    from pypdf import PdfReader, PdfWriter
    writer = PdfWriter()
    writer.append(PdfReader(BytesIO(make_text_pdf(pages))))
    writer.encrypt(password)
    buffer = BytesIO()
    writer.write(buffer)
    return buffer.getvalue()
