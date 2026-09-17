"""
pdf_cert.py - Vector PDF Certificate Generation Engine for CertValid.
Generates print-ready landscape PDF certificates featuring ornamental vector borders,
official starburst seal, embedded QR code, and cryptographic verification metadata.
"""

import io
import os
import qrcode
from PIL import Image
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib import colors
from reportlab.lib.utils import ImageReader

BASE_URL = os.environ.get('BASE_URL', 'https://ranjithbrs.pythonanywhere.com').rstrip('/')


def _safe_str(val) -> str:
    """Sanitize strings so they are safe for ReportLab Type 1 fonts without raising UnicodeEncodeError."""
    if val is None:
        return ""
    return str(val).encode('latin-1', 'replace').decode('latin-1')


def generate_vector_pdf_certificate(cert: dict, theme: str = 'gold') -> bytes:
    """
    Generate a vector PDF certificate document using ReportLab.
    Returns the binary content (bytes) of the generated PDF file.
    """
    buffer = io.BytesIO()
    # 11 x 8.5 inches landscape (792 x 612 pt)
    w, h = landscape(letter)
    c = canvas.Canvas(buffer, pagesize=landscape(letter))

    THEME_COLORS = {
        'gold': {
            'primary': colors.HexColor('#d4af37'),
            'secondary': colors.HexColor('#0f0f23'),
            'accent': colors.HexColor('#9333ea'),
            'bg_border': colors.HexColor('#1e1b4b'),
            'text_dark': colors.HexColor('#0f172a'),
            'text_muted': colors.HexColor('#475569')
        },
        'emerald': {
            'primary': colors.HexColor('#10b981'),
            'secondary': colors.HexColor('#0a1e19'),
            'accent': colors.HexColor('#059669'),
            'bg_border': colors.HexColor('#064e3b'),
            'text_dark': colors.HexColor('#0f172a'),
            'text_muted': colors.HexColor('#475569')
        },
        'navy': {
            'primary': colors.HexColor('#3b82f6'),
            'secondary': colors.HexColor('#0f172a'),
            'accent': colors.HexColor('#1d4ed8'),
            'bg_border': colors.HexColor('#1e3a8a'),
            'text_dark': colors.HexColor('#0f172a'),
            'text_muted': colors.HexColor('#475569')
        },
        'ruby': {
            'primary': colors.HexColor('#ef4444'),
            'secondary': colors.HexColor('#280a14'),
            'accent': colors.HexColor('#b91c1c'),
            'bg_border': colors.HexColor('#881337'),
            'text_dark': colors.HexColor('#0f172a'),
            'text_muted': colors.HexColor('#475569')
        },
        'monochrome': {
            'primary': colors.HexColor('#475569'),
            'secondary': colors.HexColor('#18181b'),
            'accent': colors.HexColor('#334155'),
            'bg_border': colors.HexColor('#27272a'),
            'text_dark': colors.HexColor('#0f172a'),
            'text_muted': colors.HexColor('#475569')
        }
    }

    pal = THEME_COLORS.get(theme.lower(), THEME_COLORS['gold'])

    # ── Background Tint ──
    c.setFillColor(colors.HexColor('#fcfbf7'))
    c.rect(0, 0, w, h, fill=True, stroke=False)

    # ── Vector Ornamental Borders ──
    # Outer Border
    c.setStrokeColor(pal['primary'])
    c.setLineWidth(4)
    c.rect(20, 20, w - 40, h - 40)

    # Secondary Inner Border
    c.setStrokeColor(pal['bg_border'])
    c.setLineWidth(1)
    c.rect(28, 28, w - 56, h - 56)

    # Corner Decorative Squares
    corner_size = 14
    for cx, cy in [(28, 28), (w - 28 - corner_size, 28), (28, h - 28 - corner_size), (w - 28 - corner_size, h - 28 - corner_size)]:
        c.setFillColor(pal['primary'])
        c.rect(cx, cy, corner_size, corner_size, fill=True, stroke=False)

    # ── Header & Organization Title ──
    c.setFillColor(pal['secondary'])
    c.setFont("Helvetica-Bold", 13)
    c.drawCentredString(w / 2, h - 70, "CERTVALID ENTERPRISE CREDENTIAL REGISTRY")

    c.setFillColor(pal['primary'])
    c.setFont("Times-BoldItalic", 34)
    c.drawCentredString(w / 2, h - 110, "Certificate of Completion")

    # Decorative Header Line
    c.setStrokeColor(pal['primary'])
    c.setLineWidth(1.5)
    c.line(w / 2 - 140, h - 125, w / 2 + 140, h - 125)

    # ── Presentation Line ──
    c.setFillColor(pal['text_muted'])
    c.setFont("Helvetica", 12)
    c.drawCentredString(w / 2, h - 155, "This is to officially certify that")

    # ── Recipient Name ──
    c.setFillColor(pal['text_dark'])
    c.setFont("Helvetica-Bold", 28)
    student_name = _safe_str(cert.get('student_name', 'Student Name'))
    c.drawCentredString(w / 2, h - 195, student_name)

    # Name Underline
    name_width = c.stringWidth(student_name, "Helvetica-Bold", 28)
    c.setStrokeColor(pal['primary'])
    c.setLineWidth(1)
    c.line(w / 2 - name_width / 2 - 15, h - 203, w / 2 + name_width / 2 + 15, h - 203)

    # ── Course & Achievement ──
    c.setFillColor(pal['text_muted'])
    c.setFont("Helvetica", 12)
    c.drawCentredString(w / 2, h - 235, "has successfully fulfilled all institutional requirements for")

    c.setFillColor(pal['secondary'])
    c.setFont("Helvetica-Bold", 20)
    course_name = _safe_str(cert.get('course_name', 'Course / Programme'))
    c.drawCentredString(w / 2, h - 265, course_name)

    # ── Middle Divider ──
    c.setStrokeColor(colors.HexColor('#e2e8f0'))
    c.setLineWidth(1)
    c.line(80, h - 310, w - 80, h - 310)

    # ── Left Metadata Column ──
    col_x = 75
    y_start = h - 340
    c.setFont("Helvetica-Bold", 10)
    c.setFillColor(pal['text_muted'])
    c.drawString(col_x, y_start, "ISSUING AUTHORITY:")
    c.setFont("Helvetica-Bold", 12)
    c.setFillColor(pal['text_dark'])
    c.drawString(col_x, y_start - 16, _safe_str(cert.get('issuer_name', 'CertValid Authority')))

    c.setFont("Helvetica-Bold", 10)
    c.setFillColor(pal['text_muted'])
    c.drawString(col_x, y_start - 42, "ISSUE DATE:")
    c.setFont("Helvetica", 11)
    c.setFillColor(pal['text_dark'])
    c.drawString(col_x, y_start - 56, _safe_str(cert.get('issue_date', '')))

    c.setFont("Helvetica-Bold", 10)
    c.setFillColor(pal['text_muted'])
    c.drawString(col_x, y_start - 80, "VALIDITY / EXPIRATION:")
    c.setFont("Helvetica", 11)
    exp_text = _safe_str(cert.get('expires_at') or "Lifetime Validity (Permanent)")
    if cert.get('is_expired'):
        c.setFillColor(colors.HexColor('#b91c1c'))
        exp_text += " [EXPIRED]"
    else:
        c.setFillColor(colors.HexColor('#059669'))
    c.drawString(col_x, y_start - 94, exp_text)

    c.setFont("Helvetica-Bold", 10)
    c.setFillColor(pal['text_muted'])
    c.drawString(col_x, y_start - 118, "CERTIFICATE ID:")
    c.setFont("Courier-Bold", 12)
    c.setFillColor(pal['secondary'])
    c.drawString(col_x, y_start - 132, _safe_str(cert.get('cert_id', '')))

    # ── Right Seal Column: Official Rosette Emblem ──
    seal_x = w - 150
    seal_y = h - 410

    # Outer decorative circle
    c.setStrokeColor(pal['primary'])
    c.setLineWidth(2)
    c.circle(seal_x, seal_y, 45, fill=False, stroke=True)

    # Inner filled circle
    c.setFillColor(pal['primary'])
    c.setStrokeColor(pal['bg_border'])
    c.setLineWidth(1)
    c.circle(seal_x, seal_y, 38, fill=True, stroke=True)

    # Seal Typography
    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 8)
    c.drawCentredString(seal_x, seal_y + 14, "OFFICIAL SEAL")
    c.setFont("Helvetica-Bold", 14)
    c.drawCentredString(seal_x, seal_y - 2, "* VALID *")
    c.setFont("Helvetica-Bold", 7.5)
    c.drawCentredString(seal_x, seal_y - 18, "VERIFIED AUTHENTIC")

    # ── Center QR Code ──
    cert_id = cert.get('cert_id', '')
    verify_url = f"{BASE_URL}/verify/{cert_id}"

    qr = qrcode.QRCode(version=1, box_size=4, border=1)
    qr.add_data(verify_url)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white")

    qr_buffer = io.BytesIO()
    qr_img.save(qr_buffer, format='PNG')
    qr_buffer.seek(0)
    qr_reader = ImageReader(qr_buffer)

    qr_size = 90
    qr_x = w / 2 - qr_size / 2
    qr_y = h - 445
    c.drawImage(qr_reader, qr_x, qr_y, width=qr_size, height=qr_size)

    c.setFont("Helvetica", 8)
    c.setFillColor(pal['text_muted'])
    c.drawCentredString(w / 2, qr_y - 12, "Scan to verify authenticity via public registry")

    # ── Cryptographic Signature & Hash Footer ──
    c.setStrokeColor(colors.HexColor('#e2e8f0'))
    c.setLineWidth(0.5)
    c.line(40, 50, w - 40, 50)

    c.setFont("Courier", 7)
    c.setFillColor(colors.HexColor('#64748b'))
    file_hash = cert.get('file_hash', '')
    c.drawString(45, 38, f"SHA-256 HASH: {file_hash}")

    sig = cert.get('signature', '')
    sig_display = (sig[:64] + '...') if len(sig) > 64 else sig
    c.drawString(45, 28, f"Ed25519 SIGNATURE: {sig_display}")

    c.drawRightString(w - 45, 28, "SECURED BY CERTVALID ENTERPRISE ARCHITECTURE")

    # Finalize PDF page
    c.showPage()
    c.save()
    buffer.seek(0)
    return buffer.getvalue()
