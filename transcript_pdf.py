"""
transcript_pdf.py - Vector PDF Academic Transcript Generator for CertValid.
Generates print-ready portrait PDF transcripts featuring institutional headers,
itemized course matrix table, embedded verification QR code, and cryptographic attestation.
"""

import io
import os
import qrcode
from PIL import Image

try:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.utils import ImageReader
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

BASE_URL = os.environ.get('BASE_URL', 'https://ranjithbrs.pythonanywhere.com').rstrip('/')


def _safe_str(val) -> str:
    """Sanitize strings so they are safe for ReportLab standard fonts without raising UnicodeEncodeError."""
    if val is None:
        return ""
    return str(val).encode('latin-1', 'replace').decode('latin-1')


def generate_transcript_pdf(bundle: dict) -> bytes:
    """
    Generate an official portrait vector PDF academic transcript document using ReportLab.
    Returns the binary content (bytes) of the generated PDF file.
    """
    if not HAS_REPORTLAB:
        raise RuntimeError("ReportLab library is not installed.")

    buffer = io.BytesIO()
    # 8.5 x 11 inches portrait (612 x 792 pt)
    w, h = letter
    c = canvas.Canvas(buffer, pagesize=letter)

    primary_color   = colors.HexColor('#1e293b')  # Slate 800
    accent_color    = colors.HexColor('#6366f1')  # Indigo
    gold_color      = colors.HexColor('#d4af37')  # Gold
    emerald_color   = colors.HexColor('#10b981')  # Emerald
    red_color       = colors.HexColor('#ef4444')  # Red
    border_color    = colors.HexColor('#cbd5e1')  # Slate 300
    text_dark       = colors.HexColor('#0f172a')  # Slate 900
    text_muted      = colors.HexColor('#64748b')  # Slate 500

    # ── Background Tint ──
    c.setFillColor(colors.HexColor('#f8fafc'))
    c.rect(0, 0, w, h, fill=True, stroke=False)

    # ── Double Outer Border ──
    c.setStrokeColor(primary_color)
    c.setLineWidth(2.5)
    c.rect(24, 24, w - 48, h - 48)

    c.setStrokeColor(gold_color)
    c.setLineWidth(1.0)
    c.rect(30, 30, w - 60, h - 60)

    # Corner Decorative Marks
    corner_sz = 10
    for cx, cy in [(30, 30), (w - 30 - corner_sz, 30), (30, h - 30 - corner_sz), (w - 30 - corner_sz, h - 30 - corner_sz)]:
        c.setFillColor(gold_color)
        c.rect(cx, cy, corner_sz, corner_sz, fill=True, stroke=False)

    # ── Header Banner ──
    # Top institutional badge
    c.setFillColor(primary_color)
    c.rect(40, h - 110, w - 80, 65, fill=True, stroke=False)

    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 16)
    inst_title = _safe_str(bundle.get('institution_name', 'CERTVALLID ACADEMIC AUTHORITY').upper())
    c.drawCentredString(w / 2, h - 70, inst_title)

    c.setFillColor(gold_color)
    c.setFont("Helvetica-Bold", 10)
    c.drawCentredString(w / 2, h - 86, "OFFICIAL ACADEMIC TRANSCRIPT & CREDENTIAL RECORD")

    c.setFillColor(colors.HexColor('#94a3b8'))
    c.setFont("Helvetica", 8)
    c.drawCentredString(w / 2, h - 100, f"TRANSCRIPT ID: {bundle.get('bundle_id')}  |  ISSUED: {bundle.get('issue_date')}")

    # ── Transcript Title ──
    c.setFillColor(text_dark)
    c.setFont("Helvetica-Bold", 15)
    transcript_title = _safe_str(bundle.get('title', 'Academic & Professional Transcript'))
    c.drawCentredString(w / 2, h - 140, transcript_title)

    # ── Candidate Information Card ──
    card_y = h - 215
    card_h = 60
    c.setFillColor(colors.HexColor('#ffffff'))
    c.setStrokeColor(border_color)
    c.setLineWidth(1)
    c.roundRect(40, card_y, w - 80, card_h, 6, fill=True, stroke=True)

    # Candidate Name & Details
    c.setFillColor(text_muted)
    c.setFont("Helvetica-Bold", 8)
    c.drawString(55, card_y + 42, "CANDIDATE / RECIPIENT NAME")
    c.drawString(55, card_y + 16, "EMAIL / CANDIDATE ID")

    c.drawString(w / 2 - 20, card_y + 42, "TOTAL CREDENTIALS")
    c.drawString(w / 2 - 20, card_y + 16, "OVERALL VALIDITY STATUS")

    c.setFillColor(text_dark)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(55, card_y + 28, _safe_str(bundle.get('recipient_name', 'N/A')))

    c.setFont("Helvetica", 9)
    c.drawString(55, card_y + 4, _safe_str(bundle.get('recipient_email') or 'Verified Identity'))

    c.setFont("Helvetica-Bold", 12)
    c.drawString(w / 2 - 20, card_y + 28, f"{bundle.get('total_certs', 0)} Credential(s)")

    status_str = bundle.get('overall_status', 'AUTHENTIC')
    if status_str == 'AUTHENTIC':
        c.setFillColor(emerald_color)
        status_label = "[AUTHENTIC] ALL CREDENTIALS VALID"
    elif status_str == 'REVOKED':
        c.setFillColor(red_color)
        status_label = "[REVOKED] TRANSCRIPT REVOKED"
    else:
        c.setFillColor(colors.HexColor('#d97706'))
        status_label = f"[{status_str}] ATTENTION REQUIRED"

    c.setFont("Helvetica-Bold", 9)
    c.drawString(w / 2 - 20, card_y + 4, status_label)

    # ── Itemized Course & Credential Matrix Table ──
    table_top = card_y - 25
    c.setFillColor(primary_color)
    c.setFont("Helvetica-Bold", 11)
    c.drawString(42, table_top, "ITEMIZED CREDENTIAL MATRIX")

    # Table Header Row
    th_y = table_top - 20
    c.setFillColor(colors.HexColor('#e2e8f0'))
    c.rect(40, th_y, w - 80, 18, fill=True, stroke=False)

    c.setFillColor(primary_color)
    c.setFont("Helvetica-Bold", 8)
    c.drawString(45, th_y + 5, "#")
    c.drawString(65, th_y + 5, "COURSE / PROGRAMME TITLE")
    c.drawString(290, th_y + 5, "CREDENTIAL ID")
    c.drawString(400, th_y + 5, "ISSUE DATE")
    c.drawString(475, th_y + 5, "STATUS")

    # Table Data Rows
    row_y = th_y - 20
    certs = bundle.get('certificates', [])
    for idx, cert in enumerate(certs[:12], start=1):
        # Alternating background
        if idx % 2 == 0:
            c.setFillColor(colors.HexColor('#f1f5f9'))
            c.rect(40, row_y, w - 80, 18, fill=True, stroke=False)

        c.setFillColor(text_muted)
        c.setFont("Helvetica", 8)
        c.drawString(45, row_y + 5, str(idx))

        c.setFillColor(text_dark)
        c.setFont("Helvetica-Bold", 8.5)
        cname = _safe_str(cert.get('course_name', 'N/A'))
        if len(cname) > 38:
            cname = cname[:36] + '..'
        c.drawString(65, row_y + 5, cname)

        c.setFont("Helvetica", 8)
        c.drawString(290, row_y + 5, _safe_str(cert.get('cert_id', 'N/A')))
        c.drawString(400, row_y + 5, _safe_str(cert.get('issue_date', 'N/A')))

        c_status = cert.get('effective_status', cert.get('status', 'active')).upper()
        if c_status == 'ACTIVE':
            c.setFillColor(emerald_color)
            c.setFont("Helvetica-Bold", 8)
            c.drawString(475, row_y + 5, "VERIFIED")
        elif c_status == 'REVOKED':
            c.setFillColor(red_color)
            c.setFont("Helvetica-Bold", 8)
            c.drawString(475, row_y + 5, "REVOKED")
        elif c_status == 'EXPIRED':
            c.setFillColor(colors.HexColor('#d97706'))
            c.setFont("Helvetica-Bold", 8)
            c.drawString(475, row_y + 5, "EXPIRED")
        else:
            c.setFillColor(text_muted)
            c.setFont("Helvetica", 8)
            c.drawString(475, row_y + 5, c_status)

        row_y -= 20

    # ── Cryptographic Verification Box ──
    crypto_box_y = 120
    crypto_box_h = 100
    c.setFillColor(colors.HexColor('#ffffff'))
    c.setStrokeColor(border_color)
    c.setLineWidth(1)
    c.roundRect(40, crypto_box_y, w - 80, crypto_box_h, 6, fill=True, stroke=True)

    # Section Title
    c.setFillColor(primary_color)
    c.setFont("Helvetica-Bold", 9)
    c.drawString(55, crypto_box_y + crypto_box_h - 18, "CRYPTOGRAPHIC INTEGRITY & BUNDLE ATTESTATION")

    # Hash
    c.setFillColor(text_muted)
    c.setFont("Helvetica", 7.5)
    c.drawString(55, crypto_box_y + crypto_box_h - 32, "Bundle SHA-256 Digest:")
    c.setFillColor(primary_color)
    c.setFont("Courier", 7.5)
    c.drawString(55, crypto_box_y + crypto_box_h - 44, _safe_str(bundle.get('bundle_hash', 'N/A')))

    # Signature
    c.setFillColor(text_muted)
    c.setFont("Helvetica", 7.5)
    c.drawString(55, crypto_box_y + crypto_box_h - 58, "Ed25519 Asymmetric Digital Signature:")
    c.setFillColor(primary_color)
    c.setFont("Courier", 7.5)
    sig_str = _safe_str(bundle.get('signature', 'N/A'))
    if len(sig_str) > 70:
        sig_str = sig_str[:68] + '...'
    c.drawString(55, crypto_box_y + crypto_box_h - 70, sig_str)

    # Verification URL
    verify_url = f"{BASE_URL}/transcript/{bundle.get('bundle_id')}"
    c.setFillColor(text_muted)
    c.setFont("Helvetica", 7.5)
    c.drawString(55, crypto_box_y + crypto_box_h - 84, "Public Verification URL:")
    c.setFillColor(accent_color)
    c.setFont("Helvetica-Bold", 7.5)
    c.drawString(160, crypto_box_y + crypto_box_h - 84, verify_url)

    # QR Code inside box
    qr_size = 76
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=4,
        border=1,
    )
    qr.add_data(verify_url)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="#0f172a", back_color="#ffffff").convert('RGB')

    qr_io = io.BytesIO()
    qr_img.save(qr_io, format='PNG')
    qr_io.seek(0)
    c.drawImage(ImageReader(qr_io), w - 40 - qr_size - 12, crypto_box_y + (crypto_box_h - qr_size) / 2, width=qr_size, height=qr_size)

    # ── Registrar & Seal Sign-off ──
    c.setFillColor(text_muted)
    c.setFont("Helvetica", 7)
    c.drawCentredString(w / 2, 82, "This academic transcript is an official tamper-evident cryptographic document issued by CertValid.")
    c.drawCentredString(w / 2, 70, "Scan the embedded QR code or visit the verification URL to validate authenticity in real time.")

    # Bottom border line
    c.setStrokeColor(gold_color)
    c.setLineWidth(1)
    c.line(40, 56, w - 40, 56)

    c.setFillColor(text_muted)
    c.setFont("Helvetica-Bold", 7)
    c.drawString(45, 42, "CERTVALLID VERIFIABLE CREDENTIALS PLATFORM")
    c.drawRightString(w - 45, 42, "PAGE 1 OF 1  |  CRYPTOGRAPHICALLY SEALED")

    c.save()
    buffer.seek(0)
    return buffer.getvalue()
