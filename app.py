"""
app.py - Flask application for the Certificate Verification & Management System.
Handles public verification (file upload or cert ID), admin dashboard, certificate issuance.
"""

import os
import io
import uuid
import hashlib
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, send_file, flash
)
from PIL import Image, ImageDraw, ImageFont
import qrcode

import db

# ─── App Setup ───────────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'certvalid-dev-secret-change-in-production')

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'static', 'uploads')
CERT_FOLDER   = os.path.join(os.path.dirname(__file__), 'static', 'certs')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(CERT_FOLDER,   exist_ok=True)

ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'pdf'}
MAX_FILE_SIZE_MB   = 10


# ─── Helpers ─────────────────────────────────────────────────────────────────

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin'))
        return f(*args, **kwargs)
    return decorated


def generate_certificate_image(cert_data: dict, cert_id: str) -> str:
    """
    Generate a certificate PNG image with embedded QR code.
    Returns the relative path (relative to static/) to the saved image.
    """
    W, H = 1100, 780
    img = Image.new('RGB', (W, H), color=(15, 15, 35))
    draw = ImageDraw.Draw(img)

    # Background gradient effect using rectangles
    for i in range(H):
        ratio = i / H
        r = int(15 + (30 - 15) * ratio)
        g = int(15 + (20 - 15) * ratio)
        b = int(35 + (60 - 35) * ratio)
        draw.line([(0, i), (W, i)], fill=(r, g, b))

    # Gold border
    border = 18
    draw.rectangle([border, border, W - border, H - border],
                   outline=(212, 175, 55), width=3)
    draw.rectangle([border + 6, border + 6, W - border - 6, H - border - 6],
                   outline=(212, 175, 55, 80), width=1)

    # Try to use a system font; fall back to default
    def try_font(size):
        for name in ['arialbd.ttf', 'Arial Bold.ttf', 'DejaVuSans-Bold.ttf', 'Arial.ttf']:
            try:
                return ImageFont.truetype(name, size)
            except Exception:
                pass
        return ImageFont.load_default()

    def try_font_regular(size):
        for name in ['arial.ttf', 'Arial.ttf', 'DejaVuSans.ttf']:
            try:
                return ImageFont.truetype(name, size)
            except Exception:
                pass
        return ImageFont.load_default()

    gold  = (212, 175, 55)
    white = (255, 255, 255)
    light = (180, 180, 210)

    # Header
    draw.text((W // 2, 55),  'CERTIFICATE OF COMPLETION',
              fill=gold, font=try_font(38), anchor='mm')
    draw.line([(100, 95), (W - 100, 95)], fill=gold, width=2)

    # Body
    draw.text((W // 2, 145), 'This is to certify that',
              fill=light, font=try_font_regular(20), anchor='mm')
    draw.text((W // 2, 210), cert_data['student_name'],
              fill=white, font=try_font(46), anchor='mm')
    draw.line([(200, 250), (W - 200, 250)], fill=gold, width=1)
    draw.text((W // 2, 290), 'has successfully completed the course',
              fill=light, font=try_font_regular(20), anchor='mm')
    draw.text((W // 2, 355), cert_data['course_name'],
              fill=gold, font=try_font(34), anchor='mm')

    # Footer info
    y_base = 450
    draw.text((200, y_base), 'Issued By', fill=light, font=try_font_regular(16), anchor='mm')
    draw.text((200, y_base + 28), cert_data['issuer_name'],
              fill=white, font=try_font(18), anchor='mm')

    draw.text((W // 2, y_base), 'Issue Date', fill=light, font=try_font_regular(16), anchor='mm')
    draw.text((W // 2, y_base + 28), cert_data['issue_date'],
              fill=white, font=try_font(18), anchor='mm')

    draw.text((870, y_base), 'Certificate ID', fill=light, font=try_font_regular(16), anchor='mm')
    draw.text((870, y_base + 28), cert_id,
              fill=white, font=try_font(14), anchor='mm')

    draw.line([(80, 530), (W - 80, 530)], fill=gold, width=1)

    # QR Code (verify URL)
    verify_url = f'http://127.0.0.1:5000/verify/{cert_id}'
    qr = qrcode.QRCode(version=1, box_size=6, border=2)
    qr.add_data(verify_url)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color='black', back_color='white').convert('RGB')
    qr_size = 150
    qr_img = qr_img.resize((qr_size, qr_size), Image.LANCZOS)
    qr_x = W // 2 - qr_size // 2
    qr_y = 555
    img.paste(qr_img, (qr_x, qr_y))

    draw.text((W // 2, qr_y + qr_size + 18),
              'Scan to verify authenticity',
              fill=light, font=try_font_regular(14), anchor='mm')

    # Hash fingerprint
    short_hash = cert_data['file_hash'][:32] + '...'
    draw.text((W // 2, H - 30),
              f'SHA-256: {short_hash}',
              fill=(100, 100, 140), font=try_font_regular(11), anchor='mm')

    # Save
    filename = f'{cert_id}.png'
    save_path = os.path.join(CERT_FOLDER, filename)
    img.save(save_path, 'PNG')
    return f'certs/{filename}'


# ─── Public Routes ────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('upload.html')


@app.route('/verify', methods=['POST'])
def verify():
    ip = request.remote_addr
    mode = request.form.get('mode', 'file')

    # ── Mode: verify by Certificate ID ──
    if mode == 'id':
        cert_id = request.form.get('cert_id', '').strip().upper()
        if not cert_id:
            flash('Please enter a Certificate ID.', 'error')
            return redirect(url_for('index'))

        cert = db.get_certificate_by_id(cert_id)
        if not cert:
            db.log_verification(cert_id, None, None, 'INVALID',
                                'Certificate ID not found in registry.', ip)
            return render_template('result.html',
                                   status='INVALID',
                                   reason='Certificate ID not found in the registry.',
                                   cert=None, mode='id',
                                   computed_hash=None,
                                   verified_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

        if cert['status'] == 'revoked':
            db.log_verification(cert_id, None, None, 'REVOKED',
                                'Certificate has been revoked.', ip)
            return render_template('result.html',
                                   status='REVOKED',
                                   reason='This certificate has been officially revoked.',
                                   cert=cert, mode='id',
                                   computed_hash=None,
                                   verified_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

        db.log_verification(cert_id, None, None, 'AUTHENTIC',
                            'Valid certificate ID found in registry.', ip)
        return render_template('result.html',
                               status='AUTHENTIC',
                               reason='Certificate ID verified successfully.',
                               cert=cert, mode='id',
                               computed_hash=None,
                               verified_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    # ── Mode: verify by file upload ──
    if 'certificate' not in request.files or request.files['certificate'].filename == '':
        flash('No file selected for upload.', 'error')
        return redirect(url_for('index'))

    file = request.files['certificate']

    if not allowed_file(file.filename):
        flash('Unsupported file type. Please upload JPG, PNG, or PDF.', 'error')
        return redirect(url_for('index'))

    file_bytes = file.read()
    if len(file_bytes) > MAX_FILE_SIZE_MB * 1024 * 1024:
        flash(f'File too large. Max size is {MAX_FILE_SIZE_MB} MB.', 'error')
        return redirect(url_for('index'))

    computed_hash = db.compute_file_hash(file_bytes)
    cert = db.get_certificate_by_hash(computed_hash)
    filename = file.filename
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if not cert:
        # Check if any cert exists with this hash (status=revoked)
        db.log_verification(None, filename, computed_hash, 'INVALID',
                            'No matching certificate found. File may be tampered or unregistered.', ip)
        return render_template('result.html',
                               status='INVALID',
                               reason='No matching certificate found in the registry. The file may have been tampered with or was never issued.',
                               cert=None, mode='file',
                               computed_hash=computed_hash,
                               verified_at=now_str)

    if cert['status'] == 'revoked':
        db.log_verification(cert['cert_id'], filename, computed_hash, 'REVOKED',
                            'Certificate has been revoked.', ip)
        return render_template('result.html',
                               status='REVOKED',
                               reason='This certificate has been officially revoked by the issuing authority.',
                               cert=cert, mode='file',
                               computed_hash=computed_hash,
                               verified_at=now_str)

    db.log_verification(cert['cert_id'], filename, computed_hash, 'AUTHENTIC',
                        'File hash matches registry. No tampering detected.', ip)
    return render_template('result.html',
                           status='AUTHENTIC',
                           reason='File hash matches the registry. No tampering detected.',
                           cert=cert, mode='file',
                           computed_hash=computed_hash,
                           verified_at=now_str)


@app.route('/verify/<cert_id>')
def verify_by_id(cert_id):
    """QR code scan endpoint — direct link verification."""
    ip = request.remote_addr
    cert_id = cert_id.strip().upper()
    cert = db.get_certificate_by_id(cert_id)
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if not cert:
        db.log_verification(cert_id, None, None, 'INVALID', 'QR scan: ID not found.', ip)
        return render_template('result.html',
                               status='INVALID',
                               reason='Certificate ID not found in the registry.',
                               cert=None, mode='id',
                               computed_hash=None,
                               verified_at=now_str)

    if cert['status'] == 'revoked':
        db.log_verification(cert_id, None, None, 'REVOKED', 'QR scan: certificate revoked.', ip)
        return render_template('result.html',
                               status='REVOKED',
                               reason='This certificate has been officially revoked.',
                               cert=cert, mode='id',
                               computed_hash=None,
                               verified_at=now_str)

    db.log_verification(cert_id, None, None, 'AUTHENTIC', 'QR scan: certificate verified.', ip)
    return render_template('result.html',
                           status='AUTHENTIC',
                           reason='Certificate verified via QR code.',
                           cert=cert, mode='id',
                           computed_hash=None,
                           verified_at=now_str)


@app.route('/download/<cert_id>')
def download_cert(cert_id):
    """Download the generated certificate PNG image."""
    cert_id = cert_id.strip().upper()
    cert_path = os.path.join(CERT_FOLDER, f'{cert_id}.png')
    if not os.path.exists(cert_path):
        flash('Certificate image not available for download.', 'error')
        return redirect(url_for('index'))
    return send_file(cert_path, as_attachment=True, download_name=f'Certificate_{cert_id}.png')


# ─── Admin Routes ─────────────────────────────────────────────────────────────

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'login':
            username = request.form.get('username', '')
            password = request.form.get('password', '')
            if db.verify_admin(username, password):
                session['admin_logged_in'] = True
                session['admin_user'] = username
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Invalid username or password.', 'error')
                return render_template('admin.html', logged_in=False)

    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard'))

    return render_template('admin.html', logged_in=False)


@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    certs = db.get_all_certificates()
    logs  = db.get_all_logs(50)
    stats = db.get_stats()
    return render_template('admin.html', logged_in=True,
                           certs=certs, logs=logs, stats=stats,
                           active_tab='overview')


@app.route('/admin/issue', methods=['POST'])
@login_required
def admin_issue():
    student_name = request.form.get('student_name', '').strip()
    course_name  = request.form.get('course_name', '').strip()
    issue_date   = request.form.get('issue_date', '').strip()
    issuer_name  = request.form.get('issuer_name', '').strip()

    if not all([student_name, course_name, issue_date, issuer_name]):
        flash('All fields are required to issue a certificate.', 'error')
        return redirect(url_for('admin_dashboard'))

    # Generate a stable unique file_hash for this certificate record
    unique_seed = f'{student_name}|{course_name}|{issue_date}|{issuer_name}|{uuid.uuid4()}'
    file_hash = hashlib.sha256(unique_seed.encode()).hexdigest()

    cert_id = db.add_certificate(student_name, course_name, issue_date, issuer_name, file_hash)

    cert_data = {
        'student_name': student_name,
        'course_name':  course_name,
        'issue_date':   issue_date,
        'issuer_name':  issuer_name,
        'file_hash':    file_hash,
    }
    try:
        generate_certificate_image(cert_data, cert_id)
    except Exception as e:
        app.logger.error(f'Certificate image generation failed: {e}')

    flash(f'Certificate issued successfully! ID: {cert_id}', 'success')
    return redirect(url_for('admin_dashboard') + '?tab=registry')


@app.route('/admin/revoke/<cert_id>', methods=['POST'])
@login_required
def admin_revoke(cert_id):
    cert_id = cert_id.strip().upper()
    db.revoke_certificate(cert_id)
    flash(f'Certificate {cert_id} has been revoked.', 'warning')
    return redirect(url_for('admin_dashboard') + '?tab=registry')


@app.route('/admin/reactivate/<cert_id>', methods=['POST'])
@login_required
def admin_reactivate(cert_id):
    cert_id = cert_id.strip().upper()
    db.reactivate_certificate(cert_id)
    flash(f'Certificate {cert_id} has been reactivated.', 'success')
    return redirect(url_for('admin_dashboard') + '?tab=registry')


@app.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect(url_for('admin'))


# ─── App Entry ────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    db.init_db()
    app.run(debug=True)