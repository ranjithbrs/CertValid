"""
app.py - Flask application for the Certificate Verification & Management System.
Handles public verification (file upload or cert ID), admin dashboard, certificate issuance.
Includes rate limiting, anti-spam, security headers, pHash, OCR text extraction, Ed25519 digital signatures, and Cloud Storage.
"""

import os
import io
import uuid
import hashlib
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, send_file, flash
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from PIL import Image, ImageDraw, ImageFont
import qrcode
import imagehash

import db
import storage

# ─── App Setup ───────────────────────────────────────────────────────────────

app = Flask(__name__)

_secret = os.environ.get('SECRET_KEY', '')
if not _secret:
    import secrets
    _secret = secrets.token_hex(32)
app.secret_key = _secret

# Session expires after 1 hour of inactivity
app.permanent_session_lifetime = timedelta(hours=1)

# Rate Limiter setup
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'static', 'uploads')
CERT_FOLDER   = os.path.join(os.path.dirname(__file__), 'static', 'certs')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(CERT_FOLDER,   exist_ok=True)

ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'pdf'}
MAX_FILE_SIZE_MB   = 10

# Base URL for QR codes — reads from env var so live site uses the real domain
BASE_URL = os.environ.get('BASE_URL', 'https://ranjithbrs.pythonanywhere.com').rstrip('/')


# ─── Security Response Headers Middleware ────────────────────────────────────

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response


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
    Computes and stores its perceptual hash (pHash) and uploads to S3 if configured.
    Returns the relative path (relative to static/) to the saved image.
    """
    W, H = 1100, 780

    try:
        import numpy as np
        arr = np.zeros((H, W, 3), dtype=np.uint8)
        for i in range(H):
            ratio = i / H
            arr[i, :] = [
                int(15 + 15 * ratio),
                int(15 +  5 * ratio),
                int(35 + 25 * ratio),
            ]
        img = Image.fromarray(arr, 'RGB')
    except ImportError:
        img = Image.new('RGB', (W, H), color=(15, 15, 35))
        top = Image.new('RGB', (W, H // 2), color=(15, 15, 35))
        bot = Image.new('RGB', (W, H // 2), color=(30, 20, 60))
        img.paste(top, (0, 0))
        img.paste(bot, (0, H // 2))

    draw = ImageDraw.Draw(img)

    border = 18
    draw.rectangle([border, border, W - border, H - border],
                   outline=(212, 175, 55), width=3)
    draw.rectangle([border + 6, border + 6, W - border - 6, H - border - 6],
                   outline=(212, 175, 55), width=1)

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

    draw.text((W // 2, 55), 'CERTIFICATE OF COMPLETION',
              fill=gold, font=try_font(38), anchor='mm')
    draw.line([(100, 95), (W - 100, 95)], fill=gold, width=2)

    draw.text((W // 2, 145), 'This is to certify that',
              fill=light, font=try_font_regular(20), anchor='mm')
    draw.text((W // 2, 210), cert_data['student_name'],
              fill=white, font=try_font(46), anchor='mm')
    draw.line([(200, 250), (W - 200, 250)], fill=gold, width=1)
    draw.text((W // 2, 290), 'has successfully completed the course',
              fill=light, font=try_font_regular(20), anchor='mm')
    draw.text((W // 2, 355), cert_data['course_name'],
              fill=gold, font=try_font(34), anchor='mm')

    y_base = 450
    draw.text((200, y_base),       'Issued By',           fill=light, font=try_font_regular(16), anchor='mm')
    draw.text((200, y_base + 28),  cert_data['issuer_name'], fill=white, font=try_font(18), anchor='mm')
    draw.text((W // 2, y_base),    'Issue Date',          fill=light, font=try_font_regular(16), anchor='mm')
    draw.text((W // 2, y_base + 28), cert_data['issue_date'], fill=white, font=try_font(18), anchor='mm')
    draw.text((870, y_base),       'Certificate ID',      fill=light, font=try_font_regular(16), anchor='mm')
    draw.text((870, y_base + 28),  cert_id,               fill=white, font=try_font(14), anchor='mm')

    draw.line([(80, 530), (W - 80, 530)], fill=gold, width=1)

    verify_url = f'{BASE_URL}/verify/{cert_id}'
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

    short_hash = cert_data['file_hash'][:32] + '...'
    draw.text((W // 2, H - 30),
              f'SHA-256: {short_hash}',
              fill=(100, 100, 140), font=try_font_regular(11), anchor='mm')

    filename  = f'{cert_id}.png'
    save_path = os.path.join(CERT_FOLDER, filename)
    img.save(save_path, 'PNG')

    # Cloud Storage S3 upload (if configured via S3_BUCKET_NAME)
    storage.upload_to_s3(save_path)

    try:
        phash_str = str(imagehash.phash(img))
        db.update_certificate_phash(cert_id, phash_str)
    except Exception as e:
        app.logger.error(f'Failed to compute/update pHash for {cert_id}: {e}')

    return f'certs/{filename}'


# ─── Error Handlers ──────────────────────────────────────────────────────────

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', code=404,
                           title='Page Not Found',
                           message='The page you are looking for does not exist.'), 404


@app.errorhandler(500)
def internal_error(e):
    return render_template('error.html', code=500,
                           title='Server Error',
                           message='Something went wrong on our end. Please try again.'), 500


@app.errorhandler(429)
def rate_limit_exceeded(e):
    return render_template('error.html', code=429,
                           title='Rate Limit Exceeded',
                           message='Too many requests from your IP. Please slow down and try again in a few minutes.'), 429


# ─── Public Routes ────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('upload.html')


@app.route('/verify', methods=['POST'])
@limiter.limit("10 per minute")
def verify():
    ip      = request.remote_addr
    mode    = request.form.get('mode', 'file')
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    pub_key_b64 = db.get_public_key_b64()

    # ── Verify by Certificate ID ──
    if mode == 'id':
        cert_id = request.form.get('cert_id', '').strip().upper()
        if not cert_id:
            flash('Please enter a Certificate ID.', 'error')
            return redirect(url_for('index'))

        cert = db.get_certificate_by_id(cert_id)
        if not cert:
            db.log_verification(cert_id, None, None, 'INVALID',
                                'Certificate ID not found in registry.', ip)
            return render_template('result.html', status='INVALID',
                                   reason='Certificate ID not found in the registry.',
                                   cert=None, mode='id', computed_hash=None,
                                   computed_phash=None, match_type=None, visual_similarity=0.0,
                                   ocr_cert_id=None, signature_valid=False, public_key_b64=pub_key_b64,
                                   verified_at=now_str)

        sig_valid = False
        if cert and cert.get('signature'):
            payload = db.build_cert_payload(cert['cert_id'], cert['student_name'], cert['course_name'], cert['issue_date'], cert['file_hash'])
            sig_valid = db.verify_payload_signature(payload, cert['signature'])

        if cert['status'] == 'revoked':
            db.log_verification(cert_id, None, None, 'REVOKED',
                                'Certificate has been revoked.', ip)
            return render_template('result.html', status='REVOKED',
                                   reason='This certificate has been officially revoked.',
                                   cert=cert, mode='id', computed_hash=None,
                                   computed_phash=None, match_type=None, visual_similarity=0.0,
                                   ocr_cert_id=None, signature_valid=sig_valid, public_key_b64=pub_key_b64,
                                   verified_at=now_str)

        db.log_verification(cert_id, None, None, 'AUTHENTIC',
                            'Valid certificate ID found in registry.', ip)
        return render_template('result.html', status='AUTHENTIC',
                               reason='Certificate ID verified successfully.',
                               cert=cert, mode='id', computed_hash=None,
                               computed_phash=None, match_type='exact', visual_similarity=100.0,
                               ocr_cert_id=None, signature_valid=sig_valid, public_key_b64=pub_key_b64,
                               verified_at=now_str)

    # ── Verify by File Upload ──
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

    filename       = file.filename
    computed_hash  = db.compute_file_hash(file_bytes)
    computed_phash = db.compute_file_phash(file_bytes)
    ocr_cert_id    = None

    # Tier 1: Try exact SHA-256 byte hash match
    cert = db.get_certificate_by_hash(computed_hash)
    match_type = 'exact'
    similarity = 100.0

    # Tier 2: If SHA-256 misses, try Perceptual Hash (pHash) visual similarity match
    if not cert and computed_phash:
        phash_match, dist, sim = db.get_certificate_by_phash(computed_phash, max_distance=10)
        if phash_match:
            cert = phash_match
            match_type = 'visual'
            similarity = sim

    # Tier 3: If Tiers 1 & 2 miss, perform OCR / PDF text extraction & Regex match
    if not cert:
        extracted_text = db.extract_text_from_file(file_bytes, filename)
        ocr_cert_id = db.extract_cert_id_from_text(extracted_text)
        if ocr_cert_id:
            ocr_cert = db.get_certificate_by_id(ocr_cert_id)
            if ocr_cert:
                cert = ocr_cert
                match_type = 'ocr'
                similarity = 100.0

    sig_valid = False
    if cert and cert.get('signature'):
        payload = db.build_cert_payload(cert['cert_id'], cert['student_name'], cert['course_name'], cert['issue_date'], cert['file_hash'])
        sig_valid = db.verify_payload_signature(payload, cert['signature'])

    if not cert:
        db.log_verification(None, filename, computed_hash, 'INVALID',
                            'No matching certificate found by SHA-256, visual pHash, or OCR text.', ip)
        return render_template('result.html', status='INVALID',
                               reason='No matching certificate found in the registry. '
                                      'The file may have been altered significantly or was never issued.',
                               cert=None, mode='file', computed_hash=computed_hash,
                               computed_phash=computed_phash, match_type=None, visual_similarity=0.0,
                               ocr_cert_id=None, signature_valid=False, public_key_b64=pub_key_b64,
                               verified_at=now_str)

    if cert['status'] == 'revoked':
        db.log_verification(cert['cert_id'], filename, computed_hash, 'REVOKED',
                            'Certificate has been revoked.', ip)
        return render_template('result.html', status='REVOKED',
                               reason='This certificate has been officially revoked by the issuing authority.',
                               cert=cert, mode='file', computed_hash=computed_hash,
                               computed_phash=computed_phash, match_type=match_type,
                               visual_similarity=similarity, ocr_cert_id=ocr_cert_id,
                               signature_valid=sig_valid, public_key_b64=pub_key_b64,
                               verified_at=now_str)

    if match_type == 'exact':
        reason = 'File hash matches the registry exactly (100% byte-perfect).'
    elif match_type == 'visual':
        reason = f'Visual content matches registered certificate ({similarity}% visual similarity).'
    else:
        reason = f'Certificate ID ({ocr_cert_id}) successfully extracted from document text via OCR/PDF parsing.'

    db.log_verification(cert['cert_id'], filename, computed_hash, 'AUTHENTIC', reason, ip)
    return render_template('result.html', status='AUTHENTIC',
                           reason=reason, cert=cert, mode='file',
                           computed_hash=computed_hash, computed_phash=computed_phash,
                           match_type=match_type, visual_similarity=similarity,
                           ocr_cert_id=ocr_cert_id, signature_valid=sig_valid,
                           public_key_b64=pub_key_b64, verified_at=now_str)


@app.route('/verify/<cert_id>')
def verify_by_id(cert_id):
    """QR code scan endpoint — direct link verification."""
    ip      = request.remote_addr
    cert_id = cert_id.strip().upper()
    cert    = db.get_certificate_by_id(cert_id)
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    pub_key_b64 = db.get_public_key_b64()

    sig_valid = False
    if cert and cert.get('signature'):
        payload = db.build_cert_payload(cert['cert_id'], cert['student_name'], cert['course_name'], cert['issue_date'], cert['file_hash'])
        sig_valid = db.verify_payload_signature(payload, cert['signature'])

    if not cert:
        db.log_verification(cert_id, None, None, 'INVALID', 'QR scan: ID not found.', ip)
        return render_template('result.html', status='INVALID',
                               reason='Certificate ID not found in the registry.',
                               cert=None, mode='id', computed_hash=None,
                               computed_phash=None, match_type=None, visual_similarity=0.0,
                               ocr_cert_id=None, signature_valid=False, public_key_b64=pub_key_b64,
                               verified_at=now_str)

    if cert['status'] == 'revoked':
        db.log_verification(cert_id, None, None, 'REVOKED', 'QR scan: certificate revoked.', ip)
        return render_template('result.html', status='REVOKED',
                               reason='This certificate has been officially revoked.',
                               cert=cert, mode='id', computed_hash=None,
                               computed_phash=None, match_type=None, visual_similarity=0.0,
                               ocr_cert_id=None, signature_valid=sig_valid, public_key_b64=pub_key_b64,
                               verified_at=now_str)

    db.log_verification(cert_id, None, None, 'AUTHENTIC', 'QR scan: certificate verified.', ip)
    return render_template('result.html', status='AUTHENTIC',
                           reason='Certificate verified via QR code.',
                           cert=cert, mode='id', computed_hash=None,
                           computed_phash=None, match_type='exact', visual_similarity=100.0,
                           ocr_cert_id=None, signature_valid=sig_valid, public_key_b64=pub_key_b64,
                           verified_at=now_str)


@app.route('/download/<cert_id>')
def download_cert(cert_id):
    """Download the generated certificate PNG image, generating it on-the-fly if needed."""
    cert_id   = cert_id.strip().upper()
    cert_path = os.path.join(CERT_FOLDER, f'{cert_id}.png')

    if not os.path.exists(cert_path):
        cert = db.get_certificate_by_id(cert_id)
        if cert:
            try:
                generate_certificate_image(cert, cert_id)
            except Exception as e:
                app.logger.error(f'Dynamic image generation failed: {e}')
                flash('Certificate image generation failed.', 'error')
                return redirect(url_for('index'))
        else:
            flash('Certificate not found.', 'error')
            return redirect(url_for('index'))

    return send_file(cert_path, as_attachment=True,
                     download_name=f'Certificate_{cert_id}.png')


# ─── Admin Routes ─────────────────────────────────────────────────────────────

@app.route('/admin', methods=['GET', 'POST'])
@limiter.limit("5 per 5 minutes", methods=["POST"])
def admin():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        if db.verify_admin(username, password):
            session.permanent = True
            session['admin_logged_in'] = True
            session['admin_user'] = username
            return redirect(url_for('admin_dashboard'))
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
    course_name  = request.form.get('course_name',  '').strip()
    issue_date   = request.form.get('issue_date',   '').strip()
    issuer_name  = request.form.get('issuer_name',  '').strip()

    if not all([student_name, course_name, issue_date, issuer_name]):
        flash('All fields are required to issue a certificate.', 'error')
        return redirect(url_for('admin_dashboard'))

    unique_seed = f'{student_name}|{course_name}|{issue_date}|{issuer_name}|{uuid.uuid4()}'
    file_hash   = hashlib.sha256(unique_seed.encode()).hexdigest()
    cert_id     = db.add_certificate(student_name, course_name, issue_date, issuer_name, file_hash)

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

    flash(f'Certificate issued successfully with Ed25519 digital signature! ID: {cert_id}', 'success')
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
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(debug=debug_mode)