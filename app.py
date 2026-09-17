"""
app.py - Flask application for the Certificate Verification & Management System.
Handles public verification (file upload or cert ID), admin dashboard, certificate issuance.
Includes rate limiting, anti-spam, security headers, pHash, OCR text extraction, Ed25519 digital signatures, Cloud Storage, and RBAC Multi-Role Access Control.
"""

import os
import io
import uuid
import csv
import zipfile
import hashlib
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, send_file, flash, jsonify,
    Response, make_response
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
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Initialize database schema, migrations, and Ed25519 keys on app load (WSGI compatible)
db.init_db()

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


# ─── Helpers & RBAC Decorators ───────────────────────────────────────────────

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin'))
        return f(*args, **kwargs)
    return decorated


def role_required(*permitted_roles):
    """RBAC decorator restricting route access to specified roles."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not session.get('admin_logged_in'):
                return redirect(url_for('admin'))
            user_role = session.get('admin_role', 'superadmin')
            if user_role not in permitted_roles:
                flash(f'Access denied. Your role ({user_role}) does not have permission for this action.', 'error')
                return redirect(url_for('admin_dashboard'))
            return f(*args, **kwargs)
        return decorated
    return decorator


def api_key_required(f):
    """Decorator to require a valid API key via X-API-Key header or Bearer token."""
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            auth_header = request.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                api_key = auth_header.split('Bearer ', 1)[1].strip()

        if not api_key:
            api_key = request.args.get('api_key')

        if not api_key or not db.validate_api_key(api_key):
            return jsonify({
                'error': 'Unauthorized',
                'message': 'Invalid or missing API key. Provide header X-API-Key or Authorization: Bearer <key>.'
            }), 401

        return f(*args, **kwargs)
    return decorated


def generate_certificate_image(cert_data: dict, cert_id: str) -> str:
    """
    Generate a certificate PNG image with embedded QR code.
    Reads active visual theme (gold, emerald, navy, ruby, monochrome) from system settings.
    Computes and stores its perceptual hash (pHash) and uploads to S3 if configured.
    Returns the relative path (relative to static/) to the saved image.
    """
    W, H = 1100, 780

    THEMES = {
        'gold': {
            'bg_start': (15, 15, 35),
            'bg_end': (30, 20, 60),
            'accent': (212, 175, 55),
            'light': (180, 180, 210),
            'white': (255, 255, 255),
        },
        'emerald': {
            'bg_start': (10, 30, 25),
            'bg_end': (20, 50, 45),
            'accent': (16, 185, 129),
            'light': (160, 210, 190),
            'white': (255, 255, 255),
        },
        'navy': {
            'bg_start': (15, 23, 42),
            'bg_end': (30, 41, 59),
            'accent': (59, 130, 246),
            'light': (148, 163, 184),
            'white': (255, 255, 255),
        },
        'ruby': {
            'bg_start': (40, 10, 20),
            'bg_end': (60, 20, 35),
            'accent': (239, 68, 68),
            'light': (220, 170, 180),
            'white': (255, 255, 255),
        },
        'monochrome': {
            'bg_start': (24, 24, 27),
            'bg_end': (39, 39, 42),
            'accent': (226, 232, 240),
            'light': (161, 161, 170),
            'white': (255, 255, 255),
        }
    }

    theme_name = db.get_setting('cert_theme', 'gold')
    p = THEMES.get(theme_name, THEMES['gold'])

    try:
        import numpy as np
        arr = np.zeros((H, W, 3), dtype=np.uint8)
        for i in range(H):
            ratio = i / H
            arr[i, :] = [
                int(p['bg_start'][0] + (p['bg_end'][0] - p['bg_start'][0]) * ratio),
                int(p['bg_start'][1] + (p['bg_end'][1] - p['bg_start'][1]) * ratio),
                int(p['bg_start'][2] + (p['bg_end'][2] - p['bg_start'][2]) * ratio),
            ]
        img = Image.fromarray(arr, 'RGB')
    except ImportError:
        img = Image.new('RGB', (W, H), color=p['bg_start'])
        top = Image.new('RGB', (W, H // 2), color=p['bg_start'])
        bot = Image.new('RGB', (W, H // 2), color=p['bg_end'])
        img.paste(top, (0, 0))
        img.paste(bot, (0, H // 2))

    draw = ImageDraw.Draw(img)

    border = 18
    draw.rectangle([border, border, W - border, H - border],
                   outline=p['accent'], width=3)
    draw.rectangle([border + 6, border + 6, W - border - 6, H - border - 6],
                   outline=p['accent'], width=1)

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

    gold  = p['accent']
    white = p['white']
    light = p['light']

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
        admin_user = db.verify_admin(username, password)
        if admin_user:
            session.permanent = True
            if admin_user.get('totp_enabled'):
                session['pre_auth_user']   = admin_user['username']
                session['pre_auth_role']   = admin_user['role']
                session['pre_auth_secret'] = admin_user['totp_secret']
                return redirect(url_for('admin_2fa'))
            else:
                session['admin_logged_in'] = True
                session['admin_user'] = admin_user['username']
                session['admin_role'] = admin_user['role']
                return redirect(url_for('admin_dashboard'))
        flash('Invalid username or password.', 'error')
        return render_template('admin.html', logged_in=False)

    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard'))

    return render_template('admin.html', logged_in=False)


@app.route('/admin/2fa', methods=['GET', 'POST'])
def admin_2fa():
    """Verify 6-digit OTP code during 2-step login."""
    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard'))

    pre_user   = session.get('pre_auth_user')
    pre_secret = session.get('pre_auth_secret')
    if not pre_user or not pre_secret:
        return redirect(url_for('admin'))

    if request.method == 'POST':
        totp_code = request.form.get('totp_code', '').strip()
        if db.verify_totp_code(pre_secret, totp_code):
            session['admin_logged_in'] = True
            session['admin_user'] = session.pop('pre_auth_user')
            session['admin_role'] = session.pop('pre_auth_role')
            session.pop('pre_auth_secret', None)
            flash('Two-Factor Authentication verified successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        flash('Invalid 6-digit verification code. Please check your authenticator app.', 'error')

    return render_template('admin_2fa.html')


@app.route('/admin/2fa/setup', methods=['GET', 'POST'])
@login_required
def admin_2fa_setup():
    """Generate QR code and secret for setting up 2FA."""
    username = session.get('admin_user', 'admin')

    if request.method == 'POST':
        secret       = request.form.get('secret', '')
        confirm_code = request.form.get('confirm_code', '').strip()
        if db.verify_totp_code(secret, confirm_code):
            db.enable_admin_2fa(username, secret)
            flash('Two-Factor Authentication (2FA) enabled successfully!', 'success')
            return redirect(url_for('admin_dashboard') + '?tab=security')
        flash('Invalid verification code. Please scan the QR code and try again.', 'error')
        return redirect(url_for('admin_2fa_setup'))

    secret  = db.generate_totp_secret()
    uri     = db.get_totp_uri(username, secret)
    qr_b64  = db.generate_qr_code_b64(uri)
    return render_template('admin_2fa_setup.html', secret=secret, qr_b64=qr_b64)


@app.route('/admin/2fa/disable', methods=['POST'])
@login_required
def admin_2fa_disable():
    """Disable 2FA for the current admin user."""
    username = session.get('admin_user', 'admin')
    db.disable_admin_2fa(username)
    flash('Two-Factor Authentication has been disabled.', 'warning')
    return redirect(url_for('admin_dashboard') + '?tab=security')


@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    certs = db.get_all_certificates()
    status_filter = request.args.get('status', 'ALL')
    logs  = db.get_all_logs(limit=100, status_filter=status_filter)
    stats = db.get_stats()
    admin_role = session.get('admin_role', 'superadmin')
    username   = session.get('admin_user', 'admin')
    totp_status = db.get_admin_2fa_status(username)
    api_keys   = db.get_all_api_keys()
    current_theme = db.get_setting('cert_theme', 'gold')
    return render_template('admin.html', logged_in=True,
                           certs=certs, logs=logs, stats=stats,
                           admin_role=admin_role, totp_status=totp_status,
                           api_keys=api_keys, selected_status=status_filter,
                           current_theme=current_theme,
                           active_tab='overview')


@app.route('/admin/theme/select', methods=['POST'])
@role_required('superadmin')
def admin_select_theme():
    """Select active visual certificate theme."""
    theme = request.form.get('theme', 'gold').lower()
    if theme in ['gold', 'emerald', 'navy', 'ruby', 'monochrome']:
        db.set_setting('cert_theme', theme)
        flash(f'Certificate visual theme updated to {theme.capitalize()}!', 'success')
    return redirect(url_for('admin_dashboard') + '?tab=themes')


@app.route('/admin/logs/export/csv', methods=['GET'])
@login_required
def admin_export_logs_csv():
    """Export verification logs to a CSV file."""
    status_filter = request.args.get('status', 'ALL')
    logs = db.get_all_logs(limit=2000, status_filter=status_filter)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Log ID', 'Certificate ID', 'Uploaded File', 'SHA-256 Hash', 'Status', 'Reason', 'Verified At', 'IP Address'])

    for row in logs:
        writer.writerow([
            row.get('id', ''),
            row.get('cert_id') or '',
            row.get('file_name') or '',
            row.get('computed_hash') or '',
            row.get('status', ''),
            row.get('reason', ''),
            row.get('verified_at', ''),
            row.get('ip_address') or ''
        ])

    today_str = datetime.now().strftime('%Y%m%d')
    filename = f"CertValid_Audit_Logs_{status_filter}_{today_str}.csv"
    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    response.headers["Content-Type"] = "text/csv"
    return response


@app.route('/admin/logs/export/pdf', methods=['GET'])
@login_required
def admin_export_logs_pdf():
    """Generate and download executive PDF audit report using ReportLab."""
    status_filter = request.args.get('status', 'ALL')
    logs  = db.get_all_logs(limit=200, status_filter=status_filter)
    stats = db.get_stats()

    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
        story = []
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            'ReportTitle',
            parent=styles['Heading1'],
            fontSize=18,
            leading=22,
            textColor=colors.HexColor('#d4af37'),
            alignment=1,
            spaceAfter=8
        )
        story.append(Paragraph("🛡️ CertValid Verification Audit Report", title_style))
        story.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Filter: {status_filter}", styles['Normal']))
        story.append(Spacer(1, 10))

        summary_data = [
            ["Total Certs", "Active Certs", "Revoked Certs", "Total Verifications", "Authentic", "Invalid / Revoked"],
            [
                str(stats.get('total_certs', 0)),
                str(stats.get('active_certs', 0)),
                str(stats.get('revoked_certs', 0)),
                str(stats.get('total_verifications', 0)),
                str(stats.get('authentic_verifications', 0)),
                str(stats.get('failed_verifications', 0) + stats.get('revoked_verifications', 0))
            ]
        ]
        summary_table = Table(summary_data, colWidths=[85]*6)
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1f293d')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.HexColor('#d4af37')),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#374151')),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 14))

        log_headers = ["ID", "Cert ID", "File / Input", "Status", "Reason / Detail", "Timestamp", "IP Address"]
        log_rows = [log_headers]
        for r in logs:
            cert_id = r.get('cert_id') or '—'
            file_name = r.get('file_name') or 'Direct ID'
            status = r.get('status') or 'UNKNOWN'
            reason = (r.get('reason') or '')[:32]
            timestamp = (r.get('verified_at') or '')[:19]
            ip = r.get('ip_address') or '—'
            log_rows.append([str(r.get('id', '')), cert_id, file_name, status, reason, timestamp, ip])

        logs_table = Table(log_rows, colWidths=[25, 80, 90, 60, 130, 95, 60])
        logs_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#111827')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 7),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#1f2937')),
        ]))
        story.append(logs_table)

        doc.build(story)
        buffer.seek(0)
        pdf_bytes = buffer.getvalue()

        today_str = datetime.now().strftime('%Y%m%d')
        filename = f"CertValid_Audit_Report_{status_filter}_{today_str}.pdf"
        response = make_response(pdf_bytes)
        response.headers["Content-Disposition"] = f"attachment; filename={filename}"
        response.headers["Content-Type"] = "application/pdf"
        return response

    except Exception as e:
        app.logger.error(f'Failed to generate PDF audit report: {e}')
        flash('PDF report generation failed. Ensure ReportLab is installed.', 'error')
        return redirect(url_for('admin_dashboard') + '?tab=logs')


@app.route('/admin/api-keys/create', methods=['POST'])
@role_required('superadmin')
def admin_create_api_key():
    key_name = request.form.get('key_name', '').strip()
    if not key_name:
        flash('API Key name is required.', 'error')
        return redirect(url_for('admin_dashboard') + '?tab=apikeys')

    new_key = db.generate_api_key(key_name)
    flash(f'New API key created for "{key_name}": {new_key["api_key"]}', 'success')
    return redirect(url_for('admin_dashboard') + '?tab=apikeys')


@app.route('/admin/api-keys/revoke/<int:key_id>', methods=['POST'])
@role_required('superadmin')
def admin_revoke_api_key(key_id):
    db.revoke_api_key(key_id)
    flash('API key has been revoked.', 'warning')
    return redirect(url_for('admin_dashboard') + '?tab=apikeys')


@app.route('/admin/issue', methods=['POST'])
@role_required('superadmin', 'issuer')
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


@app.route('/admin/sample-csv')
@login_required
def admin_sample_csv():
    """Download sample CSV template for bulk certificate issuance."""
    sample_content = (
        "student_name,course_name,issue_date,issuer_name\n"
        "Aarav Patel,Full Stack Web Development,2026-09-17,CertValid University\n"
        "Ananya Roy,Data Science & Machine Learning,2026-09-17,CertValid Institute\n"
        "Vikram Singh,Cybersecurity Fundamentals,2026-09-17,CertValid Academy\n"
    )
    response = make_response(sample_content)
    response.headers["Content-Disposition"] = "attachment; filename=sample_bulk_certificates.csv"
    response.headers["Content-Type"] = "text/csv"
    return response


@app.route('/admin/issue/bulk', methods=['POST'])
@role_required('superadmin', 'issuer')
def admin_issue_bulk():
    """Process bulk certificate issuance from CSV file upload and return ZIP archive."""
    if 'csv_file' not in request.files or request.files['csv_file'].filename == '':
        flash('No CSV file selected for bulk issuance.', 'error')
        return redirect(url_for('admin_dashboard') + '?tab=bulk')

    file = request.files['csv_file']
    if not file.filename.lower().endswith('.csv'):
        flash('Invalid file type. Please upload a .csv file.', 'error')
        return redirect(url_for('admin_dashboard') + '?tab=bulk')

    try:
        stream = io.StringIO(file.read().decode('utf-8-sig'), newline=None)
        reader = csv.DictReader(stream)

        required_cols = {'student_name', 'course_name', 'issue_date', 'issuer_name'}
        if not reader.fieldnames or not required_cols.issubset(set(name.strip().lower() for name in reader.fieldnames)):
            flash('CSV missing required headers: student_name, course_name, issue_date, issuer_name', 'error')
            return redirect(url_for('admin_dashboard') + '?tab=bulk')

        issued_certs = []
        zip_buffer = io.BytesIO()

        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for row in reader:
                row_clean = {k.strip().lower(): v.strip() for k, v in row.items() if k}
                s_name = row_clean.get('student_name', '')
                c_name = row_clean.get('course_name', '')
                i_date = row_clean.get('issue_date', '')
                i_name = row_clean.get('issuer_name', '')

                if not all([s_name, c_name, i_date, i_name]):
                    continue

                seed = f'{s_name}|{c_name}|{i_date}|{i_name}|{uuid.uuid4()}'
                file_hash = hashlib.sha256(seed.encode()).hexdigest()
                cert_id = db.add_certificate(s_name, c_name, i_date, i_name, file_hash)

                cert_data = {
                    'student_name': s_name,
                    'course_name':  c_name,
                    'issue_date':   i_date,
                    'issuer_name':  i_name,
                    'file_hash':    file_hash
                }
                rel_path = generate_certificate_image(cert_data, cert_id)
                full_path = os.path.join(os.path.dirname(__file__), 'static', rel_path)

                if os.path.exists(full_path):
                    zip_file.write(full_path, arcname=f"Certificate_{cert_id}_{s_name.replace(' ', '_')}.png")
                issued_certs.append(cert_id)

        if not issued_certs:
            flash('No valid rows processed from CSV.', 'warning')
            return redirect(url_for('admin_dashboard') + '?tab=bulk')

        zip_buffer.seek(0)
        today_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"CertValid_Bulk_Certificates_{today_str}.zip"
        
        flash(f'Successfully issued {len(issued_certs)} certificates! Downloading ZIP archive...', 'success')
        response = make_response(zip_buffer.getvalue())
        response.headers["Content-Disposition"] = f"attachment; filename={filename}"
        response.headers["Content-Type"] = "application/zip"
        return response

    except Exception as e:
        app.logger.error(f'Bulk issuance failed: {e}')
        flash('Failed to process bulk issuance CSV file.', 'error')
        return redirect(url_for('admin_dashboard') + '?tab=bulk')


@app.route('/admin/revoke/confirm/<cert_id>', methods=['GET'])
@role_required('superadmin')
def admin_revoke_confirm(cert_id):
    """Render high-security confirmation page with 2FA OTP prompt for revocation."""
    cert_id = cert_id.strip().upper()
    cert    = db.get_certificate_by_id(cert_id)
    if not cert:
        flash('Certificate not found.', 'error')
        return redirect(url_for('admin_dashboard') + '?tab=registry')

    username    = session.get('admin_user', 'admin')
    totp_status = db.get_admin_2fa_status(username)
    return render_template('admin_revoke_confirm.html', cert=cert, totp_status=totp_status)


@app.route('/admin/revoke/<cert_id>', methods=['POST'])
@role_required('superadmin')
def admin_revoke(cert_id):
    """Revoke a certificate after verifying 2FA OTP code if enabled."""
    cert_id  = cert_id.strip().upper()
    username = session.get('admin_user', 'admin')
    totp_status = db.get_admin_2fa_status(username)

    if totp_status and totp_status.get('enabled'):
        totp_code = request.form.get('totp_code', '').strip()
        secret    = totp_status.get('secret')
        if not db.verify_totp_code(secret, totp_code):
            flash('Security Error: Invalid 2FA verification code. Certificate revocation cancelled.', 'error')
            return redirect(url_for('admin_dashboard') + '?tab=registry')

    db.revoke_certificate(cert_id)
    flash(f'Certificate {cert_id} has been revoked with security verification.', 'warning')
    return redirect(url_for('admin_dashboard') + '?tab=registry')


@app.route('/admin/reactivate/<cert_id>', methods=['POST'])
@role_required('superadmin')
def admin_reactivate(cert_id):
    cert_id = cert_id.strip().upper()
    db.reactivate_certificate(cert_id)
    flash(f'Certificate {cert_id} has been reactivated.', 'success')
    return redirect(url_for('admin_dashboard') + '?tab=registry')


@app.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect(url_for('admin'))


# ─── RESTful API v1 Endpoints ─────────────────────────────────────────────────

@app.route('/api/v1/health', methods=['GET'])
def api_health():
    """Public API health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'system': 'CertValid Enterprise API v1',
        'timestamp': datetime.now().isoformat(sep=' ', timespec='seconds')
    }), 200


@app.route('/api/v1/verify/id', methods=['POST'])
@api_key_required
@limiter.limit("60 per minute")
def api_verify_id():
    """Verify certificate by ID via JSON payload."""
    data = request.get_json(silent=True) or {}
    cert_id = data.get('cert_id', '').strip().upper()
    if not cert_id:
        return jsonify({'error': 'Bad Request', 'message': 'Missing required parameter cert_id'}), 400

    cert = db.get_certificate_by_id(cert_id)
    ip   = request.remote_addr
    pub_key_b64 = db.get_public_key_b64()

    if not cert:
        db.log_verification(cert_id, None, None, 'INVALID', 'API: ID not found', ip)
        return jsonify({
            'status': 'INVALID',
            'valid': False,
            'message': 'Certificate ID not found in registry',
            'cert_id': cert_id
        }), 404

    payload = db.build_cert_payload(cert['cert_id'], cert['student_name'], cert['course_name'], cert['issue_date'], cert['file_hash'])
    sig_valid = db.verify_payload_signature(payload, cert.get('signature', ''))

    if cert['status'] == 'revoked':
        db.log_verification(cert_id, None, None, 'REVOKED', 'API: Certificate revoked', ip)
        return jsonify({
            'status': 'REVOKED',
            'valid': False,
            'message': 'Certificate has been officially revoked',
            'certificate': cert,
            'signature_valid': sig_valid
        }), 200

    db.log_verification(cert_id, None, None, 'AUTHENTIC', 'API: Certificate verified', ip)
    return jsonify({
        'status': 'AUTHENTIC',
        'valid': True,
        'message': 'Certificate verified successfully',
        'certificate': cert,
        'signature_valid': sig_valid,
        'public_key_b64': pub_key_b64
    }), 200


@app.route('/api/v1/verify/file', methods=['POST'])
@api_key_required
@limiter.limit("30 per minute")
def api_verify_file():
    """Verify certificate file upload via multipart/form-data."""
    if 'certificate' not in request.files or request.files['certificate'].filename == '':
        return jsonify({'error': 'Bad Request', 'message': 'No certificate file uploaded'}), 400

    file = request.files['certificate']
    if not allowed_file(file.filename):
        return jsonify({'error': 'Unsupported Media Type', 'message': 'Allowed extensions: JPG, PNG, PDF'}), 415

    file_bytes = file.read()
    filename   = file.filename
    ip         = request.remote_addr

    computed_hash  = db.compute_file_hash(file_bytes)
    computed_phash = db.compute_file_phash(file_bytes)
    ocr_cert_id    = None

    cert = db.get_certificate_by_hash(computed_hash)
    match_type = 'exact'
    similarity = 100.0

    if not cert and computed_phash:
        phash_match, dist, sim = db.get_certificate_by_phash(computed_phash, max_distance=10)
        if phash_match:
            cert = phash_match
            match_type = 'visual'
            similarity = sim

    if not cert:
        extracted_text = db.extract_text_from_file(file_bytes, filename)
        ocr_cert_id = db.extract_cert_id_from_text(extracted_text)
        if ocr_cert_id:
            ocr_cert = db.get_certificate_by_id(ocr_cert_id)
            if ocr_cert:
                cert = ocr_cert
                match_type = 'ocr'
                similarity = 100.0

    if not cert:
        db.log_verification(None, filename, computed_hash, 'INVALID', 'API File: No match', ip)
        return jsonify({
            'status': 'INVALID',
            'valid': False,
            'message': 'No matching certificate found in registry by SHA-256, pHash, or OCR',
            'computed_hash': computed_hash,
            'computed_phash': computed_phash
        }), 200

    sig_valid = False
    if cert and cert.get('signature'):
        payload = db.build_cert_payload(cert['cert_id'], cert['student_name'], cert['course_name'], cert['issue_date'], cert['file_hash'])
        sig_valid = db.verify_payload_signature(payload, cert['signature'])

    status_str = 'REVOKED' if cert['status'] == 'revoked' else 'AUTHENTIC'
    db.log_verification(cert['cert_id'], filename, computed_hash, status_str, f'API File verification ({match_type})', ip)

    return jsonify({
        'status': status_str,
        'valid': (status_str == 'AUTHENTIC'),
        'match_type': match_type,
        'visual_similarity_percent': similarity,
        'ocr_extracted_cert_id': ocr_cert_id,
        'computed_hash': computed_hash,
        'computed_phash': computed_phash,
        'signature_valid': sig_valid,
        'certificate': cert
    }), 200


@app.route('/api/v1/issue', methods=['POST'])
@api_key_required
@limiter.limit("20 per minute")
def api_issue_certificate():
    """Programmatically issue a certificate via JSON request."""
    data = request.get_json(silent=True) or {}
    student_name = data.get('student_name', '').strip()
    course_name  = data.get('course_name', '').strip()
    issue_date   = data.get('issue_date', '').strip()
    issuer_name  = data.get('issuer_name', '').strip()

    if not all([student_name, course_name, issue_date, issuer_name]):
        return jsonify({
            'error': 'Bad Request',
            'message': 'Missing required fields: student_name, course_name, issue_date, issuer_name'
        }), 400

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
        app.logger.error(f'API Image generation failed: {e}')

    cert_record = db.get_certificate_by_id(cert_id)
    return jsonify({
        'status': 'SUCCESS',
        'message': 'Certificate issued successfully',
        'cert_id': cert_id,
        'certificate': cert_record,
        'download_url': f'{BASE_URL}/download/{cert_id}'
    }), 201


# ─── App Entry ────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(debug=debug_mode)