"""
db.py - Database initialization and helper functions for the Certificate Verification System.
Uses SQLite for local persistence or PostgreSQL/MySQL via DATABASE_URL environment variable.
Includes SHA-256, pHash, OCR text extraction, Ed25519 signatures, and RBAC Multi-Role Access Control.
"""

import sqlite3
import hashlib
import hmac
import uuid
import os
import io
import re
import base64
import json
from datetime import datetime
from PIL import Image
import imagehash
import pypdf
import pytesseract
import pyotp
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import sqlalchemy
from sqlalchemy import create_engine

DB_PATH = os.path.join(os.path.dirname(__file__), 'database.db')
KEYS_DIR = os.path.join(os.path.dirname(__file__), 'instance', 'keys')
PRIV_KEY_PATH = os.path.join(KEYS_DIR, 'ed25519_private.pem')
PUB_KEY_PATH = os.path.join(KEYS_DIR, 'ed25519_public.pem')

_private_key = None
_public_key = None

DATABASE_URL = os.environ.get('DATABASE_URL', '')
if DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

_engine = None
if DATABASE_URL:
    _engine = create_engine(DATABASE_URL, pool_pre_ping=True)


# ─── Connection ───────────────────────────────────────────────────────────────

def get_db():
    """Get a database connection."""
    if _engine:
        conn = _engine.raw_connection()
        return conn

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA foreign_keys=ON')
    return conn


# ─── Ed25519 Asymmetric Cryptography Keys & Digital Signatures ─────────────

def init_keys():
    """Initialize or load the Ed25519 asymmetric private & public key pair."""
    global _private_key, _public_key
    if _private_key and _public_key:
        return

    os.makedirs(KEYS_DIR, exist_ok=True)
    if os.path.exists(PRIV_KEY_PATH) and os.path.exists(PUB_KEY_PATH):
        try:
            with open(PRIV_KEY_PATH, 'rb') as f:
                _private_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(PUB_KEY_PATH, 'rb') as f:
                _public_key = serialization.load_pem_public_key(f.read())
            return
        except Exception:
            pass

    _private_key = ed25519.Ed25519PrivateKey.generate()
    _public_key = _private_key.public_key()

    with open(PRIV_KEY_PATH, 'wb') as f:
        f.write(_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(PUB_KEY_PATH, 'wb') as f:
        f.write(_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))


def get_public_key_b64() -> str:
    """Return the raw Ed25519 public key in Base64 encoding."""
    init_keys()
    pub_bytes = _public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return base64.b64encode(pub_bytes).decode('utf-8')


def build_cert_payload(cert_id: str, student_name: str, course_name: str, issue_date: str, file_hash: str) -> str:
    """Construct canonical string payload for digital signature verification."""
    return f"{cert_id}|{student_name}|{course_name}|{issue_date}|{file_hash}"


def sign_payload(payload_str: str) -> str:
    """Sign payload string using Ed25519 private key. Returns Base64 signature."""
    init_keys()
    sig_bytes = _private_key.sign(payload_str.encode('utf-8'))
    return base64.b64encode(sig_bytes).decode('utf-8')


def verify_payload_signature(payload_str: str, signature_b64: str) -> bool:
    """Verify an Ed25519 Base64 signature against payload string using public key."""
    if not payload_str or not signature_b64:
        return False
    init_keys()
    try:
        sig_bytes = base64.b64decode(signature_b64)
        _public_key.verify(sig_bytes, payload_str.encode('utf-8'))
        return True
    except Exception:
        return False


def build_bundle_payload(bundle_id: str, title: str, recipient_name: str, institution_name: str, issue_date: str, cert_ids: list) -> str:
    """Construct canonical string payload for academic transcript bundle signing & hashing."""
    sorted_ids = sorted([str(cid).strip().upper() for cid in cert_ids if cid])
    return f"{bundle_id.strip().upper()}|{title.strip()}|{recipient_name.strip()}|{institution_name.strip()}|{issue_date.strip()}|{','.join(sorted_ids)}"


def compute_bundle_hash(bundle_id: str, title: str, recipient_name: str, institution_name: str, issue_date: str, cert_ids: list) -> str:
    """Compute SHA-256 hash of canonical bundle payload."""
    payload = build_bundle_payload(bundle_id, title, recipient_name, institution_name, issue_date, cert_ids)
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()



# ─── Password Hashing (PBKDF2 + salt) ────────────────────────────────────────

def _hash_password(password: str) -> str:
    """Securely hash a password using PBKDF2-HMAC-SHA256 with a random salt."""
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 260_000)
    return salt.hex() + ':' + dk.hex()


def _verify_password(password: str, stored_hash: str) -> bool:
    """Constant-time password verification against a stored PBKDF2 hash."""
    try:
        salt_hex, dk_hex = stored_hash.split(':', 1)
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 260_000)
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


def _is_legacy_sha256(stored_hash: str) -> bool:
    """Check if a stored hash is the old plain SHA-256 format (no colon separator)."""
    return ':' not in stored_hash


# ─── Schema Init & Migration ──────────────────────────────────────────────────

def init_db():
    """Initialize database tables, indexes, schema migrations, keys, and seed sample data."""
    init_keys()
    conn = get_db()
    c = conn.cursor()

    # Certificates table
    c.execute('''
        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cert_id TEXT UNIQUE NOT NULL,
            student_name TEXT NOT NULL,
            course_name TEXT NOT NULL,
            issue_date TEXT NOT NULL,
            issuer_name TEXT NOT NULL,
            file_hash TEXT NOT NULL,
            phash TEXT,
            signature TEXT,
            status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL,
            expires_at TEXT
        )
    ''')

    # Migration checks for certificates table
    try:
        columns = [r['name'] if isinstance(r, dict) or hasattr(r, '__getitem__') else r[1]
                   for r in c.execute("PRAGMA table_info(certificates)").fetchall()]
        if 'phash' not in columns:
            c.execute("ALTER TABLE certificates ADD COLUMN phash TEXT")
        if 'signature' not in columns:
            c.execute("ALTER TABLE certificates ADD COLUMN signature TEXT")
        if 'expires_at' not in columns:
            c.execute("ALTER TABLE certificates ADD COLUMN expires_at TEXT")
    except Exception:
        pass

    c.execute('''
        CREATE INDEX IF NOT EXISTS idx_file_hash ON certificates(file_hash)
    ''')

    # Verification logs table
    c.execute('''
        CREATE TABLE IF NOT EXISTS verification_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cert_id TEXT,
            file_name TEXT,
            computed_hash TEXT,
            status TEXT NOT NULL,
            reason TEXT,
            verified_at TEXT NOT NULL,
            ip_address TEXT
        )
    ''')

    # Admin users table with RBAC role & TOTP 2FA
    c.execute('''
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'superadmin',
            totp_secret TEXT,
            totp_enabled INTEGER NOT NULL DEFAULT 0
        )
    ''')

    # Migration check for admin_users table role & TOTP 2FA columns
    try:
        admin_cols = [r['name'] if isinstance(r, dict) or hasattr(r, '__getitem__') else r[1]
                      for r in c.execute("PRAGMA table_info(admin_users)").fetchall()]
        if 'role' not in admin_cols:
            c.execute("ALTER TABLE admin_users ADD COLUMN role TEXT NOT NULL DEFAULT 'superadmin'")
        if 'totp_secret' not in admin_cols:
            c.execute("ALTER TABLE admin_users ADD COLUMN totp_secret TEXT")
        if 'totp_enabled' not in admin_cols:
            c.execute("ALTER TABLE admin_users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0")
    except Exception:
        pass

    # API Keys table
    c.execute('''
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_name TEXT NOT NULL,
            api_key TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active'
        )
    ''')

    # System Settings key-value table
    c.execute('''
        CREATE TABLE IF NOT EXISTS system_settings (
            key TEXT UNIQUE NOT NULL,
            value TEXT NOT NULL
        )
    ''')

    # Credential Bundles & Academic Transcripts table
    c.execute('''
        CREATE TABLE IF NOT EXISTS credential_bundles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bundle_id TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            recipient_name TEXT NOT NULL,
            recipient_email TEXT,
            institution_name TEXT NOT NULL,
            issue_date TEXT NOT NULL,
            cert_ids TEXT NOT NULL,
            bundle_hash TEXT NOT NULL,
            signature TEXT,
            status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL
        )
    ''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_bundle_recipient ON credential_bundles(recipient_name)')

    # Seed default admin with secure PBKDF2 hash & superadmin role
    existing_admin = c.execute(
        'SELECT id FROM admin_users WHERE username = ?', ('admin',)
    ).fetchone()
    if not existing_admin:
        secure_hash = _hash_password('admin123')
        c.execute(
            "INSERT INTO admin_users (username, password_hash, role) VALUES (?, ?, 'superadmin')",
            ('admin', secure_hash)
        )

    # Seed sample certificates for demonstration
    samples = [
        {
            'cert_id': 'CERT-2024-001',
            'student_name': 'Aisha Sharma',
            'course_name': 'B.Tech Computer Science',
            'issue_date': '2024-05-15',
            'issuer_name': 'National Institute of Technology',
            'file_hash': hashlib.sha256(b'CERT-2024-001-SAMPLE-HASH').hexdigest(),
            'status': 'active',
        },
        {
            'cert_id': 'CERT-2024-004',
            'student_name': 'Aisha Sharma',
            'course_name': 'Advanced Cloud Architecture & Security',
            'issue_date': '2024-06-10',
            'issuer_name': 'National Institute of Technology',
            'file_hash': hashlib.sha256(b'CERT-2024-004-SAMPLE-HASH').hexdigest(),
            'status': 'active',
        },
        {
            'cert_id': 'CERT-2024-002',
            'student_name': 'Rahul Verma',
            'course_name': 'MBA Finance',
            'issue_date': '2024-06-20',
            'issuer_name': 'Indian Institute of Management',
            'file_hash': hashlib.sha256(b'CERT-2024-002-SAMPLE-HASH').hexdigest(),
            'status': 'active',
        },
        {
            'cert_id': 'CERT-2023-099',
            'student_name': 'Priya Patel',
            'course_name': 'M.Sc Data Science',
            'issue_date': '2023-11-30',
            'issuer_name': 'University of Delhi',
            'file_hash': hashlib.sha256(b'CERT-2023-099-SAMPLE-HASH').hexdigest(),
            'status': 'revoked',
        },
    ]

    now = datetime.now().isoformat(sep=' ', timespec='seconds')
    for s in samples:
        existing = c.execute(
            'SELECT id FROM certificates WHERE cert_id = ?', (s['cert_id'],)
        ).fetchone()
        if not existing:
            payload = build_cert_payload(s['cert_id'], s['student_name'], s['course_name'], s['issue_date'], s['file_hash'])
            sig = sign_payload(payload)
            c.execute('''
                INSERT INTO certificates
                (cert_id, student_name, course_name, issue_date, issuer_name, file_hash, signature, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (s['cert_id'], s['student_name'], s['course_name'],
                  s['issue_date'], s['issuer_name'], s['file_hash'],
                  sig, s['status'], now))

    # Seed sample transcript bundle if empty
    try:
        bundle_count = c.execute('SELECT COUNT(*) FROM credential_bundles').fetchone()[0]
        if bundle_count == 0:
            b_id = 'TR-2024-001'
            b_title = 'B.Tech Computer Science & Cloud Architecture Transcript'
            b_recipient = 'Aisha Sharma'
            b_email = 'aisha.sharma@nit.edu'
            b_inst = 'National Institute of Technology'
            b_date = '2024-06-15'
            b_cids = ['CERT-2024-001', 'CERT-2024-004']
            b_hash = compute_bundle_hash(b_id, b_title, b_recipient, b_inst, b_date, b_cids)
            b_sig = sign_payload(b_hash)
            c.execute('''
                INSERT INTO credential_bundles
                (bundle_id, title, recipient_name, recipient_email, institution_name, issue_date, cert_ids, bundle_hash, signature, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)
            ''', (b_id, b_title, b_recipient, b_email, b_inst, b_date, json.dumps(b_cids), b_hash, b_sig, now))
    except Exception:
        pass

    # Seed sample verification logs if empty
    try:
        log_count = c.execute('SELECT COUNT(*) FROM verification_logs').fetchone()[0]
        if log_count == 0:
            from datetime import timedelta
            sample_logs = [
                ('CERT-2024-001', 'cert_001.png', samples[0]['file_hash'], 'AUTHENTIC', 'Exact SHA-256 hash match', 6, '192.168.1.10'),
                ('CERT-2024-001', None, None, 'AUTHENTIC', 'Direct ID verification: CERT-2024-001', 5, '10.0.0.12'),
                ('CERT-2024-002', 'cert_rahul.jpg', samples[2]['file_hash'], 'AUTHENTIC', 'pHash visual match (distance: 2, similarity: 96.9%)', 4, '172.16.0.4'),
                ('CERT-2024-002', None, None, 'AUTHENTIC', 'QR scan: certificate verified.', 3, '192.168.1.25'),
                ('CERT-2023-099', None, None, 'REVOKED', 'Direct ID verification: Certificate REVOKED.', 2, '10.0.0.8'),
                ('UNKNOWN-123', 'fake_cert.png', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'INVALID', 'No matching certificate found by SHA-256 or pHash.', 1, '203.0.113.42'),
                ('CERT-2024-001', None, None, 'AUTHENTIC', 'API: Certificate verified', 0, '198.51.100.7'),
            ]
            for cid, fname, fhash, status, reason, days_ago, ip in sample_logs:
                v_time = (datetime.now() - timedelta(days=days_ago, hours=3)).strftime('%Y-%m-%d %H:%M:%S')
                c.execute('''
                    INSERT INTO verification_logs
                    (cert_id, file_name, computed_hash, status, reason, verified_at, ip_address)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (cid, fname, fhash, status, reason, v_time, ip))
    except Exception:
        pass

    conn.commit()
    conn.close()

    # Rebuild BK-Tree in-memory metric index on DB init
    rebuild_bktree_index()


# ─── Cert ID Generator ────────────────────────────────────────────────────────

def generate_cert_id():
    """Generate a unique certificate ID like CERT-2026-XXXXXX."""
    year = datetime.now().year
    unique = str(uuid.uuid4()).replace('-', '').upper()[:6]
    return f'CERT-{year}-{unique}'


# ─── File Hashing, pHash & OCR Text Extraction ───────────────────────────────

def compute_file_hash(file_bytes: bytes) -> str:
    """Compute exact SHA-256 hash of file bytes."""
    return hashlib.sha256(file_bytes).hexdigest()


def compute_file_phash(file_bytes: bytes) -> str:
    """
    Compute Perceptual Hash (pHash) of an image file.
    Returns 16-character hex string representing the 64-bit visual hash, or None if invalid.
    """
    try:
        img = Image.open(io.BytesIO(file_bytes))
        if img.mode != 'RGB':
            img = img.convert('RGB')
        h = imagehash.phash(img)
        return str(h)
    except Exception:
        return None


def extract_text_from_file(file_bytes: bytes, filename: str = '') -> str:
    """
    Extract text content from uploaded file bytes.
    Supports native PDF parsing via pypdf and OCR image parsing via pytesseract.
    """
    extracted_text = ""
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''

    if ext == 'pdf' or file_bytes.startswith(b'%PDF'):
        try:
            reader = pypdf.PdfReader(io.BytesIO(file_bytes))
            for page in reader.pages:
                t = page.extract_text()
                if t:
                    extracted_text += t + "\n"
        except Exception:
            pass

    if not extracted_text:
        try:
            img = Image.open(io.BytesIO(file_bytes))
            if img.mode != 'RGB':
                img = img.convert('RGB')
            extracted_text = pytesseract.image_to_string(img)
        except Exception:
            pass

    return extracted_text


def extract_cert_id_from_text(text: str) -> str:
    """
    Scan text using regex to extract a Certificate ID pattern matching CERT-YYYY-XXXXXX.
    """
    if not text:
        return None
    match = re.search(r'CERT-\d{4}-[A-Z0-9]{3,8}', text, re.IGNORECASE)
    return match.group(0).upper() if match else None


# ─── Certificate CRUD ────────────────────────────────────────────────────────

def check_cert_expiry(cert: dict) -> dict:
    """
    Enrich certificate dictionary with dynamic expiration calculations:
    is_expired (bool), days_until_expiry (int or None), effective_status ('active'|'revoked'|'expired')
    """
    if not cert:
        return cert

    cert_copy = dict(cert)
    expires_at = cert_copy.get('expires_at')
    status = cert_copy.get('status', 'active')

    if not expires_at:
        cert_copy['is_expired'] = False
        cert_copy['days_until_expiry'] = None
        cert_copy['effective_status'] = status
        return cert_copy

    try:
        exp_date = datetime.strptime(expires_at.strip(), '%Y-%m-%d').date()
        today = datetime.now().date()
        days_remaining = (exp_date - today).days

        if days_remaining < 0:
            cert_copy['is_expired'] = True
            cert_copy['days_until_expiry'] = days_remaining
            cert_copy['effective_status'] = 'expired' if status == 'active' else status
        else:
            cert_copy['is_expired'] = False
            cert_copy['days_until_expiry'] = days_remaining
            cert_copy['effective_status'] = status
    except Exception:
        cert_copy['is_expired'] = False
        cert_copy['days_until_expiry'] = None
        cert_copy['effective_status'] = status

    return cert_copy


def add_certificate(student_name, course_name, issue_date, issuer_name, file_hash, phash=None, expires_at=None):
    """Insert a new certificate record with Ed25519 digital signature. Returns the generated cert_id."""
    cert_id = generate_cert_id()
    payload = build_cert_payload(cert_id, student_name, course_name, issue_date, file_hash)
    signature = sign_payload(payload)

    now = datetime.now().isoformat(sep=' ', timespec='seconds')
    conn = get_db()
    conn.execute('''
        INSERT INTO certificates
        (cert_id, student_name, course_name, issue_date, issuer_name, file_hash, phash, signature, status, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
    ''', (cert_id, student_name, course_name, issue_date, issuer_name, file_hash, phash, signature, now, expires_at))
    conn.commit()
    conn.close()
    return cert_id


# ─── Burkhard-Keller (BK-Tree) Metric Tree Data Structure ─────────────────────

class BKNode:
    """Node in a Burkhard-Keller metric tree for fast pHash Hamming distance search."""
    def __init__(self, cert_id: str, phash_str: str, hash_obj):
        self.cert_id = cert_id
        self.phash_str = phash_str
        self.hash_obj = hash_obj
        self.children = {}  # distance (int) -> BKNode


class BKTree:
    """Burkhard-Keller metric tree for O(log N) visual similarity search."""
    def __init__(self):
        self.root = None
        self.count = 0

    def insert(self, cert_id: str, phash_str: str) -> bool:
        if not phash_str:
            return False
        try:
            hash_obj = imagehash.hex_to_hash(phash_str)
        except Exception:
            return False

        if self.root is None:
            self.root = BKNode(cert_id, phash_str, hash_obj)
            self.count += 1
            return True

        curr = self.root
        while curr:
            dist = curr.hash_obj - hash_obj
            if dist == 0 and curr.cert_id == cert_id:
                return False
            if dist in curr.children:
                curr = curr.children[dist]
            else:
                curr.children[dist] = BKNode(cert_id, phash_str, hash_obj)
                self.count += 1
                return True

    def search(self, target_phash_str: str, max_distance: int = 10):
        """
        Search BK-Tree for nearest neighbor within max_distance bits.
        Uses triangle inequality subtree pruning: low = dist - max_distance, high = dist + max_distance.
        Returns (best_cert_id, min_distance).
        """
        if self.root is None or not target_phash_str:
            return None, None

        try:
            target_hash = imagehash.hex_to_hash(target_phash_str)
        except Exception:
            return None, None

        candidates = [self.root]
        best_cert_id = None
        min_dist = max_distance + 1

        while candidates:
            node = candidates.pop()
            dist = node.hash_obj - target_hash

            if dist < min_dist:
                min_dist = dist
                best_cert_id = node.cert_id

            low = dist - max_distance
            high = dist + max_distance

            for d, child in node.children.items():
                if low <= d <= high:
                    candidates.append(child)

        if best_cert_id and min_dist <= max_distance:
            return best_cert_id, min_dist
        return None, None


_bktree_index = BKTree()


def rebuild_bktree_index() -> int:
    """Build or rebuild the in-memory BK-Tree index from all active registered certificate pHashes."""
    global _bktree_index
    new_tree = BKTree()
    conn = get_db()
    rows = conn.execute(
        "SELECT cert_id, phash FROM certificates WHERE phash IS NOT NULL AND phash != ''"
    ).fetchall()
    conn.close()

    for r in rows:
        new_tree.insert(r['cert_id'], r['phash'])

    _bktree_index = new_tree
    return _bktree_index.count


def update_certificate_phash(cert_id, phash):
    """Update the pHash field for a certificate record and insert into BK-Tree index."""
    conn = get_db()
    conn.execute("UPDATE certificates SET phash = ? WHERE cert_id = ?", (phash, cert_id))
    conn.commit()
    conn.close()
    if phash:
        _bktree_index.insert(cert_id, phash)


def get_certificate_by_id(cert_id):
    """Fetch a certificate record by cert_id."""
    conn = get_db()
    row = conn.execute('SELECT * FROM certificates WHERE cert_id = ?', (cert_id,)).fetchone()
    conn.close()
    return check_cert_expiry(dict(row)) if row else None


def get_certificate_by_hash(file_hash):
    """Fetch a certificate record by its exact SHA-256 file hash."""
    conn = get_db()
    row = conn.execute('SELECT * FROM certificates WHERE file_hash = ?', (file_hash,)).fetchone()
    conn.close()
    return check_cert_expiry(dict(row)) if row else None


def get_certificate_by_phash(uploaded_phash_str, max_distance=10):
    """
    Match an uploaded image's pHash against registered certificates using O(log N) BK-Tree metric search.
    Threshold max_distance = 10 bits out of 64 (>= 84.4% visual similarity).
    Returns (certificate_dict, distance, similarity_percent) or (None, None, 0.0).
    """
    if not uploaded_phash_str:
        return None, None, 0.0

    if _bktree_index.root is None:
        rebuild_bktree_index()

    matched_cert_id, dist = _bktree_index.search(uploaded_phash_str, max_distance=max_distance)
    if matched_cert_id and dist is not None:
        cert = get_certificate_by_id(matched_cert_id)
        if cert:
            similarity = round((1.0 - (dist / 64.0)) * 100, 1)
            return cert, dist, similarity

    return None, None, 0.0


def get_all_certificates():
    """Fetch all certificates ordered by creation date descending with expiry calculations."""
    conn = get_db()
    rows = conn.execute('SELECT * FROM certificates ORDER BY created_at DESC').fetchall()
    conn.close()
    return [check_cert_expiry(dict(r)) for r in rows]


def revoke_certificate(cert_id):
    """Set a certificate status to revoked."""
    conn = get_db()
    conn.execute("UPDATE certificates SET status = 'revoked' WHERE cert_id = ?", (cert_id,))
    conn.commit()
    conn.close()


def reactivate_certificate(cert_id):
    """Set a certificate status back to active."""
    conn = get_db()
    conn.execute("UPDATE certificates SET status = 'active' WHERE cert_id = ?", (cert_id,))
    conn.commit()
    conn.close()


# ─── Academic Transcripts & Credential Bundles ────────────────────────────

def generate_bundle_id() -> str:
    """Generate a unique academic transcript bundle ID like TR-2026-XXXXXX."""
    year = datetime.now().year
    unique = str(uuid.uuid4()).replace('-', '').upper()[:6]
    return f'TR-{year}-{unique}'


def create_bundle(title: str, recipient_name: str, recipient_email: str, institution_name: str, issue_date: str, cert_ids: list, bundle_id: str = None) -> str:
    """Create a new academic transcript bundle with Ed25519 signature."""
    if not bundle_id:
        bundle_id = generate_bundle_id()
    else:
        bundle_id = bundle_id.strip().upper()

    title = (title or "Academic Transcript").strip()
    recipient_name = recipient_name.strip()
    recipient_email = (recipient_email or '').strip()
    institution_name = (institution_name or "CertValid Academic Board").strip()
    issue_date = issue_date.strip() if issue_date else datetime.now().strftime('%Y-%m-%d')
    sorted_cert_ids = sorted(list(set(str(cid).strip().upper() for cid in cert_ids if cid)))

    bundle_hash = compute_bundle_hash(bundle_id, title, recipient_name, institution_name, issue_date, sorted_cert_ids)
    sig = sign_payload(bundle_hash)
    now = datetime.now().isoformat(sep=' ', timespec='seconds')
    cert_ids_json = json.dumps(sorted_cert_ids)

    conn = get_db()
    conn.execute('''
        INSERT INTO credential_bundles
        (bundle_id, title, recipient_name, recipient_email, institution_name, issue_date, cert_ids, bundle_hash, signature, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)
    ''', (bundle_id, title, recipient_name, recipient_email, institution_name, issue_date, cert_ids_json, bundle_hash, sig, now))
    conn.commit()
    conn.close()
    return bundle_id


def get_bundle(bundle_id: str) -> dict:
    """Fetch an academic transcript bundle with resolved certificates, metrics, and signature verification."""
    if not bundle_id:
        return None
    bundle_id = bundle_id.strip().upper()
    conn = get_db()
    row = conn.execute('SELECT * FROM credential_bundles WHERE bundle_id = ?', (bundle_id,)).fetchone()
    conn.close()
    if not row:
        return None

    b = dict(row)
    try:
        cert_ids = json.loads(b.get('cert_ids', '[]'))
    except Exception:
        cert_ids = [cid.strip() for cid in b.get('cert_ids', '').split(',') if cid.strip()]

    resolved_certs = []
    for cid in cert_ids:
        cert = get_certificate_by_id(cid)
        if cert:
            resolved_certs.append(cert)
        else:
            resolved_certs.append({
                'cert_id': cid,
                'student_name': b['recipient_name'],
                'course_name': 'Unknown / Unregistered Credential',
                'issue_date': 'N/A',
                'issuer_name': b['institution_name'],
                'status': 'missing',
                'effective_status': 'missing',
                'is_expired': False
            })

    total_certs = len(resolved_certs)
    active_certs = sum(1 for c in resolved_certs if c.get('effective_status') == 'active')
    revoked_certs = sum(1 for c in resolved_certs if c.get('status') == 'revoked')
    expired_certs = sum(1 for c in resolved_certs if c.get('effective_status') == 'expired')

    expected_hash = compute_bundle_hash(b['bundle_id'], b['title'], b['recipient_name'], b['institution_name'], b['issue_date'], cert_ids)
    hash_valid = (expected_hash == b['bundle_hash'])
    sig_valid = verify_payload_signature(b['bundle_hash'], b.get('signature', ''))

    if b.get('status') == 'revoked':
        overall_status = 'REVOKED'
        overall_reason = 'This transcript bundle has been officially revoked.'
    elif revoked_certs > 0:
        overall_status = 'CONTAINS_REVOKED'
        overall_reason = f'Warning: {revoked_certs} credential(s) in this transcript have been revoked.'
    elif expired_certs > 0 and active_certs == 0:
        overall_status = 'EXPIRED'
        overall_reason = 'All credentials in this transcript have expired.'
    elif not hash_valid or not sig_valid:
        overall_status = 'TAMPERED'
        overall_reason = 'Cryptographic integrity check failed for this transcript.'
    else:
        overall_status = 'AUTHENTIC'
        overall_reason = 'All credentials verified and cryptographically authentic.'

    b['cert_ids_list'] = cert_ids
    b['certificates'] = resolved_certs
    b['total_certs'] = total_certs
    b['active_certs'] = active_certs
    b['revoked_certs'] = revoked_certs
    b['expired_certs'] = expired_certs
    b['hash_valid'] = hash_valid
    b['signature_valid'] = sig_valid
    b['overall_status'] = overall_status
    b['overall_reason'] = overall_reason
    return b


def get_all_bundles() -> list:
    """Fetch all transcript bundles with item counts and status overview."""
    conn = get_db()
    rows = conn.execute('SELECT * FROM credential_bundles ORDER BY id DESC').fetchall()
    conn.close()
    bundles = []
    for r in rows:
        b = dict(r)
        try:
            cids = json.loads(b.get('cert_ids', '[]'))
        except Exception:
            cids = []
        b['cert_count'] = len(cids)
        bundles.append(b)
    return bundles


def revoke_bundle(bundle_id: str):
    """Set an academic transcript bundle status to revoked."""
    bundle_id = bundle_id.strip().upper()
    conn = get_db()
    conn.execute("UPDATE credential_bundles SET status = 'revoked' WHERE bundle_id = ?", (bundle_id,))
    conn.commit()
    conn.close()


def reactivate_bundle(bundle_id: str):
    """Set an academic transcript bundle status back to active."""
    bundle_id = bundle_id.strip().upper()
    conn = get_db()
    conn.execute("UPDATE credential_bundles SET status = 'active' WHERE bundle_id = ?", (bundle_id,))
    conn.commit()
    conn.close()


def get_recipient_certificates(recipient_name: str) -> list:
    """Fetch all certificates matching recipient name."""
    if not recipient_name:
        return []
    conn = get_db()
    term = f"%{recipient_name.strip().lower()}%"
    rows = conn.execute(
        "SELECT * FROM certificates WHERE LOWER(student_name) LIKE ? ORDER BY issue_date DESC",
        (term,)
    ).fetchall()
    conn.close()
    return [check_cert_expiry(dict(r)) for r in rows]


def get_bundles_for_cert(cert_id: str) -> list:
    """Find any transcript bundles containing the specified certificate ID."""
    if not cert_id:
        return []
    cert_id = cert_id.strip().upper()
    conn = get_db()
    rows = conn.execute("SELECT * FROM credential_bundles WHERE cert_ids LIKE ?", (f'%"{cert_id}"%',)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_unique_recipients() -> list:
    """Fetch distinct recipient names with certificate counts for auto-suggestion."""
    conn = get_db()
    rows = conn.execute('''
        SELECT student_name, COUNT(*) as cert_count
        FROM certificates
        GROUP BY student_name
        ORDER BY cert_count DESC, student_name ASC
    ''').fetchall()
    conn.close()
    return [dict(r) for r in rows]



# ─── Verification Logs ────────────────────────────────────────────────────────

def log_verification(cert_id, file_name, computed_hash, status, reason, ip_address):
    """Log a verification attempt."""
    now = datetime.now().isoformat(sep=' ', timespec='seconds')
    conn = get_db()
    conn.execute('''
        INSERT INTO verification_logs
        (cert_id, file_name, computed_hash, status, reason, verified_at, ip_address)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (cert_id, file_name, computed_hash, status, reason, now, ip_address))
    conn.commit()
    conn.close()


def get_all_logs(limit=500, status_filter=None):
    """Fetch verification logs ordered by most recent, optionally filtered by status."""
    conn = get_db()
    if status_filter and status_filter.upper() != 'ALL':
        rows = conn.execute(
            'SELECT * FROM verification_logs WHERE status = ? ORDER BY verified_at DESC LIMIT ?',
            (status_filter.upper(), limit)
        ).fetchall()
    else:
        rows = conn.execute(
            'SELECT * FROM verification_logs ORDER BY verified_at DESC LIMIT ?', (limit,)
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ─── Stats (single connection, aggregate SQL) ─────────────────────────────────

def get_stats():
    """Get dashboard statistics using a single DB connection and aggregate queries."""
    conn = get_db()

    cert_row = conn.execute('''
        SELECT
            COUNT(*) AS total_certs,
            SUM(CASE WHEN status = 'active'  THEN 1 ELSE 0 END) AS active_certs,
            SUM(CASE WHEN status = 'revoked' THEN 1 ELSE 0 END) AS revoked_certs
        FROM certificates
    ''').fetchone()

    log_row = conn.execute('''
        SELECT
            COUNT(*) AS total_verifications,
            SUM(CASE WHEN status = 'AUTHENTIC' THEN 1 ELSE 0 END) AS authentic_verifications,
            SUM(CASE WHEN status IN ('INVALID', 'TAMPERED') THEN 1 ELSE 0 END) AS failed_verifications,
            SUM(CASE WHEN status = 'REVOKED'   THEN 1 ELSE 0 END) AS revoked_verifications
        FROM verification_logs
    ''').fetchone()

    conn.close()

    return {
        'total_certs':             cert_row['total_certs']             or 0,
        'active_certs':            cert_row['active_certs']            or 0,
        'revoked_certs':           cert_row['revoked_certs']           or 0,
        'total_verifications':     log_row['total_verifications']      or 0,
        'authentic_verifications': log_row['authentic_verifications']  or 0,
        'failed_verifications':    log_row['failed_verifications']     or 0,
        'revoked_verifications':   log_row['revoked_verifications']    or 0,
    }


def get_verification_analytics(days: int = 30) -> dict:
    """
    Compute comprehensive verification metrics and time-series analytics over the last `days` days.
    Returns:
      - days: int
      - timeline: list of {'date': 'YYYY-MM-DD', 'authentic': N, 'failed': N, 'revoked': N, 'expired': N, 'total': N}
      - status_counts: dict of outcome counts
      - method_counts: dict of method/channel counts
      - top_certs: list of top 5 verified certificates with recipient names and counts
      - summary: dict of KPI totals, success rates, and peak dates
    """
    from datetime import datetime, timedelta
    cutoff = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d 00:00:00')
    conn = get_db()

    rows = conn.execute('''
        SELECT id, cert_id, status, reason, verified_at, ip_address
        FROM verification_logs
        WHERE verified_at >= ?
        ORDER BY verified_at ASC
    ''', (cutoff,)).fetchall()

    date_map = {}
    for i in range(days - 1, -1, -1):
        d_str = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
        date_map[d_str] = {
            'date': d_str,
            'authentic': 0,
            'failed': 0,
            'revoked': 0,
            'expired': 0,
            'total': 0
        }

    status_counts = {'AUTHENTIC': 0, 'INVALID': 0, 'TAMPERED': 0, 'REVOKED': 0, 'EXPIRED': 0}
    method_counts = {
        'SHA-256 Hash': 0,
        'pHash Visual': 0,
        'OCR Extraction': 0,
        'QR Scan': 0,
        'Direct ID Lookup': 0,
        'REST API': 0
    }
    cert_counts = {}

    for r in rows:
        row_dict = dict(r)
        v_at = row_dict.get('verified_at', '')
        date_part = v_at.split(' ')[0] if ' ' in v_at else v_at[:10]
        status = (row_dict.get('status') or 'INVALID').upper()
        reason = (row_dict.get('reason') or '').lower()
        cert_id = row_dict.get('cert_id')

        if date_part in date_map:
            date_map[date_part]['total'] += 1
            if status == 'AUTHENTIC':
                date_map[date_part]['authentic'] += 1
            elif status in ('INVALID', 'TAMPERED'):
                date_map[date_part]['failed'] += 1
            elif status == 'REVOKED':
                date_map[date_part]['revoked'] += 1
            elif status == 'EXPIRED':
                date_map[date_part]['expired'] += 1

        if status in status_counts:
            status_counts[status] += 1
        else:
            status_counts['INVALID'] += 1

        if 'phash' in reason or 'visual' in reason:
            method_counts['pHash Visual'] += 1
        elif 'ocr' in reason:
            method_counts['OCR Extraction'] += 1
        elif 'qr' in reason:
            method_counts['QR Scan'] += 1
        elif 'api' in reason:
            method_counts['REST API'] += 1
        elif 'sha-256' in reason or 'file_hash' in reason or 'exact' in reason or 'hash match' in reason:
            method_counts['SHA-256 Hash'] += 1
        else:
            method_counts['Direct ID Lookup'] += 1

        if cert_id:
            if cert_id not in cert_counts:
                cert_counts[cert_id] = {'total': 0, 'authentic': 0}
            cert_counts[cert_id]['total'] += 1
            if status == 'AUTHENTIC':
                cert_counts[cert_id]['authentic'] += 1

    top_certs_list = []
    sorted_cert_ids = sorted(cert_counts.keys(), key=lambda k: cert_counts[k]['total'], reverse=True)[:5]
    for cid in sorted_cert_ids:
        cert_row = conn.execute('SELECT student_name, course_name FROM certificates WHERE cert_id = ?', (cid,)).fetchone()
        s_name = cert_row['student_name'] if cert_row else 'Unknown'
        c_name = cert_row['course_name'] if cert_row else ''
        top_certs_list.append({
            'cert_id': cid,
            'student_name': s_name,
            'course_name': c_name,
            'total': cert_counts[cid]['total'],
            'authentic': cert_counts[cid]['authentic']
        })

    conn.close()

    total_in_range = len(rows)
    authentic_total = status_counts.get('AUTHENTIC', 0)
    auth_rate = round((authentic_total / total_in_range * 100), 1) if total_in_range > 0 else 100.0

    peak_day = None
    peak_count = 0
    for d, info in date_map.items():
        if info['total'] > peak_count:
            peak_count = info['total']
            peak_day = d

    most_popular_method = max(method_counts.items(), key=lambda x: x[1])[0] if any(method_counts.values()) else 'Direct ID Lookup'

    return {
        'days': days,
        'timeline': list(date_map.values()),
        'status_counts': status_counts,
        'method_counts': method_counts,
        'top_certs': top_certs_list,
        'summary': {
            'total_verifications': total_in_range,
            'authentic_count': authentic_total,
            'failed_count': status_counts.get('INVALID', 0) + status_counts.get('TAMPERED', 0),
            'revoked_count': status_counts.get('REVOKED', 0),
            'expired_count': status_counts.get('EXPIRED', 0),
            'authentic_rate': auth_rate,
            'peak_day': peak_day or 'N/A',
            'peak_count': peak_count,
            'most_popular_method': most_popular_method
        }
    }


# ─── Admin Auth ───────────────────────────────────────────────────────────────

def verify_admin(username, password):
    """
    Verify admin credentials using PBKDF2 (with legacy SHA-256 upgrade path).
    Returns admin user dict with role if valid, or None if invalid.
    """
    conn = get_db()
    row = conn.execute(
        'SELECT * FROM admin_users WHERE username = ?', (username,)
    ).fetchone()

    if not row:
        conn.close()
        return None

    r_dict = dict(row)
    stored_hash = r_dict['password_hash']
    role = r_dict.get('role', 'superadmin')
    totp_enabled = bool(r_dict.get('totp_enabled', 0))
    totp_secret = r_dict.get('totp_secret')

    user_dict = {
        'id': r_dict['id'],
        'username': r_dict['username'],
        'role': role,
        'totp_enabled': totp_enabled,
        'totp_secret': totp_secret
    }

    if _is_legacy_sha256(stored_hash):
        old_hash = hashlib.sha256(password.encode()).hexdigest()
        if hmac.compare_digest(old_hash, stored_hash):
            new_hash = _hash_password(password)
            conn.execute(
                'UPDATE admin_users SET password_hash = ? WHERE username = ?',
                (new_hash, username)
            )
            conn.commit()
            conn.close()
            return user_dict
        conn.close()
        return None

    conn.close()
    if _verify_password(password, stored_hash):
        return user_dict

    return None


# ─── TOTP Two-Factor Authentication (2FA) Helpers ───────────────────────────

def generate_totp_secret() -> str:
    """Generate a random Base32 secret key for TOTP 2FA."""
    return pyotp.random_base32()


def get_totp_uri(username: str, secret: str) -> str:
    """Generate standard otpauth:// URI for authenticator QR codes."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name='CertValid')


def generate_qr_code_b64(data_uri: str) -> str:
    """Generate a Base64 encoded PNG string of a QR code from URI string."""
    qr = qrcode.QRCode(version=1, box_size=5, border=2)
    qr.add_data(data_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color='black', back_color='white')
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    return base64.b64encode(buf.getvalue()).decode('utf-8')


def verify_totp_code(secret: str, code: str) -> bool:
    """Verify a 6-digit TOTP code against a secret key with 30s window tolerance."""
    if not secret or not code:
        return False
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(str(code).strip(), valid_window=1)
    except Exception:
        return False


def enable_admin_2fa(username: str, secret: str):
    """Enable 2FA for an admin user and store their secret."""
    conn = get_db()
    conn.execute(
        'UPDATE admin_users SET totp_secret = ?, totp_enabled = 1 WHERE username = ?',
        (secret, username)
    )
    conn.commit()
    conn.close()


def disable_admin_2fa(username: str):
    """Disable 2FA for an admin user."""
    conn = get_db()
    conn.execute(
        'UPDATE admin_users SET totp_secret = NULL, totp_enabled = 0 WHERE username = ?',
        (username,)
    )
    conn.commit()
    conn.close()


def get_admin_2fa_status(username: str) -> dict:
    """Get 2FA status and secret for an admin user."""
    conn = get_db()
    row = conn.execute(
        'SELECT totp_secret, totp_enabled FROM admin_users WHERE username = ?', (username,)
    ).fetchone()
    conn.close()
    if row:
        r = dict(row)
        return {'enabled': bool(r.get('totp_enabled')), 'secret': r.get('totp_secret')}
    return {'enabled': False, 'secret': None}


# ─── API Key Management & Authentication Helpers ─────────────────────────────

def generate_api_key(key_name: str) -> dict:
    """Generate a new API key with 'cv_live_' prefix and store in DB."""
    raw_key = f"cv_live_{uuid.uuid4().hex}"
    now = datetime.now().isoformat(sep=' ', timespec='seconds')
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        INSERT INTO api_keys (key_name, api_key, created_at, status)
        VALUES (?, ?, ?, 'active')
    ''', (key_name, raw_key, now))
    key_id = c.lastrowid
    conn.commit()
    conn.close()
    return {
        'id': key_id,
        'key_name': key_name,
        'api_key': raw_key,
        'created_at': now,
        'status': 'active'
    }


def validate_api_key(api_key: str) -> bool:
    """Validate if an API key is valid and active."""
    if not api_key:
        return False
    conn = get_db()
    row = conn.execute(
        "SELECT id FROM api_keys WHERE api_key = ? AND status = 'active'", (api_key.strip(),)
    ).fetchone()
    conn.close()
    return row is not None


def get_all_api_keys() -> list:
    """Fetch all API keys ordered by creation date descending."""
    conn = get_db()
    rows = conn.execute("SELECT * FROM api_keys ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def revoke_api_key(key_id: int):
    """Revoke an API key by setting status = 'revoked'."""
    conn = get_db()
    conn.execute("UPDATE api_keys SET status = 'revoked' WHERE id = ?", (key_id,))
    conn.commit()
    conn.close()


# ─── System Settings Helpers ─────────────────────────────────────────────────

def get_setting(key: str, default: str = None) -> str:
    """Get a system setting by key."""
    conn = get_db()
    row = conn.execute("SELECT value FROM system_settings WHERE key = ?", (key,)).fetchone()
    conn.close()
    if row:
        return dict(row).get('value')
    return default


def set_setting(key: str, value: str):
    """Insert or update a system setting by key."""
    conn = get_db()
    conn.execute(
        "INSERT INTO system_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = ?",
        (key, value, value)
    )
    conn.commit()
    conn.close()


# ─── Database Backup & Snapshot Helpers ──────────────────────────────────────

def export_database_json() -> str:
    """
    Export full database contents to a structured JSON string with SHA-256 integrity checksum.
    """
    conn = get_db()
    certs = [dict(r) for r in conn.execute("SELECT * FROM certificates ORDER BY id ASC").fetchall()]
    bundles = [dict(r) for r in conn.execute("SELECT * FROM credential_bundles ORDER BY id ASC").fetchall()]
    logs  = [dict(r) for r in conn.execute("SELECT * FROM audit_logs ORDER BY id ASC").fetchall()]
    keys  = [dict(r) for r in conn.execute("SELECT id, key_name, api_key, created_at, status FROM api_keys ORDER BY id ASC").fetchall()]
    sets  = [dict(r) for r in conn.execute("SELECT * FROM system_settings ORDER BY key ASC").fetchall()]
    conn.close()

    payload = {
        'certificates': certs,
        'credential_bundles': bundles,
        'audit_logs': logs,
        'api_keys': keys,
        'system_settings': sets
    }

    serialized_data = json.dumps(payload, sort_keys=True)
    checksum = hashlib.sha256(serialized_data.encode('utf-8')).hexdigest()

    snapshot = {
        'system': 'CertValid Enterprise Database Snapshot',
        'version': '1.0',
        'exported_at': datetime.now().isoformat(),
        'record_counts': {
            'certificates': len(certs),
            'credential_bundles': len(bundles),
            'audit_logs': len(logs),
            'api_keys': len(keys),
            'system_settings': len(sets)
        },
        'checksum_sha256': checksum,
        'data': payload
    }
    return json.dumps(snapshot, indent=2)


def restore_database_json(snapshot_dict: dict) -> dict:
    """
    Validate and restore database snapshot from parsed JSON object.
    Merges records safely into certificates, credential_bundles, audit_logs, and system_settings.
    """
    if not isinstance(snapshot_dict, dict) or 'data' not in snapshot_dict or 'checksum_sha256' not in snapshot_dict:
        return {'success': False, 'message': 'Invalid snapshot format: missing data or checksum.'}

    data = snapshot_dict['data']
    checksum_given = snapshot_dict['checksum_sha256']
    serialized_data = json.dumps(data, sort_keys=True)
    checksum_calc  = hashlib.sha256(serialized_data.encode('utf-8')).hexdigest()

    if checksum_given != checksum_calc:
        return {'success': False, 'message': 'Checksum Verification Failed! The snapshot file may be corrupted or altered.'}

    conn = get_db()
    c = conn.cursor()

    restored_certs = 0
    restored_bundles = 0
    restored_logs = 0

    # Restore Certificates
    for cert in data.get('certificates', []):
        c.execute('''
            INSERT INTO certificates (cert_id, student_name, course_name, issue_date, issuer_name, file_hash, status, signature, phash, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cert_id) DO UPDATE SET
              student_name = excluded.student_name,
              course_name  = excluded.course_name,
              issue_date   = excluded.issue_date,
              issuer_name  = excluded.issuer_name,
              file_hash    = excluded.file_hash,
              status       = excluded.status,
              signature    = excluded.signature,
              phash        = excluded.phash,
              expires_at   = excluded.expires_at
        ''', (
            cert.get('cert_id'), cert.get('student_name'), cert.get('course_name'),
            cert.get('issue_date'), cert.get('issuer_name'), cert.get('file_hash'),
            cert.get('status', 'active'), cert.get('signature'), cert.get('phash'),
            cert.get('expires_at')
        ))
        restored_certs += 1

    # Restore Credential Bundles
    for b in data.get('credential_bundles', []):
        c.execute('''
            INSERT INTO credential_bundles (bundle_id, title, recipient_name, recipient_email, institution_name, issue_date, cert_ids, bundle_hash, signature, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(bundle_id) DO UPDATE SET
              title = excluded.title,
              recipient_name = excluded.recipient_name,
              recipient_email = excluded.recipient_email,
              institution_name = excluded.institution_name,
              issue_date = excluded.issue_date,
              cert_ids = excluded.cert_ids,
              bundle_hash = excluded.bundle_hash,
              signature = excluded.signature,
              status = excluded.status
        ''', (
            b.get('bundle_id'), b.get('title'), b.get('recipient_name'),
            b.get('recipient_email'), b.get('institution_name'), b.get('issue_date'),
            b.get('cert_ids'), b.get('bundle_hash'), b.get('signature'),
            b.get('status', 'active'), b.get('created_at', datetime.now().isoformat())
        ))
        restored_bundles += 1

    # Restore Settings
    for st in data.get('system_settings', []):
        if st.get('key') and st.get('value'):
            c.execute('''
                INSERT INTO system_settings (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
            ''', (st['key'], st['value']))

    conn.commit()
    conn.close()

    # Rebuild BK-Tree in memory
    init_db()

    return {
        'success': True,
        'message': f'Database restored successfully! Imported/merged {restored_certs} certificates.'
    }




