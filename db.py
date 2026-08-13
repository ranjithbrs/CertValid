"""
db.py - Database initialization and helper functions for the Certificate Verification System.
Uses SQLite for persistence. All certificate data and verification logs are stored here.
"""

import sqlite3
import hashlib
import hmac
import uuid
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), 'database.db')


# ─── Connection ───────────────────────────────────────────────────────────────

def get_db():
    """Get a database connection with WAL mode for better concurrency."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA foreign_keys=ON')
    return conn


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


# ─── Schema Init ─────────────────────────────────────────────────────────────

def init_db():
    """Initialize database tables, indexes, and seed sample data if empty."""
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
            status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL
        )
    ''')

    # Performance: index on file_hash for O(1) lookups on every file upload verify
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

    # Admin users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')

    # Seed default admin with secure PBKDF2 hash
    existing_admin = c.execute(
        'SELECT id FROM admin_users WHERE username = ?', ('admin',)
    ).fetchone()
    if not existing_admin:
        secure_hash = _hash_password('admin123')
        c.execute(
            'INSERT INTO admin_users (username, password_hash) VALUES (?, ?)',
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
            c.execute('''
                INSERT INTO certificates
                (cert_id, student_name, course_name, issue_date, issuer_name, file_hash, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (s['cert_id'], s['student_name'], s['course_name'],
                  s['issue_date'], s['issuer_name'], s['file_hash'],
                  s['status'], now))

    conn.commit()
    conn.close()


# ─── Cert ID Generator ────────────────────────────────────────────────────────

def generate_cert_id():
    """Generate a unique certificate ID like CERT-2026-XXXXXX."""
    year = datetime.now().year
    unique = str(uuid.uuid4()).replace('-', '').upper()[:6]
    return f'CERT-{year}-{unique}'


# ─── File Hash ────────────────────────────────────────────────────────────────

def compute_file_hash(file_bytes: bytes) -> str:
    """Compute SHA-256 hash of file bytes."""
    return hashlib.sha256(file_bytes).hexdigest()


# ─── Certificate CRUD ────────────────────────────────────────────────────────

def add_certificate(student_name, course_name, issue_date, issuer_name, file_hash):
    """Insert a new certificate record. Returns the generated cert_id."""
    cert_id = generate_cert_id()
    now = datetime.now().isoformat(sep=' ', timespec='seconds')
    conn = get_db()
    conn.execute('''
        INSERT INTO certificates
        (cert_id, student_name, course_name, issue_date, issuer_name, file_hash, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 'active', ?)
    ''', (cert_id, student_name, course_name, issue_date, issuer_name, file_hash, now))
    conn.commit()
    conn.close()
    return cert_id


def get_certificate_by_id(cert_id):
    """Fetch a certificate record by cert_id."""
    conn = get_db()
    row = conn.execute('SELECT * FROM certificates WHERE cert_id = ?', (cert_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_certificate_by_hash(file_hash):
    """Fetch a certificate record by its file hash (uses index)."""
    conn = get_db()
    row = conn.execute('SELECT * FROM certificates WHERE file_hash = ?', (file_hash,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_certificates():
    """Fetch all certificates ordered by creation date descending."""
    conn = get_db()
    rows = conn.execute('SELECT * FROM certificates ORDER BY created_at DESC').fetchall()
    conn.close()
    return [dict(r) for r in rows]


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


def get_all_logs(limit=100):
    """Fetch verification logs ordered by most recent."""
    conn = get_db()
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


# ─── Admin Auth ───────────────────────────────────────────────────────────────

def verify_admin(username, password):
    """
    Verify admin credentials using PBKDF2 (with legacy SHA-256 upgrade path).
    Returns True if valid.
    """
    conn = get_db()
    row = conn.execute(
        'SELECT id, password_hash FROM admin_users WHERE username = ?', (username,)
    ).fetchone()

    if not row:
        conn.close()
        return False

    stored_hash = row['password_hash']

    # Legacy: old plain SHA-256 hash — verify and silently upgrade to PBKDF2
    if _is_legacy_sha256(stored_hash):
        old_hash = hashlib.sha256(password.encode()).hexdigest()
        if hmac.compare_digest(old_hash, stored_hash):
            # Upgrade to PBKDF2 on the fly
            new_hash = _hash_password(password)
            conn.execute(
                'UPDATE admin_users SET password_hash = ? WHERE username = ?',
                (new_hash, username)
            )
            conn.commit()
            conn.close()
            return True
        conn.close()
        return False

    conn.close()
    return _verify_password(password, stored_hash)
