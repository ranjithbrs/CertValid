"""
db.py - Database initialization and helper functions for the Certificate Verification System.
Uses SQLite for persistence. All certificate data and verification logs are stored here.
"""

import sqlite3
import hashlib
import uuid
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), 'database.db')


def get_db():
    """Get a database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize database tables and seed sample data if empty."""
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

    # Seed default admin if not exists
    admin_pw_hash = hashlib.sha256('admin123'.encode()).hexdigest()
    c.execute('INSERT OR IGNORE INTO admin_users (username, password_hash) VALUES (?, ?)',
              ('admin', admin_pw_hash))

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
        existing = c.execute('SELECT id FROM certificates WHERE cert_id = ?', (s['cert_id'],)).fetchone()
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


def generate_cert_id():
    """Generate a unique certificate ID like CERT-2024-XXXX."""
    year = datetime.now().year
    unique = str(uuid.uuid4()).replace('-', '').upper()[:6]
    return f'CERT-{year}-{unique}'


def compute_file_hash(file_bytes: bytes) -> str:
    """Compute SHA-256 hash of file bytes."""
    return hashlib.sha256(file_bytes).hexdigest()


def add_certificate(student_name, course_name, issue_date, issuer_name, file_hash):
    """
    Insert a new certificate record.
    Returns the generated cert_id.
    """
    cert_id = generate_cert_id()
    now = datetime.now().isoformat(sep=' ', timespec='seconds')
    conn = get_db()
    conn.execute('''
        INSERT INTO certificates (cert_id, student_name, course_name, issue_date, issuer_name, file_hash, status, created_at)
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
    """Fetch a certificate record by its file hash."""
    conn = get_db()
    row = conn.execute('SELECT * FROM certificates WHERE file_hash = ?', (file_hash,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_certificates():
    """Fetch all certificates ordered by creation date."""
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


def log_verification(cert_id, file_name, computed_hash, status, reason, ip_address):
    """Log a verification attempt."""
    now = datetime.now().isoformat(sep=' ', timespec='seconds')
    conn = get_db()
    conn.execute('''
        INSERT INTO verification_logs (cert_id, file_name, computed_hash, status, reason, verified_at, ip_address)
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


def get_stats():
    """Get dashboard statistics."""
    conn = get_db()
    total_certs = conn.execute("SELECT COUNT(*) FROM certificates").fetchone()[0]
    active_certs = conn.execute("SELECT COUNT(*) FROM certificates WHERE status='active'").fetchone()[0]
    revoked_certs = conn.execute("SELECT COUNT(*) FROM certificates WHERE status='revoked'").fetchone()[0]
    total_verifications = conn.execute("SELECT COUNT(*) FROM verification_logs").fetchone()[0]
    authentic_verifications = conn.execute(
        "SELECT COUNT(*) FROM verification_logs WHERE status='AUTHENTIC'"
    ).fetchone()[0]
    tampered_verifications = conn.execute(
        "SELECT COUNT(*) FROM verification_logs WHERE status='TAMPERED'"
    ).fetchone()[0]
    invalid_verifications = conn.execute(
        "SELECT COUNT(*) FROM verification_logs WHERE status='INVALID'"
    ).fetchone()[0]
    conn.close()
    return {
        'total_certs': total_certs,
        'active_certs': active_certs,
        'revoked_certs': revoked_certs,
        'total_verifications': total_verifications,
        'authentic_verifications': authentic_verifications,
        'tampered_verifications': tampered_verifications,
        'invalid_verifications': invalid_verifications,
    }


def verify_admin(username, password):
    """Verify admin credentials. Returns True if valid."""
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    conn = get_db()
    row = conn.execute(
        'SELECT id FROM admin_users WHERE username = ? AND password_hash = ?',
        (username, pw_hash)
    ).fetchone()
    conn.close()
    return row is not None
