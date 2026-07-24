# CertValid — Certificate Verification System

A **Flask-based** Certificate Verification & Management System with cryptographic SHA-256 tamper detection, QR code generation, and a modern dark-themed UI.

---

## ✨ Features

- 🔐 **SHA-256 Cryptographic Verification** — Detects any byte-level file tampering
- 🔍 **Certificate ID Lookup** — Instant registry search by unique Certificate ID
- 📱 **QR Code Generation** — Each certificate gets a scannable QR that links to live verification
- 🎓 **Certificate Image Generator** — Downloadable PNG certificate with QR code embedded
- 🚫 **Revoke / Reactivate** — Admin can toggle certificate status
- 📜 **Audit Trail** — Every verification attempt logged with IP and timestamp
- 🛡️ **Admin Dashboard** — Secure login, issue certs, manage registry, view logs

---

## 🚀 Quick Start

### 1. Clone the repo
```bash
git clone https://github.com/ranjithbrs/CertValid.git
cd CertValid
```

### 2. Install dependencies
```bash
pip install flask pillow qrcode
```

### 3. Run the app
```bash
python app.py
```

### 4. Open in browser
- **Public Verification:** http://127.0.0.1:5000
- **Admin Dashboard:** http://127.0.0.1:5000/admin

---

## 🔑 Default Admin Credentials

| Username | Password |
|----------|----------|
| `admin`  | `admin123` |

> ⚠️ Change these credentials before deploying to production.

---

## 📁 Project Structure

```
certvalid/
├── app.py              # Flask application & routes
├── db.py               # SQLite database layer & helpers
├── database.db         # Auto-generated SQLite database
├── static/
│   ├── style.css       # Modern glassmorphism CSS design system
│   ├── uploads/        # Temporary uploaded files
│   └── certs/          # Generated certificate images (PNG)
└── templates/
    ├── upload.html     # Public verification portal
    ├── result.html     # Verification result report
    └── admin.html      # Admin login & dashboard
```

---

## 🧪 Test with Sample Data

Three certificates are pre-seeded in the database on first run:

| Certificate ID   | Recipient     | Course                  | Status  |
|------------------|---------------|-------------------------|---------|
| `CERT-2024-001`  | Aisha Sharma  | B.Tech Computer Science | Active  |
| `CERT-2024-002`  | Rahul Verma   | MBA Finance             | Active  |
| `CERT-2023-099`  | Priya Patel   | M.Sc Data Science       | Revoked |

Try searching `CERT-2024-001` in the **Search by ID** tab on the public portal!

---

## 🔒 How Verification Works

1. **Upload a file** → SHA-256 hash computed → matched against registry hash
2. **Enter a Certificate ID** → direct registry lookup
3. **Scan QR code** → instant browser-based verification via unique URL
4. Result shows: Authentic ✅ / Invalid ❌ / Revoked 🚫

---

## 🛠️ Tech Stack

- **Backend:** Python, Flask, SQLite
- **Image Generation:** Pillow (PIL)
- **QR Codes:** qrcode
- **Frontend:** Vanilla HTML, CSS (glassmorphism dark theme)
- **Security:** SHA-256 hashing, session-based admin auth

---

## 📄 License

MIT License — free to use and modify.
