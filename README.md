# 🛡️ CertValid — Certificate Verification & Management System

[![Live Demo](https://img.shields.io/badge/Live%20Demo-PythonAnywhere-brightgreen?style=for-the-badge&logo=python)](https://ranjithbrs.pythonanywhere.com)
[![GitHub Repo](https://img.shields.io/badge/GitHub-Repository-blue?style=for-the-badge&logo=github)](https://github.com/ranjithbrs/CertValid)
[![License](https://img.shields.io/badge/License-MIT-purple?style=for-the-badge)](LICENSE)

A modern, enterprise-ready **Flask-based** Certificate Verification & Management System. Supports cryptographic SHA-256 file tamper detection, Certificate ID lookup, scannable QR code generation, dynamic PNG certificate downloading, salted PBKDF2 password security, and a full Admin Management Dashboard with audit trail logging.

---

## 🔗 Live Application & Links

- 🌐 **Live Public Portal:** [ranjithbrs.pythonanywhere.com](https://ranjithbrs.pythonanywhere.com)
- 🔑 **Admin Dashboard:** [ranjithbrs.pythonanywhere.com/admin](https://ranjithbrs.pythonanywhere.com/admin)
- 🐙 **GitHub Repository:** [github.com/ranjithbrs/CertValid](https://github.com/ranjithbrs/CertValid)

---

## ✨ Features

- 🔐 **Cryptographic SHA-256 Tamper Detection** — Uploaded certificate files (JPG/PNG/PDF) have their SHA-256 hash computed and compared against the indexed registry. Any byte-level alteration instantly triggers a **TAMPERED / INVALID** alert.
- 🛡️ **Salted PBKDF2 Password Security** — Admin credentials are encrypted using `PBKDF2-HMAC-SHA256` (260,000 iterations + 16-byte random salt) with constant-time verification (`hmac.compare_digest`). Includes automatic transparent migration from legacy hashes.
- 🔍 **Dual Verification Modes** — Verify certificates by **Drag-and-Drop File Upload** or **Certificate ID Search**.
- 📱 **Embedded Live-Domain QR Codes** — Every issued certificate includes a QR code generated with the live production domain (`BASE_URL`). Scanning it opens a live verification page in the browser.
- 🎓 **Dynamic Certificate Image Generator** — Certificates are generated on-the-fly with custom typography, issue details, and embedded QR codes. High-resolution PNGs are created dynamically if not present on disk.
- ⚡ **Database Optimizations** — Indexed `file_hash` lookup ($O(1)$ complexity), SQLite WAL (Write-Ahead Logging) mode enabled, and single-connection aggregate SQL dashboard statistics.
- 🚫 **Revoke & Reactivate Control** — Administrators can instantly revoke fraudulent or compromised certificates or reactivate them.
- 📜 **Full Audit Logging** — Every verification request is logged with timestamp, computed hash, IP address, and verification status.
- 🎨 **Modern Dark Glassmorphism UI & Error Pages** — Built with clean HTML5 & CSS3 featuring glassmorphic cards, micro-animations, responsive tables, custom status badges, and styled 404/500 error handlers.

---

## 🧪 Sample Certificates for Live Testing

Try these test certificates on the [Live Site](https://ranjithbrs.pythonanywhere.com):

| Certificate ID | Recipient Name | Course | Status | Direct Verification Link |
|----------------|----------------|--------|--------|--------------------------|
| `CERT-2024-001` | Aisha Sharma | B.Tech Computer Science | ✅ **Authentic** | [Verify CERT-2024-001](https://ranjithbrs.pythonanywhere.com/verify/CERT-2024-001) |
| `CERT-2024-002` | Rahul Verma | MBA Finance | ✅ **Authentic** | [Verify CERT-2024-002](https://ranjithbrs.pythonanywhere.com/verify/CERT-2024-002) |
| `CERT-2023-099` | Priya Patel | M.Sc Data Science | 🚫 **Revoked** | [Verify CERT-2023-099](https://ranjithbrs.pythonanywhere.com/verify/CERT-2023-099) |

---

## 🔑 Default Admin Credentials

Access the Admin Panel at [ranjithbrs.pythonanywhere.com/admin](https://ranjithbrs.pythonanywhere.com/admin):

| Username | Password |
|----------|----------|
| `admin`  | `admin123` |

---

## 🚀 Quick Start (Local Setup)

### 1. Clone the repository
```bash
git clone https://github.com/ranjithbrs/CertValid.git
cd CertValid
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Initialize Database & Run
```bash
python app.py
```

Open your browser to:
- **Public Portal:** `http://127.0.0.1:5000`
- **Admin Dashboard:** `http://127.0.0.1:5000/admin`

---

## ⚙️ Environment Variables (Optional)

| Variable | Description | Default |
|----------|-------------|---------|
| `BASE_URL` | Base URL used in generated QR code verification links | `https://ranjithbrs.pythonanywhere.com` |
| `SECRET_KEY` | Flask session secret key | Auto-generated random 32-byte hex token |
| `FLASK_DEBUG` | Enable debug mode (`true` / `false`) | `false` |

---

## 🌐 Deploying to PythonAnywhere

1. **Clone repository on PythonAnywhere:**
   ```bash
   git clone https://github.com/ranjithbrs/CertValid.git
   cd CertValid
   pip install --user -r requirements.txt
   ```

2. **Initialize Database:**
   ```bash
   python -c "import db; db.init_db()"
   ```

3. **Configure Web App in PythonAnywhere Web Tab:**
   - Select **Python 3.10**
   - Point WSGI file to:
     ```python
     import sys, os
     project_home = '/home/<your-username>/CertValid'
     if project_home not in sys.path:
         sys.path.insert(0, project_home)
     from app import app as application
     ```
   - Set Static Files mapping: `/static/` → `/home/<your-username>/CertValid/static/`
   - Click **Reload**!

---

## 📁 Project Structure

```
CertValid/
├── app.py              # Flask app, routes, image generator & error handlers
├── db.py               # SQLite database layer, indexing, PBKDF2 auth & CRUD
├── database.db         # SQLite database file (auto-initialized)
├── wsgi.py             # WSGI entry point for production deployment
├── requirements.txt    # Python package dependencies
├── README.md           # Comprehensive project documentation
├── .gitignore          # Git exclusion rules
├── static/
│   ├── style.css       # Custom Glassmorphism CSS design system
│   ├── uploads/        # Temporary uploaded certificate files
│   └── certs/          # Generated certificate PNG images
└── templates/
    ├── upload.html     # Public verification portal (upload & ID search)
    ├── result.html     # Verification report & cryptographic audit view
    ├── admin.html      # Admin dashboard, certificate issuer & audit logs
    └── error.html      # Styled 404 / 500 error pages
```

---

## 🔒 Verification Workflow Architecture

```mermaid
graph TD
    A[User Uploads File / Enters ID] --> B{Verification Mode}
    B -- File Upload --> C[Compute SHA-256 Hash]
    C --> D[Lookup Hash in Registry Index]
    B -- Certificate ID --> E[Lookup ID in Registry]
    D -- Hash Match --> F{Check Status}
    D -- No Hash Match --> G[Status: INVALID / TAMPERED]
    E -- Found --> F
    E -- Not Found --> G
    F -- Active --> H[Status: AUTHENTIC ✅]
    F -- Revoked --> I[Status: REVOKED 🚫]
    H --> J[Log Attempt & Display Detailed Report]
    G --> J
    I --> J
```

---

## 🛠️ Technology Stack

- **Backend:** Python 3, Flask
- **Database:** SQLite3 (WAL mode, indexed)
- **Image Processing & QR:** Pillow (PIL), `qrcode`, NumPy
- **Frontend:** HTML5, Modern Vanilla CSS (Glassmorphism design system)
- **Security:** SHA-256 file hashing, PBKDF2-HMAC-SHA256 password security, constant-time comparison, 1-hr session timeout
- **Hosting:** PythonAnywhere

---

## 📄 License

This project is open-source and available under the [MIT License](LICENSE).
