# 🛡️ CertValid — Enterprise Certificate Verification & Management System

[![Live Demo](https://img.shields.io/badge/Live%20Demo-PythonAnywhere-brightgreen?style=for-the-badge&logo=python&logoColor=white)](https://ranjithbrs.pythonanywhere.com)
[![Framework: Flask](https://img.shields.io/badge/Framework-Flask-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Database: SQLAlchemy](https://img.shields.io/badge/Database-SQLAlchemy%20%2F%20PostgreSQL-003B57?style=for-the-badge&logo=postgresql&logoColor=white)](https://www.sqlalchemy.org/)
[![Security: Ed25519](https://img.shields.io/badge/Security-Ed25519%20Digital%20Signatures-indigo?style=for-the-badge&logo=securityscorecard&logoColor=white)](app.py)
[![License: MIT](https://img.shields.io/badge/License-MIT-purple?style=for-the-badge)](LICENSE)

> An enterprise-grade **Flask-based** Certificate Verification & Management System. Features 3-tier multi-modal verification (SHA-256 byte hashing, 64-bit Perceptual Image Hashing, and OCR PDF/text parsing), Ed25519 asymmetric cryptographic digital signatures, AWS S3 cloud storage, Flask-Limiter rate limiting, and Role-Based Access Control (RBAC).

---

## 🔗 Live Application & Portals

- 🌐 **Live Public Portal:** [ranjithbrs.pythonanywhere.com](https://ranjithbrs.pythonanywhere.com)
- 🔑 **Admin Management Dashboard:** [ranjithbrs.pythonanywhere.com/admin](https://ranjithbrs.pythonanywhere.com/admin)
- 🐙 **GitHub Repository:** [github.com/ranjithbrs/CertValid](https://github.com/ranjithbrs/CertValid)

---

## 🔒 Multi-Layer Verification Architecture

```mermaid
flowchart TD
    subgraph Client["🖥️ Verification Inputs"]
        A[User Uploads File / PDF / Image] --> C{Verification Controller}
        B[User Enters Certificate ID] --> C
        QR[Scans QR Code] --> C
    end

    subgraph Tier1["Tier 1: Cryptographic SHA-256"]
        C -->|File Upload| D[Compute SHA-256 Digest]
        D --> E{Exact DB Hash Match?}
        E -->|Match Found| OK[✅ AUTHENTIC: Exact Byte Match]
    end

    subgraph Tier2["Tier 2: Perceptual Image Hash (pHash)"]
        E -->|Mismatch| F[Compute 64-bit pHash & Hamming Distance]
        F --> G{Visual Similarity >= 84%?}
        G -->|Visual Match| OK2[👁️ AUTHENTIC: Visual Image Match]
    end

    subgraph Tier3["Tier 3: OCR & PDF Text Extraction"]
        G -->|Mismatch| H[Extract PDF/Image Text & Parse CERT-YYYY-XXXXXX]
        H --> I{Extracted ID Found in Registry?}
        I -->|ID Match| OK3[📄 AUTHENTIC: OCR Text Match]
        I -->|No Match| FAIL[❌ INVALID / ALTERED]
    end

    subgraph CryptoSign["🔏 Ed25519 Signature Verification"]
        OK --> V[Verify Asymmetric Ed25519 Digital Signature]
        OK2 --> V
        OK3 --> V
    end
```

---

## ✨ Enterprise Features & Upgrades

- 🔏 **Ed25519 Asymmetric Digital Signatures** — Every certificate payload (`cert_id|name|course|date|hash`) is signed using an **Ed25519 Private Key**. Anyone holding the Public Key can verify mathematical authenticity offline without a database.
- 👁️ **Perceptual Image Hashing (pHash)** — 64-bit visual hashing (`imagehash`) detects authentic certificates even if re-saved, compressed (PNG $\rightarrow$ JPG), or resized ($\ge 84.4\%$ similarity match).
- 📄 **OCR & PDF Text Extraction** — Parses PDF text (`pypdf`) and scanned images (`pytesseract`) using regex matching (`r'CERT-\d{4}-[A-Z0-9]{3,8}'`) to verify uploaded documents.
- 🛡️ **Flask-Limiter Rate Limiting** — Protects against request spam and brute-force attacks (10 req/min on `/verify`, 5 attempts/5min on `/admin`).
- 🔐 **Salted PBKDF2 Password Security** — Credentials hashed via `PBKDF2-HMAC-SHA256` (260,000 iterations + 16-byte random salt) with constant-time verification (`hmac.compare_digest`).
- 👥 **Role-Based Access Control (RBAC)** — Three granular roles:
  - 👑 **`superadmin`**: Full system access (issue, revoke/reactivate, view logs).
  - 🎓 **`issuer`**: Certificate issuance & registry access.
  - 👁️ **`auditor`**: Read-only audit access.
- 🗄️ **SQLAlchemy Database Abstraction** — Seamlessly switches between local **SQLite** (`database.db`) and production **PostgreSQL / MySQL** via `DATABASE_URL`.
- ☁️ **AWS S3 Cloud Storage Adapter** — Uploads generated certificates to S3 buckets (`boto3`) with transparent local disk fallback.

---

## 🧪 Sample Certificates for Live Testing

Test the verification engine using these seeded records on the [Live Site](https://ranjithbrs.pythonanywhere.com):

| Certificate ID | Recipient Name | Course / Program | Status | Direct Live Verification Link |
| :--- | :--- | :--- | :--- | :--- |
| `CERT-2024-001` | Aisha Sharma | B.Tech Computer Science | ✅ **Authentic** | [Verify CERT-2024-001](https://ranjithbrs.pythonanywhere.com/verify/CERT-2024-001) |
| `CERT-2024-002` | Rahul Verma | MBA Finance | ✅ **Authentic** | [Verify CERT-2024-002](https://ranjithbrs.pythonanywhere.com/verify/CERT-2024-002) |
| `CERT-2023-099` | Priya Patel | M.Sc Data Science | 🚫 **Revoked** | [Verify CERT-2023-099](https://ranjithbrs.pythonanywhere.com/verify/CERT-2023-099) |

---

## 🔑 Default Admin Credentials

Access the Admin Dashboard at [ranjithbrs.pythonanywhere.com/admin](https://ranjithbrs.pythonanywhere.com/admin):

| Field | Default Value | Role |
| :--- | :--- | :--- |
| **Username** | `admin` | `superadmin` |
| **Password** | `admin123` | Salted & hashed via PBKDF2-HMAC-SHA256 |

---

## ⚙️ Environment Variables

| Variable | Description | Default Value |
| :--- | :--- | :--- |
| `DATABASE_URL` | PostgreSQL/MySQL URI (e.g., `postgresql://user:pass@host/db`) | SQLite (`database.db`) |
| `BASE_URL` | Base URL embedded in generated QR codes | `https://ranjithbrs.pythonanywhere.com` |
| `S3_BUCKET_NAME` | AWS S3 Bucket Name for cloud image storage | Local filesystem |
| `AWS_ACCESS_KEY_ID` | AWS Access Key ID | None |
| `AWS_SECRET_ACCESS_KEY` | AWS Secret Access Key | None |
| `SECRET_KEY` | Flask session encryption key | Auto-generated 32-byte token |
| `FLASK_DEBUG` | Enable Flask debug mode (`true` / `false`) | `false` |

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

### 3. Initialize Database & Start Server
```bash
python app.py
```

Access in browser:
- **Public Verification Portal:** `http://127.0.0.1:5000`
- **Admin Dashboard:** `http://127.0.0.1:5000/admin`

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

3. **Reload Web App in PythonAnywhere Web Tab!**

---

## 🛠️ Technology Stack

- **Backend:** Python 3, Flask, SQLAlchemy, WSGI
- **Database:** SQLite3 (WAL mode) / PostgreSQL / MySQL
- **Cryptography:** Ed25519 Elliptic Curve Signatures, SHA-256, PBKDF2-HMAC-SHA256
- **Image & Document Processing:** Pillow, `imagehash`, `pypdf`, `pytesseract`, `qrcode`
- **Cloud & Infrastructure:** AWS S3 (`boto3`), Flask-Limiter
- **Frontend:** HTML5, Modern Vanilla CSS3 (Glassmorphism design system)

---

## 👨‍💻 Author

**Ranjith B**  
🎓 *B.Tech Computer Science & Business Systems (CSBS)*  
🏛️ *Nehru Institute of Engineering and Technology, Coimbatore*  

- 💼 **LinkedIn**: [linkedin.com/in/ranjith-b-85907831a](https://linkedin.com/in/ranjith-b-85907831a)  
- 🐙 **GitHub**: [github.com/ranjithbrs](https://github.com/ranjithbrs)  
- 🌐 **Portfolio**: [ranjithbrs.github.io/portfolio](https://ranjithbrs.github.io/portfolio/)  
- 📧 **Email**: ranjithb2k06@gmail.com  

---

## 📄 License

This project is open-source under the [MIT License](LICENSE).
