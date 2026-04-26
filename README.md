# 🔐 Cipher Nest — Secure File Vault

> *Secure your files. Own your data.*

Cipher Nest is a lightweight, modular, and cryptographically strong personal file management system built entirely in Python. It provides a central encrypted vault where sensitive files can be stored, accessed, and managed securely — with the original plaintext deleted after encryption, ensuring no unprotected copy ever remains on disk.

---

## ✨ Features

- 🔐 **Fernet encryption** (AES-128-CBC + HMAC-SHA256) — industry-standard file confidentiality and tamper detection
- 🧂 **Per-file random salt** — unique salt per file via `os.urandom()`, no key ever stored on disk
- 🔑 **PBKDF2-HMAC-SHA256** key derivation with 390,000 iterations (OWASP 2023 compliant)
- 👤 **bcrypt authentication** with cost factor 12 — strong resistance to offline brute-force attacks
- 📦 **Central vault** — files encrypted and moved into a per-user vault directory, original deleted
- 🔁 **Open + Relock flow** — temporarily decrypt a file for viewing/editing, auto re-encrypt when done
- 📋 **Permanent MongoDB audit trail** — every operation logged forever, even after account deletion
- 🗑️ **Account deletion with export** — all vault files returned to you before account is wiped
- 🖥️ **Coloured CLI** with secure password entry via `getpass`
- 🏗️ **4-layer modular architecture** — GUI-ready, zero changes needed to add Tkinter

---

## 🏗️ Architecture

```
User
  ↓
cli.py          ← Interface layer (input + display only)
  ↓
core.py         ← Business logic (auth, session, vault ops)
  ↙                 ↘
crypto_engine.py    audit_db.py
(Fernet + PBKDF2)   (MongoDB)
  ↓                     ↓
cipher_nest_vault/   MongoDB Collections
  <user_id>/          users · files · audit_logs
    file.enc
    file.enc.salt
```

---

## 📁 Project Structure

```
Cipher_Nest/
  crypto_engine.py   ← Module 1: Encryption engine
  core.py            ← Module 2a: Pure business logic
  cli.py             ← Module 2b: CLI interface
  audit_db.py        ← Module 3: MongoDB integration
  requirements.txt
  README.md
```

---

## 🚀 Getting Started

### Prerequisites

- Python 3.10+
- MongoDB 6.0+ running locally

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/cipher-nest.git
cd cipher-nest

# Install dependencies
pip install -r requirements.txt

# Start MongoDB
mongod --dbpath /data/db
```

### Run

```bash
python cli.py
```

---

## 📦 Tech Stack

| Component | Library |
|---|---|
| File encryption | `cryptography` (Fernet + PBKDF2) |
| Password hashing | `bcrypt` |
| Database | `pymongo` + MongoDB |
| CLI colours | `colorama` |
| File handling | `pathlib` + `os` |
| Integrity check | `hashlib` (SHA256) |

---

## 🔄 Vault Operations

| Command | What it does |
|---|---|
| `encrypt` | Import file into vault, delete original |
| `decrypt` | Export file from vault, delete .enc |
| `open` | Temp decrypt to staging area for viewing/editing |
| `relock` | Re-encrypt temp file back into vault |
| `list` | Show all files in your vault |
| `delete` | Permanently remove a file from vault |
| `audit log` | View all your operations from MongoDB |
| `delete account` | Export all files, then wipe account + vault |

---

## 🗄️ MongoDB Collections

```
ciphernest
  ├── users        ← username + bcrypt hash + created_at
  ├── files        ← vault metadata, status tracking per file
  └── audit_logs   ← permanent insert-only operation history
```

---

## 🔐 Security Design

- **No key ever stored on disk** — Fernet key derived fresh from password + salt on every operation
- **Per-file salt** — `os.urandom(16)` ensures unique encryption even for identical files with same password
- **HMAC tamper detection** — Fernet's built-in HMAC detects any modification to .enc files
- **SHA256 integrity** — file hash stored in MongoDB, verified after decryption
- **Timing-safe login** — bcrypt comparison prevents user enumeration attacks
- **Memory safety** — password wiped from memory on logout

---

## 🔮 Future Scope

- [ ] Tkinter GUI — `gui.py` replacing `cli.py`, zero core changes needed
- [ ] MongoDB Atlas — cloud-based vault storage
- [ ] Role-based access control — admin vs regular user
- [ ] Key rotation — re-encrypt vault with new password
- [ ] Chunked encryption — support for large files (>100MB)
- [ ] Multi-user session switching — without restarting the app
- [ ] Startup orphan check — detect temp files left from crashed sessions

---

## 📄 References

1. [cryptography.io](https://cryptography.io) — Fernet + PBKDF2 library
2. [bcrypt](https://pypi.org/project/bcrypt/) — Password hashing
3. [MongoDB Docs](https://www.mongodb.com/docs/) — Database
4. [OWASP Password Storage](https://cheatsheetseries.owasp.org) — PBKDF2 iteration recommendations
5. [Python hashlib](https://docs.python.org/3/library/hashlib.html) — SHA256 hashing
6. [Python pathlib](https://docs.python.org/3/library/pathlib.html) — File handling
7. [Python logging](https://docs.python.org/3/library/logging.html) — Logging module

---

## 👤 Author

**Jerush Dannerson V C**
CSE – Cyber Security | Sri Eshwar College of Engineering
Reg No: 722825149024 | Batch: 2025–2029

---

*Built as part of the Python Programming course project.*
