# secure-file-access-portal
secure web access portal for downloading files with granular control over the access
# 🔐 Secure File Portal

A lightweight Flask-based web application for authenticated file access, search, download, and deletion. Designed for internal teams to securely manage shared folders with user-specific access.

---

## 🚀 Features

- User login with folder-based access control
- File listing with timestamps, sorted by modification time
- Search functionality across user-specific files
- Secure file download and deletion
- Session-based authentication using Flask-Login
- Optional IP whitelisting and proxy-aware client IP parsing
- SSL-enabled for secure communication

---

## 🧱 Requirements

- Python 3.7+
- Flask
- Flask-Login
- Werkzeug
- Optional: `python-dotenv` for environment variable support

Install dependencies:

```bash
pip install -r requirements.txt
