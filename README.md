# 🔐 Security Toolkit

An open-source collection of tools for checking, generating, and protecting passwords, in two parts:

- **Interactive web tools** (no server — run entirely in the browser)
- **A Python CLI tool** for password checking/generation and file encryption

---

## 🌐 Web Tools

| Tool | Description | Link |
|---|---|---|
| 🔑 Password Generator | Generates a secure random password using `crypto.getRandomValues` | [`web/password-generator.html`](./web/password-generator.html) |
| ⏱ Crack Time Estimator | Theoretical (entropy-based) estimate of how long a password would take to guess | [`web/crack-time-estimator.html`](./web/crack-time-estimator.html) |

Try it live via GitHub Pages: `https://<username>.github.io/<repo-name>/`

All calculations run locally in the browser — no internet connection or data storage involved.

---

## 🖥 CLI Tool

`cli/security_toolkit.py` — an interactive menu that includes:

1. Generate a strong password (using `secrets`)
2. Check the strength of an existing password
3. Encrypt a file with a password (PBKDF2-HMAC-SHA256 + Fernet/AES)
4. Decrypt a file
5. Compute a file's SHA-256 hash to verify integrity

### Installation and Usage

```bash
pip install -r requirements.txt
python cli/security_toolkit.py
```

---

## 🔒 How the Security Works

- **Generation**: uses cryptographically secure random generators (`secrets` in Python, `crypto.getRandomValues` in the browser) — not predictable ones like `random`/`Math.random`.
- **Encryption**: the encryption key is derived from the password via PBKDF2 (480,000 iterations, current OWASP recommendation) with a random salt per file, then used with Fernet (AES-128-CBC with HMAC integrity verification).
- **Privacy**: the web tools never send any data to a server; all computation happens in your browser.

---

## 📁 Project Structure


.
├── web/
│ ├── index.html
│ ├── password-generator.html
│ └── crack-time-estimator.html
├── cli/
│ └── security_toolkit.py
├── requirements.txt
└── .github/workflows/deploy.yml



---

## ⚠️ Disclaimer

These tools are for educational and personal use (checking/generating/encrypting your own passwords). Do not use them to guess or gain unauthorized access to accounts or data you don't own.

## License

[MIT](./LICENSE)




