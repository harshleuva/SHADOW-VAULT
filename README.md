# 🛡️ Shadow Vault

**Shadow Vault** is a local-first, offline password manager built with Python and Tkinter. Everything is encrypted and stored on your own machine — no cloud, no external servers, no telemetry.

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

---

## ✨ Features

- **AES-256-GCM encryption** for the vault, with keys derived from your master password using **Argon2id** (memory-hard, resistant to brute-force/GPU attacks).
- **SafeAuth (TOTP 2FA)** — optional 6-digit authenticator code (Google Authenticator, Authy, etc.) required after your master password.
- **Multiple entry types** — Logins, Secure Notes, Wi-Fi credentials, and License/Serial keys.
- **Password Generator** with adjustable length and character sets, plus a live strength meter.
- **Have I Been Pwned (HIBP) integration** — checks your stored passwords against known data breaches using k-anonymity (only a hash prefix is sent, never the password itself).
- **Security Audit** — flags weak, reused, and breached passwords across your vault.
- **Audit Logs** — a local, tamper-evident log of logins, SafeAuth changes, file operations, and other security-relevant events.
- **9-Rotor Enigma Backup Engine** — export/import your vault through a custom multi-rotor substitution cipher layer for offline backups.
- **Standalone File Encryption/Decryption** — encrypt any file on disk (`.shadowenc`) using the same AES-GCM + Argon2id scheme as the vault.
- **Auto-lock on inactivity**, single-session lock (prevents two instances running at once), and clipboard auto-clear after copying a secret.
- **Customizable UI** font sizing, dark themed interface.

---

## 📸 Screenshots

*<img width="811" height="598" alt="image" src="https://github.com/user-attachments/assets/6880c35c-0433-4eb0-b2da-b47efb4cc83f" />
)*

*<img width="1115" height="820" alt="Screenshot 2026-08-23 160008" src="https://github.com/user-attachments/assets/7f303a00-27e3-4566-981a-26274a2e73fb" />
<img width="1180" height="878" alt="image" src="https://github.com/user-attachments/assets/515649d9-f16c-4a09-b9f3-53453219b556" />
*

---

## 🔧 Requirements

- Python 3.9+
- Dependencies (see [`requirements.txt`](#-installation)):
  - `pyotp`
  - `pyperclip`
  - `segno`
  - `Pillow`
  - `cryptography`
  - `argon2-cffi`

Tkinter ships with most Python installations. On some Linux distros you may need to install it separately:

```bash
sudo apt install python3-tk
```

---

## 📥 Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/<your-username>/shadow-vault.git
   cd shadow-vault
   ```

2. (Recommended) Create a virtual environment:

   ```bash
   python3 -m venv venv
   source venv/bin/activate    # Windows: venv\Scripts\activate
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

   Or install manually:

   ```bash
   pip install pyotp pyperclip segno Pillow cryptography argon2-cffi
   ```

4. Run the app:

   ```bash
   python vault.py
   ```

---

## 🚀 Usage

1. On first launch, set a **master password**. This password is never stored — it's used to derive your encryption key on the fly via Argon2id.
2. Add entries from the dashboard: **Login**, **Note**, **Wi-Fi**, or **License**.
3. Optionally enable **SafeAuth** from **Settings → SafeAuth** to require a TOTP code at every login. Scan the QR code with any authenticator app.
4. Run a **Security Audit** anytime from **Settings → Security Audit** to check for weak, reused, or breached passwords.
5. Review activity anytime from **Settings → Audit Logs**.
6. Back up your vault using the **Enigma Backup** engine, or encrypt individual files from **Settings → File Encryption**.

Your vault is stored locally at:

```
~/.shadowvault/vault.dat
```

Audit logs at:

```
~/.shadowvault/audit.json
```

---

## 🔐 Security Notes

- The master password is **never saved anywhere**. Losing it means losing access to your vault — there is no recovery mechanism by design.
- Vault data is encrypted with AES-256-GCM; the key is derived per-session using Argon2id (`time_cost=3`, `memory_cost=64MB`, `parallelism=4`).
- HIBP checks only ever transmit a 5-character SHA-1 prefix of your password (k-anonymity), never the password itself.
- The Enigma Backup layer is a **secondary obfuscation step for offline exports**, not a replacement for AES-GCM — treat backup files with the same care as the vault file.
- This project has not undergone a formal third-party security audit. Use at your own risk for sensitive credentials.

---

## 🗺️ Roadmap / Ideas

- [ ] Cross-device sync (optional, end-to-end encrypted)
- [ ] Browser extension integration
- [ ] CLI mode
- [ ] Encrypted vault import from other password managers

---

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you'd like to change.

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Harsh Leuva**
🌐 [harshleuva.github.io](https://harshleuva.github.io)
