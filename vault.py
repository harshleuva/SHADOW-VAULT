import os
import sys
import json
import secrets
import io
import socket
import platform
import string
import hashlib
import copy
import time
import urllib.request
import webbrowser
from datetime import datetime
import pyotp
import pyperclip
import segno
from PIL import Image, ImageTk
import tkinter as tk
from tkinter import messagebox, ttk, filedialog
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type

# Secure hidden directory in user home folder
VAULT_DIR = os.path.join(os.path.expanduser("~"), ".shadowvault")
os.makedirs(VAULT_DIR, exist_ok=True)

VAULT_FILE = os.path.join(VAULT_DIR, "vault.dat")
LOCK_FILE = os.path.join(VAULT_DIR, "vault.lock")
AUDIT_FILE = os.path.join(VAULT_DIR, "audit.json")

# ================= 9-ROTOR ENIGMA BACKUP ENGINE =================
def generate_rotors():
    """Generates 9 distinct 256-byte substitution rotors deterministically."""
    rotors = []
    for i in range(1, 10):
        alphabet = list(range(256))
        seed_bytes = hashlib.sha256(f"shadow_vault_rotor_seed_{i}".encode()).digest()
        state = int.from_bytes(seed_bytes[:8], "big")
        for j in range(255, 0, -1):
            state = (state * 1103515245 + 12345) & 0x7fffffff
            k = state % (j + 1)
            alphabet[j], alphabet[k] = alphabet[k], alphabet[j]
        
        forward = bytes(alphabet)
        inverse = bytearray(256)
        for idx, val in enumerate(forward):
            inverse[val] = idx
        rotors.append((forward, bytes(inverse)))
    return rotors

GLOBAL_ROTORS = generate_rotors()

def enigma_encrypt(data: bytes, rotor_indices: list) -> bytes:
    current = bytearray(data)
    for r_idx in rotor_indices:
        forward, _ = GLOBAL_ROTORS[r_idx - 1]
        current = bytearray(forward[b] for b in current)
    return bytes(current)

def enigma_decrypt(data: bytes, rotor_indices: list) -> bytes:
    current = bytearray(data)
    for r_idx in reversed(rotor_indices):
        _, inverse = GLOBAL_ROTORS[r_idx - 1]
        current = bytearray(inverse[b] for b in current)
    return bytes(current)
# ================================================================

def derive_key(secret_string: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=secret_string.encode('utf-8'),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=Type.ID
    )

def save_vault(data: dict, password: str):
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    plaintext = json.dumps(data).encode('utf-8')
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    
    temp_file = VAULT_FILE + ".tmp"
    with open(temp_file, "wb") as f:
        f.write(salt + nonce + ciphertext)
    if os.path.exists(VAULT_FILE):
        os.remove(VAULT_FILE)
    os.rename(temp_file, VAULT_FILE)

def load_vault(password: str) -> dict:
    if not os.path.exists(VAULT_FILE):
        return {}
    with open(VAULT_FILE, "rb") as f:
        file_data = f.read()
    salt = file_data[:16]
    nonce = file_data[16:28]
    ciphertext = file_data[28:]
    try:
        key = derive_key(password, salt)
        aesgcm = AESGCM(key)
        decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(decrypted_data.decode('utf-8'))
    except Exception:
        return None

def generate_secure_password(length=16, use_upper=True, use_lower=True, use_nums=True, use_syms=True):
    chars = ""
    if use_upper: chars += string.ascii_uppercase
    if use_lower: chars += string.ascii_lowercase
    if use_nums: chars += string.digits
    if use_syms: chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    if not chars: chars = string.ascii_letters + string.digits
    return "".join(secrets.choice(chars) for _ in range(length))

def check_password_strength(password):
    score = 0
    feedback = []
    if len(password) >= 12: score += 2
    elif len(password) >= 8: score += 1
    else: feedback.append("Too short (<8 chars)")

    if any(c.islower() for c in password): score += 1
    else: feedback.append("Needs lowercase")

    if any(c.isupper() for c in password): score += 1
    else: feedback.append("Needs uppercase")

    if any(c.isdigit() for c in password): score += 1
    else: feedback.append("Needs numbers")

    if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password): score += 1
    else: feedback.append("Needs symbols")

    if score <= 2: return "Weak", "#ff4444", score, feedback
    elif score <= 4: return "Moderate", "#ff9800", score, feedback
    elif score <= 5: return "Strong", "#00bcd4", score, feedback
    else: return "Unbreakable", "#00ff66", score, feedback

def check_hibp_breach(password: str) -> int:
    if not password:
        return 0
    sha1pass = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1pass[:5], sha1pass[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'ShadowVault-Auditor'})
        with urllib.request.urlopen(req, timeout=3) as response:
            res_text = response.read().decode('utf-8')
        for line in res_text.splitlines():
            parts = line.split(':')
            if parts[0] == suffix:
                return int(parts[1])
    except Exception:
        pass
    return 0

class VaultGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Shadow Vault - Secure GUI")
        self.root.geometry("900x600")
        self.root.configure(bg="#121212")
        
        self.master_password = ""
        self.vault_data = {}
        self.previous_vault_state = None
        self.qr_photo = None
        self.font_size = 11
        self.session_id = secrets.token_hex(4)
        
        self.current_copied_pass = ""
        self._clipboard_timer_id = None
        
        self.last_activity = time.time()
        self.root.bind_all("<Key>", self.reset_activity)
        self.root.bind_all("<Button>", self.reset_activity)
        self.root.after(5000, self.check_inactivity)

        self.root.protocol("WM_DELETE_WINDOW", lambda: self.fade_out_and_close("Exit App"))
        self.check_single_session()
        
        self.fade_in()
        self.show_login_screen()

    def fade_in(self):
        self.root.attributes("-alpha", 0.0)
        alpha = 0.0
        def step():
            nonlocal alpha
            alpha += 0.08
            if alpha < 1.0:
                self.root.attributes("-alpha", alpha)
                self.root.after(30, step)
            else:
                self.root.attributes("-alpha", 1.0)
        step()

    def fade_out_and_close(self, event_type="Kill"):
        alpha = 1.0
        def step():
            nonlocal alpha
            alpha -= 0.1
            if alpha > 0.0:
                self.root.attributes("-alpha", alpha)
                self.root.after(25, step)
            else:
                self.root.attributes("-alpha", 0.0)
                self.execute_kill_sequence(event_type)
        step()

    def reset_activity(self, event=None):
        self.last_activity = time.time()

    def check_inactivity(self):
        if self.master_password and (time.time() - self.last_activity > 300):
            self.fade_out_and_close("Inactivity Auto-Kill")
        else:
            self.root.after(5000, self.check_inactivity)

    def log_audit(self, event_type, details=""):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        device_info = f"{socket.gethostname()} ({platform.system()} {platform.release()})"
        
        entry = {
            "timestamp": timestamp,
            "event": event_type,
            "session_id": self.session_id,
            "device": device_info,
            "details": details
        }

        audit_data = []
        if os.path.exists(AUDIT_FILE):
            try:
                with open(AUDIT_FILE, "r") as f:
                    audit_data = json.load(f)
            except:
                pass
        
        audit_data.append(entry)
        try:
            with open(AUDIT_FILE, "w") as f:
                json.dump(audit_data, f, indent=4)
        except Exception:
            pass

    def check_single_session(self):
        if os.path.exists(LOCK_FILE):
            try:
                with open(LOCK_FILE, "r") as f:
                    old_pid = int(f.read().strip())
                os.kill(old_pid, 0)
                messagebox.showerror("Session Error", "Shadow Vault is already active in another session!")
                sys.exit(1)
            except (ProcessLookupError, ValueError, OSError):
                try:
                    os.remove(LOCK_FILE)
                except:
                    pass

    def create_session_lock(self):
        try:
            with open(LOCK_FILE, "w") as f:
                f.write(str(os.getpid()))
        except Exception:
            pass

    def remove_session_lock(self):
        if os.path.exists(LOCK_FILE):
            try:
                os.remove(LOCK_FILE)
            except Exception:
                pass

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def show_login_screen(self):
        self.master_password = ""
        self.clear_window()
        self.root.geometry("650x450")
        
        frame = tk.Frame(self.root, bg="#121212")
        frame.pack(expand=True)

        tk.Label(frame, text="SHADOW VAULT LOGIN", fg="#00ff66", bg="#121212", font=("Consolas", 18, "bold")).pack(pady=10)
        tk.Label(frame, text=f"Vault location: {VAULT_FILE}", fg="#666666", bg="#121212", font=("Consolas", 8)).pack(pady=2)
        tk.Label(frame, text="Enter Master Password:", fg="#ffffff", bg="#121212", font=("Consolas", 11)).pack(pady=10)

        self.pass_entry = tk.Entry(frame, show="*", font=("Consolas", 12), width=28, bg="#1e1e1e", fg="#ffffff", insertbackground="white", relief=tk.FLAT)
        self.pass_entry.pack(pady=5, ipady=4)
        self.pass_entry.focus()
        self.pass_entry.bind("<Return>", lambda event: self.authenticate())

        tk.Button(frame, text="Unlock Vault", command=self.authenticate, bg="#00ff66", fg="#121212", font=("Consolas", 11, "bold"), width=16, relief=tk.FLAT).pack(pady=20)

    def authenticate(self):
        pwd = self.pass_entry.get()
        if not pwd:
            messagebox.showerror("Error", "Password cannot be empty.")
            return

        vault = load_vault(pwd)
        if vault is None:
            self.log_audit("Failed Master Password", "Incorrect master password provided.")
            messagebox.showerror("Error", "Incorrect Master Password or Corrupted Database.")
            return

        self.check_single_session()
        self.create_session_lock()

        self.master_password = pwd
        self.vault_data = vault
        self.log_audit("Successful Login", "Master password verified successfully.")

        if "_2fa_secret" not in self.vault_data:
            self.setup_2fa()
        else:
            self.verify_2fa_window()

    def setup_2fa(self):
        new_secret = pyotp.random_base32()
        self.vault_data["_2fa_secret"] = new_secret
        save_vault(self.vault_data, self.master_password)
        pyperclip.copy(new_secret)

        self.clear_window()
        self.root.geometry("650x680")
        
        frame = tk.Frame(self.root, bg="#121212")
        frame.pack(expand=True, pady=10)

        tk.Label(frame, text="SETUP 2FA AUTHENTICATION", fg="#00ff66", bg="#121212", font=("Consolas", 14, "bold")).pack(pady=5)
        tk.Label(frame, text=f"Secret Key (Copied to clipboard):\n{new_secret}", fg="#ffffff", bg="#121212", font=("Consolas", 9)).pack(pady=2)

        totp_temp = pyotp.TOTP(new_secret)
        uri = totp_temp.provisioning_uri(name="ShadowVault", issuer_name="ShadowVault")
        
        buffer = io.BytesIO()
        segno.make(uri).save(buffer, scale=4, kind='png')
        buffer.seek(0)
        pil_img = Image.open(buffer)
        self.qr_photo = ImageTk.PhotoImage(pil_img)

        tk.Label(frame, image=self.qr_photo, bg="#121212").pack(pady=10)
        tk.Label(frame, text="Scan QR code with your Authenticator app, then enter code:", fg="#ffffff", bg="#121212", font=("Consolas", 9)).pack(pady=2)

        code_entry = tk.Entry(frame, font=("Consolas", 12), width=15, bg="#1e1e1e", fg="#ffffff", insertbackground="white")
        code_entry.pack(pady=5)
        code_entry.focus()

        def verify_setup():
            totp = pyotp.TOTP(new_secret)
            if totp.verify(code_entry.get().strip()):
                self.log_audit("Successful 2FA Setup & Verification")
                self.show_main_dashboard()
            else:
                self.log_audit("Failed 2FA", "Invalid TOTP setup code provided.")
                messagebox.showerror("Error", "Invalid Code. Try again.")

        code_entry.bind("<Return>", lambda event: verify_setup())
        tk.Button(frame, text="Verify & Continue", command=verify_setup, bg="#00ff66", fg="#121212", font=("Consolas", 10, "bold"), relief=tk.FLAT).pack(pady=10)

    def verify_2fa_window(self):
        self.clear_window()
        self.root.geometry("650x450")
        
        frame = tk.Frame(self.root, bg="#121212")
        frame.pack(expand=True)

        tk.Label(frame, text="2FA VERIFICATION", fg="#00ff66", bg="#121212", font=("Consolas", 14, "bold")).pack(pady=10)
        tk.Label(frame, text="Enter 6-Digit Authenticator Code:", fg="#ffffff", bg="#121212", font=("Consolas", 10)).pack(pady=5)

        code_entry = tk.Entry(frame, show="*", font=("Consolas", 12), width=15, bg="#1e1e1e", fg="#ffffff", insertbackground="white")
        code_entry.pack(pady=5)
        code_entry.focus()

        def check_code():
            totp = pyotp.TOTP(self.vault_data["_2fa_secret"])
            if totp.verify(code_entry.get().strip()):
                self.log_audit("Successful 2FA Verification")
                self.show_main_dashboard()
            else:
                self.log_audit("Failed 2FA", "Invalid TOTP code provided.")
                messagebox.showerror("Error", "Invalid Code.")

        code_entry.bind("<Return>", lambda event: check_code())
        tk.Button(frame, text="Authorize", command=check_code, bg="#00ff66", fg="#121212", font=("Consolas", 10, "bold"), relief=tk.FLAT).pack(pady=10)

    def show_main_dashboard(self):
        self.clear_window()
        self.root.geometry("900x630")

        top_frame = tk.Frame(self.root, bg="#1e1e1e", height=50)
        top_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(top_frame, text="🛡️ SHADOW VAULT", fg="#00ff66", bg="#1e1e1e", font=("Consolas", max(10, self.font_size + 3), "bold")).pack(side=tk.LEFT, padx=10)
        
        tk.Button(top_frame, text="💀 Kill", command=lambda: self.fade_out_and_close("Manual Kill"), bg="#ff4444", fg="#ffffff", font=("Consolas", self.font_size, "bold"), relief=tk.FLAT).pack(side=tk.RIGHT, padx=4)
        tk.Button(top_frame, text="⚙️ Settings", command=self.show_settings_screen, bg="#2d2d2d", fg="#ff9800", font=("Consolas", self.font_size, "bold"), relief=tk.FLAT).pack(side=tk.RIGHT, padx=4)
        tk.Button(top_frame, text="🔑 Gen", command=self.open_generator_popup, bg="#2d2d2d", fg="#00ff66", font=("Consolas", self.font_size, "bold"), relief=tk.FLAT).pack(side=tk.RIGHT, padx=4)

        search_frame = tk.Frame(self.root, bg="#121212")
        search_frame.pack(fill=tk.X, padx=10, pady=5)

        tk.Label(search_frame, text="🔍 Search Title / Username:", fg="#aaaaaa", bg="#121212", font=("Consolas", self.font_size)).pack(side=tk.LEFT, padx=5)
        self.search_var = tk.StringVar()
        self.search_var.trace("w", lambda *args: self.refresh_table())
        search_entry_widget = tk.Entry(search_frame, textvariable=self.search_var, font=("Consolas", self.font_size), width=30, bg="#1e1e1e", fg="#ffffff", insertbackground="white")
        search_entry_widget.pack(side=tk.LEFT, padx=5, ipady=3)

        style = ttk.Style()
        style.theme_use("clam")
        
        # Explicitly map active/selected states to match row backgrounds so hovering causes zero color shifts
        style.configure("Treeview", background="#1e1e1e", foreground="#ffffff", fieldbackground="#1e1e1e", font=("Consolas", self.font_size), rowheight=self.font_size + 14)
        style.configure("Treeview.Heading", background="#2d2d2d", foreground="#00ff66", font=("Consolas", self.font_size, "bold"))
        style.map("Treeview", background=[('selected', '#1e1e1e'), ('active', '#1e1e1e')], foreground=[('selected', '#ffffff'), ('active', '#ffffff')])
        
        columns = ("Title", "Type", "Username / Info")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings", height=13)
        self.tree.heading("Title", text="Target / Title")
        self.tree.heading("Type", text="Type")
        self.tree.heading("Username / Info", text="Username / Detail Preview")
        self.tree.column("Title", width=270)
        self.tree.column("Type", width=140)
        self.tree.column("Username / Info", width=330)
        self.tree.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)

        self.refresh_table()

        status_bar = tk.Frame(self.root, bg="#1e1e1e", height=30)
        status_bar.pack(fill=tk.X, padx=10, pady=2)
        
        self.clipboard_lbl = tk.Label(status_bar, text="📋 Clipboard Secure: Ready", fg="#00ff66", bg="#1e1e1e", font=("Consolas", 9))
        self.clipboard_lbl.pack(side=tk.LEFT, padx=10, pady=4)

        self.clip_progress = ttk.Progressbar(status_bar, orient=tk.HORIZONTAL, length=180, mode="determinate")
        self.clip_progress.pack(side=tk.RIGHT, padx=10, pady=4)
        self.clip_progress["value"] = 0

        btn_frame1 = tk.Frame(self.root, bg="#121212")
        btn_frame1.pack(fill=tk.X, padx=10, pady=8)

        tk.Button(btn_frame1, text="+ Add Entry", command=self.add_target_popup, bg="#00ff66", fg="#121212", font=("Consolas", self.font_size, "bold"), relief=tk.FLAT).pack(side=tk.LEFT, padx=3, expand=True, fill=tk.X)
        tk.Button(btn_frame1, text="📋 Copy Cred", command=self.copy_selected_password, bg="#00bcd4", fg="#121212", font=("Consolas", self.font_size, "bold"), relief=tk.FLAT).pack(side=tk.LEFT, padx=3, expand=True, fill=tk.X)
        tk.Button(btn_frame1, text="👁️ View Details", command=self.view_password, bg="#9c27b0", fg="#ffffff", font=("Consolas", self.font_size, "bold"), relief=tk.FLAT).pack(side=tk.LEFT, padx=3, expand=True, fill=tk.X)
        tk.Button(btn_frame1, text="✏️ Edit Entry", command=self.edit_target_popup, bg="#ff9800", fg="#121212", font=("Consolas", self.font_size, "bold"), relief=tk.FLAT).pack(side=tk.LEFT, padx=3, expand=True, fill=tk.X)
        tk.Button(btn_frame1, text="🗑️ Remove", command=self.delete_target, bg="#ff4444", fg="#ffffff", font=("Consolas", self.font_size, "bold"), relief=tk.FLAT).pack(side=tk.LEFT, padx=3, expand=True, fill=tk.X)

    def refresh_table(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        query = self.search_var.get().lower() if hasattr(self, "search_var") else ""

        for title, creds in self.vault_data.items():
            if title in ("_2fa_secret", "_logs"):
                continue
            
            e_type = creds.get("type", "login")
            username = creds.get("user", "")
            
            if e_type == "login":
                preview = username if username else creds.get("pass", "••••••")
            elif e_type == "note":
                preview = creds.get("note", "")[:40] + "..."
            elif e_type == "wifi":
                preview = f"SSID: {creds.get('ssid', '')} | Security: {creds.get('security', '')}"
            elif e_type == "license":
                preview = f"Key: {creds.get('key', '')[:12]}..."
            else:
                preview = username

            if query and query not in title.lower() and query not in preview.lower() and query not in e_type.lower():
                continue

            self.tree.insert("", tk.END, values=(title, e_type.capitalize(), preview), tags=(title,))

    def show_settings_screen(self):
        self.clear_window()
        self.root.geometry("950x680")

        top_frame = tk.Frame(self.root, bg="#1e1e1e", height=50)
        top_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(top_frame, text="⚙️ VAULT SETTINGS & UTILITIES", fg="#00ff66", bg="#1e1e1e", font=("Consolas", max(10, self.font_size + 3), "bold")).pack(side=tk.LEFT, padx=10)
        tk.Button(top_frame, text="← Back to Vault", command=self.show_main_dashboard, bg="#2d2d2d", fg="#ffffff", font=("Consolas", self.font_size, "bold"), relief=tk.FLAT).pack(side=tk.RIGHT, padx=4)

        main_container = tk.Frame(self.root, bg="#121212")
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        sidebar = tk.Frame(main_container, bg="#181818", width=200)
        sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        sidebar.pack_propagate(False)

        content_area = tk.Frame(main_container, bg="#121212")
        content_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        tabs_dict = {}

        for name in ["🔑 Master Password", "📦 Enigma Backup", "📁 File Encryption", "🔤 Font Customizer", "🛡️ Security Audit", "📜 Audit Logs", "ℹ️ About"]:
            t_frame = tk.Frame(content_area, bg="#121212")
            tabs_dict[name] = t_frame

        current_active_tab = {"name": None}
        sidebar_buttons = {}

        def select_tab(tab_name):
            if current_active_tab["name"] == tab_name:
                return
            for name, frame in tabs_dict.items():
                frame.pack_forget()
            for name, btn in sidebar_buttons.items():
                if name == tab_name:
                    btn.config(bg="#00ff66", fg="#121212")
                else:
                    btn.config(bg="#2d2d2d", fg="#ffffff")
            tabs_dict[tab_name].pack(fill=tk.BOTH, expand=True)
            current_active_tab["name"] = tab_name

        for name in tabs_dict.keys():
            b = tk.Button(sidebar, text=name, command=lambda n=name: select_tab(n), bg="#2d2d2d", fg="#ffffff", font=("Consolas", self.font_size, "bold"), anchor="w", padx=12, relief=tk.FLAT)
            b.pack(fill=tk.X, pady=3, ipady=6)
            sidebar_buttons[name] = b

        # ---------------- TAB 1: MASTER PASSWORD ----------------
        tab_pw = tabs_dict["🔑 Master Password"]
        pw_frame = tk.Frame(tab_pw, bg="#121212")
        pw_frame.pack(expand=True)

        tk.Label(pw_frame, text="CHANGE MASTER PASSWORD", fg="#00ff66", bg="#121212", font=("Consolas", self.font_size + 1, "bold")).pack(pady=10)

        tk.Label(pw_frame, text="New Master Password:", fg="#ffffff", bg="#121212", font=("Consolas", self.font_size)).pack(anchor="w", padx=5)
        new_pass_entry = tk.Entry(pw_frame, show="*", font=("Consolas", self.font_size), width=32, bg="#1e1e1e", fg="#ffffff", insertbackground="white")
        new_pass_entry.pack(pady=2, ipady=3)

        tk.Label(pw_frame, text="Confirm New Master Password:", fg="#ffffff", bg="#121212", font=("Consolas", self.font_size)).pack(anchor="w", padx=5)
        conf_pass_entry = tk.Entry(pw_frame, show="*", font=("Consolas", self.font_size), width=32, bg="#1e1e1e", fg="#ffffff", insertbackground="white")
        conf_pass_entry.pack(pady=2, ipady=3)

        strength_lbl = tk.Label(pw_frame, text="Strength: ---", fg="#aaaaaa", bg="#121212", font=("Consolas", self.font_size))
        strength_lbl.pack(pady=5)

        def on_pass_key(*args):
            p = new_pass_entry.get()
            if not p:
                strength_lbl.config(text="Strength: ---", fg="#aaaaaa")
                return
            label, color, _, _ = check_password_strength(p)
            strength_lbl.config(text=f"Strength: {label}", fg=color)

        new_pass_entry.bind("<KeyRelease>", on_pass_key)

        def execute_change():
            new_p = new_pass_entry.get()
            conf_p = conf_pass_entry.get()

            if not new_p:
                messagebox.showerror("Error", "New password cannot be empty.")
                return
            if new_p != conf_p:
                messagebox.showerror("Error", "New passwords do not match.")
                return

            try:
                save_vault(self.vault_data, new_p)
                self.master_password = new_p
                self.log_audit("Master Password Changed", "Successfully rotated master password.")
                messagebox.showinfo("Success", "Master password changed successfully!")
                new_pass_entry.delete(0, tk.END)
                conf_pass_entry.delete(0, tk.END)
                strength_lbl.config(text="Strength: ---", fg="#aaaaaa")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to update master password: {e}")

        tk.Button(pw_frame, text="Update Master Password", command=execute_change, bg="#00ff66", fg="#121212", font=("Consolas", self.font_size, "bold"), width=24, relief=tk.FLAT).pack(pady=15)

        # ---------------- TAB 2: BACKUP & ENIGMA SYNC ----------------
        tab_backup = tabs_dict["📦 Enigma Backup"]
        bak_container = tk.Frame(tab_backup, bg="#121212")
        bak_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=15)

        tk.Label(bak_container, text="ENIGMA 9-ROTOR SECURE BACKUP & MERGE", fg="#00ff66", bg="#121212", font=("Consolas", self.font_size + 1, "bold")).pack(pady=5)
        tk.Label(bak_container, text="Encrypted entirely using your 4-rotor sequence + backup file.", fg="#aaaaaa", bg="#121212", font=("Consolas", 8)).pack(pady=2)

        form_frame = tk.Frame(bak_container, bg="#121212")
        form_frame.pack(pady=10)

        tk.Label(form_frame, text="4-Rotor Code (e.g. 1352):", fg="#ffffff", bg="#121212", font=("Consolas", self.font_size)).grid(row=0, column=0, sticky="w", pady=5)
        rotor_entry = tk.Entry(form_frame, font=("Consolas", self.font_size), width=25, bg="#1e1e1e", fg="#ffffff", insertbackground="white")
        rotor_entry.insert(0, "1352")
        rotor_entry.grid(row=0, column=1, padx=10, pady=5, ipady=3)

        def parse_rotors(text):
            text = text.strip()
            if len(text) != 4 or not text.isdigit() or any(c == '0' for c in text):
                messagebox.showerror("Rotor Error", "Rotor code must be exactly 4 digits using numbers 1-9 (e.g., 1352).")
                return None
            return [int(c) for c in text]

        def export_backup():
            rotors = parse_rotors(rotor_entry.get())
            if not rotors: return
            file_path = filedialog.asksaveasfilename(defaultextension=".shadowbak", filetypes=[("Shadow Vault Enigma Backup", "*.shadowbak"), ("All Files", "*.*")])
            if not file_path: return

            try:
                salt = secrets.token_bytes(16)
                nonce = secrets.token_bytes(12)
                key = derive_key(rotor_entry.get().strip(), salt)
                aesgcm = AESGCM(key)
                plaintext = json.dumps(self.vault_data).encode('utf-8')
                ciphertext = aesgcm.encrypt(nonce, plaintext, None)
                enigma_ciphertext = enigma_encrypt(ciphertext, rotors)
                header = json.dumps({"rotors": rotors}).encode('utf-8')
                header_len = len(header).to_bytes(4, 'big')

                with open(file_path, "wb") as f:
                    f.write(header_len + header + salt + nonce + enigma_ciphertext)

                self.log_audit("Exported Enigma Backup", f"Saved backup to {os.path.basename(file_path)}")
                messagebox.showinfo("Success", "Enigma encrypted backup created successfully!")
            except Exception as e:
                messagebox.showerror("Export Failed", f"Could not create backup: {e}")

        def import_backup():
            input_rotors = parse_rotors(rotor_entry.get())
            if not input_rotors: return
            file_path = filedialog.askopenfilename(filetypes=[("Shadow Vault Enigma Backup", "*.shadowbak"), ("All Files", "*.*")])
            if not file_path: return

            try:
                with open(file_path, "rb") as f:
                    file_bytes = f.read()

                header_len = int.from_bytes(file_bytes[:4], 'big')
                header = json.loads(file_bytes[4:4+header_len].decode('utf-8'))
                file_rotors = header.get("rotors")

                if file_rotors != input_rotors:
                    messagebox.showerror("Decryption Failed", "Incorrect 4-rotor code! Decryption aborted.")
                    return

                salt = file_bytes[4+header_len:4+header_len+16]
                nonce = file_bytes[4+header_len+16:4+header_len+28]
                enigma_ciphertext = file_bytes[4+header_len+28:]

                ciphertext = enigma_decrypt(enigma_ciphertext, file_rotors)
                key = derive_key(rotor_entry.get().strip(), salt)
                aesgcm = AESGCM(key)
                decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
                imported_data = json.loads(decrypted_bytes.decode('utf-8'))

                self.previous_vault_state = copy.deepcopy(self.vault_data)
                merged_count = 0
                for site, creds in imported_data.items():
                    if site.startswith("_"): continue
                    self.vault_data[site] = creds
                    merged_count += 1

                save_vault(self.vault_data, self.master_password)
                self.log_audit("Imported & Merged Backup", f"Successfully merged {merged_count} items.")
                messagebox.showinfo("Success", f"Backup imported successfully!\nMerged {merged_count} entries into your vault.")
            except Exception as e:
                self.log_audit("Failed Backup Import", str(e))
                messagebox.showerror("Import Failed", "Decryption failed! Wrong rotor code or corrupted backup file.")

        def undo_import():
            if self.previous_vault_state is None:
                messagebox.showwarning("Undo Unavailable", "No recent import actions to undo in this session.")
                return
            if messagebox.askyesno("Confirm Undo", "Revert to vault state before last import?"):
                self.vault_data = copy.deepcopy(self.previous_vault_state)
                save_vault(self.vault_data, self.master_password)
                self.previous_vault_state = None
                self.log_audit("Undo Import", "Reverted vault to pre-import state.")
                messagebox.showinfo("Success", "Vault successfully reverted!")

        btn_action_frame = tk.Frame(bak_container, bg="#121212")
        btn_action_frame.pack(pady=10)

        tk.Button(btn_action_frame, text="🔒 Export", command=export_backup, bg="#00ff66", fg="#121212", font=("Consolas", 10, "bold"), width=15, relief=tk.FLAT).pack(side=tk.LEFT, padx=4)
        tk.Button(btn_action_frame, text="🔓 Import", command=import_backup, bg="#00bcd4", fg="#121212", font=("Consolas", 10, "bold"), width=15, relief=tk.FLAT).pack(side=tk.LEFT, padx=4)
        tk.Button(btn_action_frame, text="↩️ Undo", command=undo_import, bg="#ff9800", fg="#121212", font=("Consolas", 10, "bold"), width=15, relief=tk.FLAT).pack(side=tk.LEFT, padx=4)

        # ---------------- TAB 3: FILE ENCRYPTION UTILITY ----------------
        tab_fileenc = tabs_dict["📁 File Encryption"]
        file_enc_container = tk.Frame(tab_fileenc, bg="#121212")
        file_enc_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=15)

        tk.Label(file_enc_container, text="SECURE FILE ENCRYPTION / DECRYPTION", fg="#00ff66", bg="#121212", font=("Consolas", self.font_size + 1, "bold")).pack(pady=(5, 2))
        tk.Label(file_enc_container, text="Encrypt private SSH keys, recovery docs, or secret files using your master key.", fg="#aaaaaa", bg="#121212", font=("Consolas", 8)).pack(pady=(0, 10))

        file_action_frame = tk.Frame(file_enc_container, bg="#121212")
        file_action_frame.pack(expand=True, fill=tk.BOTH, pady=10)

        def encrypt_user_file():
            file_path = filedialog.askopenfilename(title="Select File to Encrypt")
            if not file_path: return
            try:
                with open(file_path, "rb") as f:
                    file_bytes = f.read()
                
                salt = secrets.token_bytes(16)
                nonce = secrets.token_bytes(12)
                key = derive_key(self.master_password, salt)
                aesgcm = AESGCM(key)
                ciphertext = aesgcm.encrypt(nonce, file_bytes, None)

                original_name = os.path.basename(file_path).encode('utf-8')
                name_len = len(original_name).to_bytes(2, 'big')

                out_path = file_path + ".shadowenc"
                with open(out_path, "wb") as f:
                    f.write(salt + nonce + name_len + original_name + ciphertext)

                messagebox.showinfo("Success", f"File encrypted successfully!\nSaved to:\n{out_path}")
                self.log_audit("File Encrypted", f"Encrypted file: {os.path.basename(file_path)}")
            except Exception as e:
                messagebox.showerror("Encryption Failed", str(e))

        def decrypt_user_file():
            file_path = filedialog.askopenfilename(title="Select .shadowenc File to Decrypt", filetypes=[("Shadow Vault Encrypted", "*.shadowenc"), ("All Files", "*.*")])
            if not file_path: return
            try:
                with open(file_path, "rb") as f:
                    data = f.read()

                salt = data[:16]
                nonce = data[16:28]
                name_len = int.from_bytes(data[28:30], 'big')
                original_name = data[30:30+name_len].decode('utf-8')
                ciphertext = data[30+name_len:]

                key = derive_key(self.master_password, salt)
                aesgcm = AESGCM(key)
                plaintext = aesgcm.decrypt(nonce, ciphertext, None)

                default_out = os.path.join(os.path.dirname(file_path), "decrypted_" + original_name)
                save_path = filedialog.asksaveasfilename(initialfile="decrypted_" + original_name, title="Save Decrypted File As")
                if not save_path: save_path = default_out

                with open(save_path, "wb") as f:
                    f.write(plaintext)

                messagebox.showinfo("Success", f"File decrypted successfully!\nSaved to:\n{save_path}")
                self.log_audit("File Decrypted", f"Decrypted file: {original_name}")
            except Exception as e:
                messagebox.showerror("Decryption Failed", "Invalid master password or corrupted file structure.")

        tk.Button(file_action_frame, text="🔒 Encrypt Any File...", command=encrypt_user_file, bg="#00ff66", fg="#121212", font=("Consolas", 11, "bold"), width=30, relief=tk.FLAT).pack(pady=12)
        tk.Button(file_action_frame, text="🔓 Decrypt .shadowenc File...", command=decrypt_user_file, bg="#00bcd4", fg="#121212", font=("Consolas", 11, "bold"), width=30, relief=tk.FLAT).pack(pady=12)

        # ---------------- TAB 4: FONT SIZE ----------------
        tab_font = tabs_dict["🔤 Font Customizer"]
        font_frame = tk.Frame(tab_font, bg="#121212")
        font_frame.pack(expand=True)

        tk.Label(font_frame, text="SELECT INTERFACE FONT SIZE", fg="#00ff66", bg="#121212", font=("Consolas", self.font_size + 1, "bold")).pack(pady=10)

        def set_size(size):
            self.font_size = size
            messagebox.showinfo("Font Updated", f"Interface font size changed to {size}pt.")
            self.show_main_dashboard()

        tk.Button(font_frame, text="Small (9pt)", command=lambda: set_size(9), bg="#1e1e1e", fg="#ffffff", font=("Consolas", 10), width=24, relief=tk.FLAT).pack(pady=5)
        tk.Button(font_frame, text="Medium (11pt - Default)", command=lambda: set_size(11), bg="#1e1e1e", fg="#ffffff", font=("Consolas", 10), width=24, relief=tk.FLAT).pack(pady=5)
        tk.Button(font_frame, text="Large (13pt)", command=lambda: set_size(13), bg="#1e1e1e", fg="#ffffff", font=("Consolas", 10), width=24, relief=tk.FLAT).pack(pady=5)

        # ---------------- TAB 5: SECURITY AUDIT & HIBP CHECK ----------------
        tab_audit = tabs_dict["🛡️ Security Audit"]
        audit_container = tk.Frame(tab_audit, bg="#121212")
        audit_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        txt_area = tk.Text(audit_container, bg="#1e1e1e", fg="#ffffff", font=("Consolas", self.font_size), relief=tk.FLAT)
        txt_area.pack(fill=tk.BOTH, expand=True)

        passwords_seen = {}
        weak_count = 0
        reused_count = 0
        breached_count = 0
        total_sites = 0

        report = "=== SHADOW VAULT SECURITY REPORT (WITH HIBP) ===\n\n"
        for title, creds in self.vault_data.items():
            if title in ("_2fa_secret", "_logs") or creds.get("type", "login") != "login":
                continue
            total_sites += 1
            pwd = creds.get("pass", "")
            label, color, score, feedback = check_password_strength(pwd)
            if score <= 2:
                weak_count += 1
                report += f"[!] WEAK PASSWORD: '{title}' ({label})\n"
            
            hibp_hits = check_hibp_breach(pwd)
            if hibp_hits > 0:
                breached_count += 1
                report += f"[!] DATA LEAK ALERT: '{title}' appeared in public data breaches ({hibp_hits} times)!\n"

            if pwd in passwords_seen:
                reused_count += 1
                report += f"[!] REUSED PASSWORD: '{title}' shares password with '{passwords_seen[pwd]}'\n"
            else:
                passwords_seen[pwd] = title

        report += f"\n--- SUMMARY ---\nTotal Login Vault Items: {total_sites}\nWeak Passwords: {weak_count}\nReused Passwords: {reused_count}\nBreached Passwords (HIBP): {breached_count}\n"
        if weak_count == 0 and reused_count == 0 and breached_count == 0:
            report += "\n[+] Outstanding! Your vault security posture is strong and clean."
        else:
            report += "\n[!] Recommendation: Update weak, duplicate, or breached passwords."

        txt_area.insert(tk.END, report)
        txt_area.config(state=tk.DISABLED)

        # ---------------- TAB 6: AUDIT LOGS ----------------
        tab_logs = tabs_dict["📜 Audit Logs"]
        logs_container = tk.Frame(tab_logs, bg="#121212")
        logs_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        log_cols = ("Timestamp", "Event", "Session ID", "Device")
        log_tree = ttk.Treeview(logs_container, columns=log_cols, show="headings", height=13)
        log_tree.heading("Timestamp", text="Timestamp")
        log_tree.heading("Event", text="Authentication Event")
        log_tree.heading("Session ID", text="Session ID")
        log_tree.heading("Device", text="Device / Hostname")
        log_tree.column("Timestamp", width=140)
        log_tree.column("Event", width=180)
        log_tree.column("Session ID", width=90)
        log_tree.column("Device", width=250)
        log_tree.pack(fill=tk.BOTH, expand=True)

        audit_data = []
        if os.path.exists(AUDIT_FILE):
            try:
                with open(AUDIT_FILE, "r") as f:
                    audit_data = json.load(f)
            except:
                pass

        for entry in reversed(audit_data):
            log_tree.insert("", tk.END, values=(entry.get("timestamp"), entry.get("event"), entry.get("session_id"), entry.get("device")))

        # ---------------- TAB 7: ABOUT (WITH HYPERLINK) ----------------
        tab_about = tabs_dict["ℹ️ About"]
        about_frame = tk.Frame(tab_about, bg="#121212")
        about_frame.pack(expand=True)

        tk.Label(about_frame, text="🛡️ SHADOW VAULT", fg="#00ff66", bg="#121212", font=("Consolas", 16, "bold")).pack(pady=10)
        tk.Label(about_frame, text="Secure Local Offline Password Manager & Enigma Vault", fg="#aaaaaa", bg="#121212", font=("Consolas", 9)).pack(pady=2)
        
        tk.Label(about_frame, text="\nCreated by:\n", fg="#ffffff", bg="#121212", font=("Consolas", 11)).pack()
        tk.Label(about_frame, text="HARSH LEUVA", fg="#00ff66", bg="#121212", font=("Consolas", 13, "bold")).pack(pady=2)
        
        tk.Label(about_frame, text="Website:", fg="#aaaaaa", bg="#121212", font=("Consolas", 9)).pack(pady=(10, 2))
        
        # Interactive HTML-like clickable link (href style)
        link_lbl = tk.Label(about_frame, text="harshleuva.github.io", fg="#00bcd4", bg="#121212", font=("Consolas", 11, "underline"), cursor="hand2")
        link_lbl.pack(pady=2)
        link_lbl.bind("<Button-1>", lambda e: webbrowser.open("https://harshleuva.github.io"))
        link_lbl.bind("<Enter>", lambda e: link_lbl.config(fg="#00ff66"))
        link_lbl.bind("<Leave>", lambda e: link_lbl.config(fg="#00bcd4"))

        select_tab("🔑 Master Password")

    def open_generator_popup(self, target_entry=None):
        popup = tk.Toplevel(self.root)
        popup.title("Secure Password Generator & Strength Meter")
        popup.geometry("420x420")
        popup.configure(bg="#121212")

        tk.Label(popup, text="PASSWORD GENERATOR", fg="#00ff66", bg="#121212", font=("Consolas", 12, "bold")).pack(pady=10)

        pass_display = tk.Entry(popup, font=("Consolas", 14), width=28, bg="#1e1e1e", fg="#00ff66", justify="center", insertbackground="white")
        pass_display.pack(pady=5, ipady=4)

        strength_lbl = tk.Label(popup, text="Strength: ---", fg="#aaaaaa", bg="#121212", font=("Consolas", 10, "bold"))
        strength_lbl.pack(pady=5)

        length_frame = tk.Frame(popup, bg="#121212")
        length_frame.pack(pady=5)
        tk.Label(length_frame, text="Length:", fg="#ffffff", bg="#121212", font=("Consolas", 9)).pack(side=tk.LEFT, padx=5)
        length_slider = tk.Scale(length_frame, from_=8, to=32, orient=tk.HORIZONTAL, bg="#121212", fg="#ffffff", highlightbackground="#121212")
        length_slider.set(16)
        length_slider.pack(side=tk.LEFT, padx=5)

        opt_frame = tk.Frame(popup, bg="#121212")
        opt_frame.pack(pady=5)

        upper_var = tk.BooleanVar(value=True)
        lower_var = tk.BooleanVar(value=True)
        nums_var = tk.BooleanVar(value=True)
        syms_var = tk.BooleanVar(value=True)

        tk.Checkbutton(opt_frame, text="A-Z", variable=upper_var, bg="#121212", fg="#ffffff", selectcolor="#1e1e1e", font=("Consolas", 9)).grid(row=0, column=0, padx=5)
        tk.Checkbutton(opt_frame, text="a-z", variable=lower_var, bg="#121212", fg="#ffffff", selectcolor="#1e1e1e", font=("Consolas", 9)).grid(row=0, column=1, padx=5)
        tk.Checkbutton(opt_frame, text="0-9", variable=nums_var, bg="#121212", fg="#ffffff", selectcolor="#1e1e1e", font=("Consolas", 9)).grid(row=0, column=2, padx=5)
        tk.Checkbutton(opt_frame, text="Symbols", variable=syms_var, bg="#121212", fg="#ffffff", selectcolor="#1e1e1e", font=("Consolas", 9)).grid(row=0, column=3, padx=5)

        def update_gen(*args):
            p = generate_secure_password(length=length_slider.get(), use_upper=upper_var.get(), use_lower=lower_var.get(), use_nums=nums_var.get(), use_syms=syms_var.get())
            pass_display.delete(0, tk.END)
            pass_display.insert(0, p)
            label, color, score, feedback = check_password_strength(p)
            fb_text = f" | {', '.join(feedback)}" if feedback else ""
            strength_lbl.config(text=f"Strength: {label}{fb_text}", fg=color)

        length_slider.config(command=update_gen)
        update_gen()

        tk.Button(popup, text="🔄 Generate New", command=update_gen, bg="#2d2d2d", fg="#00ff66", font=("Consolas", 9, "bold"), relief=tk.FLAT).pack(pady=5)

        def use_generated():
            p = pass_display.get()
            if target_entry is not None:
                target_entry.delete(0, tk.END)
                target_entry.insert(0, p)
                popup.destroy()
            else:
                pyperclip.copy(p)
                messagebox.showinfo("Copied", "Generated password copied to clipboard!")
                popup.destroy()

        tk.Button(popup, text="Use Password", command=use_generated, bg="#00ff66", fg="#121212", font=("Consolas", 10, "bold"), width=20, relief=tk.FLAT).pack(pady=10)

    def start_clipboard_countdown(self, seconds=30):
        if self._clipboard_timer_id is not None:
            self.root.after_cancel(self._clipboard_timer_id)
        
        self.clip_progress["maximum"] = seconds
        
        def tick(rem):
            if rem > 0:
                self.clipboard_lbl.config(text=f"📋 Clipboard auto-clearing in {rem}s", fg="#00bcd4")
                self.clip_progress["value"] = rem
                self._clipboard_timer_id = self.root.after(1000, lambda: tick(rem - 1))
            else:
                try:
                    if pyperclip.paste() == self.current_copied_pass:
                        pyperclip.copy("")
                except Exception:
                    pass
                self.clipboard_lbl.config(text="📋 Clipboard Secure: Cleared", fg="#ff4444")
                self.clip_progress["value"] = 0
                self.current_copied_pass = ""

        tick(seconds)

    def copy_to_clipboard_with_timeout(self, text_to_copy):
        self.current_copied_pass = text_to_copy
        pyperclip.copy(text_to_copy)
        self.start_clipboard_countdown(30)
        messagebox.showinfo("Copied", "Sensitive data copied to clipboard!\nAuto-wipe scheduled in 30 seconds.")

    def add_target_popup(self):
        popup = tk.Toplevel(self.root)
        popup.title("Add New Vault Entry")
        popup.geometry("420x450")
        popup.configure(bg="#121212")

        tk.Label(popup, text="ENTRY TYPE:", fg="#00ff66", bg="#121212", font=("Consolas", 10, "bold")).pack(pady=5)
        type_var = tk.StringVar(value="login")
        
        type_frame = tk.Frame(popup, bg="#121212")
        type_frame.pack(pady=2)

        fields_container = tk.Frame(popup, bg="#121212")
        fields_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=5)

        form_data = {}

        def rebuild_form(*args):
            for widget in fields_container.winfo_children():
                widget.destroy()
            form_data.clear()
            
            t = type_var.get()
            if t == "login":
                tk.Label(fields_container, text="Target Site / App Name:", fg="#ffffff", bg="#121212", font=("Consolas", 9)).pack(anchor="w")
                form_data["site"] = tk.Entry(fields_container, font=("Consolas", 10), width=35, bg="#1e1e1e", fg="#ffffff", insertbackground="white")
                form_data["site"].pack(pady=2, ipady=3)

                tk.Label(fields_container, text="Username / Email:", fg="#ffffff", bg="#121212", font=("Consolas", 9)).pack(anchor="w")
                form_data["user"] = tk.Entry(fields_container, font=("Consolas", 10), width=35, bg="#1e1e1e", fg="#ffffff", insertbackground="white")
                form_data["user"].pack(pady=2, ipady=3)

                tk.Label(fields_container, text="Password:", fg="#ffffff", bg="#121212", font=("Consolas", 9)).pack(anchor="w")
                form_data["pass"] = tk.Entry(fields_container, show="*", font=("Consolas", 10), width=35, bg="#1e1e1e", fg="#ffffff", insertbackground="white")
                form_data["pass"].pack(pady=2, ipady=3)

                gen_btn = tk.Button(fields_container, text="🎲 Generate Password", command=lambda: self.open_generator_popup(target_entry=form_data["pass"]), bg="#2d2d2d", fg="#00ff66", font=("Consolas", 8, "bold"), relief=tk.FLAT)
                gen_btn.pack(pady=5)

            elif t == "note":
                tk.Label(fields_container, text="Note Title / Subject:", fg="#ffffff", bg="#121212", font=("Consolas", 9)).pack(anchor="w")
                form_data["site"] = tk.Entry(fields_container, font=("Consolas", 10), width=35, bg="#1e1e1e", fg="#ffffff", insertbackground="white")
                form_data["site"].pack(pady=2, ipady=3)

                tk.Label(fields_container, text="Secure Note Content:", fg="#ffffff", bg="#121212", font=("Consolas", 9)).pack(anchor="w")
                form_data["note"] = tk.Text(fields_container, height=6, width=35, bg="#1e1e1e", fg="#ffffff", insertbackground="white", font=("Consolas", 9))
                form_data["note"].pack(pady=2)

            elif t == "wifi":
                tk.Label(fields_container, text="Network Profile Name:", fg="#ffffff", bg="#121212", font=("Consolas", 9)).pack(anchor="w")
                form_data["site"] = tk.Entry(fields_container, font=("Consolas", 10), width=35, bg="#1e1e1e", fg="#ffffff", insertbackground="white")
                form_data["site"].pack(pady=2, ipady=3)

                tk.Label(fields_container, text="SSID:", fg="#ffffff", bg="#121212", font=("Consolas", 9)).pack(anchor="w")
                form_data["ssid"] = tk.Entry(fields_container, font=("Consolas", 10), width=35, bg="#1e1e1e", fg="#ffffff", insertbackground="white")
                form_data["ssid"].pack(pady=2, ipady=3)

                tk.Label(fields_container, text="Wi-Fi Password / Key:", fg="#ffffff", bg="#121212", font=("Consolas", 9)).pack(anchor="w")
                form_data["pass"] = tk.Entry(fields_container, show="*", font=("Consolas", 10), width=35, bg="#1e1e1e", fg="#ffffff", insertbackground="white")
                form_data["pass"].pack(pady=2, ipady=3)

            elif t == "license":
                tk.Label(fields_container, text="Software / Product Name:", fg="#ffffff", bg="#121212", font=("Consolas", 9)).pack(anchor="w")
                form_data["site"] = tk.Entry(fields_container, font=("Consolas", 10), width=35, bg="#1e1e1e", fg="#ffffff", insertbackground="white")
                form_data["site"].pack(pady=2, ipady=3)

                tk.Label(fields_container, text="License / Serial Key:", fg="#ffffff", bg="#121212", font=("Consolas", 9)).pack(anchor="w")
                form_data["pass"] = tk.Entry(fields_container, font=("Consolas", 10), width=35, bg="#1e1e1e", fg="#ffffff", insertbackground="white")
                form_data["pass"].pack(pady=2, ipady=3)

        tk.Radiobutton(type_frame, text="Login", variable=type_var, value="login", command=rebuild_form, bg="#121212", fg="#00ff66", selectcolor="#1e1e1e", font=("Consolas", 9)).pack(side=tk.LEFT, padx=5)
        tk.Radiobutton(type_frame, text="Note", variable=type_var, value="note", command=rebuild_form, bg="#121212", fg="#00ff66", selectcolor="#1e1e1e", font=("Consolas", 9)).pack(side=tk.LEFT, padx=5)
        tk.Radiobutton(type_frame, text="Wi-Fi", variable=type_var, value="wifi", command=rebuild_form, bg="#121212", fg="#00ff66", selectcolor="#1e1e1e", font=("Consolas", 9)).pack(side=tk.LEFT, padx=5)
        tk.Radiobutton(type_frame, text="License", variable=type_var, value="license", command=rebuild_form, bg="#121212", fg="#00ff66", selectcolor="#1e1e1e", font=("Consolas", 9)).pack(side=tk.LEFT, padx=5)

        rebuild_form()

        def save_new():
            title = form_data.get("site").get().strip() if "site" in form_data else ""
            if not title:
                messagebox.showerror("Error", "Title / Name cannot be empty.")
                return

            t = type_var.get()
            entry_payload = {"type": t}

            if t == "login":
                entry_payload["user"] = form_data["user"].get().strip()
                entry_payload["pass"] = form_data["pass"].get()
            elif t == "note":
                entry_payload["note"] = form_data["note"].get("1.0", tk.END).strip()
            elif t == "wifi":
                entry_payload["ssid"] = form_data["ssid"].get().strip()
                entry_payload["pass"] = form_data["pass"].get()
            elif t == "license":
                entry_payload["key"] = form_data["pass"].get()

            self.vault_data[title] = entry_payload
            save_vault(self.vault_data, self.master_password)
            self.refresh_table()
            popup.destroy()
            messagebox.showinfo("Success", f"Added '{title}' to vault!")

        tk.Button(popup, text="Save Entry", command=save_new, bg="#00ff66", fg="#121212", font=("Consolas", 10, "bold"), width=22, relief=tk.FLAT).pack(pady=10)

    def edit_target_popup(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Select Row", "Please select a target row to edit.")
            return

        item_data = self.tree.item(selected_item)
        title_name = item_data["values"][0]
        creds = self.vault_data.get(title_name, {})
        e_type = creds.get("type", "login")

        popup = tk.Toplevel(self.root)
        popup.title(f"Edit Entry: {title_name}")
        popup.geometry("380x350")
        popup.configure(bg="#121212")

        tk.Label(popup, text=f"Editing ({e_type.upper()}): {title_name}", fg="#ff9800", bg="#121212", font=("Consolas", 10, "bold")).pack(pady=10)

        fields_frame = tk.Frame(popup, bg="#121212")
        fields_frame.pack(fill=tk.BOTH, expand=True, padx=20)

        user_entry = None
        pass_entry = None
        note_text = None
        ssid_entry = None

        if e_type == "login":
            tk.Label(fields_frame, text="Username:", fg="#ffffff", bg="#121212", font=("Consolas", 9)).pack(anchor="w")
            user_entry = tk.Entry(fields_frame, font=("Consolas", 10), width=32, bg="#1e1e1e", fg="#ffffff", insertbackground="white")
            user_entry.insert(0, creds.get("user", ""))
            user_entry.pack(pady=2, ipady=3)

            tk.Label(fields_frame, text="Password:", fg="#ffffff", bg="#121212", font=("Consolas", 9)).pack(anchor="w")
            pass_entry = tk.Entry(fields_frame, show="*", font=("Consolas", 10), width=32, bg="#1e1e1e", fg="#ffffff", insertbackground="white")
            pass_entry.insert(0, creds.get("pass", ""))
            pass_entry.pack(pady=2, ipady=3)
        elif e_type == "note":
            tk.Label(fields_frame, text="Note Content:", fg="#ffffff", bg="#121212", font=("Consolas", 9)).pack(anchor="w")
            note_text = tk.Text(fields_frame, height=6, width=32, bg="#1e1e1e", fg="#ffffff", insertbackground="white", font=("Consolas", 9))
            note_text.insert("1.0", creds.get("note", ""))
            note_text.pack(pady=2)
        elif e_type == "wifi":
            tk.Label(fields_frame, text="SSID:", fg="#ffffff", bg="#121212", font=("Consolas", 9)).pack(anchor="w")
            ssid_entry = tk.Entry(fields_frame, font=("Consolas", 10), width=32, bg="#1e1e1e", fg="#ffffff", insertbackground="white")
            ssid_entry.insert(0, creds.get("ssid", ""))
            ssid_entry.pack(pady=2, ipady=3)

            tk.Label(fields_frame, text="Password / Key:", fg="#ffffff", bg="#121212", font=("Consolas", 9)).pack(anchor="w")
            pass_entry = tk.Entry(fields_frame, show="*", font=("Consolas", 10), width=32, bg="#1e1e1e", fg="#ffffff", insertbackground="white")
            pass_entry.insert(0, creds.get("pass", ""))
            pass_entry.pack(pady=2, ipady=3)
        elif e_type == "license":
            tk.Label(fields_frame, text="License / Serial Key:", fg="#ffffff", bg="#121212", font=("Consolas", 9)).pack(anchor="w")
            pass_entry = tk.Entry(fields_frame, font=("Consolas", 10), width=32, bg="#1e1e1e", fg="#ffffff", insertbackground="white")
            pass_entry.insert(0, creds.get("key", ""))
            pass_entry.pack(pady=2, ipady=3)

        def save_changes():
            updated = {"type": e_type}
            if e_type == "login":
                updated["user"] = user_entry.get().strip()
                updated["pass"] = pass_entry.get()
            elif e_type == "note":
                updated["note"] = note_text.get("1.0", tk.END).strip()
            elif e_type == "wifi":
                updated["ssid"] = ssid_entry.get().strip()
                updated["pass"] = pass_entry.get()
            elif e_type == "license":
                updated["key"] = pass_entry.get()

            self.vault_data[title_name] = updated
            save_vault(self.vault_data, self.master_password)
            self.refresh_table()
            popup.destroy()
            messagebox.showinfo("Success", f"Updated entry for {title_name}!")

        tk.Button(popup, text="Save Changes", command=save_changes, bg="#ff9800", fg="#121212", font=("Consolas", 10, "bold"), width=20, relief=tk.FLAT).pack(pady=15)

    def view_password(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Select Row", "Please click on a target row first.")
            return
        
        item_data = self.tree.item(selected_item)
        title_name = item_data["values"][0]
        creds = self.vault_data.get(title_name, {})
        e_type = creds.get("type", "login")

        popup = tk.Toplevel(self.root)
        popup.title(f"View Details - {title_name}")
        popup.geometry("400x260")
        popup.configure(bg="#121212")

        tk.Label(popup, text=f"Target: {title_name}", fg="#00ff66", bg="#121212", font=("Consolas", 11, "bold")).pack(pady=8)
        tk.Label(popup, text=f"Type: {e_type.upper()}", fg="#aaaaaa", bg="#121212", font=("Consolas", 9)).pack(pady=2)

        secret_val = ""
        if e_type == "login":
            user = creds.get("user", "(None)")
            secret_val = creds.get("pass", "")
            tk.Label(popup, text=f"Username: {user}", fg="#ffffff", bg="#121212", font=("Consolas", 9)).pack(pady=2)
            tk.Label(popup, text=f"Password: {secret_val}", fg="#00bcd4", bg="#121212", font=("Consolas", 11, "bold")).pack(pady=8)
        elif e_type == "note":
            secret_val = creds.get("note", "")
            tk.Label(popup, text=f"Note:\n{secret_val}", fg="#00bcd4", bg="#121212", font=("Consolas", 10)).pack(pady=8)
        elif e_type == "wifi":
            ssid = creds.get("ssid", "")
            secret_val = creds.get("pass", "")
            tk.Label(popup, text=f"SSID: {ssid}", fg="#ffffff", bg="#121212", font=("Consolas", 9)).pack(pady=2)
            tk.Label(popup, text=f"Wi-Fi Password: {secret_val}", fg="#00bcd4", bg="#121212", font=("Consolas", 11, "bold")).pack(pady=8)
        elif e_type == "license":
            secret_val = creds.get("key", "")
            tk.Label(popup, text=f"License Key: {secret_val}", fg="#00bcd4", bg="#121212", font=("Consolas", 10, "bold")).pack(pady=8)

        def copy_secret():
            popup.destroy()
            self.copy_to_clipboard_with_timeout(secret_val)

        if secret_val:
            tk.Button(popup, text="📋 Copy Sensitive Data", command=copy_secret, bg="#00bcd4", fg="#121212", font=("Consolas", 9, "bold"), relief=tk.FLAT).pack(pady=5)

    def copy_selected_password(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Select Row", "Please select a target row first.")
            return
        
        item_data = self.tree.item(selected_item)
        title_name = item_data["values"][0]
        creds = self.vault_data.get(title_name, {})
        e_type = creds.get("type", "login")

        secret_val = ""
        if e_type in ("login", "wifi"):
            secret_val = creds.get("pass", "")
        elif e_type == "note":
            secret_val = creds.get("note", "")
        elif e_type == "license":
            secret_val = creds.get("key", "")

        if secret_val:
            self.copy_to_clipboard_with_timeout(secret_val)
        else:
            messagebox.showwarning("Error", "No copyable secret found for this entry.")

    def delete_target(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Select Row", "Please select a target row to delete.")
            return

        item_data = self.tree.item(selected_item)
        title_name = item_data["values"][0]

        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete '{title_name}'?"):
            if title_name in self.vault_data:
                del self.vault_data[title_name]
                save_vault(self.vault_data, self.master_password)
                self.refresh_table()
                messagebox.showinfo("Deleted", f"Target '{title_name}' removed.")

    def execute_kill_sequence(self, event_type="Kill"):
        self.clear_window()
        
        if hasattr(self, "vault_data") and self.vault_data:
            self.vault_data.clear()
            
        if hasattr(self, "master_password") and self.master_password:
            self.master_password = "\x00" * len(self.master_password)
            self.master_password = ""

        self.log_audit(event_type, "Application killed and sensitive memory scrubbed.")
        self.remove_session_lock()
        try:
            self.root.destroy()
        except Exception:
            pass
        sys.exit(0)

if __name__ == "__main__":
    root = tk.Tk()
    app = VaultGUI(root)
    root.mainloop()