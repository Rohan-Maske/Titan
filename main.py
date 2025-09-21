import customtkinter as ctk
from tkinter import filedialog, messagebox, ttk
import nacl.secret
import nacl.utils
import nacl.pwhash
import base64
import os
import sqlite3
import hashlib
import threading
import json
import pyperclip
import uuid
import time
import binascii
import logging
from concurrent.futures import ThreadPoolExecutor
import platform
import psutil
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
from PIL import Image, ImageTk

logging.basicConfig(filename="titan_errors.log", level=logging.DEBUG, 
                    format="%(asctime)s - %(levelname)s - %(message)s")

KEY_SIZE = nacl.secret.SecretBox.KEY_SIZE
NONCE_SIZE = nacl.secret.SecretBox.NONCE_SIZE
DB_FILE = "titan.db"
SESSION_FILE = "collab_sessions.json"
DEFAULT_ADMIN = {"username": "Admin", "password": "Admin123"}

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

CARD_STYLE = {
    "fg_color": "#2a2a3d",
    "border_color": "#6a6aff",
    "border_width": 1,
    "corner_radius": 15,
    "bg_color": "transparent",
}

BUTTON_STYLE = {
    "border_color": "#6a6aff",
    "border_width": 1,
    "text_color": "#ffffff",
    "font": ("Roboto", 12, "bold"),
    "fg_color": "#6a6aff",
    "hover_color": "#8a8aff",
    "corner_radius": 8,
    "height": 35
}

EYE_BUTTON_STYLE = {
    "width": 35,
    "height": 35,
    "font": ("Roboto", 16),
    "fg_color": "#3a3a4d",
    "hover_color": "#5a5a6d",
    "corner_radius": 8,
    "border_width": 0
}

NOTIFICATION_STYLE = {
    "fg_color": "#2a2a3d",
    "text_color": "#ffffff",
    "border_color": "#6a6aff",
    "border_width": 1,
    "corner_radius": 8,
    "font": ("Roboto", 12)
}

class CustomToggleButton(ctk.CTkFrame):
    def __init__(self, master, option1, option2, command, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.option1 = option1
        self.option2 = option2
        self.command = command
        self.state = True

        self.toggle_container = ctk.CTkFrame(self, fg_color="#3a3a4d", corner_radius=20, height=40, width=200)
        self.toggle_container.pack(pady=5)

        self.slider = ctk.CTkFrame(self.toggle_container, fg_color="#6a6aff", corner_radius=20, width=100, height=36)
        self.slider.place(x=2, y=2)

        self.label1 = ctk.CTkLabel(self.toggle_container, text=option1, font=("Roboto", 12, "bold"), 
                                  text_color="#ffffff" if self.state else "#aaaaaa", width=100)
        self.label1.place(x=0, y=0, relheight=1)

        self.label2 = ctk.CTkLabel(self.toggle_container, text=option2, font=("Roboto", 12, "bold"), 
                                  text_color="#aaaaaa" if self.state else "#ffffff", width=100)
        self.label2.place(x=100, y=0, relheight=1)

        self.toggle_container.bind("<Button-1>", self.toggle)
        self.label1.bind("<Button-1>", self.toggle)
        self.label2.bind("<Button-1>", self.toggle)

    def toggle(self, event=None):
        self.state = not self.state
        if self.state:
            self.slider.place(x=2, y=2)
            self.label1.configure(text_color="#ffffff")
            self.label2.configure(text_color="#aaaaaa")
        else:
            self.slider.place(x=98, y=2)
            self.label1.configure(text_color="#aaaaaa")
            self.label2.configure(text_color="#ffffff")
        if self.command:
            self.command()

class CustomMessageBox(ctk.CTkToplevel):
    def __init__(self, parent, title, message, is_error=False):
        super().__init__(parent)
        self.transient(parent)
        self.title(title)
        self.configure(fg_color="#2a2a3d")
        self.geometry("400x200+{}+{}".format(
            parent.winfo_rootx() + (parent.winfo_width() - 400) // 2,
            parent.winfo_rooty() + (parent.winfo_height() - 200) // 2
        ))
        self.resizable(False, False)
        
        frame = ctk.CTkFrame(self, **CARD_STYLE)
        frame.pack(padx=15, pady=15, fill="both", expand=True)
        
        ctk.CTkLabel(frame, text=message, font=("Roboto", 12), text_color="#ffffff", wraplength=350).pack(pady=15)
        button = ctk.CTkButton(frame, text="OK", command=self.destroy, **BUTTON_STYLE, width=100)
        button.pack(pady=10)
        
        if is_error:
            frame.configure(border_color="#ff4d4d")
            button.configure(fg_color="#ff4d4d", hover_color="#ff6666")
        
        self.grab_set()
        self.lift()
        self.focus_force()
        self.after(50, lambda: self.focus_force())

class TitanApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Titan Encryption Tool")
        self.root.geometry("900x650")
        self.current_user = None
        self.is_admin = False
        self.device_id = self.get_device_id()
        self.device_name = platform.node()
        self.failed_attempts = {}
        self.setup_db()
        self.load_collab_sessions()
        self.session_key = None
        self.shared_files = []
        self.chat_messages = []
        self.chat_days = set()
        self.executor = ThreadPoolExecutor(max_workers=10)
        self.monitoring = False
        self.start_time = time.time()
        self.setup_gui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def get_device_id(self):
        return str(uuid.getnode())

    def load_collab_sessions(self):
        try:
            with open(SESSION_FILE, "r") as f:
                data = json.load(f)
                self.__class__.collab_sessions = {}
                for session_key, session_data in data.items():
                    session_data["users"] = {username: None for username in session_data.get("users", {}).keys()}
                    session_data["messages"] = session_data.get("messages", [])
                    session_data["files"] = session_data.get("files", [])
                    session_data["status"] = session_data.get("status", "stopped")
                    session_data["server_id"] = session_data.get("server_id", "N/A")
                    session_data["port"] = session_data.get("port", "N/A")
                    session_data["start_time"] = session_data.get("start_time", time.time())
                    self.__class__.collab_sessions[session_key] = session_data
        except FileNotFoundError:
            self.__class__.collab_sessions = {}
        except Exception as e:
            logging.error(f"Failed to load collab sessions: {str(e)}")
            self.__class__.collab_sessions = {}

    def save_collab_sessions(self):
        try:
            sessions_to_save = {}
            for session_key, session_data in self.__class__.collab_sessions.items():
                session_copy = session_data.copy()
                session_copy["users"] = {username: None for username in session_data["users"].keys()}
                sessions_to_save[session_key] = session_copy
            with open(SESSION_FILE, "w") as f:
                json.dump(sessions_to_save, f)
        except Exception as e:
            logging.error(f"Failed to save collab sessions: {str(e)}")

    def on_closing(self):
        self.monitoring = False
        if self.current_user in self.__class__.active_users:
            del self.__class__.active_users[self.current_user]
        self.save_collab_sessions()
        self.executor.shutdown(wait=True)
        self.root.destroy()

    def setup_db(self):
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT,
                is_admin INTEGER,
                device_id TEXT,
                device_name TEXT,
                banned INTEGER,
                unique_number TEXT,
                registration_date REAL,
                last_login REAL,
                full_name TEXT,
                name_changed INTEGER DEFAULT 0
            )''')
            c.execute('''CREATE TABLE IF NOT EXISTS keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                key TEXT,
                name TEXT,
                file_name TEXT,
                key_id TEXT,
                encryption_time REAL,
                status TEXT,
                device_id TEXT
            )''')
            c.execute("PRAGMA table_info(users)")
            user_columns = [col[1] for col in c.fetchall()]
            if "device_name" not in user_columns:
                c.execute("ALTER TABLE users ADD COLUMN device_name TEXT")
            if "unique_number" not in user_columns:
                c.execute("ALTER TABLE users ADD COLUMN unique_number TEXT")
            if "registration_date" not in user_columns:
                c.execute("ALTER TABLE users ADD COLUMN registration_date REAL")
            if "last_login" not in user_columns:
                c.execute("ALTER TABLE users ADD COLUMN last_login REAL")
            if "full_name" not in user_columns:
                c.execute("ALTER TABLE users ADD COLUMN full_name TEXT")
            if "name_changed" not in user_columns:
                c.execute("ALTER TABLE users ADD COLUMN name_changed INTEGER DEFAULT 0")

            c.execute("PRAGMA table_info(keys)")
            key_columns = [col[1] for col in c.fetchall()]
            if "file_name" not in key_columns:
                c.execute("ALTER TABLE keys ADD COLUMN file_name TEXT")
            if "key_id" not in key_columns:
                c.execute("ALTER TABLE keys ADD COLUMN key_id TEXT")
            if "encryption_time" not in key_columns:
                c.execute("ALTER TABLE keys ADD COLUMN encryption_time REAL")
            if "status" not in key_columns:
                c.execute("ALTER TABLE keys ADD COLUMN status TEXT")
            if "device_id" not in key_columns:
                c.execute("ALTER TABLE keys ADD COLUMN device_id TEXT")

            c.execute("SELECT * FROM users WHERE username = ?", (DEFAULT_ADMIN["username"],))
            if not c.fetchone():
                password_hash = self.hash_password(DEFAULT_ADMIN["password"])
                unique_number = str(uuid.uuid4())
                c.execute("INSERT INTO users (username, password_hash, is_admin, device_id, device_name, banned, unique_number, registration_date, last_login, full_name, name_changed) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                          (DEFAULT_ADMIN["username"], password_hash, 1, "", "", 0, unique_number, time.time(), time.time(), "Default Admin", 0))
            conn.commit()

    def hash_password(self, password):
        return base64.b64encode(nacl.pwhash.argon2id.kdf(32, password.encode(), b'somesalt12345678')).decode()

    def verify_password(self, password, password_hash):
        try:
            stored_hash = base64.b64decode(password_hash)
            nacl.pwhash.argon2id.kdf(32, password.encode(), b'somesalt12345678')
            return True
        except:
            return False

    def setup_gui(self):
        self.root.configure(fg_color="#1e1e2e")
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)

        style = ttk.Style()
        style.configure("TNotebook", background="#1e1e2e")
        style.configure("TNotebook.Tab", background="#2a2a3d", foreground="#000000", padding=[10, 5], font=("Roboto", 10, "bold"))
        style.map("TNotebook.Tab", 
                 background=[("selected", "#6a6aff"), ("active", "#3a3a4d")],
                 foreground=[("selected", "#000000"), ("active", "#000000")])

        self.auth_frame = ctk.CTkFrame(self.notebook, fg_color="#1e1e2e")
        self.tools_frame = ctk.CTkFrame(self.notebook, fg_color="#1e1e2e")
        self.key_manager_frame = ctk.CTkFrame(self.notebook, fg_color="#1e1e2e")
        self.user_info_frame = ctk.CTkFrame(self.notebook, fg_color="#1e1e2e")
        self.user_manager_frame = ctk.CTkFrame(self.notebook, fg_color="#1e1e2e")
        self.admin_panel_frame = ctk.CTkFrame(self.notebook, fg_color="#1e1e2e")
        self.collab_frame = ctk.CTkFrame(self.notebook, fg_color="#1e1e2e")
        self.server_info_frame = ctk.CTkFrame(self.notebook, fg_color="#1e1e2e")
        self.shared_files_frame = ctk.CTkFrame(self.notebook, fg_color="#1e1e2e")
        self.trinity_frame = ctk.CTkFrame(self.notebook, fg_color="#1e1e2e")
        self.legal_frame = ctk.CTkFrame(self.notebook, fg_color="#1e1e2e")
        self.software_info_frame = ctk.CTkFrame(self.notebook, fg_color="#1e1e2e")

        self.notebook.add(self.auth_frame, text="Auth")
        self.setup_auth_gui()

        self.__class__.active_users = {}

    def setup_auth_gui(self):
        for widget in self.auth_frame.winfo_children():
            widget.destroy()

        self.auth_card = ctk.CTkFrame(self.auth_frame, **CARD_STYLE)
        self.auth_card.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.4, relheight=0.85)

        self.auth_label = ctk.CTkLabel(self.auth_card, text="Titan Encryption Tool", font=("Roboto", 24, "bold"), text_color="#6a6aff")
        self.auth_label.pack(pady=(30, 10))
        
        self.auth_subtitle = ctk.CTkLabel(self.auth_card, text="Securely access your account", font=("Roboto", 12), text_color="#cccccc")
        self.auth_subtitle.pack(pady=(0, 15))

        self.auth_toggle = CustomToggleButton(self.auth_card, "Login", "Register", self.toggle_auth_mode)
        self.auth_toggle.pack(pady=10)

        self.login_frame = ctk.CTkFrame(self.auth_card, fg_color="transparent")
        self.register_frame = ctk.CTkFrame(self.auth_card, fg_color="transparent")

        self.setup_login_gui()
        self.setup_register_gui()

        self.is_login_mode = True
        self.update_auth_mode()

    def setup_login_gui(self):
        ctk.CTkLabel(self.login_frame, text="Username", text_color="#ffffff", font=("Roboto", 12)).pack(anchor="w", padx=30)
        self.auth_username = ctk.CTkEntry(self.login_frame, width=300, placeholder_text="Enter username", font=("Roboto", 12), height=35, corner_radius=8)
        self.auth_username.pack(fill="x", pady=(3, 0), padx=30)

        ctk.CTkLabel(self.login_frame, text="Password", text_color="#ffffff", font=("Roboto", 12)).pack(anchor="w", padx=30, pady=(5, 0))
        password_inner_frame = ctk.CTkFrame(self.login_frame, fg_color="transparent")
        password_inner_frame.pack(fill="x", padx=30)
        self.auth_password = ctk.CTkEntry(password_inner_frame, width=200, show="*", placeholder_text="Enter password", font=("Roboto", 12), height=35, corner_radius=8)
        self.auth_password.pack(side="left", fill="x", expand=True, pady=(3, 0))
        self.auth_eye_button = ctk.CTkButton(password_inner_frame, text="🙈", command=self.toggle_auth_password, **EYE_BUTTON_STYLE)
        self.auth_eye_button.pack(side="left", padx=(6, 0), pady=(3, 0))
        self.auth_password_shown = False

        self.login_button = ctk.CTkButton(self.login_frame, text="Login", command=self.login, width=300, **BUTTON_STYLE)
        self.login_button.pack(pady=20, padx=30)

    def setup_register_gui(self):
        ctk.CTkLabel(self.register_frame, text="Full Name", text_color="#ffffff", font=("Roboto", 12)).pack(anchor="w", padx=30)
        self.register_full_name = ctk.CTkEntry(self.register_frame, width=300, placeholder_text="Enter your full name", font=("Roboto", 12), height=35, corner_radius=8)
        self.register_full_name.pack(fill="x", pady=(3, 0), padx=30)

        ctk.CTkLabel(self.register_frame, text="Username", text_color="#ffffff", font=("Roboto", 12)).pack(anchor="w", padx=30, pady=(5, 0))
        self.register_username = ctk.CTkEntry(self.register_frame, width=300, placeholder_text="Enter username", font=("Roboto", 12), height=35, corner_radius=8)
        self.register_username.pack(fill="x", pady=(3, 0), padx=30)

        ctk.CTkLabel(self.register_frame, text="Password", text_color="#ffffff", font=("Roboto", 12)).pack(anchor="w", padx=30, pady=(5, 0))
        password_inner_frame = ctk.CTkFrame(self.register_frame, fg_color="transparent")
        password_inner_frame.pack(fill="x", padx=30)
        self.register_password = ctk.CTkEntry(password_inner_frame, width=200, show="*", placeholder_text="Enter password", font=("Roboto", 12), height=35, corner_radius=8)
        self.register_password.pack(side="left", fill="x", expand=True, pady=(3, 0))
        self.register_eye_button = ctk.CTkButton(password_inner_frame, text="🙈", command=self.toggle_register_password, **EYE_BUTTON_STYLE)
        self.register_eye_button.pack(side="left", padx=(6, 0), pady=(3, 0))
        self.register_password_shown = False

        agreement_frame = ctk.CTkFrame(self.register_frame, fg_color="transparent")
        agreement_frame.pack(fill="x", padx=30, pady=(5, 0))
        
        self.agree_var = ctk.BooleanVar(value=False)
        self.agree_checkbox = ctk.CTkCheckBox(
            agreement_frame,
            text="I agree to the ",
            variable=self.agree_var,
            command=self.toggle_register_button_state,
            font=("Roboto", 12),
            text_color="#ffffff",
            fg_color="#6a6aff",
            hover_color="#8a8aff"
        )
        self.agree_checkbox.pack(side="left", pady=(5, 0))

        self.user_agreement_link = ctk.CTkLabel(
            agreement_frame,
            text="User Agreement",
            text_color="#6a6aff",
            font=("Roboto", 12, "underline"),
            cursor="hand2"
        )
        self.user_agreement_link.pack(side="left", pady=(5, 0))
        self.user_agreement_link.bind("<Button-1>", lambda e: self.show_user_agreement_from_register())

        ctk.CTkLabel(
            agreement_frame,
            text=" and ",
            text_color="#ffffff",
            font=("Roboto", 12)
        ).pack(side="left", pady=(5, 0))

        self.privacy_policy_link = ctk.CTkLabel(
            agreement_frame,
            text="Privacy Policy",
            text_color="#6a6aff",
            font=("Roboto", 12, "underline"),
            cursor="hand2"
        )
        self.privacy_policy_link.pack(side="left", pady=(5, 0))
        self.privacy_policy_link.bind("<Button-1>", lambda e: self.show_privacy_policy_from_register())

        self.register_button = ctk.CTkButton(
            self.register_frame,
            text="Register",
            command=self.register,
            width=300,
            **BUTTON_STYLE,
            state="disabled"
        )
        self.register_button.pack(pady=20, padx=30)

    def toggle_register_button_state(self):
        if self.agree_var.get():
            self.register_button.configure(state="normal")
        else:
            self.register_button.configure(state="disabled")

    def show_user_agreement_from_register(self):
        content = """User Agreement for Titan Encryption Tool

Last Updated: May 07, 2025

1. Acceptance of Terms
By using the Titan Encryption Tool ("Service"), you agree to be bound by the following terms and conditions ("Terms"). If you do not agree to these Terms, please do not use the Service.

2. Eligibility
You must be at least 13 years of age to use the Service. By using the Service, you represent and warrant that you meet this age requirement.

3. Account Registration
To access certain features of the Service, you must register for an account. You agree to provide accurate and complete information during registration and to keep your account information updated.

4. User Responsibilities
- You are responsible for maintaining the confidentiality of your account credentials.
- You agree not to use the Service for any illegal or unauthorized purpose.
- You are solely responsible for any data you encrypt or decrypt using the Service.

5. Data Security
The Service provides encryption and decryption tools. While we strive to ensure the security of your data, you acknowledge that no system is completely secure, and you use the Service at your own risk.

6. Termination
We reserve the right to suspend or terminate your account at our discretion if you violate these Terms.

7. Limitation of Liability
To the fullest extent permitted by law, Titan Encryption Tool shall not be liable for any indirect, incidental, special, consequential, or punitive damages arising out of or related to your use of the Service.

8. Changes to Terms
We may update these Terms from time to time. We will notify you of changes by posting the updated Terms on this page. Your continued use of the Service after such changes constitutes your acceptance of the new Terms.

9. Contact Us
If you have any questions about these Terms, please contact us at support@titanencryption.com.
"""
        self.setup_legal_gui()
        self.notebook.forget(self.auth_frame)
        self.notebook.add(self.legal_frame, text="Legal Information")
        self.notebook.select(self.legal_frame)
        self.show_legal_content("User Agreement", content, lambda: self.return_to_auth())

    def show_privacy_policy_from_register(self):
        content = """Privacy Policy for Titan Encryption Tool

Last Updated: May 07, 2025

1. Introduction
Titan Encryption Tool ("we", "us", "our") is committed to protecting your privacy. This Privacy Policy explains how we collect, use, and safeguard your information when you use our Service.

2. Information We Collect
- Account Information: When you register, we collect your username, full name, and device information.
- Usage Data: We may collect information about how you use the Service, such as encryption and decryption activities.
- Keys: Encryption keys are stored in our database but are not linked to your personal identity beyond your username.

3. How We Use Your Information
- To provide and maintain the Service.
- To improve the Service and develop new features.
- To monitor for security threats and prevent abuse.

4. Data Security
We implement reasonable measures to protect your data, including encryption of stored keys. However, no method of transmission or storage is completely secure, and we cannot guarantee absolute security.

5. Sharing Your Information
We do not share your personal information with third parties except as required by law or to protect our rights.

6. Your Choices
You may update your account information at any time. You can also delete your account, which will remove your personal information from our systems, subject to any legal obligations.

7. Children's Privacy
The Service is not intended for users under 13 years of age. We do not knowingly collect information from children under 13.

8. Changes to This Privacy Policy
We may update this Privacy Policy from time to time. We will notify you of changes by posting the updated policy on this page.

9. Contact Us
If you have any questions about this Privacy Policy, please contact us at privacy@titanencryption.com.
"""
        self.setup_legal_gui()
        self.notebook.forget(self.auth_frame)
        self.notebook.add(self.legal_frame, text="Legal Information")
        self.notebook.select(self.legal_frame)
        self.show_legal_content("Privacy Policy", content, lambda: self.return_to_auth())

    def return_to_auth(self):
        self.notebook.forget(self.legal_frame)
        self.notebook.add(self.auth_frame, text="Auth")
        self.notebook.select(self.auth_frame)
        self.setup_auth_gui()

    def toggle_auth_mode(self):
        self.is_login_mode = not self.is_login_mode
        self.update_auth_mode()

    def update_auth_mode(self):
        if self.is_login_mode:
            self.auth_label.configure(text="Titan Encryption Tool")
            self.auth_subtitle.configure(text="Securely access your account")
            self.register_frame.pack_forget()
            self.login_frame.pack(fill="y", expand=True)
        else:
            self.auth_label.configure(text="Titan Encryption Tool")
            self.auth_subtitle.configure(text="Create a new account")
            self.login_frame.pack_forget()
            self.register_frame.pack(fill="y", expand=True)

    def toggle_auth_password(self):
        if self.auth_password_shown:
            self.auth_password.configure(show="*")
            self.auth_eye_button.configure(text="🙈")
            self.auth_password_shown = False
        else:
            self.auth_password.configure(show="")
            self.auth_eye_button.configure(text="🙉")
            self.auth_password_shown = True

    def toggle_register_password(self):
        if self.register_password_shown:
            self.register_password.configure(show="*")
            self.register_eye_button.configure(text="🙈")
            self.register_password_shown = False
        else:
            self.register_password.configure(show="")
            self.register_eye_button.configure(text="🙉")
            self.register_password_shown = True

    def get_greeting(self, username):
        hour = int(time.strftime("%H"))
        if 0 <= hour < 12:
            return f"Good Morning, {username}!"
        elif 12 <= hour < 17:
            return f"Good Afternoon, {username}!"
        else:
            return f"Good Evening, {username}!"

    def login(self):
        username = self.auth_username.get()
        password = self.auth_password.get()
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("SELECT password_hash, is_admin, banned FROM users WHERE username = ?", (username,))
            result = c.fetchone()
            if result and not result[2]:
                if self.verify_password(password, result[0]):
                    self.current_user = username
                    self.is_admin = result[1]
                    c.execute("UPDATE users SET last_login = ? WHERE username = ?", (time.time(), username))
                    conn.commit()
                    self.__class__.active_users[username] = True
                    self.notebook.forget(self.auth_frame)
                    self.auth_frame.destroy()
                    self.setup_main_gui()
                    greeting = self.get_greeting(username)
                    CustomMessageBox(self.root, "Welcome", greeting)
                else:
                    CustomMessageBox(self.root, "Error", "Invalid password", is_error=True)
            else:
                CustomMessageBox(self.root, "Error", "Invalid username or banned", is_error=True)

    def register(self):
        full_name = self.register_full_name.get()
        username = self.register_username.get()
        password = self.register_password.get()
        
        if not full_name or not username or not password:
            CustomMessageBox(self.root, "Error", "All fields are required", is_error=True)
            return

        if not self.agree_var.get():
            CustomMessageBox(self.root, "Error", "You must agree to the User Agreement and Privacy Policy", is_error=True)
            return

        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            try:
                password_hash = self.hash_password(password)
                unique_number = str(uuid.uuid4())
                c.execute("INSERT INTO users (username, password_hash, is_admin, device_id, device_name, banned, unique_number, registration_date, last_login, full_name, name_changed) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                          (username, password_hash, 0, self.device_id, self.device_name, 0, unique_number, time.time(), time.time(), full_name, 0))
                conn.commit()
                CustomMessageBox(self.root, "Success", "Registered successfully")
                self.register_full_name.delete(0, "end")
                self.register_username.delete(0, "end")
                self.register_password.delete(0, "end")
                self.agree_var.set(False)
                self.toggle_register_button_state()
                self.is_login_mode = True
                self.update_auth_mode()
            except sqlite3.IntegrityError:
                CustomMessageBox(self.root, "Error", "Username already exists", is_error=True)

    def logout(self):
        if self.session_key and self.session_key in self.__class__.collab_sessions:
            if self.current_user in self.__class__.collab_sessions[self.session_key]["users"]:
                del self.__class__.collab_sessions[self.session_key]["users"][self.current_user]
                self.broadcast_to_session(f"🚪 {self.current_user} left")
                self.session_key = None
                self.shared_files = []
                self.chat_messages = []
                self.chat_days = set()
                try:
                    self.notebook.forget(self.shared_files_frame)
                except:
                    pass

        self.monitoring = False
        if self.current_user in self.__class__.active_users:
            del self.__class__.active_users[self.current_user]

        self.current_user = None
        self.is_admin = False
        self.session_key = None
        self.shared_files = []
        self.chat_messages = []
        self.chat_days = set()

        for tab_id in self.notebook.tabs():
            self.notebook.forget(tab_id)

        self.auth_frame = ctk.CTkFrame(self.notebook, fg_color="#1e1e2e")
        self.tools_frame = ctk.CTkFrame(self.notebook, fg_color="#1e1e2e")
        self.key_manager_frame = ctk.CTkFrame(self.notebook, fg_color="#1e1e2e")
        self.user_info_frame = ctk.CTkFrame(self.notebook, fg_color="#1e1e2e")
        self.user_manager_frame = ctk.CTkFrame(self.notebook, fg_color="#1e1e2e")
        self.admin_panel_frame = ctk.CTkFrame(self.notebook, fg_color="#1e1e2e")
        self.collab_frame = ctk.CTkFrame(self.notebook, fg_color="#1e1e2e")
        self.server_info_frame = ctk.CTkFrame(self.notebook, fg_color="#1e1e2e")
        self.shared_files_frame = ctk.CTkFrame(self.notebook, fg_color="#1e1e2e")
        self.trinity_frame = ctk.CTkFrame(self.notebook, fg_color="#1e1e2e")
        self.legal_frame = ctk.CTkFrame(self.notebook, fg_color="#1e1e2e")
        self.software_info_frame = ctk.CTkFrame(self.notebook, fg_color="#1e1e2e")

        self.notebook.add(self.auth_frame, text="Auth")
        self.setup_auth_gui()

        CustomMessageBox(self.root, "Success", "Logged out successfully")

    def setup_main_gui(self):
        self.notebook.add(self.tools_frame, text="Tools")
        self.setup_tools_gui()

        self.notebook.add(self.key_manager_frame, text="Key Manager")
        self.setup_key_manager_gui()

        self.notebook.add(self.user_info_frame, text="User Info")
        self.setup_user_info_gui()

        self.notebook.add(self.collab_frame, text="Collaboration")
        self.setup_collab_gui()

        if self.is_admin:
            self.notebook.add(self.user_manager_frame, text="User Manager")
            self.setup_user_manager_gui()

            self.notebook.add(self.admin_panel_frame, text="Admin Panel")
            self.setup_admin_panel_gui()

            self.notebook.add(self.server_info_frame, text="Server Info")
            self.setup_server_info_gui()

            self.notebook.add(self.trinity_frame, text="Trinity Engine")
            self.setup_trinity_gui()

        self.notebook.add(self.software_info_frame, text="Software Info")
        self.setup_software_info_gui()

        self.notebook.add(self.legal_frame, text="Legal Information")
        self.setup_legal_gui()

        self.notebook.select(self.tools_frame)

    def setup_tools_gui(self):
        for widget in self.tools_frame.winfo_children():
            widget.destroy()

        tools_card = ctk.CTkFrame(self.tools_frame, **CARD_STYLE)
        tools_card.pack(fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(tools_card, text="Encryption Tools", font=("Roboto", 20, "bold"), text_color="#6a6aff").pack(pady=10)

        self.tools_toggle = CustomToggleButton(tools_card, "Encrypt", "Decrypt", self.toggle_tools_mode)
        self.tools_toggle.pack(pady=10)

        self.encrypt_frame = ctk.CTkFrame(tools_card, fg_color="transparent")
        self.decrypt_frame = ctk.CTkFrame(tools_card, fg_color="transparent")

        self.setup_encrypt_gui()
        self.setup_decrypt_gui()

        self.is_encrypt_mode = True
        self.update_tools_mode()

    def setup_encrypt_gui(self):
        ctk.CTkLabel(self.encrypt_frame, text="Select File", text_color="#ffffff", font=("Roboto", 12)).pack(anchor="w", padx=10)
        file_inner_frame = ctk.CTkFrame(self.encrypt_frame, fg_color="transparent")
        file_inner_frame.pack(fill="x", padx=10)
        self.encrypt_file_path = ctk.CTkEntry(file_inner_frame, width=465, placeholder_text="Select a file", font=("Roboto", 12), height=35, corner_radius=8)
        self.encrypt_file_path.pack(side="left", fill="x", expand=True, pady=(3, 0))
        ctk.CTkButton(file_inner_frame, text="Browse", command=lambda: self.browse_file(self.encrypt_file_path), **BUTTON_STYLE, width=100).pack(side="left", padx=(6, 0), pady=(3, 0))

        ctk.CTkButton(self.encrypt_frame, text="Encrypt", command=self.encrypt_file, **BUTTON_STYLE).pack(pady=15)

    def setup_decrypt_gui(self):
        ctk.CTkLabel(self.decrypt_frame, text="Select File", text_color="#ffffff", font=("Roboto", 12)).pack(anchor="w", padx=10)
        file_inner_frame = ctk.CTkFrame(self.decrypt_frame, fg_color="transparent")
        file_inner_frame.pack(fill="x", padx=10)
        self.decrypt_file_path = ctk.CTkEntry(file_inner_frame, width=465, placeholder_text="Select a file", font=("Roboto", 12), height=35, corner_radius=8)
        self.decrypt_file_path.pack(side="left", fill="x", expand=True, pady=(3, 0))
        ctk.CTkButton(file_inner_frame, text="Browse", command=lambda: self.browse_file(self.decrypt_file_path), **BUTTON_STYLE, width=100).pack(side="left", padx=(6, 0), pady=(3, 0))

        ctk.CTkLabel(self.decrypt_frame, text="Key (base64)", text_color="#ffffff", font=("Roboto", 12)).pack(anchor="w", padx=10, pady=(5, 0))
        self.decrypt_key_entry = ctk.CTkEntry(self.decrypt_frame, width=500, placeholder_text="Enter base64 key", font=("Roboto", 12), height=35, corner_radius=8)
        self.decrypt_key_entry.pack(fill="x", pady=(3, 0), padx=10)

        ctk.CTkButton(self.decrypt_frame, text="Decrypt", command=self.decrypt_file, **BUTTON_STYLE).pack(pady=15)

    def toggle_tools_mode(self):
        self.is_encrypt_mode = not self.is_encrypt_mode
        self.update_tools_mode()

    def update_tools_mode(self):
        if self.is_encrypt_mode:
            self.decrypt_frame.pack_forget()
            self.encrypt_frame.pack(fill="y", expand=True)
        else:
            self.encrypt_frame.pack_forget()
            self.decrypt_frame.pack(fill="y", expand=True)

    def browse_file(self, entry):
        file = filedialog.askopenfilename()
        if file:
            entry.delete(0, "end")
            entry.insert(0, file)

    def generate_and_store_key(self, file_path):
        key = nacl.utils.random(KEY_SIZE)
        key_b64 = base64.b64encode(key).decode()
        name = f"Key_{int(time.time())}"
        file_name = os.path.basename(file_path)
        key_id = str(uuid.uuid4())
        encryption_time = time.time()

        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("INSERT INTO keys (username, key, name, file_name, key_id, encryption_time, status, device_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                      (self.current_user, key_b64, name, file_name, key_id, encryption_time, "active", self.device_id))
            conn.commit()

        self.refresh_key_list()
        return key, key_b64

    def validate_key(self, key_b64):
        try:
            if not isinstance(key_b64, str):
                return None, "Key must be a string"
            key = base64.b64decode(key_b64.strip())
            if len(key) != KEY_SIZE:
                return None, "Invalid key length (must be 32 bytes)"
            return key, None
        except binascii.Error:
            return None, "Invalid base64 encoding"
        except Exception as e:
            return None, f"Key validation failed: {str(e)}"

    def delete_key(self, key_b64=None):
        try:
            if key_b64:
                with sqlite3.connect(DB_FILE) as conn:
                    c = conn.cursor()
                    c.execute("DELETE FROM keys WHERE username = ? AND key = ?", (self.current_user, key_b64))
                    conn.commit()
            else:
                selected_item = self.key_table.selection()
                if not selected_item:
                    CustomMessageBox(self.root, "Warning", "Please select a key to delete")
                    return
                key_b64 = self.key_table.item(selected_item)["values"][0]
                with sqlite3.connect(DB_FILE) as conn:
                    c = conn.cursor()
                    c.execute("DELETE FROM keys WHERE username = ? AND key = ?", (self.current_user, key_b64))
                    conn.commit()
            self.refresh_key_list()
            CustomMessageBox(self.root, "Success", "Key deleted from database")
        except Exception as e:
            logging.error(f"Delete key failed: {str(e)}")
            CustomMessageBox(self.root, "Error", f"Failed to delete key: {str(e)}", is_error=True)

    def terminate_key(self):
        try:
            selected_item = self.key_table.selection()
            if not selected_item:
                CustomMessageBox(self.root, "Warning", "Please select a key to terminate")
                return
            key_b64 = self.key_table.item(selected_item)["values"][0]
            with sqlite3.connect(DB_FILE) as conn:
                c = conn.cursor()
                c.execute("SELECT status FROM keys WHERE username = ? AND key = ?", (self.current_user, key_b64))
                result = c.fetchone()
                if not result:
                    CustomMessageBox(self.root, "Error", "Key not found", is_error=True)
                    return
                current_status = result[0]
                if current_status == "terminated":
                    CustomMessageBox(self.root, "Info", "Key is already terminated")
                    return
                c.execute("UPDATE keys SET status = 'terminated' WHERE username = ? AND key = ?", (self.current_user, key_b64))
                conn.commit()
            self.refresh_key_list()
            CustomMessageBox(self.root, "Success", "Key has been terminated and can no longer be used for decryption")
        except Exception as e:
            logging.error(f"Terminate key failed: {str(e)}")
            CustomMessageBox(self.root, "Error", f"Failed to terminate key: {str(e)}", is_error=True)

    def encrypt_file(self):
        file_path = self.encrypt_file_path.get()
        if not file_path:
            CustomMessageBox(self.root, "Error", "File path required", is_error=True)
            return

        key, key_b64 = self.generate_and_store_key(file_path)
        try:
            output_file = os.path.splitext(file_path)[0] + ".titan"
            start_time = time.time()
            logging.info(f"Encrypting file {file_path} with key {key_b64}")
            self.stream_encrypt_file(file_path, output_file, key)
            elapsed = time.time() - start_time
            CustomMessageBox(self.root, "Success", f"Encrypted to {output_file}\nKey: {key_b64}\nTime: {elapsed:.2f}s")
            self.failed_attempts.pop(file_path, None)
        except Exception as e:
            logging.error(f"Encryption failed: {str(e)}")
            CustomMessageBox(self.root, "Error", f"Encryption failed: {str(e)}", is_error=True)

    def decrypt_file(self):
        file_path = self.decrypt_file_path.get()
        key_b64 = self.decrypt_key_entry.get().strip()
        if not file_path or not key_b64:
            CustomMessageBox(self.root, "Error", "File and key required", is_error=True)
            return
        if not file_path.endswith(".titan"):
            CustomMessageBox(self.root, "Error", "Invalid file format (must be .titan)", is_error=True)
            return

        # Initialize failed attempts for this file if not already tracked
        if file_path not in self.failed_attempts:
            self.failed_attempts[file_path] = 0

        # Check if the key exists in the database
        key_status = None
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("SELECT status FROM keys WHERE username = ? AND key = ?", (self.current_user, key_b64))
            result = c.fetchone()
            if not result:
                # Key not found, increment failed attempts
                self.failed_attempts[file_path] += 1
                remaining_attempts = 3 - self.failed_attempts[file_path]
                if self.failed_attempts[file_path] >= 3:
                    # Lock the file after 3 failed attempts
                    locked_file = file_path.replace(".titan", ".locked")
                    if os.path.exists(file_path):
                        os.rename(file_path, locked_file)
                    CustomMessageBox(self.root, "Error", f"Too many failed attempts. The file is now permanently undecryptable: {locked_file}", is_error=True)
                    self.failed_attempts.pop(file_path)
                    self.decrypt_key_entry.delete(0, "end")
                    return
                CustomMessageBox(self.root, "Error", f"Key not found in database\nYou have {remaining_attempts} attempts left", is_error=True)
                self.decrypt_key_entry.delete(0, "end")
                return
            key_status = result[0]
            if key_status == "terminated":
                CustomMessageBox(self.root, "Error", "This key has been terminated and cannot be used for decryption", is_error=True)
                self.decrypt_key_entry.delete(0, "end")
                return

        key, error = self.validate_key(key_b64)
        if error:
            self.failed_attempts[file_path] += 1
            remaining_attempts = 3 - self.failed_attempts[file_path]
            if self.failed_attempts[file_path] >= 3:
                # Terminate and delete the key
                with sqlite3.connect(DB_FILE) as conn:
                    c = conn.cursor()
                    c.execute("UPDATE keys SET status = 'terminated' WHERE username = ? AND key = ?", (self.current_user, key_b64))
                    c.execute("DELETE FROM keys WHERE username = ? AND key = ?", (self.current_user, key_b64))
                    conn.commit()
                self.refresh_key_list()
                # Lock the file
                locked_file = file_path.replace(".titan", ".locked")
                if os.path.exists(file_path):
                    os.rename(file_path, locked_file)
                CustomMessageBox(self.root, "Success", f"Key {key_b64} has been dumped (terminated and deleted) due to too many failed attempts.", is_error=False)
                CustomMessageBox(self.root, "Error", f"The file is now permanently undecryptable: {locked_file}", is_error=True)
                self.failed_attempts.pop(file_path)
                self.decrypt_key_entry.delete(0, "end")
                return
            CustomMessageBox(self.root, "Error", f"Wrong key: {error}\nYou have {remaining_attempts} attempts left", is_error=True)
            self.decrypt_key_entry.delete(0, "end")
            return

        try:
            output_file = file_path.replace(".titan", "_decrypted" + os.path.splitext(file_path)[1])
            start_time = time.time()
            logging.info(f"Decrypting file {file_path} with key {key_b64}")
            self.stream_decrypt_file(file_path, output_file, key)
            elapsed = time.time() - start_time
            self.delete_key(key_b64)
            CustomMessageBox(self.root, "Success", f"Decrypted to {output_file}\nTime: {elapsed:.2f}s")
            self.failed_attempts.pop(file_path, None)
        except nacl.exceptions.CryptoError as e:
            self.failed_attempts[file_path] += 1
            remaining_attempts = 3 - self.failed_attempts[file_path]
            if self.failed_attempts[file_path] >= 3:
                # Terminate and delete the key
                with sqlite3.connect(DB_FILE) as conn:
                    c = conn.cursor()
                    c.execute("UPDATE keys SET status = 'terminated' WHERE username = ? AND key = ?", (self.current_user, key_b64))
                    c.execute("DELETE FROM keys WHERE username = ? AND key = ?", (self.current_user, key_b64))
                    conn.commit()
                self.refresh_key_list()
                # Lock the file
                locked_file = file_path.replace(".titan", ".locked")
                if os.path.exists(file_path):
                    os.rename(file_path, locked_file)
                CustomMessageBox(self.root, "Success", f"Key {key_b64} has been dumped (terminated and deleted) due to too many failed attempts.", is_error=False)
                CustomMessageBox(self.root, "Error", f"The file is now permanently undecryptable: {locked_file}", is_error=True)
                self.failed_attempts.pop(file_path)
            else:
                CustomMessageBox(self.root, "Error", f"Wrong key or corrupted file\nYou have {remaining_attempts} attempts left", is_error=True)
            self.decrypt_key_entry.delete(0, "end")
        except Exception as e:
            logging.error(f"Decryption failed: {str(e)}")
            CustomMessageBox(self.root, "Error", f"Decryption failed: {str(e)}", is_error=True)
            self.decrypt_key_entry.delete(0, "end")
        finally:
            self.decrypt_key_entry.delete(0, "end")

    def stream_encrypt_file(self, input_file, output_file, key):
        box = nacl.secret.SecretBox(key)
        nonce = nacl.utils.random(NONCE_SIZE)
        chunk_size = 1024 * 1024
        original_ext = os.path.splitext(input_file)[1]
        metadata = json.dumps({"ext": original_ext}).encode()
        metadata_cipher = box.encrypt(metadata, nonce)

        with open(input_file, "rb") as f_in, open(output_file, "wb") as f_out:
            f_out.write(nonce)
            metadata_len = len(metadata_cipher) - NONCE_SIZE
            f_out.write(metadata_len.to_bytes(4, byteorder='big'))
            f_out.write(metadata_cipher[NONCE_SIZE:])
            while True:
                chunk = f_in.read(chunk_size)
                if not chunk:
                    break
                cipher_chunk = box.encrypt(chunk, nonce)
                f_out.write(cipher_chunk[NONCE_SIZE:])

    def stream_decrypt_file(self, input_file, output_file, key):
        box = nacl.secret.SecretBox(key)
        chunk_size = 1024 * 1024 + box.MACBYTES

        with open(input_file, "rb") as f_in:
            nonce = f_in.read(NONCE_SIZE)
            if len(nonce) != NONCE_SIZE:
                raise ValueError("Invalid nonce")
            metadata_len_bytes = f_in.read(4)
            if len(metadata_len_bytes) != 4:
                raise ValueError("Invalid metadata length")
            metadata_len = int.from_bytes(metadata_len_bytes, byteorder='big')
            metadata_cipher = f_in.read(metadata_len)
            if len(metadata_cipher) != metadata_len:
                raise ValueError("Incomplete metadata")
            metadata_full = nonce + metadata_cipher
            metadata = box.decrypt(metadata_full)
            original_ext = json.loads(metadata.decode())["ext"]
            output_file = output_file.replace("_decrypted", "_decrypted") + original_ext

            with open(output_file, "wb") as f_out:
                while True:
                    chunk = f_in.read(chunk_size)
                    if not chunk:
                        break
                    full_cipher_chunk = nonce + chunk
                    plain_chunk = box.decrypt(full_cipher_chunk)
                    f_out.write(plain_chunk)

    def setup_key_manager_gui(self):
        for widget in self.key_manager_frame.winfo_children():
            widget.destroy()

        key_manager_card = ctk.CTkFrame(self.key_manager_frame, **CARD_STYLE)
        key_manager_card.pack(fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(key_manager_card, text="Key Manager", font=("Roboto", 20, "bold"), text_color="#6a6aff").pack(pady=10)

        search_frame = ctk.CTkFrame(key_manager_card, **CARD_STYLE)
        search_frame.pack(pady=5, padx=10, fill="x")
        self.search_entry = ctk.CTkEntry(search_frame, width=500, placeholder_text="Search by file name or date (YYYY-MM-DD)", font=("Roboto", 12), height=35, corner_radius=8)
        self.search_entry.pack(side="left", padx=(10, 5), pady=5, expand=True, fill="x")
        self.search_entry.bind("<KeyRelease>", self.filter_keys)
        ctk.CTkButton(search_frame, text="❌", command=self.clear_search, width=100, **BUTTON_STYLE).pack(side="left", padx=(0, 10), pady=5)

        table_frame = ctk.CTkFrame(key_manager_card, fg_color="transparent")
        table_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.columns = ("key", "file_name", "status", "generation_date", "device_id")
        self.key_table = ttk.Treeview(table_frame, columns=self.columns, show="headings")
        self.key_table.heading("key", text="Key")
        self.key_table.heading("file_name", text="File Name")
        self.key_table.heading("status", text="Status")
        self.key_table.heading("generation_date", text="Generation Date")
        self.key_table.heading("device_id", text="Device ID")
        self.key_table.column("key", width=200)
        self.key_table.column("file_name", width=150)
        self.key_table.column("status", width=100)
        self.key_table.column("generation_date", width=150)
        self.key_table.column("device_id", width=150)
        self.key_table.pack(fill="both", expand=True)

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.key_table.yview)
        self.key_table.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

        self.key_table.bind("<Double-1>", self.copy_key)

        button_frame = ctk.CTkFrame(key_manager_card, fg_color="transparent")
        button_frame.pack(pady=5)
        ctk.CTkButton(button_frame, text="Delete Key", command=self.delete_key, **BUTTON_STYLE).pack(side="left", padx=5)
        ctk.CTkButton(button_frame, text="Terminate Key", command=self.terminate_key, **BUTTON_STYLE).pack(side="left", padx=5)
        ctk.CTkButton(button_frame, text="Copy Key", command=self.copy_key_manual, **BUTTON_STYLE).pack(side="left", padx=5)

        self.refresh_key_list()

    def filter_keys(self, event=None):
        search_term = self.search_entry.get().strip().lower()
        self.key_table.delete(*self.key_table.get_children())

        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("SELECT key, file_name, status, encryption_time, device_id FROM keys WHERE username = ?", (self.current_user,))
            rows = c.fetchall()

        if search_term:
            self.key_table.configure(columns=("key", "file_name"))
            self.key_table.heading("key", text="Key")
            self.key_table.heading("file_name", text="File Name")
            self.key_table.column("key", width=300)
            self.key_table.column("file_name", width=300)

            for key, file_name, status, enc_time, device_id in rows:
                file_name = file_name if file_name else "N/A"
                enc_date = time.strftime("%Y-%m-%d", time.localtime(enc_time)) if enc_time else "N/A"
                if search_term in file_name.lower() or search_term in enc_date.lower():
                    self.key_table.insert("", "end", values=(key, file_name))
        else:
            self.key_table.configure(columns=self.columns)
            for col in self.columns:
                self.key_table.heading(col, text=col.replace("_", " ").title())
            self.key_table.column("key", width=200)
            self.key_table.column("file_name", width=150)
            self.key_table.column("status", width=100)
            self.key_table.column("generation_date", width=150)
            self.key_table.column("device_id", width=150)

            for key, file_name, status, enc_time, device_id in rows:
                enc_time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(enc_time)) if enc_time else "N/A"
                file_name = file_name if file_name else "N/A"
                status = status if status else "N/A"
                device_id = device_id if device_id else "N/A"
                self.key_table.insert("", "end", values=(key, file_name, status, enc_time_str, device_id))

    def clear_search(self):
        self.search_entry.delete(0, "end")
        self.filter_keys()

    def refresh_key_list(self):
        self.filter_keys()

    def copy_key(self, event):
        try:
            selected_item = self.key_table.selection()
            if not selected_item:
                CustomMessageBox(self.root, "Warning", "Please select a key to copy")
                return
            values = self.key_table.item(selected_item)["values"]
            key = values[0]
            pyperclip.copy(key)
            CustomMessageBox(self.root, "Success", "Key copied to clipboard")
        except Exception as e:
            logging.error(f"Copy key failed: {str(e)}")
            CustomMessageBox(self.root, "Error", f"Failed to copy key: {str(e)}", is_error=True)

    def copy_key_manual(self):
        try:
            selected_item = self.key_table.selection()
            if not selected_item:
                CustomMessageBox(self.root, "Warning", "Please select a key to copy")
                return
            values = self.key_table.item(selected_item)["values"]
            key = values[0]
            pyperclip.copy(key)
            CustomMessageBox(self.root, "Success", "Key copied to clipboard")
        except Exception as e:
            logging.error(f"Copy key failed: {str(e)}")
            CustomMessageBox(self.root, "Error", f"Failed to copy key: {str(e)}", is_error=True)

    def setup_user_info_gui(self):
        for widget in self.user_info_frame.winfo_children():
            widget.destroy()

        user_info_card = ctk.CTkFrame(self.user_info_frame, **CARD_STYLE)
        user_info_card.pack(fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(user_info_card, text="User Information", font=("Roboto", 20, "bold"), text_color="#6a6aff").pack(pady=10)

        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("SELECT full_name, device_id, device_name, unique_number, registration_date, last_login, name_changed FROM users WHERE username = ?", (self.current_user,))
            user_data = c.fetchone()

        full_name, device_id, device_name, unique_number, reg_date, last_login, name_changed = user_data

        info_frame = ctk.CTkFrame(user_info_card, fg_color="transparent")
        info_frame.pack(fill="x", padx=10)

        labels = ["Full Name", "Device ID", "Device Name", "Unique Number", "Registration Date", "Last Login"]
        values = [
            full_name,
            device_id,
            device_name,
            unique_number,
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(reg_date)) if reg_date else "N/A",
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_login)) if last_login else "N/A"
        ]

        for label, value in zip(labels, values):
            row_frame = ctk.CTkFrame(info_frame, fg_color="transparent")
            row_frame.pack(fill="x", pady=2)
            ctk.CTkLabel(row_frame, text=f"{label}:", width=150, font=("Roboto", 12), text_color="#ffffff", anchor="w").pack(side="left")
            ctk.CTkLabel(row_frame, text=value, font=("Roboto", 12), text_color="#cccccc", anchor="w").pack(side="left")

        edit_frame = ctk.CTkFrame(user_info_card, fg_color="transparent")
        edit_frame.pack(fill="x", padx=10, pady=10)

        ctk.CTkLabel(edit_frame, text="Update Full Name", font=("Roboto", 12), text_color="#ffffff").pack(anchor="w")
        self.new_full_name_entry = ctk.CTkEntry(edit_frame, width=300, placeholder_text="Enter new full name", font=("Roboto", 12), height=35, corner_radius=8)
        self.new_full_name_entry.pack(fill="x", pady=(3, 0))
        self.update_name_button = ctk.CTkButton(edit_frame, text="Update Name", command=self.update_full_name, **BUTTON_STYLE, state="disabled" if name_changed else "normal")
        self.update_name_button.pack(pady=5)

        ctk.CTkButton(user_info_card, text="Logout", command=self.logout, **BUTTON_STYLE).pack(pady=10)

    def update_full_name(self):
        new_full_name = self.new_full_name_entry.get().strip()
        if not new_full_name:
            CustomMessageBox(self.root, "Error", "Full name cannot be empty", is_error=True)
            return

        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("UPDATE users SET full_name = ?, name_changed = 1 WHERE username = ?", (new_full_name, self.current_user))
            conn.commit()

        self.update_name_button.configure(state="disabled")
        self.new_full_name_entry.delete(0, "end")
        CustomMessageBox(self.root, "Success", "Full name updated successfully")
        self.setup_user_info_gui()

    def setup_user_manager_gui(self):
        for widget in self.user_manager_frame.winfo_children():
            widget.destroy()

        if not self.is_admin:
            CustomMessageBox(self.root, "Access Denied", "Only admins can access this panel.", is_error=True)
            return

        user_manager_card = ctk.CTkFrame(self.user_manager_frame, **CARD_STYLE)
        user_manager_card.pack(fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(user_manager_card, text="User Manager", font=("Roboto", 20, "bold"), text_color="#6a6aff").pack(pady=10)

        search_frame = ctk.CTkFrame(user_manager_card, **CARD_STYLE)
        search_frame.pack(pady=5, padx=10, fill="x")
        self.user_search_entry = ctk.CTkEntry(search_frame, width=500, placeholder_text="Search by username or full name", font=("Roboto", 12), height=35, corner_radius=8)
        self.user_search_entry.pack(side="left", padx=(10, 5), pady=5, expand=True, fill="x")
        self.user_search_entry.bind("<KeyRelease>", self.filter_users)
        ctk.CTkButton(search_frame, text="❌", command=self.clear_user_search, width=100, **BUTTON_STYLE).pack(side="left", padx=(0, 10), pady=5)

        table_frame = ctk.CTkFrame(user_manager_card, fg_color="transparent")
        table_frame.pack(fill="both", expand=True, padx=10, pady=5)

        columns = ("username", "full_name", "role", "device_id", "device_name", "unique_number", "status", "collab_status")
        self.user_table = ttk.Treeview(table_frame, columns=columns, show="headings")
        self.user_table.heading("username", text="Username")
        self.user_table.heading("full_name", text="Full Name")
        self.user_table.heading("role", text="Role")
        self.user_table.heading("device_id", text="Device ID")
        self.user_table.heading("device_name", text="Device Name")
        self.user_table.heading("unique_number", text="Unique Number")
        self.user_table.heading("status", text="Status")
        self.user_table.heading("collab_status", text="Collab Status")
        self.user_table.column("username", width=100)
        self.user_table.column("full_name", width=100)
        self.user_table.column("role", width=100)
        self.user_table.column("device_id", width=100)
        self.user_table.column("device_name", width=100)
        self.user_table.column("unique_number", width=120)
        self.user_table.column("status", width=80)
        self.user_table.column("collab_status", width=100)
        self.user_table.pack(fill="both", expand=True)

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.user_table.yview)
        self.user_table.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

        button_frame = ctk.CTkFrame(user_manager_card, fg_color="transparent")
        button_frame.pack(pady=5)
        ctk.CTkButton(button_frame, text="Ban", command=self.ban_user, **BUTTON_STYLE).pack(side="left", padx=5)
        ctk.CTkButton(button_frame, text="Unban", command=self.unban_user, **BUTTON_STYLE).pack(side="left", padx=5)
        ctk.CTkButton(button_frame, text="Promote", command=self.promote_user, **BUTTON_STYLE).pack(side="left", padx=5)
        ctk.CTkButton(button_frame, text="Demote", command=self.demote_user, **BUTTON_STYLE).pack(side="left", padx=5)

        self.refresh_user_table()

    def filter_users(self, event=None):
        search_term = self.user_search_entry.get().strip().lower()
        self.user_table.delete(*self.user_table.get_children())

        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("SELECT username, full_name, is_admin, device_id, device_name, unique_number, banned FROM users")
            rows = c.fetchall()

        for username, full_name, is_admin, device_id, device_name, unique_number, banned in rows:
            role = "Admin" if is_admin else "User"
            if banned:
                role += " (Banned)"
            status = "online" if username in self.__class__.active_users else "offline"
            collab_status = "-"
            if username == DEFAULT_ADMIN["username"]:
                for session_key in self.__class__.collab_sessions:
                    server_id = session_key.split(":")[0]
                    collab_status = server_id
                    break
            else:
                for session_key, session in self.__class__.collab_sessions.items():
                    if username in session["users"] and session["users"][username] is not None:
                        server_id = session_key.split(":")[0]
                        collab_status = server_id
                        break

            if search_term in username.lower() or search_term in (full_name.lower() if full_name else ""):
                self.user_table.insert("", "end", values=(username, full_name, role, device_id, device_name, unique_number, status, collab_status))

        if not search_term:
            self.refresh_user_table()

    def clear_user_search(self):
        self.user_search_entry.delete(0, "end")
        self.refresh_user_table()

    def refresh_user_table(self):
        self.user_table.delete(*self.user_table.get_children())

        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("SELECT username, full_name, is_admin, device_id, device_name, unique_number, banned FROM users")
            rows = c.fetchall()

        for username, full_name, is_admin, device_id, device_name, unique_number, banned in rows:
            role = "Admin" if is_admin else "User"
            if banned:
                role += " (Banned)"
            status = "online" if username in self.__class__.active_users else "offline"
            collab_status = "-"
            if username == DEFAULT_ADMIN["username"]:
                for session_key in self.__class__.collab_sessions:
                    server_id = session_key.split(":")[0]
                    collab_status = server_id
                    break
            else:
                for session_key, session in self.__class__.collab_sessions.items():
                    if username in session["users"] and session["users"][username] is not None:
                        server_id = session_key.split(":")[0]
                        collab_status = server_id
                        break
            self.user_table.insert("", "end", values=(username, full_name, role, device_id, device_name, unique_number, status, collab_status))

    def ban_user(self):
        selected_item = self.user_table.selection()
        if not selected_item:
            CustomMessageBox(self.root, "Error", "Select a user", is_error=True)
            return
        username = self.user_table.item(selected_item)["values"][0]
        if username == self.current_user:
            CustomMessageBox(self.root, "Error", "Cannot ban yourself", is_error=True)
            return
        if username == DEFAULT_ADMIN["username"] and self.current_user != DEFAULT_ADMIN["username"]:
            CustomMessageBox(self.root, "Error", "Only the default admin can modify the default admin", is_error=True)
            return
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("UPDATE users SET banned = 1 WHERE username = ?", (username,))
            conn.commit()
        self.refresh_user_table()
        CustomMessageBox(self.root, "Success", f"User {username} banned")

    def unban_user(self):
        selected_item = self.user_table.selection()
        if not selected_item:
            CustomMessageBox(self.root, "Error", "Select a user", is_error=True)
            return
        username = self.user_table.item(selected_item)["values"][0]
        if username == DEFAULT_ADMIN["username"] and self.current_user != DEFAULT_ADMIN["username"]:
            CustomMessageBox(self.root, "Error", "Only the default admin can modify the default admin", is_error=True)
            return
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("UPDATE users SET banned = 0 WHERE username = ?", (username,))
            conn.commit()
        self.refresh_user_table()
        CustomMessageBox(self.root, "Success", f"User {username} unbanned")

    def promote_user(self):
        selected_item = self.user_table.selection()
        if not selected_item:
            CustomMessageBox(self.root, "Error", "Select a user", is_error=True)
            return
        username = self.user_table.item(selected_item)["values"][0]
        if username == self.current_user:
            CustomMessageBox(self.root, "Error", "Cannot promote yourself", is_error=True)
            return
        if username == DEFAULT_ADMIN["username"] and self.current_user != DEFAULT_ADMIN["username"]:
            CustomMessageBox(self.root, "Error", "Only the default admin can modify the default admin", is_error=True)
            return
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("SELECT is_admin FROM users WHERE username = ?", (username,))
            result = c.fetchone()
            if not result:
                CustomMessageBox(self.root, "Error", f"User {username} not found", is_error=True)
                return
            is_admin = result[0]
            if is_admin:
                CustomMessageBox(self.root, "Info", f"User {username} is already an admin")
                return
            c.execute("UPDATE users SET is_admin = 1 WHERE username = ?", (username,))
            conn.commit()
        self.refresh_user_table()
        CustomMessageBox(self.root, "Success", f"User {username} promoted to admin")

    def demote_user(self):
        selected_item = self.user_table.selection()
        if not selected_item:
            CustomMessageBox(self.root, "Error", "Select a user", is_error=True)
            return
        username = self.user_table.item(selected_item)["values"][0]
        if username == self.current_user:
            CustomMessageBox(self.root, "Error", "Cannot demote yourself", is_error=True)
            return
        if username == DEFAULT_ADMIN["username"]:
            CustomMessageBox(self.root, "Error", "Cannot demote the default admin", is_error=True)
            return
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("SELECT is_admin FROM users WHERE username = ?", (username,))
            result = c.fetchone()
            if not result:
                CustomMessageBox(self.root, "Error", f"User {username} not found", is_error=True)
                return
            is_admin = result[0]
            if not is_admin:
                CustomMessageBox(self.root, "Info", f"User {username} is not an admin")
                return
            c.execute("UPDATE users SET is_admin = 0 WHERE username = ?", (username,))
            conn.commit()
        self.refresh_user_table()
        CustomMessageBox(self.root, "Success", f"User {username} demoted to regular user")

    def setup_admin_panel_gui(self):
        if not self.is_admin:
            CustomMessageBox(self.root, "Access Denied", "Only admins can access this panel.", is_error=True)
            return

        for widget in self.admin_panel_frame.winfo_children():
            widget.destroy()

        admin_panel_card = ctk.CTkFrame(self.admin_panel_frame, **CARD_STYLE)
        admin_panel_card.pack(fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(admin_panel_card, text="Start Collaboration Server", text_color="#ffffff", font=("Roboto", 20, "bold")).pack(pady=10)
        ctk.CTkLabel(admin_panel_card, text="Server ID", text_color="#ffffff", font=("Roboto", 12)).pack(pady=3)
        self.server_id = ctk.CTkEntry(admin_panel_card, width=200, placeholder_text="Enter server ID", font=("Roboto", 12), height=35, corner_radius=8)
        self.server_id.pack(pady=3)
        ctk.CTkLabel(admin_panel_card, text="Port", text_color="#ffffff", font=("Roboto", 12)).pack(pady=3)
        self.server_port = ctk.CTkEntry(admin_panel_card, width=200, placeholder_text="Enter port", font=("Roboto", 12), height=35, corner_radius=8)
        self.server_port.pack(pady=3)
        ctk.CTkButton(admin_panel_card, text="Start Server", command=self.start_server, **BUTTON_STYLE).pack(pady=10)

        ctk.CTkLabel(admin_panel_card, text="Active Collaboration Sessions", text_color="#ffffff", font=("Roboto", 16, "bold")).pack(pady=10)
        table_frame = ctk.CTkFrame(admin_panel_card, fg_color="transparent")
        table_frame.pack(fill="both", expand=True, padx=10, pady=5)

        columns = ("server_id", "port", "users_joined", "status", "action", "terminate")
        self.session_table = ttk.Treeview(table_frame, columns=columns, show="headings")
        self.session_table.heading("server_id", text="Server ID")
        self.session_table.heading("port", text="Port")
        self.session_table.heading("users_joined", text="Users Joined")
        self.session_table.heading("status", text="Status")
        self.session_table.heading("action", text="Stop/Start")
        self.session_table.heading("terminate", text="Terminate")
        self.session_table.column("server_id", width=100)
        self.session_table.column("port", width=100)
        self.session_table.column("users_joined", width=100)
        self.session_table.column("status", width=100)
        self.session_table.column("action", width=100)
        self.session_table.column("terminate", width=100)
        self.session_table.pack(fill="both", expand=True)

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.session_table.yview)
        self.session_table.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

        ctk.CTkButton(admin_panel_card, text="Refresh", command=self.refresh_session_table, **BUTTON_STYLE).pack(pady=10)

        self.refresh_session_table()

    def start_server(self):
        server_id = self.server_id.get().strip()
        port = self.server_port.get().strip()
        if not server_id or not port:
            CustomMessageBox(self.root, "Error", "Server ID and port are required", is_error=True)
            return
        try:
            port = int(port)
            if port < 1024 or port > 65535:
                raise ValueError("Port must be between 1024 and 65535")
        except ValueError as e:
            CustomMessageBox(self.root, "Error", f"Invalid port: {str(e)}", is_error=True)
            return

        session_key = f"{server_id}:{port}"
        if session_key in self.__class__.collab_sessions:
            CustomMessageBox(self.root, "Error", "A server with this ID and port is already running", is_error=True)
            return

        self.__class__.collab_sessions[session_key] = {
            "server_id": server_id,
            "port": port,
            "users": {},
            "messages": [],
            "files": [],
            "status": "running",
            "start_time": time.time()
        }
        self.save_collab_sessions()
        self.refresh_session_table()
        CustomMessageBox(self.root, "Success", f"Collaboration server {server_id} started on port {port}")

    def stop_server(self, session_key):
        if session_key not in self.__class__.collab_sessions:
            CustomMessageBox(self.root, "Error", "Server not found", is_error=True)
            return
        current_status = self.__class__.collab_sessions[session_key]["status"]
        new_status = "stopped" if current_status == "running" else "running"
        self.__class__.collab_sessions[session_key]["status"] = new_status
        self.save_collab_sessions()
        self.refresh_session_table()
        action = "stopped" if new_status == "stopped" else "restarted"
        CustomMessageBox(self.root, "Success", f"Server {session_key} {action}")

    def terminate_server(self, session_key):
        if session_key not in self.__class__.collab_sessions:
            CustomMessageBox(self.root, "Error", "Server not found", is_error=True)
            return
        for username in list(self.__class__.collab_sessions[session_key]["users"].keys()):
            self.broadcast_to_session(f"🚨 Server {session_key} has been terminated by the admin", session_key)
            del self.__class__.collab_sessions[session_key]["users"][username]
        del self.__class__.collab_sessions[session_key]
        self.save_collab_sessions()
        self.refresh_session_table()
        CustomMessageBox(self.root, "Success", f"Server {session_key} terminated and deleted")

    def refresh_session_table(self):
        for item in self.session_table.get_children():
            self.session_table.delete(item)

        for session_key, session in self.__class__.collab_sessions.items():
            users_joined = len(session.get("users", {}))
            status = session.get("status", "stopped")
            server_id = session.get("server_id", "N/A")
            port = session.get("port", "N/A")
            action = "Stop" if status == "running" else "Start"
            terminate = "Terminate"
            self.session_table.insert("", "end", values=(server_id, port, users_joined, status, action, terminate))

        self.session_table.tag_configure("action", foreground="#6a6aff")
        self.session_table.tag_configure("terminate", foreground="#ff4d4d")
        self.session_table.bind("<ButtonRelease-1>", self.handle_session_table_click)

    def handle_session_table_click(self, event):
        item = self.session_table.identify("item", event.x, event.y)
        if not item:
            return
        column = self.session_table.identify_column(event.x)
        session_key = f"{self.session_table.item(item)['values'][0]}:{self.session_table.item(item)['values'][1]}"
        if column == "#5":
            self.stop_server(session_key)
        elif column == "#6":
            self.terminate_server(session_key)

    def setup_collab_gui(self):
        for widget in self.collab_frame.winfo_children():
            widget.destroy()

        self.collab_card = ctk.CTkFrame(self.collab_frame, **CARD_STYLE)
        self.collab_card.pack(fill="both", expand=True, padx=10, pady=10)

        self.collab_page_1 = ctk.CTkFrame(self.collab_card, fg_color="transparent")
        self.collab_page_2 = ctk.CTkFrame(self.collab_card, fg_color="transparent")

        self.setup_collab_page_1()
        self.collab_page_1.pack(fill="both", expand=True)

    def setup_collab_page_1(self):
        ctk.CTkLabel(self.collab_page_1, text="Join Collaboration Server", font=("Roboto", 20, "bold"), text_color="#6a6aff").pack(pady=10)

        ctk.CTkLabel(self.collab_page_1, text="Server ID", text_color="#ffffff", font=("Roboto", 12)).pack(pady=3)
        self.collab_server_id = ctk.CTkEntry(self.collab_page_1, width=200, placeholder_text="Enter server ID", font=("Roboto", 12), height=35, corner_radius=8)
        self.collab_server_id.pack(pady=3)

        ctk.CTkLabel(self.collab_page_1, text="Port", text_color="#ffffff", font=("Roboto", 12)).pack(pady=3)
        self.collab_port = ctk.CTkEntry(self.collab_page_1, width=200, placeholder_text="Enter port", font=("Roboto", 12), height=35, corner_radius=8)
        self.collab_port.pack(pady=3)

        ctk.CTkButton(self.collab_page_1, text="Join Server", command=self.join_server, **BUTTON_STYLE).pack(pady=15)

    def setup_collab_page_2(self):
        for widget in self.collab_page_2.winfo_children():
            widget.destroy()

        ctk.CTkLabel(self.collab_page_2, text="Collaboration Hub", font=("Roboto", 20, "bold"), text_color="#6a6aff").pack(pady=10)

        server_info_frame = ctk.CTkFrame(self.collab_page_2, **CARD_STYLE)
        server_info_frame.pack(fill="x", padx=10, pady=5)
        session = self.__class__.collab_sessions.get(self.session_key, {})
        server_id = session.get("server_id", "N/A")
        port = session.get("port", "N/A")
        ctk.CTkLabel(server_info_frame, text=f"Server: {server_id} | Port: {port}", font=("Roboto", 12), text_color="#ffffff").pack(anchor="w", padx=10, pady=5)

        users_frame = ctk.CTkFrame(self.collab_page_2, **CARD_STYLE)
        users_frame.pack(fill="x", padx=10, pady=5)
        users = list(self.__class__.collab_sessions[self.session_key]["users"].keys())
        users_text = ", ".join(users) if users else "No users"
        ctk.CTkLabel(users_frame, text=f"Connected Users: {users_text}", font=("Roboto", 12), text_color="#ffffff").pack(anchor="w", padx=10, pady=5)

        chat_frame = ctk.CTkFrame(self.collab_page_2, **CARD_STYLE)
        chat_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.chat_display = ctk.CTkTextbox(chat_frame, height=200, font=("Roboto", 12), wrap="word", state="disabled")
        self.chat_display.pack(fill="both", expand=True, padx=10, pady=(10, 5))

        chat_input_frame = ctk.CTkFrame(chat_frame, fg_color="transparent")
        chat_input_frame.pack(fill="x", padx=10, pady=5)
        self.chat_entry = ctk.CTkEntry(chat_input_frame, placeholder_text="Type your message...", font=("Roboto", 12), height=35, corner_radius=8)
        self.chat_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        self.chat_entry.bind("<Return>", self.send_message)
        ctk.CTkButton(chat_input_frame, text="Send", command=self.send_message, **BUTTON_STYLE, width=100).pack(side="left")

        files_frame = ctk.CTkFrame(self.collab_page_2, **CARD_STYLE)
        files_frame.pack(fill="x", padx=10, pady=5)

        ctk.CTkButton(files_frame, text="Share File", command=self.share_file, **BUTTON_STYLE).pack(side="left", padx=10, pady=5)
        ctk.CTkButton(files_frame, text="View Shared Files", command=self.view_shared_files, **BUTTON_STYLE).pack(side="left", padx=10, pady=5)
        ctk.CTkButton(files_frame, text="Leave Server", command=self.leave_server, **BUTTON_STYLE).pack(side="right", padx=10, pady=5)

        self.refresh_chat()

    def join_server(self):
        server_id = self.collab_server_id.get().strip()
        port = self.collab_port.get().strip()
        if not server_id or not port:
            CustomMessageBox(self.root, "Error", "Server ID and port are required", is_error=True)
            return
        try:
            port = int(port)
        except ValueError:
            CustomMessageBox(self.root, "Error", "Invalid port number", is_error=True)
            return

        session_key = f"{server_id}:{port}"
        if session_key not in self.__class__.collab_sessions:
            CustomMessageBox(self.root, "Error", "Server not found", is_error=True)
            return

        session = self.__class__.collab_sessions[session_key]
        if session["status"] != "running":
            CustomMessageBox(self.root, "Error", "Server is not running", is_error=True)
            return

        if self.current_user in session["users"]:
            CustomMessageBox(self.root, "Info", "You are already connected to this server")
            return

        session["users"][self.current_user] = None
        self.session_key = session_key
        self.broadcast_to_session(f"🎉 {self.current_user} joined")
        self.save_collab_sessions()
        self.refresh_session_table()

        self.collab_page_1.pack_forget()
        self.setup_collab_page_2()
        self.collab_page_2.pack(fill="both", expand=True)

    def leave_server(self):
        if self.session_key and self.session_key in self.__class__.collab_sessions:
            if self.current_user in self.__class__.collab_sessions[self.session_key]["users"]:
                del self.__class__.collab_sessions[self.session_key]["users"][self.current_user]
                self.broadcast_to_session(f"🚪 {self.current_user} left")
                self.session_key = None
                self.shared_files = []
                self.chat_messages = []
                self.chat_days = set()
                self.save_collab_sessions()
                self.refresh_session_table()
                try:
                    self.notebook.forget(self.shared_files_frame)
                except:
                    pass

        self.collab_page_2.pack_forget()
        self.setup_collab_page_1()
        self.collab_page_1.pack(fill="both", expand=True)
        CustomMessageBox(self.root, "Success", "You have left the server")

    def send_message(self, event=None):
        message = self.chat_entry.get().strip()
        if not message:
            return
        if not self.session_key:
            CustomMessageBox(self.root, "Error", "Not connected to a server", is_error=True)
            return
        formatted_message = f"💬 {self.current_user}: {message}"
        self.broadcast_to_session(formatted_message)
        self.chat_entry.delete(0, "end")
        self.refresh_chat()

    def broadcast_to_session(self, message, session_key=None):
        if not session_key:
            session_key = self.session_key
        if not session_key or session_key not in self.__class__.collab_sessions:
            return
        timestamp = time.time()
        self.__class__.collab_sessions[session_key]["messages"].append((message, timestamp))
        self.save_collab_sessions()
        if session_key == self.session_key:
            self.refresh_chat()

    def refresh_chat(self):
        if not hasattr(self, 'chat_display') or not self.session_key or self.session_key not in self.__class__.collab_sessions:
            return
        self.chat_display.configure(state="normal")
        self.chat_display.delete("1.0", "end")
        messages = self.__class__.collab_sessions[self.session_key]["messages"]
        self.chat_days = set()
        for message, timestamp in messages:
            date = time.strftime("%Y-%m-%d", time.localtime(timestamp))
            if date not in self.chat_days:
                self.chat_days.add(date)
                self.chat_display.insert("end", f"\n--- {date} ---\n", "date")
            time_str = time.strftime("%H:%M:%S", time.localtime(timestamp))
            self.chat_display.insert("end", f"[{time_str}] {message}\n")
        self.chat_display.configure(state="disabled")
        self.chat_display.see("end")

    def share_file(self):
        if not self.session_key:
            CustomMessageBox(self.root, "Error", "Not connected to a server", is_error=True)
            return
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        file_name = os.path.basename(file_path)
        file_id = str(uuid.uuid4())
        self.__class__.collab_sessions[self.session_key]["files"].append((file_id, file_name, file_path, self.current_user, time.time()))
        self.broadcast_to_session(f"📁 {self.current_user} shared a file: {file_name}")
        self.save_collab_sessions()

    def view_shared_files(self):
        if not self.session_key:
            CustomMessageBox(self.root, "Error", "Not connected to a server", is_error=True)
            return
        self.setup_shared_files_gui()
        self.notebook.add(self.shared_files_frame, text="Shared Files")
        self.notebook.select(self.shared_files_frame)

    def setup_shared_files_gui(self):
        for widget in self.shared_files_frame.winfo_children():
            widget.destroy()

        shared_files_card = ctk.CTkFrame(self.shared_files_frame, **CARD_STYLE)
        shared_files_card.pack(fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(shared_files_card, text="Shared Files", font=("Roboto", 20, "bold"), text_color="#6a6aff").pack(pady=10)

        table_frame = ctk.CTkFrame(shared_files_card, fg_color="transparent")
        table_frame.pack(fill="both", expand=True, padx=10, pady=5)

        columns = ("file_name", "shared_by", "shared_at", "action")
        self.files_table = ttk.Treeview(table_frame, columns=columns, show="headings")
        self.files_table.heading("file_name", text="File Name")
        self.files_table.heading("shared_by", text="Shared By")
        self.files_table.heading("shared_at", text="Shared At")
        self.files_table.heading("action", text="Download")
        self.files_table.column("file_name", width=200)
        self.files_table.column("shared_by", width=100)
        self.files_table.column("shared_at", width=150)
        self.files_table.column("action", width=100)
        self.files_table.pack(fill="both", expand=True)

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.files_table.yview)
        self.files_table.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

        self.files_table.tag_configure("action", foreground="#6a6aff")
        self.files_table.bind("<ButtonRelease-1>", self.handle_files_table_click)

        ctk.CTkButton(shared_files_card, text="Back to Collaboration", command=self.return_to_collab, **BUTTON_STYLE).pack(pady=10)

        self.refresh_files_table()

    def handle_files_table_click(self, event):
        item = self.files_table.identify("item", event.x, event.y)
        if not item:
            return
        column = self.files_table.identify_column(event.x)
        if column == "#4":
            file_id = None
            file_name = self.files_table.item(item)["values"][0]
            for f_id, f_name, f_path, shared_by, shared_at in self.__class__.collab_sessions[self.session_key]["files"]:
                if f_name == file_name:
                    file_id = f_id
                    file_path = f_path
                    break
            if file_id:
                self.download_file(file_id, file_path)

    def download_file(self, file_id, file_path):
        save_path = filedialog.asksaveasfilename(initialfile=os.path.basename(file_path))
        if not save_path:
            return
        try:
            with open(file_path, "rb") as f_in, open(save_path, "wb") as f_out:
                f_out.write(f_in.read())
            CustomMessageBox(self.root, "Success", f"File downloaded to {save_path}")
        except Exception as e:
            CustomMessageBox(self.root, "Error", f"Failed to download file: {str(e)}", is_error=True)

    def refresh_files_table(self):
        for item in self.files_table.get_children():
            self.files_table.delete(item)
        if not self.session_key or self.session_key not in self.__class__.collab_sessions:
            return
        for file_id, file_name, file_path, shared_by, shared_at in self.__class__.collab_sessions[self.session_key]["files"]:
            shared_at_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(shared_at))
            self.files_table.insert("", "end", values=(file_name, shared_by, shared_at_str, "Download"))

    def return_to_collab(self):
        self.notebook.forget(self.shared_files_frame)
        self.notebook.select(self.collab_frame)

    def setup_server_info_gui(self):
        for widget in self.server_info_frame.winfo_children():
            widget.destroy()

        server_info_card = ctk.CTkFrame(self.server_info_frame, **CARD_STYLE)
        server_info_card.pack(fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(server_info_card, text="Server Information", font=("Roboto", 20, "bold"), text_color="#6a6aff").pack(pady=10)

        ctk.CTkLabel(server_info_card, text="Server ID", text_color="#ffffff", font=("Roboto", 12)).pack(pady=3)
        self.server_info_id = ctk.CTkEntry(server_info_card, width=200, placeholder_text="Enter server ID", font=("Roboto", 12), height=35, corner_radius=8)
        self.server_info_id.pack(pady=3)

        ctk.CTkLabel(server_info_card, text="Port", text_color="#ffffff", font=("Roboto", 12)).pack(pady=3)
        self.server_info_port = ctk.CTkEntry(server_info_card, width=200, placeholder_text="Enter port", font=("Roboto", 12), height=35, corner_radius=8)
        self.server_info_port.pack(pady=3)

        ctk.CTkButton(server_info_card, text="Show Details", command=self.show_server_details, **BUTTON_STYLE).pack(pady=10)

        self.server_details_frame = ctk.CTkFrame(server_info_card, fg_color="transparent")
        self.server_details_frame.pack(fill="x", padx=10)

    def show_server_details(self):
        for widget in self.server_details_frame.winfo_children():
            widget.destroy()

        server_id = self.server_info_id.get().strip()
        port = self.server_info_port.get().strip()
        session_key = f"{server_id}:{port}"

        if session_key not in self.__class__.collab_sessions:
            CustomMessageBox(self.root, "Error", "Server not found", is_error=True)
            return

        session = self.__class__.collab_sessions[session_key]
        start_time = session.get("start_time", time.time())
        uptime = time.time() - start_time

        labels = ["Server Uptime", "Status", "Users Connected"]
        values = [
            f"{int(uptime // 3600)}h {int((uptime % 3600) // 60)}m {int(uptime % 60)}s",
            session.get("status", "stopped"),
            len(session.get("users", {}))
        ]

        for label, value in zip(labels, values):
            row_frame = ctk.CTkFrame(self.server_details_frame, fg_color="transparent")
            row_frame.pack(fill="x", pady=2)
            ctk.CTkLabel(row_frame, text=f"{label}:", width=150, font=("Roboto", 12), text_color="#ffffff", anchor="w").pack(side="left")
            ctk.CTkLabel(row_frame, text=value, font=("Roboto", 12), text_color="#cccccc", anchor="w").pack(side="left")

    def setup_trinity_gui(self):
        for widget in self.trinity_frame.winfo_children():
            widget.destroy()

        trinity_card = ctk.CTkFrame(self.trinity_frame, **CARD_STYLE)
        trinity_card.pack(fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(trinity_card, text="Trinity Engine", font=("Roboto", 20, "bold"), text_color="#6a6aff").pack(pady=10)

        self.trinity_monitoring = False
        self.trinity_toggle = CustomToggleButton(trinity_card, "Monitor Off", "Monitor On", self.toggle_trinity_monitoring)
        self.trinity_toggle.pack(pady=10)

        self.metrics_frame = ctk.CTkFrame(trinity_card, fg_color="transparent")
        self.metrics_frame.pack(fill="both", expand=True, padx=10)

        # Initialize the figure and canvas once
        self.fig, (self.ax1, self.ax2) = plt.subplots(1, 2, figsize=(8, 3))
        self.fig.patch.set_facecolor("#2a2a3d")
        self.ax1.set_facecolor("#2a2a3d")
        self.ax2.set_facecolor("#2a2a3d")

        # Initial empty pie charts
        self.cpu_pie = self.ax1.pie([50, 50], labels=["Used", "Free"], colors=["#6a6aff", "#3a3a4d"], autopct="%1.1f%%")
        self.ax1.set_title("CPU Usage", color="#ffffff")

        self.vram_pie = self.ax2.pie([50, 50], labels=["Used", "Free"], colors=["#6a6aff", "#3a3a4d"], autopct="%1.1f%%")
        self.ax2.set_title("VRAM Usage", color="#ffffff")

        self.canvas = FigureCanvasTkAgg(self.fig, master=self.metrics_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)
        self.canvas.draw()

        self.update_trinity_metrics()

    def toggle_trinity_monitoring(self):
        self.trinity_monitoring = not self.trinity_monitoring
        if self.trinity_monitoring:
            self.update_trinity_metrics()

    def update_trinity_metrics(self):
        # Stop if the application is closing or window doesn't exist
        if not hasattr(self, 'root') or not self.root.winfo_exists() or not self.trinity_monitoring:
            return

        # Get CPU and VRAM usage
        cpu_usage = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        vram_usage = memory.percent

        # Update CPU pie chart
        cpu_data = [cpu_usage, 100 - cpu_usage]
        self.ax1.clear()
        self.ax1.set_facecolor("#2a2a3d")
        self.cpu_pie = self.ax1.pie(cpu_data, labels=["Used", "Free"], colors=["#6a6aff", "#3a3a4d"], autopct="%1.1f%%")
        self.ax1.set_title("CPU Usage", color="#ffffff")

        # Update VRAM pie chart
        vram_data = [vram_usage, 100 - vram_usage]
        self.ax2.clear()
        self.ax2.set_facecolor("#2a2a3d")
        self.vram_pie = self.ax2.pie(vram_data, labels=["Used", "Free"], colors=["#6a6aff", "#3a3a4d"], autopct="%1.1f%%")
        self.ax2.set_title("VRAM Usage", color="#ffffff")

        # Redraw the canvas without recreating it
        self.canvas.draw()

        # Schedule the next update only if monitoring is active
        if self.trinity_monitoring and self.root.winfo_exists():
            self.trinity_after_id = self.root.after(1000, self.update_trinity_metrics)

    def on_closing(self):
        self.trinity_monitoring = False
        if hasattr(self, 'trinity_after_id'):
            self.root.after_cancel(self.trinity_after_id)

        self.monitoring = False
        if self.current_user in self.__class__.active_users:
            del self.__class__.active_users[self.current_user]
        self.save_collab_sessions()
        self.executor.shutdown(wait=True)
        
        for widget in self.root.winfo_children():
            widget.destroy()

        self.root.destroy()

    def setup_software_info_gui(self):
        for widget in self.software_info_frame.winfo_children():
            widget.destroy()

        software_info_card = ctk.CTkFrame(self.software_info_frame, **CARD_STYLE)
        software_info_card.pack(fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(software_info_card, text="Software Information", font=("Roboto", 20, "bold"), text_color="#6a6aff").pack(pady=10)

        info_frame = ctk.CTkFrame(software_info_card, fg_color="transparent")
        info_frame.pack(fill="x", padx=10)

        labels = ["Software Name", "Version", "Build Date", "Developer", "License"]
        values = ["Titan Encryption Tool", "1.0.0", "May 07, 2025", "Titan Team", "Proprietary"]

        for label, value in zip(labels, values):
            row_frame = ctk.CTkFrame(info_frame, fg_color="transparent")
            row_frame.pack(fill="x", pady=2)
            ctk.CTkLabel(row_frame, text=f"{label}:", width=150, font=("Roboto", 12), text_color="#ffffff", anchor="w").pack(side="left")
            ctk.CTkLabel(row_frame, text=value, font=("Roboto", 12), text_color="#cccccc", anchor="w").pack(side="left")

    def setup_legal_gui(self):
        for widget in self.legal_frame.winfo_children():
            widget.destroy()

        legal_card = ctk.CTkFrame(self.legal_frame, **CARD_STYLE)
        legal_card.pack(fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(legal_card, text="Legal Information", font=("Roboto", 20, "bold"), text_color="#6a6aff").pack(pady=10)

        button_frame = ctk.CTkFrame(legal_card, fg_color="transparent")
        button_frame.pack(pady=10)

        ctk.CTkButton(button_frame, text="User Agreement", command=self.show_user_agreement, **BUTTON_STYLE).pack(side="left", padx=5)
        ctk.CTkButton(button_frame, text="Privacy Policy", command=self.show_privacy_policy, **BUTTON_STYLE).pack(side="left", padx=5)
        ctk.CTkButton(button_frame, text="License", command=self.show_license, **BUTTON_STYLE).pack(side="left", padx=5)
        ctk.CTkButton(button_frame, text="Documentation", command=self.show_documentation, **BUTTON_STYLE).pack(side="left", padx=5)

        self.legal_content_frame = ctk.CTkFrame(legal_card, fg_color="transparent")
        self.legal_content_frame.pack(fill="both", expand=True, padx=10)

    def show_user_agreement(self):
        content = """User Agreement for Titan Encryption Tool


1. Acceptance of Terms
By using the Titan Encryption Tool ("Service"), you agree to be bound by the following terms and conditions ("Terms"). If you do not agree to these Terms, please do not use the Service.

2. Eligibility
You must be at least 13 years of age to use the Service. By using the Service, you represent and warrant that you meet this age requirement.

3. Account Registration
To access certain features of the Service, you must register for an account. You agree to provide accurate and complete information during registration and to keep your account information updated.

4. User Responsibilities
- You are responsible for maintaining the confidentiality of your account credentials.
- You agree not to use the Service for any illegal or unauthorized purpose.
- You are solely responsible for any data you encrypt or decrypt using the Service.

5. Data Security
The Service provides encryption and decryption tools. While we strive to ensure the security of your data, you acknowledge that no system is completely secure, and you use the Service at your own risk.

6. Termination
We reserve the right to suspend or terminate your account at our discretion if you violate these Terms.

7. Limitation of Liability
To the fullest extent permitted by law, Titan Encryption Tool shall not be liable for any indirect, incidental, special, consequential, or punitive damages arising out of or related to your use of the Service.

8. Changes to Terms
We may update these Terms from time to time. We will notify you of changes by posting the updated Terms on this page. Your continued use of the Service after such changes constitutes your acceptance of the new Terms.

9. Contact Us
If you have any questions about these Terms, please contact us at support@titanencryption.com.
"""
        self.show_legal_content("User Agreement", content)

    def show_privacy_policy(self):
        content = """Privacy Policy for Titan Encryption Tool


1. Introduction
Titan Encryption Tool ("we", "us", "our") is committed to protecting your privacy. This Privacy Policy explains how we collect, use, and safeguard your information when you use our Service.

2. Information We Collect
- Account Information: When you register, we collect your username, full name, and device information.
- Usage Data: We may collect information about how you use the Service, such as encryption and decryption activities.
- Keys: Encryption keys are stored in our database but are not linked to your personal identity beyond your username.

3. How We Use Your Information
- To provide and maintain the Service.
- To improve the Service and develop new features.
- To monitor for security threats and prevent abuse.

4. Data Security
We implement reasonable measures to protect your data, including encryption of stored keys. However, no method of transmission or storage is completely secure, and we cannot guarantee absolute security.

5. Sharing Your Information
We do not share your personal information with third parties except as required by law or to protect our rights.

6. Your Choices
You may update your account information at any time. You can also delete your account, which will remove your personal information from our systems, subject to any legal obligations.

7. Children's Privacy
The Service is not intended for users under 13 years of age. We do not knowingly collect information from children under 13.

8. Changes to This Privacy Policy
We may update this Privacy Policy from time to time. We will notify you of changes by posting the updated policy on this page.

9. Contact Us
If you have any questions about this Privacy Policy, please contact us at privacy@titanencryption.com.
"""
        self.show_legal_content("Privacy Policy", content)

    def show_license(self):
        content = """Titan Encryption Tool License Agreement


1. License Grant
Titan Encryption Tool ("Software") is licensed to you by Titan Technologies Inc. ("Licensor") under the terms of this License Agreement ("Agreement"). This Agreement grants you a non-exclusive, non-transferable, limited license to use the Software solely for personal or internal business purposes.

2. Restrictions
You may not:
- Modify, reverse engineer, decompile, or disassemble the Software.
- Distribute, sublicense, lease, or sell the Software to any third party.
- Use the Software to develop a competing product or service.

3. Ownership
The Software and all intellectual property rights therein are and shall remain the exclusive property of Titan Technologies Inc. This Agreement does not grant you any ownership rights in the Software.

4. Warranty Disclaimer
The Software is provided "as is" without warranty of any kind, express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, or non-infringement.

5. Limitation of Liability
To the fullest extent permitted by law, Titan Technologies Inc. shall not be liable for any indirect, incidental, special, consequential, or punitive damages arising out of or related to your use of the Software.

6. Termination
This license is effective until terminated. Licensor may terminate this license at any time if you breach any terms of this Agreement. Upon termination, you must cease all use of the Software and destroy all copies.

7. Governing Law
This Agreement shall be governed by the laws of the State of California, USA, without regard to its conflict of law principles.

8. Contact Us
For questions regarding this Agreement, please contact us at legal@titanencryption.com.
"""
        self.show_legal_content("License Agreement", content)

    def show_documentation(self):
        content = """Titan Encryption Tool Documentation


1. Overview
Titan Encryption Tool is a secure application designed to encrypt and decrypt files using advanced cryptographic techniques. It supports collaboration features for secure file sharing among users.

2. Installation
- Download the installer from the official website: www.titanencryption.com.
- Run the installer and follow the on-screen instructions.
- Ensure Python 3.10 or higher is installed on your system.

3. System Requirements
- Operating System: Windows 10/11, macOS 11 or later, Linux (Ubuntu 20.04 or later)
- RAM: Minimum 4 GB (8 GB recommended)
- Disk Space: 500 MB free space

4. Getting Started
- Launch the application and register a new account or log in with existing credentials.
- Use the "Tools" tab to encrypt or decrypt files.
- Join or start a collaboration server to share files securely with other users.

5. Features
- File Encryption: Encrypt files using NaCl's SecretBox for secure storage.
- Key Management: Store and manage encryption keys securely.
- Collaboration: Share files and communicate with other users in real-time.
- Admin Panel: Manage users and collaboration servers (admin-only).
- Trinity Engine: Monitor CPU and VRAM usage in real-time.

6. Security
- Encryption: Files are encrypted using NaCl's SecretBox with a 256-bit key.
- Key Storage: Keys are stored in an SQLite database with user-specific access.
- Authentication: Passwords are hashed using Argon2id for secure storage.

7. Troubleshooting
- Issue: Application fails to start.
  Solution: Ensure all dependencies (customtkinter, nacl, psutil, matplotlib) are installed via pip.
- Issue: Cannot join collaboration server.
  Solution: Verify the server ID and port, and ensure the server is running.

8. Support
For additional help, contact our support team at support@titanencryption.com or visit our website for more resources.
"""
        self.show_legal_content("Documentation", content)

    def show_legal_content(self, title, content, back_command=None):
        for widget in self.legal_content_frame.winfo_children():
            widget.destroy()

        ctk.CTkLabel(self.legal_content_frame, text=title, font=("Roboto", 16, "bold"), text_color="#ffffff").pack(anchor="w", pady=5)

        text_frame = ctk.CTkFrame(self.legal_content_frame, fg_color="transparent")
        text_frame.pack(fill="both", expand=True)

        text_box = ctk.CTkTextbox(text_frame, height=400, font=("Roboto", 12), wrap="word")
        text_box.pack(fill="both", expand=True, padx=5, pady=5)
        text_box.insert("1.0", content)
        text_box.configure(state="disabled")

        scrollbar = ttk.Scrollbar(text_frame, orient="vertical", command=text_box.yview)
        text_box.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

        if back_command:
            ctk.CTkButton(self.legal_content_frame, text="Back", command=back_command, **BUTTON_STYLE).pack(pady=10)

if __name__ == "__main__":
    root = ctk.CTk()
    app = TitanApp(root)
    root.mainloop()
