import customtkinter as ctk
import os, time, threading, re
from tkinter import messagebox as mb

from crypto_utils import encrypt_password, decrypt_password, generate_password, password_strength, md5_name, derive_key
from database import init_db, get_user, create_user, set_vault_hash, save_password, get_passwords, update_password, delete_password
from security import hash_password, verify_password
from config import APP_WIDTH, APP_HEIGHT, BACKUP_DIR, AUTO_LOCK_SECONDS, CLIPBOARD_CLEAR_SECONDS

os.makedirs(BACKUP_DIR, exist_ok=True)

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")
EMAIL_REGEX = r"^[\w\.-]+@[\w\.-]+\.\w+$"

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.geometry(f"{APP_WIDTH}x{APP_HEIGHT}")
        self.title("Secure Password Manager")
        init_db()

        self.email = None
        self.vault_key = None
        self.last_activity = time.time()
        self.theme_mode = "dark"
        self.edit_entry_id = None

        self.container = ctk.CTkFrame(self)
        self.container.pack(expand=True, fill="both")

        threading.Thread(target=self.auto_lock_check, daemon=True).start()
        self.show_login()

    # ----------------- UTILS -----------------
    def reset_timer(self, *_):
        self.last_activity = time.time()

    def auto_lock_check(self):
        while True:
            if self.vault_key and time.time() - self.last_activity > AUTO_LOCK_SECONDS:
                self.vault_key = None
                self.email = None
                self.show_login()
            time.sleep(1)

    def clear(self):
        for w in self.container.winfo_children():
            w.destroy()

    def animate(self, frame):
        frame.place(x=APP_WIDTH, y=0, relwidth=1, relheight=1)
        for x in range(APP_WIDTH, 0, -30):
            frame.place(x=x, y=0)
            frame.update()
        frame.place(x=0, y=0, relwidth=1, relheight=1)

    def valid_email(self, email):
        return re.match(EMAIL_REGEX, email)

    # ----------------- LOGIN -----------------
    def show_login(self):
        self.clear()
        f = ctk.CTkFrame(self.container)
        self.animate(f)

        ctk.CTkLabel(f, text="LOGIN", font=("Arial", 32)).pack(pady=40)
        email = ctk.CTkEntry(f, placeholder_text="Email", width=360)
        pwd = ctk.CTkEntry(f, placeholder_text="Password", show="*", width=360)
        msg = ctk.CTkLabel(f, text="", text_color="red")
        email.pack(pady=12); pwd.pack(pady=12); msg.pack()

        def login():
            if not email.get() or not pwd.get():
                msg.configure(text="Email and password required")
                return
            if not self.valid_email(email.get()):
                msg.configure(text="Invalid email format")
                return
            user = get_user(email.get())
            if not user or not verify_password(pwd.get(), user[2]):
                msg.configure(text="Invalid email or password")
                return
            self.email = email.get()
            self.show_unlock()

        ctk.CTkButton(f, text="Login", command=login, width=220).pack(pady=15)
        ctk.CTkButton(f, text="Signup", command=self.show_signup, width=220).pack()

    # ----------------- SIGNUP -----------------
    def show_signup(self):
        self.clear()
        f = ctk.CTkFrame(self.container)
        self.animate(f)
        ctk.CTkLabel(f, text="CREATE ACCOUNT", font=("Arial", 32)).pack(pady=40)
        email = ctk.CTkEntry(f, placeholder_text="Email", width=360)
        pwd = ctk.CTkEntry(f, placeholder_text="Password", show="*", width=360)
        msg = ctk.CTkLabel(f, text="", text_color="red")
        email.pack(pady=12); pwd.pack(pady=12); msg.pack()

        def signup():
            if not email.get() or not pwd.get():
                msg.configure(text="All fields required")
                return
            if not self.valid_email(email.get()):
                msg.configure(text="Invalid email format")
                return
            if get_user(email.get()):
                msg.configure(text="Email already used")
                return
            salt = os.urandom(16)
            create_user(email.get(), hash_password(pwd.get()), salt)
            msg.configure(text="Account created ✔", text_color="green")
            self.after(1200, self.show_login)

        ctk.CTkButton(f, text="Create Account", command=signup, width=220).pack(pady=15)
        ctk.CTkButton(f, text="Back", command=self.show_login, width=220).pack()

    # ----------------- VAULT UNLOCK -----------------
    def show_unlock(self):
        self.clear()
        f = ctk.CTkFrame(self.container)
        self.animate(f)
        ctk.CTkLabel(f, text="UNLOCK VAULT", font=("Arial", 32)).pack(pady=40)
        pwd = ctk.CTkEntry(f, placeholder_text="Vault Password", show="*", width=360)
        msg = ctk.CTkLabel(f, text="", text_color="red"); pwd.pack(pady=12); msg.pack()
        user = get_user(self.email)

        def unlock():
            if not pwd.get():
                msg.configure(text="Vault password required")
                return
            if not user[3]:  # first-time vault setup
                derived = derive_key(pwd.get(), user[4])
                set_vault_hash(self.email, hash_password(pwd.get()))
                self.vault_key = derived
                self.show_dashboard()
            else:
                if verify_password(pwd.get(), user[3]):
                    derived = derive_key(pwd.get(), user[4])
                    self.vault_key = derived
                    self.show_dashboard()
                else:
                    msg.configure(text="Wrong vault password")

        ctk.CTkButton(f, text="Unlock", command=unlock, width=220).pack(pady=15)

    # ----------------- DASHBOARD -----------------
    def show_dashboard(self):
        from functools import partial
        self.clear()
        f = ctk.CTkFrame(self.container)
        self.animate(f)
        ctk.CTkLabel(f, text="DASHBOARD", font=("Arial", 36)).pack(pady=40)
        btn_frame = ctk.CTkFrame(f); btn_frame.pack(pady=30)

        ctk.CTkButton(btn_frame, text="➕ ADD PASSWORD", width=280,
                      command=self.show_add_password).grid(row=0, column=0, padx=15, pady=15)
        ctk.CTkButton(btn_frame, text="📂 VIEW / SEARCH PASSWORDS", width=280,
                      command=self.show_view_passwords).grid(row=0, column=1, padx=15, pady=15)
        ctk.CTkButton(btn_frame, text="🔐 GENERATE PASSWORD", width=280,
                      command=self.show_generator).grid(row=1, column=0, padx=15, pady=15)
        ctk.CTkButton(btn_frame, text="⚙ SETTINGS", width=280,
                      command=self.show_settings).grid(row=1, column=1, padx=15, pady=15)
        ctk.CTkButton(f, text="🔒 LOGOUT", width=220, fg_color="red",
                      command=self.logout).pack(pady=40)

    def logout(self):
        self.vault_key = None
        self.email = None
        self.show_login()

    # ----------------- ADD / EDIT PASSWORD -----------------
    def show_add_password(self, prefill=None):
        self.clear()
        f = ctk.CTkFrame(self.container)
        self.animate(f)
        ctk.CTkLabel(f, text="ADD / EDIT PASSWORD", font=("Arial", 28)).pack(pady=25)

        # Website/App
        ctk.CTkLabel(f, text="Website / App").pack(anchor="w", padx=80)
        site = ctk.CTkEntry(f, placeholder_text="e.g. google.com", width=500); site.pack(pady=5)

        # Username
        ctk.CTkLabel(f, text="Username / Email").pack(anchor="w", padx=80)
        username = ctk.CTkEntry(f, placeholder_text="e.g. user@gmail.com", width=500); username.pack(pady=5)

        # Password
        ctk.CTkLabel(f, text="Password").pack(anchor="w", padx=80)
        pwd = ctk.CTkEntry(f, placeholder_text="Enter or generate password", width=500); pwd.pack(pady=5)
        strength_label = ctk.CTkLabel(f, text=""); strength_label.pack()

        # Notes
        ctk.CTkLabel(f, text="Notes").pack(anchor="w", padx=80)
        note = ctk.CTkTextbox(f, width=500, height=100); note.pack(pady=5)

        # Prefill for edit
        if prefill:
            self.edit_entry_id = prefill[0]
            site.insert(0, prefill[3])
            username.insert(0, prefill[4])
            pwd.insert(0, decrypt_password(self.vault_key, prefill[5], prefill[6]))
            note.insert("1.0", prefill[7])

        def update_strength(e=None):
            strength_label.configure(text=password_strength(pwd.get()))
        pwd.bind("<KeyRelease>", update_strength)

        def generate_pw():
            p = generate_password(16, True, True, True, True)
            pwd.delete(0,"end"); pwd.insert(0,p); update_strength()

        ctk.CTkButton(f, text="Generate Password", width=220, command=generate_pw).pack(pady=8)

        def save():
            if not site.get() or not username.get() or not pwd.get():
                strength_label.configure(text="All fields required", text_color="red")
                return
            iv, ct = encrypt_password(self.vault_key, pwd.get())
            if self.edit_entry_id:
                update_password(self.edit_entry_id, site.get(), username.get(), iv, ct, note.get("1.0","end"))
                self.edit_entry_id = None
            else:
                save_password(self.email, site.get(), username.get(), iv, ct, note.get("1.0","end"))
            # Backup
            fname = os.path.join(BACKUP_DIR, md5_name(site.get()+"_"+username.get())+".txt")
            with open(fname, "wb") as ftxt:
                ftxt.write(iv + b"||" + ct)
            self.show_dashboard()

        ctk.CTkButton(f, text="Save Password", width=220, command=save).pack(pady=15)
        ctk.CTkButton(f, text="Back to Dashboard", width=220, command=self.show_dashboard).pack(pady=10)

    # ----------------- VIEW / SEARCH PASSWORDS -----------------
    def show_view_passwords(self):
        self.clear()
        f = ctk.CTkFrame(self.container)
        self.animate(f)
        ctk.CTkLabel(f, text="SAVED PASSWORDS", font=("Arial", 28)).pack(pady=25)
        search = ctk.CTkEntry(f, placeholder_text="Search by website/username", width=500); search.pack(pady=10)
        scroll = ctk.CTkScrollableFrame(f, width=950, height=350); scroll.pack(pady=15)

        def update_list(*_):
            for w in scroll.winfo_children(): w.destroy()
            for row in get_passwords(self.email):
                wid, uname = row[3], row[4]
                if search.get().lower() in wid.lower() or search.get().lower() in uname.lower():
                    try: decrypted = decrypt_password(self.vault_key, row[5], row[6])
                    except: decrypted = "DECRYPT ERROR"
                    frame = ctk.CTkFrame(scroll); frame.pack(fill="x", pady=5, padx=5)
                    ctk.CTkLabel(frame, text=f"Website: {wid} | User: {uname} | Note: {row[7][:30]}...").pack(side="left", padx=5)
                    btn_frame = ctk.CTkFrame(frame); btn_frame.pack(side="right")

                    def view_pw(r=row): mb.showinfo("Password", decrypt_password(self.vault_key, r[5], r[6]))
                    def copy_pw(r=row):
                        self.clipboard_clear(); self.clipboard_append(decrypt_password(self.vault_key, r[5], r[6]))
                        self.after(CLIPBOARD_CLEAR_SECONDS*1000, self.clipboard_clear)
                        mb.showinfo("Copied","Password copied to clipboard for 30 seconds")
                    def edit_pw(r=row): self.show_add_password(prefill=r)
                    def del_pw(r=row):
                        if mb.askyesno("Delete","Are you sure you want to delete this entry?"):
                            delete_password(r[0]); update_list()

                    ctk.CTkButton(btn_frame, text="View", width=60, command=view_pw).pack(side="left", padx=2)
                    ctk.CTkButton(btn_frame, text="Copy", width=60, command=copy_pw).pack(side="left", padx=2)
                    ctk.CTkButton(btn_frame, text="Edit", width=60, command=edit_pw).pack(side="left", padx=2)
                    ctk.CTkButton(btn_frame, text="Delete", width=60, fg_color="red", command=del_pw).pack(side="left", padx=2)

        search.bind("<KeyRelease>", update_list)
        update_list()
        ctk.CTkButton(f, text="Back to Dashboard", width=260, command=self.show_dashboard).pack(pady=20)

    # ----------------- PASSWORD GENERATOR -----------------
    def show_generator(self):
        self.clear()
        f = ctk.CTkFrame(self.container); self.animate(f)
        ctk.CTkLabel(f, text="PASSWORD GENERATOR", font=("Arial", 28)).pack(pady=25)
        length_var = ctk.IntVar(value=16)
        ctk.CTkLabel(f, text="Length").pack()
        ctk.CTkSlider(f, from_=8, to=64, variable=length_var).pack(pady=10)
        upper_var = ctk.BooleanVar(value=True); lower_var = ctk.BooleanVar(value=True)
        digit_var = ctk.BooleanVar(value=True); symbol_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(f, text="Uppercase", variable=upper_var).pack()
        ctk.CTkCheckBox(f, text="Lowercase", variable=lower_var).pack()
        ctk.CTkCheckBox(f, text="Digits", variable=digit_var).pack()
        ctk.CTkCheckBox(f, text="Symbols", variable=symbol_var).pack()
        out = ctk.CTkEntry(f, placeholder_text="Generated Password", width=500); out.pack(pady=15)
        strength = ctk.CTkLabel(f, text=""); strength.pack()

        def gen():
            p = generate_password(length_var.get(), upper_var.get(), lower_var.get(), digit_var.get(), symbol_var.get())
            out.delete(0,"end"); out.insert(0,p); strength.configure(text=password_strength(p))

        ctk.CTkButton(f, text="Generate", width=220, command=gen).pack(pady=10)
        ctk.CTkButton(f, text="Back to Dashboard", width=220, command=self.show_dashboard).pack(pady=10)

    # ----------------- SETTINGS -----------------
    def show_settings(self):
        self.clear()
        f = ctk.CTkFrame(self.container); self.animate(f)
        ctk.CTkLabel(f, text="SETTINGS", font=("Arial", 28)).pack(pady=25)

        def toggle_theme():
            if self.theme_mode=="dark": ctk.set_appearance_mode("light"); self.theme_mode="light"
            else: ctk.set_appearance_mode("dark"); self.theme_mode="dark"
            btn_theme.configure(text=f"Toggle Theme (Current: {self.theme_mode})")

        btn_theme = ctk.CTkButton(f, text=f"Toggle Theme (Current: {self.theme_mode})", width=300, command=toggle_theme)
        btn_theme.pack(pady=15)
        ctk.CTkLabel(f, text="About App:\nSecure Password Manager v2025-26\nAuthors: Syed Shaheer Hussain, Ghulam Asghar, Mohammad Hamza\nAll rights reserved ©", justify="left").pack(pady=15)
        ctk.CTkLabel(f, text="Privacy Policy:\nAll passwords encrypted with AES-256, master password hashed with bcrypt + salt", justify="left").pack(pady=10)
        ctk.CTkLabel(f, text="Terms & Conditions:\nUse responsibly. Password manager stores encrypted data locally only.", justify="left").pack(pady=10)
        ctk.CTkButton(f, text="Back to Dashboard", width=220, command=self.show_dashboard).pack(pady=20)

if __name__ == "__main__":
    App().mainloop()
