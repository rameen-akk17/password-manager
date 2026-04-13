import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

class PasswordManager:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Password Manager")
        self.root.geometry("950x680")
        self.root.configure(bg="#0f172a")

        self.master_password = None
        self.fernet = None
        self.db_path = "passwords.db"

        self.init_database()
        self.show_login_screen()

    def init_database(self):
        """Create tables for passwords and config (salt + verification)"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS passwords (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        service TEXT NOT NULL,
                        username TEXT NOT NULL,
                        password_enc BLOB NOT NULL,
                        notes TEXT)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS config (
                        key TEXT PRIMARY KEY,
                        value BLOB NOT NULL)''')
        conn.commit()
        conn.close()

    def get_config(self, key):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT value FROM config WHERE key=?", (key,))
        result = c.fetchone()
        conn.close()
        return result[0] if result else None

    def set_config(self, key, value):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", (key, value))
        conn.commit()
        conn.close()

    def derive_fernet(self, master_password: str, salt: bytes) -> Fernet:
        """Derive encryption key from master password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode('utf-8')))
        return Fernet(key)

    def is_first_run(self):
        return self.get_config('salt') is None

    # ====================== MASTER PASSWORD HANDLING ======================
    def show_login_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        if self.is_first_run():
            # First-time setup
            tk.Label(self.root, text="🔐 First Time Setup", font=("Arial", 18, "bold"), bg="#0f172a", fg="#67e8f9").pack(pady=40)
            tk.Label(self.root, text="Create a strong Master Password", font=("Arial", 12), bg="#0f172a", fg="#e2e8f0").pack(pady=10)

            tk.Label(self.root, text="Master Password:", bg="#0f172a", fg="#e2e8f0").pack(pady=(20,5))
            master_entry = tk.Entry(self.root, show="*", width=40, font=("Arial", 12))
            master_entry.pack(pady=5)

            tk.Label(self.root, text="Confirm Master Password:", bg="#0f172a", fg="#e2e8f0").pack(pady=(15,5))
            confirm_entry = tk.Entry(self.root, show="*", width=40, font=("Arial", 12))
            confirm_entry.pack(pady=5)

            def create_master():
                if master_entry.get() != confirm_entry.get():
                    messagebox.showerror("Error", "Passwords do not match!")
                    return
                if len(master_entry.get()) < 8:
                    messagebox.showerror("Error", "Master password must be at least 8 characters!")
                    return

                salt = os.urandom(16)
                self.set_config('salt', salt)

                fernet = self.derive_fernet(master_entry.get(), salt)
                verification = fernet.encrypt(b"VERIFICATION_TOKEN")
                self.set_config('verification', verification)

                messagebox.showinfo("Success", "Master password set successfully!\nYour vault is ready.")
                self.master_password = master_entry.get()
                self.fernet = fernet
                self.show_main_screen()

            tk.Button(self.root, text="Create Master Password", command=create_master,
                      bg="#22d3ee", fg="#0f172a", font=("Arial", 12, "bold"), height=2).pack(pady=30)

        else:
            # Normal login
            tk.Label(self.root, text="🔐 Password Manager", font=("Arial", 20, "bold"), bg="#0f172a", fg="#67e8f9").pack(pady=50)
            tk.Label(self.root, text="Enter your Master Password", font=("Arial", 12), bg="#0f172a", fg="#e2e8f0").pack(pady=10)

            master_entry = tk.Entry(self.root, show="*", width=40, font=("Arial", 14))
            master_entry.pack(pady=20)
            master_entry.focus()

            def login():
                if self.verify_master_password(master_entry.get()):
                    self.show_main_screen()
                else:
                    messagebox.showerror("Access Denied", "Incorrect master password!")
                    master_entry.delete(0, tk.END)

            tk.Button(self.root, text="Unlock Vault", command=login,
                      bg="#22d3ee", fg="#0f172a", font=("Arial", 14, "bold"), height=2, width=25).pack(pady=20)

    def verify_master_password(self, master_password: str) -> bool:
        salt = self.get_config('salt')
        verification = self.get_config('verification')
        if not salt or not verification:
            return False

        try:
            fernet = self.derive_fernet(master_password, salt)
            decrypted = fernet.decrypt(verification)
            if decrypted == b"VERIFICATION_TOKEN":
                self.master_password = master_password
                self.fernet = fernet
                return True
        except Exception:
            pass
        return False

    # ====================== MAIN APPLICATION SCREEN ======================
    def show_main_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        # Top bar
        top_frame = tk.Frame(self.root, bg="#1e2937")
        top_frame.pack(fill=tk.X, padx=10, pady=8)

        tk.Label(top_frame, text="🔍 Search:", bg="#1e2937", fg="#e2e8f0").pack(side=tk.LEFT, padx=5)
        self.search_var = tk.StringVar()
        search_entry = tk.Entry(top_frame, textvariable=self.search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(top_frame, text="Search", command=self.search_passwords).pack(side=tk.LEFT, padx=5)

        tk.Button(top_frame, text="Refresh", command=self.load_passwords).pack(side=tk.LEFT, padx=10)
        tk.Button(top_frame, text="➕ Add New", command=self.show_add_dialog, bg="#22d3ee", fg="#0f172a").pack(side=tk.LEFT)

        tk.Button(top_frame, text="Logout", command=self.logout, bg="#ef4444", fg="white").pack(side=tk.RIGHT, padx=10)

        # Treeview
        columns = ("ID", "Service", "Username", "Notes")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings", height=22)
        for col, width in zip(columns, [60, 280, 250, 300]):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width)

        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Buttons
        btn_frame = tk.Frame(self.root, bg="#0f172a")
        btn_frame.pack(fill=tk.X, padx=10, pady=8)

        tk.Button(btn_frame, text="👁 View/Edit", command=self.view_edit_selected).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="📋 Copy Password", command=self.copy_selected_password).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="🗑 Delete", command=self.delete_selected, bg="#ef4444", fg="white").pack(side=tk.LEFT, padx=5)

        self.load_passwords()

    # ====================== CORE LOGIC FUNCTIONS ======================
    def get_all_entries(self):
        """Fetch and decrypt all passwords"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT id, service, username, password_enc, notes FROM passwords")
        rows = c.fetchall()
        conn.close()

        entries = []
        for row in rows:
            try:
                decrypted_pass = self.fernet.decrypt(row[3]).decode('utf-8')
                entries.append({
                    'id': row[0],
                    'service': row[1],
                    'username': row[2],
                    'password': decrypted_pass,
                    'notes': row[4] or ""
                })
            except Exception:
                continue  # skip corrupted entries
        return entries

    def load_passwords(self, filtered=None):
        for item in self.tree.get_children():
            self.tree.delete(item)

        data = filtered if filtered is not None else self.get_all_entries()
        for entry in data:
            self.tree.insert("", tk.END, values=(
                entry['id'], entry['service'], entry['username'], entry['notes']
            ))

    def search_passwords(self):
        query = self.search_var.get().strip().lower()
        if not query:
            self.load_passwords()
            return

        all_entries = self.get_all_entries()
        filtered = [e for e in all_entries if query in e['service'].lower() or 
                                               query in e['username'].lower() or 
                                               query in e['notes'].lower()]
        self.load_passwords(filtered)

    def password_strength(self, password: str) -> str:
        if len(password) < 8:
            return "Weak"
        score = sum([
            len(password) >= 12,
            any(c.isupper() for c in password),
            any(c.islower() for c in password),
            any(c.isdigit() for c in password),
            any(not c.isalnum() for c in password)
        ])
        if score <= 2: return "Weak"
        elif score <= 4: return "Medium"
        return "Strong"

    def show_add_dialog(self):
        self._show_entry_dialog("Add New Password", None)

    def view_edit_selected(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select an entry!")
            return
        pid = int(self.tree.item(selected[0], "values")[0])
        self._show_entry_dialog("Edit Password", pid)

    def _show_entry_dialog(self, title: str, entry_id=None):
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("500x420")
        dialog.configure(bg="#1e2937")

        # Fields
        tk.Label(dialog, text="Service / Website:", bg="#1e2937", fg="#e2e8f0").grid(row=0, column=0, sticky="e", padx=10, pady=8)
        service_entry = tk.Entry(dialog, width=40, font=("Arial", 11))
        service_entry.grid(row=0, column=1, pady=8)

        tk.Label(dialog, text="Username / Email:", bg="#1e2937", fg="#e2e8f0").grid(row=1, column=0, sticky="e", padx=10, pady=8)
        username_entry = tk.Entry(dialog, width=40, font=("Arial", 11))
        username_entry.grid(row=1, column=1, pady=8)

        tk.Label(dialog, text="Password:", bg="#1e2937", fg="#e2e8f0").grid(row=2, column=0, sticky="e", padx=10, pady=8)
        password_entry = tk.Entry(dialog, width=40, font=("Arial", 11), show="*")
        password_entry.grid(row=2, column=1, pady=8)

        strength_label = tk.Label(dialog, text="Strength: ", bg="#1e2937", fg="#e2e8f0")
        strength_label.grid(row=3, column=1, sticky="w", padx=10)

        def update_strength(*args):
            strength_label.config(text=f"Strength: {self.password_strength(password_entry.get())}")
        password_entry.bind("<KeyRelease>", update_strength)

        tk.Label(dialog, text="Notes (optional):", bg="#1e2937", fg="#e2e8f0").grid(row=4, column=0, sticky="e", padx=10, pady=8)
        notes_entry = tk.Entry(dialog, width=40, font=("Arial", 11))
        notes_entry.grid(row=4, column=1, pady=8)

        # Pre-fill if editing
        if entry_id:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("SELECT service, username, password_enc, notes FROM passwords WHERE id=?", (entry_id,))
            row = c.fetchone()
            conn.close()
            if row:
                service_entry.insert(0, row[0])
                username_entry.insert(0, row[1])
                try:
                    decrypted = self.fernet.decrypt(row[2]).decode('utf-8')
                    password_entry.insert(0, decrypted)
                    update_strength()
                except:
                    pass
                notes_entry.insert(0, row[3] or "")

        def save_entry():
            service = service_entry.get().strip()
            username = username_entry.get().strip()
            password = password_entry.get().strip()
            notes = notes_entry.get().strip()

            if not all([service, username, password]):
                messagebox.showerror("Error", "Service, Username and Password are required!")
                return

            encrypted_pass = self.fernet.encrypt(password.encode('utf-8'))

            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            if entry_id:
                c.execute("""UPDATE passwords 
                             SET service=?, username=?, password_enc=?, notes=?
                             WHERE id=?""",
                          (service, username, encrypted_pass, notes, entry_id))
            else:
                c.execute("INSERT INTO passwords (service, username, password_enc, notes) VALUES (?, ?, ?, ?)",
                          (service, username, encrypted_pass, notes))
            conn.commit()
            conn.close()

            messagebox.showinfo("Success", "Password saved securely!")
            dialog.destroy()
            self.load_passwords()

        tk.Button(dialog, text="Save Securely", command=save_entry,
                  bg="#22d3ee", fg="#0f172a", font=("Arial", 12, "bold")).grid(row=5, column=1, pady=25)

    def copy_selected_password(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select an entry!")
            return
        pid = int(self.tree.item(selected[0], "values")[0])

        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT password_enc FROM passwords WHERE id=?", (pid,))
        row = c.fetchone()
        conn.close()

        if row:
            try:
                password = self.fernet.decrypt(row[0]).decode('utf-8')
                self.root.clipboard_clear()
                self.root.clipboard_append(password)
                messagebox.showinfo("Copied", "Password copied to clipboard!")
            except Exception:
                messagebox.showerror("Error", "Failed to decrypt password.")

    def delete_selected(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select an entry!")
            return
        pid = int(self.tree.item(selected[0], "values")[0])

        if messagebox.askyesno("Confirm", "Delete this password entry permanently?"):
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("DELETE FROM passwords WHERE id=?", (pid,))
            conn.commit()
            conn.close()
            self.load_passwords()
            messagebox.showinfo("Deleted", "Entry removed successfully.")

    def logout(self):
        if messagebox.askyesno("Logout", "Lock the vault and return to login screen?"):
            self.master_password = None
            self.fernet = None
            self.show_login_screen()

if __name__ == "__main__":
    app = PasswordManager()
    app.root.mainloop()
