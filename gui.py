import tkinter as tk
from tkinter import ttk, messagebox
import json

from analyzer import analyze_password
from hashing import md5_hash, sha256_hash, bcrypt_hash
from cracker_dictionary import dictionary_attack
from cracker_bruteforce import brute_force_attack
from hybrid_attack import hybrid_attack
from hashcat_attack import run_hashcat
from logger import log_event
from report_generator import generate_report


class PasswordToolGUI:
    def __init__(self, root):
        self.root = root
        root.title("Password Analyzer and Cracking Tool")
        root.geometry("1100x700")
        root.configure(bg="#0f172a")

        # ---------------- STYLES ----------------
        style = ttk.Style()
        style.theme_use("clam")

        style.configure("TButton", font=("Segoe UI", 10), padding=8)
        style.configure("TCheckbutton", background="#1e293b", foreground="white")

        TITLE = ("Segoe UI", 18, "bold")
        SUB = ("Segoe UI", 10)
        MONO = ("Consolas", 10)

        # ---------------- HEADER ----------------
        header = tk.Frame(root, bg="#020617", height=70)
        header.pack(fill="x")

        tk.Label(
            header,
            text="🔐 Password Analyzer and Cracking Tool",
            font=TITLE,
            fg="#22d3ee",
            bg="#020617",
            pady=18
        ).pack()

        # ---------------- WELCOME PANEL ----------------
        welcome = tk.Frame(root, bg="#1e293b", padx=20, pady=15)
        welcome.pack(fill="x", padx=20, pady=(10, 15))

        tk.Label(
            welcome,
            text="🎯 Welcome to Password Analyzer and Cracking Tool",
            fg="#22c55e",
            bg="#1e293b",
            font=("Segoe UI", 11, "bold")
        ).pack(anchor="w")

        tips = [
            "• Enter your password in the input field below",
            "• You can check strength and crack password",
        ]

        for tip in tips:
            tk.Label(
                welcome,
                text=tip,
                fg="#cbd5f5",
                bg="#1e293b",
                font=SUB
            ).pack(anchor="w", pady=2)

        # ---------------- MAIN ----------------
        main = tk.Frame(root, bg="#0f172a")
        main.pack(fill="both", expand=True, padx=20, pady=10)

        # ---------------- LEFT PANEL ----------------
        left = tk.Frame(main, bg="#020617", width=320)
        left.pack(side="left", fill="y", padx=(0, 12))

        tk.Label(
            left, text="🔑 Password Input",
            fg="#facc15", bg="#020617",
            font=("Segoe UI", 11, "bold")
        ).pack(anchor="w", padx=12, pady=(12, 6))

        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(
            left, textvariable=self.password_var,
            show="*", bg="#020617", fg="white",
            insertbackground="white", relief="solid"
        )
        self.password_entry.pack(fill="x", padx=12, pady=5)

        self.show_var = tk.BooleanVar()
        ttk.Checkbutton(
            left, text="Show password",
            variable=self.show_var,
            command=self.toggle_password
        ).pack(anchor="w", padx=12, pady=(0, 10))

        # -------- Buttons --------
        tk.Label(
            left, text="📊 Security Analysis",
            fg="#38bdf8", bg="#020617",
            font=("Segoe UI", 11, "bold")
        ).pack(anchor="w", padx=12, pady=(10, 6))

        self.make_btn(left, "Analyze Password Strength", self.analyze)
        self.make_btn(left, "Dictionary Attack", self.dictionary)
        self.make_btn(left, "Brute Force Attack", self.bruteforce)
        self.make_btn(left, "Hybrid Attack", self.hybrid)
        self.make_btn(left, "Hashcat Attack", self.hashcat)

        # ---------------- RIGHT PANEL ----------------
        right = tk.Frame(main, bg="#020617")
        right.pack(side="right", fill="both", expand=True)

        header_r = tk.Frame(right, bg="#020617")
        header_r.pack(fill="x", pady=5)

        tk.Label(
            header_r, text="📟 Analysis Output Console",
            fg="#f59e0b", bg="#020617",
            font=("Segoe UI", 11, "bold")
        ).pack(side="left", padx=10)

        tk.Button(
            header_r, text="🧹 Clear",
            bg="#ef4444", fg="white",
            command=self.clear
        ).pack(side="right", padx=10)

        self.output = tk.Text(
            right, bg="#020617", fg="#22d3ee",
            font=MONO, wrap="word",
            insertbackground="white",
            padx=10, pady=10
        )
        self.output.pack(fill="both", expand=True, padx=10, pady=5)

        self.show_welcome()

    # ---------------- HELPERS ----------------
    def make_btn(self, parent, text, cmd):
        tk.Button(
            parent, text="🔹 " + text,
            bg="#0ea5e9", fg="white",
            relief="flat", command=cmd
        ).pack(fill="x", padx=12, pady=4)

    def toggle_password(self):
        self.password_entry.config(show="" if self.show_var.get() else "*")

    def write(self, text):
        self.output.insert(tk.END, text)
        self.output.see(tk.END)

    def clear(self):
        self.output.delete("1.0", tk.END)

    def show_welcome(self):
        self.clear()
        self.write("🚀 Console Ready\n")
        self.write("─────────────────\n\n")

    # ---------------- FEATURES ----------------
    def analyze(self):
        self.clear()
        pwd = self.password_var.get()
        if not pwd:
            messagebox.showwarning("Input Error", "Please enter a password")
            return

        strength, entropy, issues = analyze_password(pwd)

        self.write("🔍 ANALYZING PASSWORD STRENGTH\n")
        self.write("──────────────────────────────\n")
        self.write(f"✔ Password Strength : {strength}\n")
        self.write(f"✔ Entropy Score     : {entropy:.2f} bits\n\n")

        if issues:
            self.write("⚠ SECURITY VULNERABILITIES DETECTED:\n")
            for issue in issues:
                self.write(f"  • {issue}\n")

        self.write("\n🔐 GENERATED HASHES:\n")
        self.write(f"MD5     : {md5_hash(pwd)}\n")
        self.write(f"SHA256  : {sha256_hash(pwd)}\n")
        self.write(f"bcrypt  : {bcrypt_hash(pwd)}\n")

        generate_report(pwd, strength, entropy, False)
        self.write("\n📄 Report saved as report.txt\n")
        log_event("Password analyzed")

    def dictionary(self):
        self.clear()
        pwd = self.password_var.get()
        if not pwd:
            messagebox.showwarning("Input Error", "Please enter a password")
            return
        
        self.write("🔍 RUNNING DICTIONARY ATTACK\n")
        self.write("──────────────────────────────\n\n")
        
        result = dictionary_attack(md5_hash(pwd))
        
        if result:
            if isinstance(result, dict):
                for key, value in result.items():
                    self.write(f"{key.replace('_', ' ').title():<20}: {value}\n")
            else:
                try:
                    data = json.loads(result)
                    for key, value in data.items():
                        self.write(f"{key.replace('_', ' ').title():<20}: {value}\n")
                except:
                    self.write(str(result) + "\n")
        else:
            self.write("❌ Password not found in dictionary\n")
        
        self.write("\n✅ Dictionary attack completed\n")
        log_event("Dictionary attack performed")

    def bruteforce(self):
        self.clear()
        pwd = self.password_var.get()
        if not pwd:
            messagebox.showwarning("Input Error", "Please enter a password")
            return
        
        self.write("🔍 RUNNING BRUTE FORCE ATTACK\n")
        self.write("──────────────────────────────\n\n")
        
        result = brute_force_attack(pwd)
        
        if result:
            if isinstance(result, dict):
                for key, value in result.items():
                    self.write(f"{key.replace('_', ' ').title():<20}: {value}\n")
            else:
                try:
                    data = json.loads(result)
                    for key, value in data.items():
                        self.write(f"{key.replace('_', ' ').title():<20}: {value}\n")
                except:
                    self.write(str(result) + "\n")
        else:
            self.write("❌ Password not cracked\n")
        
        self.write("\n✅ Brute force attack completed\n")
        log_event("Brute force attack performed")

    def hybrid(self):
        self.clear()
        pwd = self.password_var.get()
        if not pwd:
            messagebox.showwarning("Input Error", "Please enter a password")
            return
        
        self.write("🔍 RUNNING HYBRID ATTACK\n")
        self.write("──────────────────────────────\n\n")
        
        result = hybrid_attack(md5_hash(pwd))
        
        if result:
            if isinstance(result, dict):
                for key, value in result.items():
                    self.write(f"{key.replace('_', ' ').title():<20}: {value}\n")
            else:
                try:
                    data = json.loads(result)
                    for key, value in data.items():
                        self.write(f"{key.replace('_', ' ').title():<20}: {value}\n")
                except:
                    self.write(str(result) + "\n")
        else:
            self.write("❌ Password not found\n")
        
        self.write("\n✅ Hybrid attack completed\n")
        log_event("Hybrid attack performed")

    def hashcat(self):
        self.clear()
        pwd = self.password_var.get()
        if not pwd:
            messagebox.showwarning("Input Error", "Please enter a password")
            return
        
        self.write("🔍 RUNNING HASHCAT ATTACK\n")
        self.write("──────────────────────────────\n\n")
        
        result = run_hashcat(md5_hash(pwd))
        
        if result:
            if isinstance(result, dict):
                for key, value in result.items():
                    self.write(f"{key.replace('_', ' ').title():<20}: {value}\n")
            else:
                try:
                    data = json.loads(result)
                    for key, value in data.items():
                        self.write(f"{key.replace('_', ' ').title():<20}: {value}\n")
                except:
                    self.write(str(result) + "\n")
        else:
            self.write("❌ Password not found\n")
        
        self.write("\n✅ Hashcat attack completed\n")
        log_event("Hashcat attack performed")
