import os
import sys
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk
from crypto_engine import CryptoEngine

# Configure CustomTkinter appearance
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


class PyCipherVaultApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("PyCipher Vault — Python Cryptography & Security Studio")
        self.geometry("1100x750")
        self.minsize(950, 650)

        # Configure Grid Layout (1 row, 2 columns)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # Build Sidebar & Main Container
        self._create_sidebar()
        self._create_main_container()

    # ------------------------------------------------------------------
    # UI Component Builders
    # ------------------------------------------------------------------
    def _create_sidebar(self):
        self.sidebar_frame = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(8, weight=1)

        # Title Logo
        logo_label = ctk.CTkLabel(
            self.sidebar_frame,
            text="🔒 PyCipher Studio",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        sub_logo = ctk.CTkLabel(
            self.sidebar_frame,
            text="Pure Python Cryptography",
            font=ctk.CTkFont(size=12, slant="italic"),
            text_color="gray"
        )
        sub_logo.grid(row=1, column=0, padx=20, pady=(0, 20))

        # Navigation Buttons
        self.btn_aes = ctk.CTkButton(
            self.sidebar_frame, text="🔐 AES & File Vault",
            command=lambda: self.select_tab("AES")
        )
        self.btn_aes.grid(row=2, column=0, padx=20, pady=8)

        self.btn_rsa = ctk.CTkButton(
            self.sidebar_frame, text="🔑 RSA Key Studio",
            command=lambda: self.select_tab("RSA")
        )
        self.btn_rsa.grid(row=3, column=0, padx=20, pady=8)

        self.btn_stego = ctk.CTkButton(
            self.sidebar_frame, text="🖼️ Steganography",
            command=lambda: self.select_tab("Stego")
        )
        self.btn_stego.grid(row=4, column=0, padx=20, pady=8)

        self.btn_hash = ctk.CTkButton(
            self.sidebar_frame, text="⚡ Hash & HMAC",
            command=lambda: self.select_tab("Hash")
        )
        self.btn_hash.grid(row=5, column=0, padx=20, pady=8)

        self.btn_pass = ctk.CTkButton(
            self.sidebar_frame, text="📊 Password Entropy",
            command=lambda: self.select_tab("Entropy")
        )
        self.btn_pass.grid(row=6, column=0, padx=20, pady=8)

        self.btn_classic = ctk.CTkButton(
            self.sidebar_frame, text="📜 Classic Ciphers",
            command=lambda: self.select_tab("Classic")
        )
        self.btn_classic.grid(row=7, column=0, padx=20, pady=8)

        # Appearance Option
        self.theme_label = ctk.CTkLabel(self.sidebar_frame, text="Appearance Mode:", anchor="w")
        self.theme_label.grid(row=9, column=0, padx=20, pady=(10, 0))
        self.theme_optionmenu = ctk.CTkOptionMenu(
            self.sidebar_frame,
            values=["Dark", "Light", "System"],
            command=self.change_appearance_mode
        )
        self.theme_optionmenu.grid(row=10, column=0, padx=20, pady=(10, 20))

    def _create_main_container(self):
        self.main_frame = ctk.CTkFrame(self, corner_radius=10)
        self.main_frame.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.main_frame.grid_rowconfigure(1, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        # Header Title
        self.header_title = ctk.CTkLabel(
            self.main_frame,
            text="AES-256 Symmetric & File Encryption Vault",
            font=ctk.CTkFont(size=22, weight="bold")
        )
        self.header_title.grid(row=0, column=0, padx=20, pady=(15, 10), sticky="w")

        # Tabview Frame Container
        self.tab_container = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.tab_container.grid(row=1, column=0, padx=15, pady=10, sticky="nsew")
        self.tab_container.grid_rowconfigure(0, weight=1)
        self.tab_container.grid_columnconfigure(0, weight=1)

        # Create Views
        self.frames = {}
        self.frames["AES"] = self._build_aes_view()
        self.frames["RSA"] = self._build_rsa_view()
        self.frames["Stego"] = self._build_stego_view()
        self.frames["Hash"] = self._build_hash_view()
        self.frames["Entropy"] = self._build_entropy_view()
        self.frames["Classic"] = self._build_classic_view()

        # Select initial view
        self.select_tab("AES")

    def select_tab(self, tab_name: str):
        titles = {
            "AES": "🔐 AES-256 Symmetric & File Encryption",
            "RSA": "🔑 RSA Key Pair Generation & OAEP Cipher",
            "Stego": "🖼️ LSB Image Steganography Studio",
            "Hash": "⚡ Multi-Algorithm Hashing & HMAC Engine",
            "Entropy": "📊 Password Entropy & Strength Analyzer",
            "Classic": "📜 Classic Ciphers & Auto Brute-Force Cracker"
        }
        self.header_title.configure(text=titles.get(tab_name, "PyCipher Vault"))

        for name, frame in self.frames.items():
            if name == tab_name:
                frame.grid(row=0, column=0, sticky="nsew")
            else:
                frame.grid_forget()

    def change_appearance_mode(self, mode: str):
        ctk.set_appearance_mode(mode)

    def copy_to_clipboard(self, text: str):
        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo("Success", "Copied payload to clipboard!")

    # ------------------------------------------------------------------
    # TAB 1: AES-256 Symmetric & File Encryption
    # ------------------------------------------------------------------
    def _build_aes_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.tab_container)
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        tabview = ctk.CTkTabview(frame)
        tabview.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        tab_text = tabview.add("Text Encryption")
        tab_file = tabview.add("File Encryption")

        # --- Sub-tab: Text Encryption ---
        tab_text.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(tab_text, text="Plaintext / Ciphertext Input:").grid(row=0, column=0, padx=10, pady=5, sticky="nw")
        aes_input = ctk.CTkTextbox(tab_text, height=100)
        aes_input.grid(row=0, column=1, padx=10, pady=5, sticky="ew")

        ctk.CTkLabel(tab_text, text="Secret Password:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        aes_pass = ctk.CTkEntry(tab_text, show="*")
        aes_pass.grid(row=1, column=1, padx=10, pady=5, sticky="ew")

        btn_box = ctk.CTkFrame(tab_text, fg_color="transparent")
        btn_box.grid(row=2, column=1, pady=10, sticky="w")

        ctk.CTkLabel(tab_text, text="Output Payload:").grid(row=3, column=0, padx=10, pady=5, sticky="nw")
        aes_output = ctk.CTkTextbox(tab_text, height=120)
        aes_output.grid(row=3, column=1, padx=10, pady=5, sticky="ew")

        def do_encrypt():
            p = aes_pass.get()
            txt = aes_input.get("1.0", "end-1c").strip()
            if not p or not txt:
                messagebox.showwarning("Warning", "Please enter input text and password.")
                return
            try:
                enc = CryptoEngine.encrypt_text_aes(txt, p)
                aes_output.delete("1.0", "end")
                aes_output.insert("1.0", enc)
            except Exception as e:
                messagebox.showerror("Error", str(e))

        def do_decrypt():
            p = aes_pass.get()
            cipher = aes_input.get("1.0", "end-1c").strip()
            if not p or not cipher:
                messagebox.showwarning("Warning", "Please enter ciphertext and password.")
                return
            try:
                dec = CryptoEngine.decrypt_text_aes(cipher, p)
                aes_output.delete("1.0", "end")
                aes_output.insert("1.0", dec)
            except Exception as e:
                messagebox.showerror("Error", str(e))

        ctk.CTkButton(btn_box, text="🔒 Encrypt AES-256", command=do_encrypt, fg_color="#1f538d").pack(side="left", padx=5)
        ctk.CTkButton(btn_box, text="🔓 Decrypt AES-256", command=do_decrypt, fg_color="#2fa572").pack(side="left", padx=5)
        ctk.CTkButton(btn_box, text="📋 Copy Output", command=lambda: self.copy_to_clipboard(aes_output.get("1.0", "end-1c"))).pack(side="left", padx=5)

        # --- Sub-tab: File Encryption ---
        tab_file.grid_columnconfigure(1, weight=1)

        file_in_var = tk.StringVar()
        file_out_var = tk.StringVar()

        ctk.CTkLabel(tab_file, text="Target File:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        ctk.CTkEntry(tab_file, textvariable=file_in_var).grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        def browse_in():
            f = filedialog.askopenfilename()
            if f:
                file_in_var.set(f)
                file_out_var.set(f + ".enc" if not f.endswith(".enc") else f.rsplit(".enc", 1)[0] + "_dec.bin")

        ctk.CTkButton(tab_file, text="Browse File", command=browse_in).grid(row=0, column=2, padx=10, pady=10)

        ctk.CTkLabel(tab_file, text="Output File Destination:").grid(row=1, column=0, padx=10, pady=10, sticky="w")
        ctk.CTkEntry(tab_file, textvariable=file_out_var).grid(row=1, column=1, padx=10, pady=10, sticky="ew")

        def browse_out():
            f = filedialog.asksaveasfilename()
            if f:
                file_out_var.set(f)

        ctk.CTkButton(tab_file, text="Save As...", command=browse_out).grid(row=1, column=2, padx=10, pady=10)

        ctk.CTkLabel(tab_file, text="Master Password:").grid(row=2, column=0, padx=10, pady=10, sticky="w")
        file_pass = ctk.CTkEntry(tab_file, show="*")
        file_pass.grid(row=2, column=1, padx=10, pady=10, sticky="ew")

        file_status = ctk.CTkLabel(tab_file, text="Status: Ready", text_color="gray")
        file_status.grid(row=3, column=1, pady=5, sticky="w")

        def enc_file():
            i, o, p = file_in_var.get(), file_out_var.get(), file_pass.get()
            if not i or not o or not p:
                messagebox.showwarning("Warning", "Please select input/output paths and enter a password.")
                return
            try:
                CryptoEngine.encrypt_file_aes(i, o, p)
                file_status.configure(text="Status: Successfully Encrypted File! ✅", text_color="#2fa572")
                messagebox.showinfo("Success", f"File encrypted successfully to:\n{o}")
            except Exception as e:
                file_status.configure(text=f"Status: Error - {e}", text_color="red")
                messagebox.showerror("Error", str(e))

        def dec_file():
            i, o, p = file_in_var.get(), file_out_var.get(), file_pass.get()
            if not i or not o or not p:
                messagebox.showwarning("Warning", "Please select input/output paths and enter a password.")
                return
            try:
                CryptoEngine.decrypt_file_aes(i, o, p)
                file_status.configure(text="Status: Successfully Decrypted File! ✅", text_color="#2fa572")
                messagebox.showinfo("Success", f"File decrypted successfully to:\n{o}")
            except Exception as e:
                file_status.configure(text=f"Status: Error - {e}", text_color="red")
                messagebox.showerror("Error", str(e))

        file_btn_box = ctk.CTkFrame(tab_file, fg_color="transparent")
        file_btn_box.grid(row=4, column=1, pady=20, sticky="w")
        ctk.CTkButton(file_btn_box, text="🔒 Encrypt File", command=enc_file, fg_color="#1f538d").pack(side="left", padx=10)
        ctk.CTkButton(file_btn_box, text="🔓 Decrypt File", command=dec_file, fg_color="#2fa572").pack(side="left", padx=10)

        return frame

    # ------------------------------------------------------------------
    # TAB 2: RSA Key Studio
    # ------------------------------------------------------------------
    def _build_rsa_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.tab_container)
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        top_bar = ctk.CTkFrame(frame, fg_color="transparent")
        top_bar.grid(row=0, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

        ctk.CTkLabel(top_bar, text="Key Size:").pack(side="left", padx=5)
        keysize_var = ctk.StringVar(value="2048")
        ctk.CTkOptionMenu(top_bar, variable=keysize_var, values=["2048", "4096"]).pack(side="left", padx=5)

        # Text Boxes for Keys
        priv_box = ctk.CTkTextbox(frame, height=150)
        priv_box.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")

        pub_box = ctk.CTkTextbox(frame, height=150)
        pub_box.grid(row=1, column=1, padx=10, pady=5, sticky="nsew")

        def gen_keys():
            size = int(keysize_var.get())
            try:
                priv, pub = CryptoEngine.generate_rsa_keys(size)
                priv_box.delete("1.0", "end")
                priv_box.insert("1.0", priv)
                pub_box.delete("1.0", "end")
                pub_box.insert("1.0", pub)
            except Exception as e:
                messagebox.showerror("Error", str(e))

        ctk.CTkButton(top_bar, text="⚡ Generate New RSA Key Pair", command=gen_keys).pack(side="left", padx=15)

        # Message & Action Section
        bottom_box = ctk.CTkFrame(frame)
        bottom_box.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky="ew")
        bottom_box.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(bottom_box, text="Message Input / Output:").grid(row=0, column=0, padx=10, pady=5, sticky="nw")
        rsa_msg_input = ctk.CTkTextbox(bottom_box, height=80)
        rsa_msg_input.grid(row=0, column=1, padx=10, pady=5, sticky="ew")

        rsa_btn_box = ctk.CTkFrame(bottom_box, fg_color="transparent")
        rsa_btn_box.grid(row=1, column=1, pady=5, sticky="w")

        def rsa_enc():
            msg = rsa_msg_input.get("1.0", "end-1c").strip()
            pub_pem = pub_box.get("1.0", "end-1c").strip()
            if not msg or not pub_pem:
                messagebox.showwarning("Warning", "Please enter message and public key.")
                return
            try:
                res = CryptoEngine.rsa_encrypt(msg, pub_pem)
                rsa_msg_input.delete("1.0", "end")
                rsa_msg_input.insert("1.0", res)
            except Exception as e:
                messagebox.showerror("Error", str(e))

        def rsa_dec():
            cipher = rsa_msg_input.get("1.0", "end-1c").strip()
            priv_pem = priv_box.get("1.0", "end-1c").strip()
            if not cipher or not priv_pem:
                messagebox.showwarning("Warning", "Please enter ciphertext and private key.")
                return
            try:
                res = CryptoEngine.rsa_decrypt(cipher, priv_pem)
                rsa_msg_input.delete("1.0", "end")
                rsa_msg_input.insert("1.0", res)
            except Exception as e:
                messagebox.showerror("Error", str(e))

        ctk.CTkButton(rsa_btn_box, text="🔒 RSA Encrypt (with Public Key)", command=rsa_enc, fg_color="#1f538d").pack(side="left", padx=5)
        ctk.CTkButton(rsa_btn_box, text="🔓 RSA Decrypt (with Private Key)", command=rsa_dec, fg_color="#2fa572").pack(side="left", padx=5)

        return frame

    # ------------------------------------------------------------------
    # TAB 3: LSB Image Steganography
    # ------------------------------------------------------------------
    def _build_stego_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.tab_container)
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        tabview = ctk.CTkTabview(frame)
        tabview.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        tab_hide = tabview.add("Hide Text in Image")
        tab_ext = tabview.add("Extract Text from Image")

        # --- Hide Tab ---
        tab_hide.grid_columnconfigure(1, weight=1)
        stego_img_in = tk.StringVar()
        stego_img_out = tk.StringVar()

        ctk.CTkLabel(tab_hide, text="Source Cover Image:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        ctk.CTkEntry(tab_hide, textvariable=stego_img_in).grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        def browse_stego_in():
            f = filedialog.askopenfilename(filetypes=[("Images", "*.png;*.bmp")])
            if f:
                stego_img_in.set(f)
                stego_img_out.set(f.rsplit(".", 1)[0] + "_stego.png")

        ctk.CTkButton(tab_hide, text="Browse Image", command=browse_stego_in).grid(row=0, column=2, padx=10, pady=10)

        ctk.CTkLabel(tab_hide, text="Output Stego PNG Path:").grid(row=1, column=0, padx=10, pady=10, sticky="w")
        ctk.CTkEntry(tab_hide, textvariable=stego_img_out).grid(row=1, column=1, padx=10, pady=10, sticky="ew")

        ctk.CTkLabel(tab_hide, text="Secret Message to Hide:").grid(row=2, column=0, padx=10, pady=10, sticky="nw")
        secret_box = ctk.CTkTextbox(tab_hide, height=100)
        secret_box.grid(row=2, column=1, padx=10, pady=10, sticky="ew")

        ctk.CTkLabel(tab_hide, text="AES Encryption Password (Optional):").grid(row=3, column=0, padx=10, pady=10, sticky="w")
        stego_pass_hide = ctk.CTkEntry(tab_hide, show="*")
        stego_pass_hide.grid(row=3, column=1, padx=10, pady=10, sticky="ew")

        def do_hide():
            src, out, text, p = stego_img_in.get(), stego_img_out.get(), secret_box.get("1.0", "end-1c").strip(), stego_pass_hide.get()
            if not src or not out or not text:
                messagebox.showwarning("Warning", "Please select source image, output path, and secret text.")
                return
            try:
                CryptoEngine.hide_text_in_image(src, out, text, password=p)
                messagebox.showinfo("Success", f"Secret text embedded successfully into image:\n{out}")
            except Exception as e:
                messagebox.showerror("Error", str(e))

        ctk.CTkButton(tab_hide, text="🖼️ Embed Secret Text in Image", command=do_hide, fg_color="#1f538d").grid(row=4, column=1, pady=15, sticky="w")

        # --- Extract Tab ---
        tab_ext.grid_columnconfigure(1, weight=1)
        stego_ext_img = tk.StringVar()

        ctk.CTkLabel(tab_ext, text="Stego Image File:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        ctk.CTkEntry(tab_ext, textvariable=stego_ext_img).grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        def browse_ext_img():
            f = filedialog.askopenfilename(filetypes=[("PNG/BMP Images", "*.png;*.bmp")])
            if f:
                stego_ext_img.set(f)

        ctk.CTkButton(tab_ext, text="Browse Image", command=browse_ext_img).grid(row=0, column=2, padx=10, pady=10)

        ctk.CTkLabel(tab_ext, text="Decryption Password (if encrypted):").grid(row=1, column=0, padx=10, pady=10, sticky="w")
        stego_pass_ext = ctk.CTkEntry(tab_ext, show="*")
        stego_pass_ext.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

        ctk.CTkLabel(tab_ext, text="Extracted Secret Text:").grid(row=2, column=0, padx=10, pady=10, sticky="nw")
        extracted_box = ctk.CTkTextbox(tab_ext, height=120)
        extracted_box.grid(row=2, column=1, padx=10, pady=10, sticky="ew")

        def do_extract():
            src, p = stego_ext_img.get(), stego_pass_ext.get()
            if not src:
                messagebox.showwarning("Warning", "Please select a stego image.")
                return
            try:
                res = CryptoEngine.extract_text_from_image(src, password=p)
                extracted_box.delete("1.0", "end")
                extracted_box.insert("1.0", res)
                messagebox.showinfo("Success", "Extracted hidden payload!")
            except Exception as e:
                messagebox.showerror("Error", str(e))

        ctk.CTkButton(tab_ext, text="🔍 Extract Secret Payload", command=do_extract, fg_color="#2fa572").grid(row=3, column=1, pady=15, sticky="w")

        return frame

    # ------------------------------------------------------------------
    # TAB 4: Hash & HMAC Generator
    # ------------------------------------------------------------------
    def _build_hash_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.tab_container)
        frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(frame, text="Input Data / Text:").grid(row=0, column=0, padx=10, pady=10, sticky="nw")
        hash_input = ctk.CTkTextbox(frame, height=90)
        hash_input.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        ctk.CTkLabel(frame, text="Algorithm:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        algo_var = ctk.StringVar(value="SHA-256")
        ctk.CTkOptionMenu(frame, variable=algo_var, values=["MD5", "SHA-1", "SHA-256", "SHA-512", "SHA3-256", "BLAKE2b"]).grid(row=1, column=1, padx=10, pady=5, sticky="w")

        ctk.CTkLabel(frame, text="Salt (Optional):").grid(row=2, column=0, padx=10, pady=5, sticky="w")
        salt_entry = ctk.CTkEntry(frame)
        salt_entry.grid(row=2, column=1, padx=10, pady=5, sticky="ew")

        ctk.CTkLabel(frame, text="HMAC Key (Optional):").grid(row=3, column=0, padx=10, pady=5, sticky="w")
        hmac_key_entry = ctk.CTkEntry(frame)
        hmac_key_entry.grid(row=3, column=1, padx=10, pady=5, sticky="ew")

        ctk.CTkLabel(frame, text="Calculated Digest:").grid(row=4, column=0, padx=10, pady=10, sticky="nw")
        hash_output = ctk.CTkEntry(frame)
        hash_output.grid(row=4, column=1, padx=10, pady=10, sticky="ew")

        btn_box = ctk.CTkFrame(frame, fg_color="transparent")
        btn_box.grid(row=5, column=1, pady=10, sticky="w")

        def calc_h():
            txt = hash_input.get("1.0", "end-1c")
            algo = algo_var.get()
            salt = salt_entry.get()
            try:
                res = CryptoEngine.calculate_hash(txt, algorithm=algo, salt=salt)
                hash_output.delete(0, "end")
                hash_output.insert(0, res)
            except Exception as e:
                messagebox.showerror("Error", str(e))

        def calc_hmac_fn():
            txt = hash_input.get("1.0", "end-1c")
            algo = algo_var.get()
            key = hmac_key_entry.get()
            if not key:
                messagebox.showwarning("Warning", "Please provide a secret key for HMAC.")
                return
            try:
                res = CryptoEngine.calculate_hmac(txt, secret_key=key, algorithm=algo)
                hash_output.delete(0, "end")
                hash_output.insert(0, res)
            except Exception as e:
                messagebox.showerror("Error", str(e))

        ctk.CTkButton(btn_box, text="⚡ Generate Hash", command=calc_h, fg_color="#1f538d").pack(side="left", padx=5)
        ctk.CTkButton(btn_box, text="🔐 Generate HMAC", command=calc_hmac_fn, fg_color="#2fa572").pack(side="left", padx=5)
        ctk.CTkButton(btn_box, text="📋 Copy Hash", command=lambda: self.copy_to_clipboard(hash_output.get())).pack(side="left", padx=5)

        return frame

    # ------------------------------------------------------------------
    # TAB 5: Password Entropy & Strength
    # ------------------------------------------------------------------
    def _build_entropy_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.tab_container)
        frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(frame, text="Test Password:").grid(row=0, column=0, padx=10, pady=15, sticky="w")
        pass_entry = ctk.CTkEntry(frame, show="*")
        pass_entry.grid(row=0, column=1, padx=10, pady=15, sticky="ew")

        # Progress Bar & Rating
        progress_bar = ctk.CTkProgressBar(frame)
        progress_bar.grid(row=1, column=1, padx=10, pady=5, sticky="ew")
        progress_bar.set(0)

        rating_label = ctk.CTkLabel(frame, text="Strength: Empty", font=ctk.CTkFont(size=16, weight="bold"))
        rating_label.grid(row=2, column=1, padx=10, pady=5, sticky="w")

        # Metrics Card Frame
        metrics_frame = ctk.CTkFrame(frame)
        metrics_frame.grid(row=3, column=0, columnspan=2, padx=10, pady=15, sticky="ew")
        metrics_frame.grid_columnconfigure((0, 1, 2), weight=1)

        lbl_entropy = ctk.CTkLabel(metrics_frame, text="Entropy: 0.0 bits", font=ctk.CTkFont(size=14))
        lbl_entropy.grid(row=0, column=0, padx=10, pady=10)

        lbl_crack = ctk.CTkLabel(metrics_frame, text="Crack Time: Instant", font=ctk.CTkFont(size=14))
        lbl_crack.grid(row=0, column=1, padx=10, pady=10)

        lbl_length = ctk.CTkLabel(metrics_frame, text="Length: 0 chars", font=ctk.CTkFont(size=14))
        lbl_length.grid(row=0, column=2, padx=10, pady=10)

        # Checkset indicators
        charset_frame = ctk.CTkFrame(frame, fg_color="transparent")
        charset_frame.grid(row=4, column=0, columnspan=2, padx=10, pady=10)

        chk_lower = ctk.CTkCheckBox(charset_frame, text="Lowercase (a-z)", state="disabled")
        chk_lower.pack(side="left", padx=10)
        chk_upper = ctk.CTkCheckBox(charset_frame, text="Uppercase (A-Z)", state="disabled")
        chk_upper.pack(side="left", padx=10)
        chk_digit = ctk.CTkCheckBox(charset_frame, text="Digits (0-9)", state="disabled")
        chk_digit.pack(side="left", padx=10)
        chk_special = ctk.CTkCheckBox(charset_frame, text="Symbols (!@#)", state="disabled")
        chk_special.pack(side="left", padx=10)

        def on_pass_change(event=None):
            pwd = pass_entry.get()
            info = CryptoEngine.analyze_password(pwd)

            score = info["score"] / 100.0
            progress_bar.set(score)

            rating_label.configure(text=f"Strength: {info['rating']}")
            lbl_entropy.configure(text=f"Entropy: {info['entropy_bits']} bits")
            lbl_crack.configure(text=f"Crack Time: {info['crack_time']}")
            lbl_length.configure(text=f"Length: {info['length']} chars")

            if info["has_lower"]:
                chk_lower.select()
            else:
                chk_lower.deselect()

            if info["has_upper"]:
                chk_upper.select()
            else:
                chk_upper.deselect()

            if info["has_digit"]:
                chk_digit.select()
            else:
                chk_digit.deselect()

            if info["has_special"]:
                chk_special.select()
            else:
                chk_special.deselect()

        pass_entry.bind("<KeyRelease>", on_pass_change)

        return frame

    # ------------------------------------------------------------------
    # TAB 6: Classic Ciphers & Auto Cracker
    # ------------------------------------------------------------------
    def _build_classic_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.tab_container)
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        tabview = ctk.CTkTabview(frame)
        tabview.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        tab_caesar = tabview.add("Caesar Cipher & Auto Cracker")
        tab_vigenere = tabview.add("Vigenère Cipher")

        # --- Caesar Tab ---
        tab_caesar.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(tab_caesar, text="Text:").grid(row=0, column=0, padx=10, pady=5, sticky="nw")
        c_text = ctk.CTkTextbox(tab_caesar, height=80)
        c_text.grid(row=0, column=1, padx=10, pady=5, sticky="ew")

        ctk.CTkLabel(tab_caesar, text="Shift (1-25):").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        shift_slider = ctk.CTkSlider(tab_caesar, from_=1, to=25, number_of_steps=24)
        shift_slider.grid(row=1, column=1, padx=10, pady=5, sticky="ew")
        shift_val_lbl = ctk.CTkLabel(tab_caesar, text="1")
        shift_val_lbl.grid(row=1, column=2, padx=5, pady=5)

        shift_slider.configure(command=lambda val: shift_val_lbl.configure(text=str(int(val))))

        c_output = ctk.CTkTextbox(tab_caesar, height=120)
        c_output.grid(row=3, column=1, padx=10, pady=5, sticky="ew")

        def enc_caesar():
            txt = c_text.get("1.0", "end-1c").strip()
            shift = int(shift_slider.get())
            res = CryptoEngine.caesar_cipher(txt, shift)
            c_output.delete("1.0", "end")
            c_output.insert("1.0", res)

        def dec_caesar():
            txt = c_text.get("1.0", "end-1c").strip()
            shift = int(shift_slider.get())
            res = CryptoEngine.caesar_cipher(txt, shift, decrypt=True)
            c_output.delete("1.0", "end")
            c_output.insert("1.0", res)

        def brute_caesar():
            txt = c_text.get("1.0", "end-1c").strip()
            if not txt:
                return
            results = CryptoEngine.caesar_bruteforce(txt)
            c_output.delete("1.0", "end")
            c_output.insert("1.0", "=== ALL 25 CAESAR SHIFT POSSIBILITIES ===\n\n")
            for shift, dec in results:
                c_output.insert("end", f"Shift {shift:02d}: {dec}\n")

        c_btn_box = ctk.CTkFrame(tab_caesar, fg_color="transparent")
        c_btn_box.grid(row=2, column=1, pady=5, sticky="w")
        ctk.CTkButton(c_btn_box, text="🔒 Encrypt Shift", command=enc_caesar, fg_color="#1f538d").pack(side="left", padx=5)
        ctk.CTkButton(c_btn_box, text="🔓 Decrypt Shift", command=dec_caesar, fg_color="#2fa572").pack(side="left", padx=5)
        ctk.CTkButton(c_btn_box, text="💥 Auto Brute-Force Crack All Shifts", command=brute_caesar, fg_color="#a03232").pack(side="left", padx=5)

        # --- Vigenere Tab ---
        tab_vigenere.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(tab_vigenere, text="Text:").grid(row=0, column=0, padx=10, pady=5, sticky="nw")
        v_text = ctk.CTkTextbox(tab_vigenere, height=80)
        v_text.grid(row=0, column=1, padx=10, pady=5, sticky="ew")

        ctk.CTkLabel(tab_vigenere, text="Secret Key Word:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        v_key = ctk.CTkEntry(tab_vigenere)
        v_key.grid(row=1, column=1, padx=10, pady=5, sticky="ew")

        v_output = ctk.CTkTextbox(tab_vigenere, height=100)
        v_output.grid(row=3, column=1, padx=10, pady=5, sticky="ew")

        def enc_vig():
            txt, k = v_text.get("1.0", "end-1c").strip(), v_key.get().strip()
            res = CryptoEngine.vigenere_cipher(txt, k)
            v_output.delete("1.0", "end")
            v_output.insert("1.0", res)

        def dec_vig():
            txt, k = v_text.get("1.0", "end-1c").strip(), v_key.get().strip()
            res = CryptoEngine.vigenere_cipher(txt, k, decrypt=True)
            v_output.delete("1.0", "end")
            v_output.insert("1.0", res)

        v_btn_box = ctk.CTkFrame(tab_vigenere, fg_color="transparent")
        v_btn_box.grid(row=2, column=1, pady=5, sticky="w")
        ctk.CTkButton(v_btn_box, text="🔒 Vigenère Encrypt", command=enc_vig, fg_color="#1f538d").pack(side="left", padx=5)
        ctk.CTkButton(v_btn_box, text="🔓 Vigenère Decrypt", command=dec_vig, fg_color="#2fa572").pack(side="left", padx=5)

        return frame


if __name__ == "__main__":
    app = PyCipherVaultApp()
    app.mainloop()
