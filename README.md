# 🔒 PyCipher Vault — Python Cryptography Studio

A client-side desktop cryptography and security studio built in 100% Python with modern GUI aesthetics (`customtkinter`).

## 🚀 Features

- **🔐 AES-256 Symmetric & File Encryption**: AES-256-GCM + PBKDF2 HMAC-SHA256 text & file vault.
- **🔑 RSA Key Studio**: 2048/4096-bit RSA keypair generator and OAEP encryption/decryption.
- **🖼️ Image Steganography**: Embed secret text in PNG/BMP images using LSB encoding with optional AES protection.
- **⚡ Multi-Algorithm Hashing & HMAC**: MD5, SHA-1, SHA-256, SHA-512, SHA3-256, BLAKE2b with custom salt & HMAC key support.
- **📊 Password Entropy Analyzer**: Real-time password strength, entropy ($H$), and crack time estimation.
- **📜 Classic Ciphers & Auto Cracker**: Caesar cipher shift + automated 25-shift brute-force cracker, Vigenère cipher.

## 📦 Requirements & Setup

```bash
pip install customtkinter cryptography pillow
```

## 🛠️ Usage

Run the GUI application:

```bash
python main.py
```

Run unit tests:

```bash
python test_crypto_engine.py
```
