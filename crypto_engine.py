import os
import base64
import math
import hashlib
import hmac
from typing import Tuple, List, Dict, Union
from PIL import Image

# Third party cryptography imports
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


class CryptoEngine:
    """Core Cryptographic & Analysis Engine for PyCipher Vault."""

    # ------------------------------------------------------------------
    # 1. AES-256 Symmetric & File Encryption (AES-GCM + PBKDF2)
    # ------------------------------------------------------------------
    @staticmethod
    def _derive_aes_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))

    @classmethod
    def encrypt_text_aes(cls, plaintext: str, password: str) -> str:
        """Encrypts plaintext using AES-256-GCM derived from password."""
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = cls._derive_aes_key(password, salt)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        # Payload format: 16-byte salt + 12-byte nonce + ciphertext (includes 16-byte tag)
        payload = salt + nonce + ciphertext
        return base64.b64encode(payload).decode('utf-8')

    @classmethod
    def decrypt_text_aes(cls, ciphertext_b64: str, password: str) -> str:
        """Decrypts AES-256-GCM ciphertext payload derived from password."""
        try:
            payload = base64.b64decode(ciphertext_b64.encode('utf-8'))
            if len(payload) < 28:
                raise ValueError("Invalid payload length.")
            salt = payload[:16]
            nonce = payload[16:28]
            ciphertext = payload[28:]
            key = cls._derive_aes_key(password, salt)
            aesgcm = AESGCM(key)
            decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
            return decrypted_bytes.decode('utf-8')
        except Exception as e:
            raise ValueError("Decryption failed. Invalid password or corrupted ciphertext.") from e

    @classmethod
    def encrypt_file_aes(cls, input_file_path: str, output_file_path: str, password: str):
        """Encrypts any binary file using AES-256-GCM."""
        with open(input_file_path, 'rb') as f:
            data = f.read()

        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = cls._derive_aes_key(password, salt)
        aesgcm = AESGCM(key)
        encrypted_data = aesgcm.encrypt(nonce, data, None)

        with open(output_file_path, 'wb') as f:
            f.write(salt + nonce + encrypted_data)

    @classmethod
    def decrypt_file_aes(cls, input_file_path: str, output_file_path: str, password: str):
        """Decrypts an AES-256-GCM encrypted file."""
        with open(input_file_path, 'rb') as f:
            payload = f.read()

        if len(payload) < 28:
            raise ValueError("File is corrupted or not a valid encrypted file.")

        salt = payload[:16]
        nonce = payload[16:28]
        encrypted_data = payload[28:]
        key = cls._derive_aes_key(password, salt)
        aesgcm = AESGCM(key)
        try:
            decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)
            with open(output_file_path, 'wb') as f:
                f.write(decrypted_data)
        except Exception as e:
            raise ValueError("File decryption failed. Invalid password or corrupted file.") from e

    # ------------------------------------------------------------------
    # 2. RSA Asymmetric Key Management & Encryption
    # ------------------------------------------------------------------
    @staticmethod
    def generate_rsa_keys(key_size: int = 2048) -> Tuple[str, str]:
        """Generates RSA Private and Public key pair in PEM format."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        return private_pem, public_pem

    @staticmethod
    def rsa_encrypt(message: str, public_key_pem: str) -> str:
        """Encrypts message using RSA Public Key with OAEP padding."""
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            ciphertext = public_key.encrypt(
                message.encode('utf-8'),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return base64.b64encode(ciphertext).decode('utf-8')
        except Exception as e:
            raise ValueError(f"RSA Encryption failed: {e}") from e

    @staticmethod
    def rsa_decrypt(ciphertext_b64: str, private_key_pem: str) -> str:
        """Decrypts ciphertext using RSA Private Key with OAEP padding."""
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode('utf-8'),
                password=None,
                backend=default_backend()
            )
            ciphertext = base64.b64decode(ciphertext_b64.encode('utf-8'))
            plaintext_bytes = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return plaintext_bytes.decode('utf-8')
        except Exception as e:
            raise ValueError("RSA Decryption failed. Invalid private key or ciphertext.") from e

    # ------------------------------------------------------------------
    # 3. LSB Image Steganography
    # ------------------------------------------------------------------
    @classmethod
    def hide_text_in_image(cls, image_path: str, output_path: str, secret_text: str, password: str = "") -> None:
        """Encodes text into image LSB. Optional password encrypts secret before embedding."""
        if password:
            text_to_hide = "ENC:" + cls.encrypt_text_aes(secret_text, password)
        else:
            text_to_hide = "RAW:" + secret_text

        # Append sentinel standard delimiter
        text_to_hide += "###END_PYCIPHER###"
        binary_data = ''.join(format(ord(char), '08b') for char in text_to_hide)
        data_len = len(binary_data)

        img = Image.open(image_path).convert('RGB')
        pixels = list(img.getdata())

        if data_len > len(pixels) * 3:
            raise ValueError("Image is too small to embed this text payload.")

        new_pixels = []
        data_idx = 0

        for pixel in pixels:
            r, g, b = pixel
            if data_idx < data_len:
                r = (r & ~1) | int(binary_data[data_idx])
                data_idx += 1
            if data_idx < data_len:
                g = (g & ~1) | int(binary_data[data_idx])
                data_idx += 1
            if data_idx < data_len:
                b = (b & ~1) | int(binary_data[data_idx])
                data_idx += 1
            new_pixels.append((r, g, b))

        stego_img = Image.new(img.mode, img.size)
        stego_img.putdata(new_pixels)
        stego_img.save(output_path, 'PNG')

    @classmethod
    def extract_text_from_image(cls, image_path: str, password: str = "") -> str:
        """Extracts text hidden in image LSB. Decrypts with password if required."""
        img = Image.open(image_path).convert('RGB')
        pixels = list(img.getdata())

        binary_chars = []
        current_byte = ""

        delimiter = "###END_PYCIPHER###"
        extracted_str = ""

        for pixel in pixels:
            for color in pixel:
                current_byte += str(color & 1)
                if len(current_byte) == 8:
                    char = chr(int(current_byte, 2))
                    extracted_str += char
                    current_byte = ""
                    if extracted_str.endswith(delimiter):
                        clean_str = extracted_str[:-len(delimiter)]
                        if clean_str.startswith("ENC:"):
                            enc_payload = clean_str[4:]
                            if not password:
                                raise ValueError("This message is encrypted. Please provide the decryption password.")
                            return cls.decrypt_text_aes(enc_payload, password)
                        elif clean_str.startswith("RAW:"):
                            return clean_str[4:]
                        else:
                            return clean_str

        raise ValueError("No hidden PyCipher steganography payload found in image.")

    # ------------------------------------------------------------------
    # 4. Multi-Algorithm Hashing & HMAC
    # ------------------------------------------------------------------
    @staticmethod
    def calculate_hash(data: Union[str, bytes], algorithm: str = "sha256", salt: str = "") -> str:
        """Calculates hash digest for text or bytes with optional salt."""
        if isinstance(data, str):
            payload = (data + salt).encode('utf-8')
        else:
            payload = data + salt.encode('utf-8')

        algo = algorithm.lower().replace("-", "")
        if hasattr(hashlib, algo):
            hash_func = getattr(hashlib, algo)
            return hash_func(payload).hexdigest()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

    @staticmethod
    def calculate_hmac(data: Union[str, bytes], secret_key: str, algorithm: str = "sha256") -> str:
        """Calculates HMAC signature for data using secret key."""
        if isinstance(data, str):
            payload = data.encode('utf-8')
        else:
            payload = data

        algo = algorithm.lower().replace("-", "")
        if hasattr(hashlib, algo):
            hash_module = getattr(hashlib, algo)
            return hmac.new(secret_key.encode('utf-8'), payload, hash_module).hexdigest()
        else:
            raise ValueError(f"Unsupported HMAC algorithm: {algorithm}")

    # ------------------------------------------------------------------
    # 5. Password Entropy & Strength Analyzer
    # ------------------------------------------------------------------
    @staticmethod
    def analyze_password(password: str) -> Dict[str, Union[int, float, str, bool]]:
        """Calculates password entropy, estimated crack time, and strength metrics."""
        if not password:
            return {
                "length": 0,
                "charset_size": 0,
                "entropy_bits": 0.0,
                "score": 0,
                "rating": "Empty",
                "crack_time": "Instant",
                "has_upper": False,
                "has_lower": False,
                "has_digit": False,
                "has_special": False
            }

        length = len(password)
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)

        charset_size = 0
        if has_lower:
            charset_size += 26
        if has_upper:
            charset_size += 26
        if has_digit:
            charset_size += 10
        if has_special:
            charset_size += 33

        # Entropy formula: H = L * log2(N)
        entropy = length * math.log2(charset_size) if charset_size > 0 else 0

        # Estimated crack time assuming 10 billion guesses/sec
        combinations = (charset_size ** length) if charset_size > 0 else 0
        guesses_per_sec = 10_000_000_000
        seconds = combinations / guesses_per_sec if guesses_per_sec > 0 else 0

        if seconds < 1:
            crack_time = "Instant (< 1 second)"
        elif seconds < 60:
            crack_time = f"{int(seconds)} seconds"
        elif seconds < 3600:
            crack_time = f"{int(seconds // 60)} minutes"
        elif seconds < 86400:
            crack_time = f"{int(seconds // 3600)} hours"
        elif seconds < 31536000:
            crack_time = f"{int(seconds // 86400)} days"
        elif seconds < 31536000 * 1000:
            crack_time = f"{int(seconds // 31536000)} years"
        elif seconds < 31536000 * 1_000_000:
            crack_time = f"{int(seconds // (31536000 * 1000))} thousand years"
        elif seconds < 31536000 * 1_000_000_000:
            crack_time = f"{int(seconds // (31536000 * 1_000_000))} million years"
        else:
            crack_time = "Trillions of years (Unbreakable)"

        # Score & Rating
        if entropy < 28:
            rating = "Very Weak 🔴"
            score = min(int(entropy * 1.5), 25)
        elif entropy < 36:
            rating = "Weak 🟠"
            score = 25 + int((entropy - 28) * 2.5)
        elif entropy < 60:
            rating = "Moderate 🟡"
            score = 50 + int((entropy - 36) * 1.0)
        elif entropy < 80:
            rating = "Strong 🟢"
            score = 75 + int((entropy - 60) * 0.75)
        else:
            rating = "Ultra Strong 🛡️"
            score = 100

        score = max(0, min(100, score))

        return {
            "length": length,
            "charset_size": charset_size,
            "entropy_bits": round(entropy, 2),
            "score": score,
            "rating": rating,
            "crack_time": crack_time,
            "has_upper": has_upper,
            "has_lower": has_lower,
            "has_digit": has_digit,
            "has_special": has_special
        }

    # ------------------------------------------------------------------
    # 6. Classic Ciphers & Auto Brute-force Cracker
    # ------------------------------------------------------------------
    @staticmethod
    def caesar_cipher(text: str, shift: int, decrypt: bool = False) -> str:
        """Encodes or decodes text using Caesar shift cipher."""
        if decrypt:
            shift = -shift
        result = []
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                shifted = (ord(char) - base + shift) % 26
                result.append(chr(base + shifted))
            else:
                result.append(char)
        return "".join(result)

    @classmethod
    def caesar_bruteforce(cls, ciphertext: str) -> List[Tuple[int, str]]:
        """Generates all 25 possible Caesar decryption shifts."""
        results = []
        for shift in range(1, 26):
            decrypted = cls.caesar_cipher(ciphertext, shift, decrypt=True)
            results.append((shift, decrypted))
        return results

    @staticmethod
    def vigenere_cipher(text: str, key: str, decrypt: bool = False) -> str:
        """Vigenère cipher encryption / decryption."""
        if not key:
            return text
        key = key.upper()
        result = []
        key_idx = 0
        for char in text:
            if char.isalpha():
                shift = ord(key[key_idx % len(key)]) - ord('A')
                if decrypt:
                    shift = -shift
                base = ord('A') if char.isupper() else ord('a')
                result.append(chr((ord(char) - base + shift) % 26 + base))
                key_idx += 1
            else:
                result.append(char)
        return "".join(result)

    @staticmethod
    def rail_fence_cipher(text: str, rails: int, decrypt: bool = False) -> str:
        """Rail Fence cipher implementation."""
        if rails <= 1:
            return text

        if not decrypt:
            fence = [[] for _ in range(rails)]
            rail = 0
            direction = 1
            for char in text:
                fence[rail].append(char)
                rail += direction
                if rail == 0 or rail == rails - 1:
                    direction = -direction
            return "".join("".join(r) for r in fence)
        else:
            # Decryption logic
            fence = [['\n' for _ in range(len(text))] for _ in range(rails)]
            rail = 0
            direction = 1
            for i in range(len(text)):
                fence[rail][i] = '*'
                rail += direction
                if rail == 0 or rail == rails - 1:
                    direction = -direction

            idx = 0
            for r in range(rails):
                for c in range(len(text)):
                    if fence[r][c] == '*' and idx < len(text):
                        fence[r][c] = text[idx]
                        idx += 1

            result = []
            rail = 0
            direction = 1
            for i in range(len(text)):
                result.append(fence[rail][i])
                rail += direction
                if rail == 0 or rail == rails - 1:
                    direction = -direction
            return "".join(result)
