import os
import unittest
from crypto_engine import CryptoEngine

class TestCryptoEngine(unittest.TestCase):
    def test_aes_text(self):
        password = "SuperSecretPassword123!"
        plaintext = "Hello, Python Cryptography Studio!"
        ciphertext = CryptoEngine.encrypt_text_aes(plaintext, password)
        self.assertNotEqual(plaintext, ciphertext)
        decrypted = CryptoEngine.decrypt_text_aes(ciphertext, password)
        self.assertEqual(plaintext, decrypted)

    def test_aes_file(self):
        password = "FilePassword456!"
        input_file = "test_in.txt"
        enc_file = "test_enc.bin"
        dec_file = "test_dec.txt"

        content = "Binary test file content for AES-256 file encryption."
        with open(input_file, "w") as f:
            f.write(content)

        CryptoEngine.encrypt_file_aes(input_file, enc_file, password)
        CryptoEngine.decrypt_file_aes(enc_file, dec_file, password)

        with open(dec_file, "r") as f:
            read_content = f.read()

        self.assertEqual(content, read_content)

        # Cleanup
        for path in [input_file, enc_file, dec_file]:
            if os.path.exists(path):
                os.remove(path)

    def test_rsa_keys_and_encryption(self):
        priv_pem, pub_pem = CryptoEngine.generate_rsa_keys(2048)
        self.assertIn("BEGIN PRIVATE KEY", priv_pem)
        self.assertIn("BEGIN PUBLIC KEY", pub_pem)

        message = "Confidential RSA Payload"
        cipher = CryptoEngine.rsa_encrypt(message, pub_pem)
        decrypted = CryptoEngine.rsa_decrypt(cipher, priv_pem)
        self.assertEqual(message, decrypted)

    def test_hashing_and_hmac(self):
        h = CryptoEngine.calculate_hash("test", algorithm="sha256")
        self.assertEqual(len(h), 64)

        sig = CryptoEngine.calculate_hmac("test_payload", secret_key="my_key", algorithm="sha256")
        self.assertEqual(len(sig), 64)

    def test_entropy(self):
        analysis = CryptoEngine.analyze_password("P@ssw0rd12345!#")
        self.assertGreater(analysis["entropy_bits"], 50)
        self.assertTrue(analysis["has_upper"])
        self.assertTrue(analysis["has_lower"])
        self.assertTrue(analysis["has_digit"])
        self.assertTrue(analysis["has_special"])

    def test_caesar(self):
        enc = CryptoEngine.caesar_cipher("HELLO", 3)
        self.assertEqual(enc, "KHOOR")
        dec = CryptoEngine.caesar_cipher("KHOOR", 3, decrypt=True)
        self.assertEqual(dec, "HELLO")
        brute = CryptoEngine.caesar_bruteforce("KHOOR")
        self.assertEqual(len(brute), 25)
        # Shift 3 decryption should match HELLO
        shift3 = next(text for s, text in brute if s == 3)
        self.assertEqual(shift3, "HELLO")

    def test_vigenere(self):
        enc = CryptoEngine.vigenere_cipher("ATTACKATDAWN", "LEMON")
        self.assertEqual(enc, "LXFOPVEFRNHR")
        dec = CryptoEngine.vigenere_cipher("LXFOPVEFRNHR", "LEMON", decrypt=True)
        self.assertEqual(dec, "ATTACKATDAWN")

if __name__ == "__main__":
    unittest.main()
