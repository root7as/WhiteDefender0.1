'''
WhiteDefender 0.1
Devlet Düzeyinde Güvenlik İçin Tasarlanmış Uçtan Uca Şifreli Belge Paylaşım Sistemi
Owned By Root7as
'''

import os
import base64
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from datetime import datetime

class WhiteDefender:
    def __init__(self, master_password: str):
        self.backend = default_backend()
        self.salt = os.urandom(16)
        self.key = self.derive_key(master_password)
        print("[+] WhiteDefender Initialized.")

    def derive_key(self, password: str) -> bytes:
        print("[*] Deriving encryption key...")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(password.encode())

    def encrypt_file(self, filepath: str, output_path: str):
        print(f"[*] Encrypting {filepath}...")
        with open(filepath, 'rb') as f:
            plaintext = f.read()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        with open(output_path, 'wb') as f:
            f.write(self.salt + iv + ciphertext)

        print(f"[+] Encrypted file saved to {output_path}.")

    def decrypt_file(self, encrypted_path: str, output_path: str):
        print(f"[*] Decrypting {encrypted_path}...")
        with open(encrypted_path, 'rb') as f:
            data = f.read()
        salt, iv, ciphertext = data[:16], data[16:32], data[32:]

        # Re-derive key with stored salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        key = kdf.derive(input("Master Password: ").encode())

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        with open(output_path, 'wb') as f:
            f.write(plaintext)

        print(f"[+] Decrypted file saved to {output_path}.")

# Örnek Kullanım:
if __name__ == '__main__':
    defender = WhiteDefender(master_password="devletSırrı2025")
    defender.encrypt_file("gizli_rapor.pdf", "rapor.enc")
    defender.decrypt_file("rapor.enc", "rapor_cozuldu.pdf")
