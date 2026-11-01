# data_integrity_engine/crypto_log.py

import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a secure 256-bit AES key from a text password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    return kdf.derive(password.encode())

def encrypt_message(message: str, password: str) -> bytes:
    """Encrypts text using AES-256 in GCM mode with a unique initialization vector."""
    salt = os.urandom(16)
    iv = os.urandom(12)
    key = derive_key(password, salt)
    
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv)
    ).encryptor()
    
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    
    # Pack salt, iv, tag, and ciphertext into a single deliverable
    return salt + iv + encryptor.tag + ciphertext

def decrypt_message(packed_data: bytes, password: str) -> str:
    """Unpacks and decrypts AES-256 GCM ciphertext using the master password."""
    try:
        salt = packed_data[:16]
        iv = packed_data[16:28]
        tag = packed_data[28:44]
        ciphertext = packed_data[44:]
        
        key = derive_key(password, salt)
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag)
        ).decryptor()
        
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode()
    except Exception:
        return "[ERROR] Decryption failed. Invalid key or corrupted payload."

if __name__ == "__main__":
    print("--- Cryptographic Engine Online ---")
    secret_phrase = "System architecture verified. Ground reality locked."
    master_pass = "ControlTheNarrative2026"
    
    # Test execution
    encrypted_payload = encrypt_message(secret_phrase, master_pass)
    print(f"\n[CIPHERTEXT RAW DATA]:\n{base64.b64encode(encrypted_payload).decode()}")
    
    decrypted_text = decrypt_message(encrypted_payload, master_pass)
    print(f"\n[DECRYPTED PLAINTEXT]:\n{decrypted_text}")

