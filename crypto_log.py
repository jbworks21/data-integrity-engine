# data_integrity_engine/crypto_log.py

import os
import sys
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
    
    # Pack salt, iv, tag, and ciphertext into a single deliverable bytes payload
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
    # Ensure minimum required positional arguments are provided via CLI
    if len(sys.argv) < 4:
        print("\n[USAGE ERROR] Explicit parameters required:")
        print("  Encrypt: python crypto_log.py encrypt 'your message' 'your_password'")
        print("  Decrypt: python crypto_log.py decrypt 'raw_ciphertext_string' 'your_password'")
        sys.exit(1)
        
    action = sys.argv[1].lower()
    payload = sys.argv[2]
    password = sys.argv[3]
    
    if action == "encrypt":
        encrypted_bytes = encrypt_message(payload, password)
        # Encode binary payload to a clean, copy-pasteable alphanumeric text string
        encoded_output = base64.b64encode(encrypted_bytes).decode()
        print(f"\n[CIPHERTEXT]\n{encoded_output}")
        
    elif action == "decrypt":
        try:
            # Decode the text string back into raw bytes prior to decryption
            raw_bytes = base64.b64decode(payload)
            decrypted_output = decrypt_message(raw_bytes, password)
            print(f"\n[DECRYPTED PLAINTEXT]\n{decrypted_output}")
        except Exception as e:
            print(f"[ERROR] Invalid data stream or corrupted padding: {str(e)}")
    else:
        print(f"[ERROR] Unknown instruction protocol: {action}")
