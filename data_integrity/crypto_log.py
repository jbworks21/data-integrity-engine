# data_integrity_engine/crypto_log.py

import os
import sys
import base64
import json
import datetime
import sqlite3
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

def initialize_database(db_path="secure_vault.db"):
    """
    Initializes a localized SQLite database file and establishes a structured
    table to index timestamps and encrypted payloads.
    """
    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()
    
    # Create the logging table if it doesn't exist yet
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS encrypted_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            ciphertext TEXT NOT NULL
        )
    """)
    
    connection.commit()
    connection.close()

def save_log_entry(ciphertext: str, db_path="secure_vault.db"):
    """Inserts a fresh timestamped ciphertext string into the database ledger."""
    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()
    
    current_time = datetime.datetime.utcnow().isoformat()
    
    cursor.execute(
        "INSERT INTO encrypted_logs (timestamp, ciphertext) VALUES (?, ?)",
        (current_time, ciphertext)
    )
    
    connection.commit()
    connection.close()
    print(f"[DATABASE] Log record successfully persisted at: {current_time} UTC")

def read_all_log_entries(db_path="secure_vault.db"):
    """Retrieves all indexed records sequentially from the database."""
    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()
    
    cursor.execute("SELECT id, timestamp, ciphertext FROM encrypted_logs ORDER BY id ASC")
    records = cursor.fetchall()
    
    connection.close()
    return records

if __name__ == "__main__":
    # Ensure the local database structure is initialized before executing commands
    database_file = "secure_vault.db"
    initialize_database(database_file)

    if len(sys.argv) < 3:
        print("\n[USAGE ERROR] Explicit parameters required:")
        print("  Encrypt & Save: python crypto_log.py encrypt 'your message' 'your_password'")
        print("  View & Decrypt:  python crypto_log.py view 'your_password'")
        sys.exit(1)
        
    action = sys.argv[1].lower()
    
    if action == "encrypt":
        if len(sys.argv) < 4:
            print("[ERROR] Password parameter missing.")
            sys.exit(1)
            
        payload = sys.argv[2]
        password = sys.argv[3]
        
        encrypted_bytes = encrypt_message(payload, password)
        encoded_output = base64.b64encode(encrypted_bytes).decode()
        
        # PERSIST TO DATABASE
        save_log_entry(encoded_output, database_file)
        print(f"\n[CIPHERTEXT STORED]:\n{encoded_output}")
        
    elif action == "view":
        password = sys.argv[2]
        stored_entries = read_all_log_entries(database_file)
        
        print(f"\n--- Decrypting Secure Vault Ledger: {len(stored_entries)} Records Found ---")
        for entry_id, timestamp, cipher_text in stored_entries:
            try:
                raw_bytes = base64.b64decode(cipher_text)
                decrypted_output = decrypt_message(raw_bytes, password)
                print(f"Record #{entry_id} [{timestamp}]: {decrypted_output}")
            except Exception:
                print(f"Record #{entry_id} [{timestamp}]: [ERROR - Decryption Failed. Invalid Key]")
    else:
        print(f"[ERROR] Unknown instruction protocol: {action}")

