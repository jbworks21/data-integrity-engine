# crypto_log.py
import os
import sys
import base64
import json
import datetime
import sqlite3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

PBKDF2_ITERATIONS = 600_000          # OWASP 2023 guidance for PBKDF2-HMAC-SHA-256


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode())


def encrypt_message(message: str, password: str) -> bytes:
    salt = os.urandom(16)
    iv = os.urandom(12)
    key = derive_key(password, salt)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return salt + iv + encryptor.tag + ciphertext


def decrypt_message(packed_data: bytes, password: str) -> str:
    try:
        salt = packed_data[:16]
        iv = packed_data[16:28]
        tag = packed_data[28:44]
        ciphertext = packed_data[44:]
        key = derive_key(password, salt)
        decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag)).decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode()
    except ValueError as e:
        # GCM tag mismatch: wrong password or corrupted ciphertext.
        return f"[ERROR] Authentication failure: {e}"
    except Exception as e:
        return f"[ERROR] Unexpected decryption failure: {e}"


def initialize_database(db_path: str = "secure_vault.db") -> None:
    """Create all tables used by the project."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS encrypted_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            ciphertext TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS project_beta_feeds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_url TEXT NOT NULL,
            http_status_code INTEGER NOT NULL,
            payload_content TEXT,
            sha256_checksum TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            source TEXT
        )
    """)
    conn.commit()
    conn.close()


def save_log_entry(ciphertext: str, db_path: str = "secure_vault.db") -> None:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    cursor.execute(
        "INSERT INTO encrypted_logs (timestamp, ciphertext) VALUES (?, ?)",
        (ts, ciphertext),
    )
    conn.commit()
    conn.close()
    print(f"[DATABASE] Log record persisted at: {ts} UTC")


def save_alert_entry(message: str, severity: str = "INFO",
                     source: str = None, db_path: str = "secure_vault.db") -> None:
    """Plaintext operational alert. Distinct from the encrypted_logs table."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    cursor.execute(
        "INSERT INTO security_alerts (timestamp, severity, message, source) "
        "VALUES (?, ?, ?, ?)",
        (ts, severity, message, source),
    )
    conn.commit()
    conn.close()
    print(f"[DATABASE] Alert ({severity}) persisted at: {ts} UTC")


def read_all_log_entries(db_path: str = "secure_vault.db"):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT id, timestamp, ciphertext FROM encrypted_logs ORDER BY id ASC")
    records = cursor.fetchall()
    conn.close()
    return records


if __name__ == "__main__":
    import getpass

    database_file = "secure_vault.db"
    initialize_database(database_file)

    if len(sys.argv) < 2:
        print("\nUsage:")
        print("  Encrypt: python crypto_log.py encrypt")
        print("  View:    python crypto_log.py view")
        sys.exit(1)

    action = sys.argv[1].lower()

    if action == "encrypt":
        payload = input("Message to encrypt: ")
        password = getpass.getpass("Password: ")
        encrypted_bytes = encrypt_message(payload, password)
        encoded_output = base64.b64encode(encrypted_bytes).decode()
        save_log_entry(encoded_output, database_file)
        print(f"\n[CIPHERTEXT STORED]:\n{encoded_output}")
    elif action == "view":
        password = getpass.getpass("Password: ")
        entries = read_all_log_entries(database_file)
        print(f"\n--- Vault: {len(entries)} Records ---")
        for entry_id, timestamp, cipher_text in entries:
            raw = base64.b64decode(cipher_text)
            print(f"Record #{entry_id} [{timestamp}]: {decrypt_message(raw, password)}")
    else:
        print(f"[ERROR] Unknown action: {action}")
        sys.exit(1)
