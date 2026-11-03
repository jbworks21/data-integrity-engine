# data_integrity_engine/test_engine.py

import unittest
import os
import tempfile
import sqlite3
import base64

# Import existing functional subsystems
from core import calculate_file_hash, generate_system_manifest
from crypto_log import encrypt_message, decrypt_message, initialize_database, save_log_entry
from sig_engine_pqc import generate_pqc_key_pair, sign_merkle_root_pqc, verify_merkle_root_pqc

class TestDataIntegrityEngine(unittest.TestCase):
    """
    Unified Automated Unit Test Suite for the Data Integrity Engine.
    Validates cryptographic hashing, encryption, database persistence, and post-quantum signatures.
    """

    def setUp(self):
        """Prepares isolated temporary working directories and files for testing."""
        self.test_dir = tempfile.TemporaryDirectory()
        self.sample_file_path = os.path.join(self.test_dir.name, "test_target.txt")
        
        with open(self.sample_file_path, "w") as f:
            f.write("Autonomous engineering verification payload.")

    def tearDown(self):
        """Cleans up temporary testing directories after execution completion."""
        self.test_dir.cleanup()

    def test_file_hashing(self):
        """Validates that 4096-byte chunked SHA-256 calculation produces correct hex digests."""
        file_hash = calculate_file_hash(self.sample_file_path)
        self.assertIsNotNone(file_hash, "Hashing engine failed to return a digest.")
        self.assertEqual(len(file_hash), 64, "SHA-256 digest length must be exactly 64 hex characters.")

    def test_aes_gcm_encryption_roundtrip(self):
        """Confirms payload encryption and decryption roundtrips via AES-256 GCM and PBKDF2."""
        secret_message = "Confidential operational ledger record."
        master_password = "secure_test_password_123"
        
        encrypted_payload = encrypt_message(secret_message, master_password)
        self.assertIsInstance(encrypted_payload, bytes, "Encrypted payload must be returned in bytes format.")
        
        decrypted_message = decrypt_message(encrypted_payload, master_password)
        self.assertEqual(secret_message, decrypted_message, "Decrypted message text does not match the original input.")

    def test_sqlite_database_persistence(self):
        """Verifies localized SQLite3 database schema creation, writing, and query retrieval."""
        db_fd, db_path = tempfile.mkstemp()
        os.close(db_fd)
        
        try:
            initialize_database(db_path)
            sample_ciphertext = "dGVzdF9jaXBoZXJ0ZXh0X2Jhc2U2NF9zdHJpbmc="
            save_log_entry(sample_ciphertext, db_path)
            
            connection = sqlite3.connect(db_path)
            cursor = connection.cursor()
            cursor.execute("SELECT ciphertext FROM encrypted_logs")
            row = cursor.fetchone()
            connection.close()
            
            self.assertIsNotNone(row, "Database record query returned empty result.")
            self.assertEqual(row[0], sample_ciphertext, "Persisted ciphertext does not match retrieved data.")
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)

    def test_post_quantum_mldsa_signing(self):
        """Evaluates post-quantum ML-DSA-65 key generation, signing, and signature verification."""
        # 1. Generate post-quantum key pair
        priv_key, pub_key = generate_pqc_key_pair()
        
        # 2. Define a sample Merkle root hash string
        test_merkle_root = "393a1931c0843bfc6c070a5449a306f63c840d26a7b488665f5370305231fe90"
        
        # 3. Sign the root using the post-quantum private key
        signature_b64 = sign_merkle_root_pqc(test_merkle_root, priv_key)
        self.assertIsInstance(signature_b64, str, "Post-quantum signature must be a string format.")
        
        # 4. Verify the valid signature against the public key
        is_valid = verify_merkle_root_pqc(test_merkle_root, signature_b64, pub_key)
        self.assertTrue(is_valid, "Valid post-quantum ML-DSA signature verification failed.")
        
        # 5. Confirm negative tampering detection (altered root hash should fail verification)
        tampered_root = "0000000000000000000000000000000000000000000000000000000000000000"
        is_tampered_valid = verify_merkle_root_pqc(tampered_root, signature_b64, pub_key)
        self.assertFalse(is_tampered_valid, "Security alert: Tampered root hash incorrectly passed post-quantum verification.")

if __name__ == "__main__":
    unittest.main()
