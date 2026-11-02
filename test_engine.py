# data_integrity_engine/test_engine.py

import unittest
import os
import tempfile
import base64
import sqlite3
import hashlib
import re
from core import calculate_file_hash
from crypto_log import encrypt_message, decrypt_message, initialize_database, save_log_entry, read_all_log_entries
from sig_engine import generate_keys, sign_merkle_root, verify_merkle_root

class TestDataIntegrityEngine(unittest.TestCase):
    
    def test_file_hashing(self):
        """Validates chunked SHA-256 calculation and hex digest formatting."""
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"test data integrity payload")
            tf_path = tf.name
        try:
            file_hash = calculate_file_hash(tf_path)
            self.assertIsNotNone(file_hash)
            self.assertEqual(len(file_hash), 64)
            expected_hash = hashlib.sha256(b"test data integrity payload").hexdigest()
            self.assertEqual(file_hash, expected_hash)
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)

    def test_crypto_roundtrip(self):
        """Confirms AES-256 GCM encryption/decryption roundtrip data integrity."""
        message = "Confidential telemetry record"
        password = "SecureMasterPassword123!"
        
        encrypted_payload = encrypt_message(message, password)
        self.assertIsInstance(encrypted_payload, bytes)
        
        decrypted_text = decrypt_message(encrypted_payload, password)
        self.assertEqual(message, decrypted_text)

    def test_database_persistence(self):
        """Verifies SQLite3 database initialization, writing, and log querying."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as db:
            db_path = db.name
        try:
            initialize_database(db_path)
            
            test_ciphertext = "dGVzdF9jaXBoZXJ0ZXh0X2RhdGE="
            save_log_entry(test_ciphertext, db_path)
            
            records = read_all_log_entries(db_path)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0][2], test_ciphertext)
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)

    def test_telemetry_anomaly_detection(self):
        """Evaluates regex log parsing and threat threshold detection."""
        log_line = '192.168.1.50 - - [01/Nov/2026:12:00:00 +0000] "GET /admin HTTP/1.1" 403 512'
        pattern = re.compile(r'(?P<ip>\S+) .* "(?P<method>\S+) (?P<endpoint>\S+) (?P<protocol>\S+)" (?P<status>\d+)')
        match = pattern.search(log_line)
        
        self.assertIsNotNone(match)
        self.assertEqual(match.group('ip'), '192.168.1.50')
        self.assertEqual(match.group('status'), '403')

class TestSigmaEngine(unittest.TestCase):
    
    def setUp(self):
        """Setup temporary test key paths for Project Sigma."""
        self.priv_path = "test_private.pem"
        self.pub_path = "test_public.pem"
        generate_keys(self.priv_path, self.pub_path)
        
    def tearDown(self):
        """Clean up temporary test keys."""
        if os.path.exists(self.priv_path):
            os.remove(self.priv_path)
        if os.path.exists(self.pub_path):
            os.remove(self.pub_path)
            
    def test_sig_generation_and_roundtrip(self):
        """Verify that signing a Merkle root and checking it with the public key passes."""
        test_root = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        sig_bytes = sign_merkle_root(test_root, self.priv_path)
        sig_b64 = base64.b64encode(sig_bytes).decode()
        
        is_valid = verify_merkle_root(test_root, sig_b64, self.pub_path)
        self.assertTrue(is_valid, "Cryptographic signature roundtrip failed.")
        
    def test_sig_tamper_detection(self):
        """Verify that modifying the Merkle root causes signature validation to fail."""
        original_root = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        tampered_root = "1111111111fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        
        sig_bytes = sign_merkle_root(original_root, self.priv_path)
        sig_b64 = base64.b64encode(sig_bytes).decode()
        
        is_valid = verify_merkle_root(tampered_root, sig_b64, self.pub_path)
        self.assertFalse(is_valid, "Tampered root incorrectly accepted as valid.")

if __name__ == "__main__":
    unittest.main()
