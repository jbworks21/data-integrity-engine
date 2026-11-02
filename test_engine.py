# data_integrity_engine/test_engine.py

import unittest
import os
import tempfile
import json

from core import calculate_file_hash, generate_system_manifest
from crypto_log import encrypt_message, decrypt_message, initialize_database, save_log_entry, read_all_log_entries
from network_monitor import parse_and_analyze_logs

class TestDataIntegrityEngine(unittest.TestCase):
    
    def setUp(self):
        # Create a temporary directory and sample file for testing file integrity
        self.test_dir = tempfile.TemporaryDirectory()
        self.test_file_path = os.path.join(self.test_dir.name, "sample.txt")
        with open(self.test_file_path, "w", encoding="utf-8") as f:
            f.write("Operational security test payload.")
            
        # Initialize a temporary isolated SQLite vault database for crypto tests
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        initialize_database(self.db_path)

    def tearDown(self):
        self.test_dir.cleanup()
        os.close(self.db_fd)
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_file_hashing(self):
        """Verify SHA-256 chunked calculation returns a valid 64-character hex digest."""
        file_hash = calculate_file_hash(self.test_file_path)
        self.assertIsNotNone(file_hash)
        self.assertEqual(len(file_hash), 64)

    def test_encryption_decryption(self):
        """Verify AES-256 GCM encryption and decryption roundtrip integrity."""
        message = "Confidential command telemetry."
        password = "MasterKey2026!"
        encrypted = encrypt_message(message, password)
        self.assertIsInstance(encrypted, bytes)
        
        decrypted = decrypt_message(encrypted, password)
        self.assertEqual(decrypted, message)

    def test_database_persistence(self):
        """Verify SQLite3 database logging and sequential record retrieval."""
        ciphertext = "dGVzdGNpcGhlcnRleHRwYXlsb2Fk" # Mock base64 ciphertext
        save_log_entry(ciphertext, self.db_path)
        
        records = read_all_log_entries(self.db_path)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0][2], ciphertext)

    def test_network_monitor_anomaly(self):
        """Verify regular expression parsing and intrusion anomaly detection thresholds."""
        mock_logs = [
            '10.0.0.45 - - [2026-11-01T21:01:15] "POST /api/v1/auth/login HTTP/1.1" 401 128',
            '10.0.0.45 - - [2026-11-01T21:01:18] "POST /api/v1/auth/login HTTP/1.1" 401 128'
        ]
        report = parse_and_analyze_logs(mock_logs)
        self.assertEqual(report["anomalies_detected"], 1)
        self.assertEqual(report["threat_ledger"][0]["ip_address"], "10.0.0.45")

if __name__ == "__main__":
    unittest.main()
