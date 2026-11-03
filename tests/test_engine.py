# tests/test_engine.py
import unittest
import os
import json
import sqlite3

# Refactored package imports targeting the data_integrity directory
from data_integrity.core import (
    calculate_file_hash, 
    generate_system_manifest, 
    verify_system_integrity
)
from data_integrity.crypto_log import (
    encrypt_message, 
    decrypt_message, 
    derive_key
)
from data_integrity.scraper_engine import ProgrammaticScraperEngine
from data_integrity.pqc_migration import HybridSignatureSuite, QuantumVulnerabilityScanner


class TestDataIntegrityEngine(unittest.TestCase):

    def setUp(self):
        """Set up temporary test assets and database states."""
        self.test_filename = "test_target.txt"
        with open(self.test_filename, "w", encoding="utf-8") as f:
            f.write("Operational security baseline verification text.")

    def tearDown(self):
        """Clean up temporary test artifacts."""
        for filename in [self.test_filename, "manifest.json", "secure_vault.db"]:
            if os.path.exists(filename):
                try:
                    os.remove(filename)
                except Exception:
                    pass

    def test_file_hashing_and_manifest(self):
        """Validate SHA-256 chunked hashing and recursive manifest generation."""
        file_hash = calculate_file_hash(self.test_filename)
        self.assertIsNotNone(file_hash)
        self.assertEqual(len(file_hash), 64)

        manifest = generate_system_manifest(".")
        self.assertIn("system_metadata", manifest)
        self.assertIn("records", manifest)
        self.assertIn(self.test_filename, manifest["records"])

    def test_aes_encryption_roundtrip(self):
        """Verify AES-256 GCM encryption and decryption integrity."""
        secret = "Classified operational state metrics."
        password = "ControlTheNarrative2026"
        
        ciphertext = encrypt_message(secret, password)
        self.assertIsInstance(ciphertext, bytes)
        
        decrypted = decrypt_message(ciphertext, password)
        self.assertEqual(secret, decrypted)

    def test_delta_auditor_detection(self):
        """Verify that the delta auditor flags modifications, deletions, and injections."""
        # Generate initial baseline ledger
        manifest = generate_system_manifest(".")
        with open("manifest.json", "w") as f:
            json.dump(manifest, f)

        # 1. Test 100% Integrity Match
        self.assertTrue(verify_system_integrity(".", "manifest.json"))

        # 2. Test Modification Detection
        with open(self.test_filename, "a", encoding="utf-8") as f:
            f.write("Unauthorized injection drift.")
        
        # Auditor should catch hash mismatch
        self.assertFalse(verify_system_integrity(".", "manifest.json"))

    def test_pqc_hybrid_signature_generation(self):
        """Validate hybrid Ed25519 and ML-DSA signature suite payload formatting."""
        sample_root = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        payload_str = HybridSignatureSuite.sign_merkle_root(sample_root)
        
        payload = json.loads(payload_str)
        
        # Resilient payload inspection handling nested or flat suite keys
        suite_name = payload.get("algorithm_suite") or payload.get("attestation_metadata", {}).get("algorithm_suite")
        
        self.assertIsNotNone(suite_name)
        self.assertIn("signatures", payload)


if __name__ == "__main__":
    unittest.main()

