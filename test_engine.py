# test_engine.py
import unittest
import os
import tempfile
import sqlite3
import base64

from core import calculate_file_hash, generate_system_manifest
from crypto_log import (
    encrypt_message, decrypt_message, initialize_database,
    save_log_entry, save_alert_entry, read_all_log_entries,
)
from merkle import MerkleTree, hash_file, hash_leaf, hash_pair
from sig_engine import (
    generate_keys, sign_merkle_root, verify_merkle_root,
)
from pqc_migration import HybridSignatureSuite

try:
    from sig_engine_pqc import (
        generate_pqc_key_pair, sign_merkle_root_pqc,
        verify_merkle_root_pqc, _MLDSA_AVAILABLE,
    )
except ImportError:
    _MLDSA_AVAILABLE = False


class TestDataIntegrityEngine(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.sample_file_path = os.path.join(self.test_dir.name, "test_target.txt")
        with open(self.sample_file_path, "w") as f:
            f.write("Autonomous engineering verification payload.")

    def tearDown(self):
        self.test_dir.cleanup()

    def test_file_hashing(self):
        h = calculate_file_hash(self.sample_file_path)
        self.assertIsNotNone(h)
        self.assertEqual(len(h), 64)

    def test_manifest_excludes_database(self):
        db_path = os.path.join(self.test_dir.name, "foo.db")
        open(db_path, "w").write("x")
        m = generate_system_manifest(self.test_dir.name, quiet=True)
        self.assertNotIn("foo.db", m["records"])

    def test_aes_gcm_encryption_roundtrip(self):
        msg = "Confidential operational ledger record."
        pw = "secure_test_password_123"
        ct = encrypt_message(msg, pw)
        self.assertEqual(decrypt_message(ct, pw), msg)

    def test_aes_gcm_wrong_password_fails_closed(self):
        ct = encrypt_message("hello", "right")
        result = decrypt_message(ct, "wrong")
        self.assertTrue(result.startswith("[ERROR]"))

    def test_sqlite_database_persistence(self):
        fd, db_path = tempfile.mkstemp()
        os.close(fd)
        try:
            initialize_database(db_path)
            save_log_entry("dGVzdA==", db_path)
            save_alert_entry("alert test", "INFO", "test", db_path)
            conn = sqlite3.connect(db_path)
            rows = conn.execute("SELECT ciphertext FROM encrypted_logs").fetchall()
            alerts = conn.execute("SELECT message FROM security_alerts").fetchall()
            conn.close()
            self.assertEqual(rows[0][0], "dGVzdA==")
            self.assertEqual(alerts[0][0], "alert test")
        finally:
            os.remove(db_path)

    def test_merkle_leaf_node_domain_separation(self):
        # leaf hash must differ from plain hash_file for same content
        self.assertNotEqual(
            hash_leaf(self.sample_file_path),
            hash_file(self.sample_file_path),
        )

    def test_merkle_pair_uses_raw_bytes(self):
        a = "00" * 32
        b = "11" * 32
        h = hash_pair(a, b)
        self.assertEqual(len(h), 64)

    def test_merkle_deterministic(self):
        t1 = MerkleTree(self.test_dir.name)
        t2 = MerkleTree(self.test_dir.name)
        self.assertEqual(t1.root_hash, t2.root_hash)

    def test_merkle_detects_change(self):
        t_before = MerkleTree(self.test_dir.name)
        with open(self.sample_file_path, "a") as f:
            f.write("tampered")
        t_after = MerkleTree(self.test_dir.name)
        self.assertNotEqual(t_before.root_hash, t_after.root_hash)

    def test_ed25519_sign_and_verify(self):
        priv = os.path.join(self.test_dir.name, "priv.pem")
        pub = os.path.join(self.test_dir.name, "pub.pem")
        generate_keys(priv, pub)
        root = "a" * 64
        sig = base64.b64encode(sign_merkle_root(root, priv)).decode()
        self.assertTrue(verify_merkle_root(root, sig, pub))
        self.assertFalse(verify_merkle_root("b" * 64, sig, pub))

    def test_composite_ed25519_half_verifies(self):
        priv = os.path.join(self.test_dir.name, "priv.pem")
        pub = os.path.join(self.test_dir.name, "pub.pem")
        generate_keys(priv, pub)
        root = "a" * 64
        payload = HybridSignatureSuite.sign_merkle_root(root, priv)
        self.assertTrue(HybridSignatureSuite.verify_merkle_root(root, payload, pub))
        self.assertFalse(HybridSignatureSuite.verify_merkle_root("b" * 64, payload, pub))

    @unittest.skipUnless(_MLDSA_AVAILABLE, "ML-DSA not available")
    def test_post_quantum_mldsa_signing(self):
        priv, pub = generate_pqc_key_pair()
        root = "393a1931c0843bfc6c070a5449a306f63c840d26a7b488665f5370305231fe90"
        sig = sign_merkle_root_pqc(root, priv)
        self.assertTrue(verify_merkle_root_pqc(root, sig, pub))
        self.assertFalse(verify_merkle_root_pqc("00" * 32, sig, pub))


if __name__ == "__main__":
    unittest.main()
