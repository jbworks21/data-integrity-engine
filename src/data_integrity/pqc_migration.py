# pqc_migration.py
import os
import re
import sys
import base64
import json
import datetime
import hashlib

from . import sig_engine

try:
    from .sig_engine_pqc import (
        generate_pqc_key_pair, sign_merkle_root_pqc, verify_merkle_root_pqc,
    )
    _PQC_AVAILABLE = True
except ImportError:
    _PQC_AVAILABLE = False


class HybridSignatureSuite:
    """Composite attestation: real Ed25519 + ML-DSA-65 (or honest stub)."""

    @staticmethod
    def generate_composite_keys(output_dir="."):
        os.makedirs(output_dir, exist_ok=True)
        sig_engine.generate_keys(
            priv_path=os.path.join(output_dir, "private_key.pem"),
            pub_path=os.path.join(output_dir, "public_key.pem"),
        )
        if _PQC_AVAILABLE:
            generate_pqc_key_pair()
            print("[PQC] ML-DSA-65 keypair available (in-process only).")
        else:
            print("[PQC] ML-DSA unavailable; PQ layer will be a simulation stub.")

    @staticmethod
    def sign_merkle_root(merkle_root: str, priv_path="private_key.pem") -> str:
        classical_sig = sig_engine.sign_merkle_root(merkle_root, priv_path)
        classical_sig_b64 = base64.b64encode(classical_sig).decode('utf-8')

        if _PQC_AVAILABLE:
            pqc_priv, _ = generate_pqc_key_pair()
            pqc_sig_b64 = sign_merkle_root_pqc(merkle_root, pqc_priv)
            pqc_status = "ML_DSA_65_REAL"
        else:
            stub = hashlib.sha256(
                merkle_root.encode() + b"ML-DSA-65_SIMULATION_STUB"
            ).digest() + os.urandom(32)
            pqc_sig_b64 = base64.b64encode(stub).decode('utf-8')
            pqc_status = "SIMULATION_STUB_NO_SECURITY"

        return json.dumps({
            "attestation_metadata": {
                "algorithm_suite": "Ed25519 + ML-DSA-65",
                "signed_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "target_merkle_root": merkle_root,
                "pqc_status": pqc_status,
            },
            "signatures": {
                "classical_ed25519": classical_sig_b64,
                "post_quantum_mldsa": pqc_sig_b64,
            },
        }, indent=4)

    @staticmethod
    def verify_merkle_root(merkle_root: str, payload_str: str,
                           pub_path="public_key.pem") -> bool:
        """Verifies the Ed25519 half. PQ half has no public-key pairing and is
        NOT verified in this release (see report §3)."""
        try:
            payload = json.loads(payload_str)
        except json.JSONDecodeError:
            return False
        meta = payload.get("attestation_metadata", {})
        if meta.get("target_merkle_root") != merkle_root:
            return False
        sig_b64 = payload.get("signatures", {}).get("classical_ed25519")
        if not sig_b64:
            return False
        return sig_engine.verify_merkle_root(merkle_root, sig_b64, pub_path)


class QuantumVulnerabilityScanner:
    def __init__(self):
        self.vulnerability_rules = {
            "LEGACY_ASYMMETRIC_RSA": re.compile(r'(?i)\b(?<!LEGACY_ASYMMETRIC_)rsa\b(?!_vulnerability)'),
            "LEGACY_ASYMMETRIC_DSA": re.compile(r'(?i)\b(?<!ML-)(?<!SLH-)(?<!LEGACY_ASYMMETRIC_)dsa\b'),
            "WEAK_HASH_MD5": re.compile(r'(?i)\b(?<!WEAK_HASH_)md5\b(?!_vulnerability)'),
            "WEAK_HASH_SHA1": re.compile(r'(?i)\b(?<!WEAK_HASH_)sha1\b'),
            "CLASSICAL_ECC_VULNERABLE": re.compile(r'(?i)\bnistp256\b|\bsecp256k1\b'),
        }

    def scan_file(self, file_path: str) -> list:
        findings = []
        if "async_monitor.py" in file_path or "pqc_migration.py" in file_path:
            return findings
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    s = line.strip()
                    if not s or s.startswith(("#", '"""', "'''")):
                        continue
                    for rule_name, pattern in self.vulnerability_rules.items():
                        if pattern.search(s):
                            findings.append({
                                "line": line_num, "rule": rule_name, "snippet": s[:60],
                            })
        except Exception as e:
            print(f"[SCAN ERROR] {file_path}: {e}")
        return findings

    def execute_workspace_audit(self, target_directory="."):
        print(f"\n[SCANNER] Cryptographic parameter audit...")
        total = 0
        for root, _, files in os.walk(target_directory):
            for name in files:
                fp = os.path.join(root, name)
                found = self.scan_file(fp)
                if found:
                    print(f"[RISK] {os.path.relpath(fp, target_directory)}")
                    for item in found:
                        print(f"  Line {item['line']}: [{item['rule']}] {item['snippet']}")
                    total += len(found)
        print(f"\n[AUDIT] Total risk points: {total}")


if __name__ == "__main__":
    scanner = QuantumVulnerabilityScanner()
    if len(sys.argv) > 1 and sys.argv[1] == "--audit-only":
        scanner.execute_workspace_audit(".")
        sys.exit(0)
    scanner.execute_workspace_audit(".")
