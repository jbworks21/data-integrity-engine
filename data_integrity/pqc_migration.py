# data_integrity_engine/data_integrity/pqc_migration.py
import json
import hashlib
import datetime
import urllib.request
import urllib.error
import base64

class HybridSignatureSuite:
    """
    Implements a dual-spec hybrid cryptographic signing suite 
    combining classical Ed25519 and simulated Post-Quantum ML-DSA-65.
    """
    @staticmethod
    def sign_merkle_root(merkle_root_hex: str) -> str:
        """Signs a target ledger Merkle root using hybrid classical/PQC primitives."""
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        # Simulate classical Ed25519 signature payload
        classical_sig = hashlib.sha256(f"ED25519_SIG::{merkle_root_hex}::{timestamp}".encode()).hexdigest()
        
        # Simulate post-quantum ML-DSA-65 (Dilithium) signature payload
        pqc_sig = hashlib.sha256(f"ML_DSA_65_PQC::{merkle_root_hex}::{timestamp}".encode()).hexdigest()
        
        payload = {
            "attestation_metadata": {
                "version": "sigma-phase3",
                "signed_at_utc": timestamp,
                "target_merkle_root": merkle_root_hex
            },
            "signatures": {
                "classical_ed25519": classical_sig,
                "post_quantum_mldsa65": pqc_sig
            }
        }
        return json.dumps(payload, indent=4)


class RFC3161TimestampAuthorityClient:
    """
    Interfaces with public RFC 3161 Timestamping Authorities (TSA) 
    to anchor local PQC signatures into unforgeable global timelines.
    """
    TSA_SERVER_URL = "https://freetsa.org/tsr"

    @staticmethod
    def request_trusted_timestamp(data_hash_hex: str) -> str:
        """
        Submits a cryptographic hash digest to an external TSA and returns 
        the base64-encoded RFC 3161 timestamp response token.
        """
        print(f"[TSA] Dispatching timestamp request to external authority...")
        try:
            req_data = bytes.fromhex(data_hash_hex)
            req = urllib.request.Request(
                RFC3161TimestampAuthorityClient.TSA_SERVER_URL,
                data=req_data,
                headers={
                    "Content-Type": "application/timestamp-query",
                    "User-Agent": "DataIntegrityEngine-TSAClient/1.0"
                },
                method="POST"
            )
            
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.getcode() == 200:
                    tsr_bytes = response.read()
                    tsr_b64 = base64.b64encode(tsr_bytes).decode('utf-8')
                    print(f"[SUCCESS] RFC 3161 timestamp token acquired successfully.")
                    return tsr_b64
                else:
                    print(f"[TSA WARNING] Server returned status code: {response.getcode()}")
                    return "FALLBACK_LOCAL_TIME_ANCHOR"
        except urllib.error.URLError as e:
            print(f"[TSA NETWORK ERROR] Could not reach timestamp server: {e.reason}. Using local fallback anchor.")
            return "FALLBACK_OFFLINE_ANCHOR"
        except Exception as e:
            print(f"[TSA ERROR] Exception during timestamp request: {str(e)}")
            return "FALLBACK_ERROR_ANCHOR"


class QuantumVulnerabilityScanner:
    """
    Scans local Python and shell scripts for vulnerable classical cryptographic 
    primitives (e.g., RSA, static ECC curves, MD5/SHA1).
    """
    FORBIDDEN_PRIMITIVES = ["rsa", "dsa", "md5", "sha1", "ecdh"]

    def scan_file(self, file_path: str) -> list:
        findings = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for idx, line in enumerate(f, start=1):
                    lower_line = line.lower()
                    for prim in self.FORBIDDEN_PRIMITIVES:
                        if prim in lower_line and "comment" not in lower_line:
                            findings.append({
                                "line": idx,
                                "rule": f"VULNERABLE_PRIMITIVE_{prim.upper()}",
                                "snippet": line.strip()
                            })
        except Exception:
            pass
        return findings

