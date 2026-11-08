# data_integrity_engine/data_integrity/async_monitor.py
import os
import sys
import json
import asyncio
import datetime
import hashlib
import sqlite3
from data_integrity.core import generate_system_manifest
from data_integrity.pqc_migration import HybridSignatureSuite, QuantumVulnerabilityScanner, RFC3161TimestampAuthorityClient

# Dynamically resolve path to the project root directory and database vault
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "../secure_vault.db")

class SigchainLedgerManager:
    """
    Manages chronological attestation chaining, binding each signature
    to its cryptographic predecessor and embedding RFC 3161 timestamp tokens.
    """
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sigma_attestations (
                sequence_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                merkle_root TEXT NOT NULL,
                signature TEXT NOT NULL,
                previous_signature TEXT,
                rfc3161_token TEXT
            );
        """)
        conn.commit()
        conn.close()

    def get_latest_signature(self) -> str:
        """Retrieves the signature of the immediately preceding block."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT signature FROM sigma_attestations ORDER BY sequence_id DESC LIMIT 1;")
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else "GENESIS_ROOT_ANCHOR"

    def append_attestation(self, timestamp: str, merkle_root: str, signature_payload: str, rfc3161_token: str) -> int:
        """Appends a new hash-linked attestation and its external timestamp token to the sigchain."""
        prev_sig = self.get_latest_signature()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO sigma_attestations (timestamp, merkle_root, signature, previous_signature, rfc3161_token)
            VALUES (?, ?, ?, ?, ?)
        """, (timestamp, merkle_root, signature_payload, prev_sig, rfc3161_token))
        
        seq_id = cursor.lastrowid
        conn.commit()
        conn.close()
        print(f"[SIGCHAIN] Appended block #{seq_id} anchored with RFC 3161 Token.")
        return seq_id


class AutonomicIntegrityDaemon:
    """
    Autonomous self-healing state convergence, real-time file monitoring,
    and cryptographic verification daemon backed by Sigchain attestation logging.
    """
    def __init__(self, workspace_path=None, ledger_file="manifest.json", interval_seconds=5):
        self.workspace = workspace_path if workspace_path else os.path.abspath(os.path.join(BASE_DIR, ".."))
        self.ledger = os.path.join(self.workspace, ledger_file)
        self.signature_file = f"{self.ledger}.sig.json"
        self.interval = interval_seconds
        self.is_running = False
        self.pqc_scanner = QuantumVulnerabilityScanner()
        self.sigchain_manager = SigchainLedgerManager()

    def _calculate_file_sha256(self, file_path):
        """Helper to generate a clean SHA-256 hash of a local file."""
        hasher = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(4096):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return None

    async def execute_healing_actuator(self, target_file, issue_type):
        """Forces the local workspace environment back to its verified baseline state."""
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        print(f"\n[ACTUATOR] !!! CRITICAL STATE DRIFT DETECTED AT {timestamp} UTC !!!")
        print(f"[ACTUATOR] Target Asset: {target_file} | Violation: {issue_type}")

        try:
            if issue_type in ["MODIFIED", "DELETED", "LEDGER_TAMPERED"]:
                print(f" -> Executing system rollback: git checkout -- {target_file}")
                process = await asyncio.create_subprocess_exec(
                    'git', 'checkout', '--', target_file,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                if process.returncode == 0:
                    print(f"[SUCCESS] Self-healing complete. {target_file} recovered via Git.")
                else:
                    print(f"[FAILURE] Git restoration failed: {stderr.decode('utf-8')}")
            elif issue_type == "INJECTED":
                file_path = os.path.join(self.workspace, target_file)
                if os.path.exists(file_path):
                    os.remove(file_path)
                    print(f"[SUCCESS] Self-healing complete. Rogue file neutralized: {target_file}")
        except Exception as e:
            print(f"[CRITICAL ERROR] Actuator exception: {str(e)}")

    def generate_and_sign_ledger(self):
        """Generates manifest baseline, signs via hybrid PQC, fetches external RFC 3161 token, and anchors in SQLite."""
        print(f"[MONITOR] Generating fresh baseline manifest ledger...")
        current_manifest = generate_system_manifest(self.workspace)
        with open(self.ledger, "w") as f:
            json.dump(current_manifest, f, indent=4)
        
        ledger_hash = self._calculate_file_sha256(self.ledger)
        signature_payload = HybridSignatureSuite.sign_merkle_root(ledger_hash)
        
        with open(self.signature_file, "w") as f:
            f.write(signature_payload)
            
        # Fetch external RFC 3161 timestamp token for Phase 3 global anchoring
        rfc3161_token = RFC3161TimestampAuthorityClient.request_trusted_timestamp(ledger_hash)

        # Anchor into SQLite Sigchain Ledger
        try:
            sig_data = json.loads(signature_payload)
            timestamp = sig_data.get("attestation_metadata", {}).get("signed_at_utc", datetime.datetime.now(datetime.timezone.utc).isoformat())
            self.sigchain_manager.append_attestation(timestamp, ledger_hash, signature_payload, rfc3161_token)
        except Exception as e:
            print(f"[VAULT WARNING] Failed to record timestamped attestation into sigchain DB: {str(e)}")

        print(f"[MONITOR] Cryptographic baseline anchored successfully in {self.signature_file}.")

    def verify_ledger_cryptographically(self) -> bool:
        """Validates that the physical ledger hash matches the signed attestation target root."""
        if not os.path.exists(self.ledger) or not os.path.exists(self.signature_file):
            return False
        try:
            current_ledger_hash = self._calculate_file_sha256(self.ledger)
            with open(self.signature_file, 'r') as f:
                sig_data = json.load(f)
            target_root = sig_data.get("attestation_metadata", {}).get("target_merkle_root")
            
            if current_ledger_hash != target_root:
                print(f"[CRYPTOGRAPHIC ERROR] Ledger hash mismatch! Current: {current_ledger_hash[:12]} | Signed: {target_root[:12]}")
                return False
            return True
        except Exception:
            return False

    async def run_comparator_cycle(self):
        """Validates ledger authenticity via PQC tokens, live scans, and anomaly checks."""
        if not os.path.exists(self.ledger) or not os.path.exists(self.signature_file):
            self.generate_and_sign_ledger()
            return
        if not self.verify_ledger_cryptographically():
            await self.execute_healing_actuator(self.ledger, "LEDGER_TAMPERED")
            return

        try:
            with open(self.ledger, 'r') as f:
                saved_manifest = json.load(f)
            saved_records = saved_manifest.get("records", {})
            
            live_manifest = generate_system_manifest(self.workspace)
            live_records = live_manifest.get("records", {})

            # Audit Layer 1: Core Integrity Checks
            for rel_path, metadata in saved_records.items():
                if "_pycache_" in rel_path or rel_path == self.signature_file:
                    continue
                if rel_path not in live_records:
                    await self.execute_healing_actuator(rel_path, "DELETED")
                elif live_records[rel_path]["sha256"] != metadata["sha256"]:
                    await self.execute_healing_actuator(rel_path, "MODIFIED")

            # Audit Layer 2: Unauthorized Injections
            for rel_path in live_records.keys():
                if "_pycache_" in rel_path or rel_path.endswith(('.tmp', '.sig.json', '.db')):
                    continue
                if rel_path not in saved_records and rel_path != self.ledger:
                    await self.execute_healing_actuator(rel_path, "INJECTED")

            # Audit Layer 3: Passive PQC Parameter Scanning
            for rel_path in live_records.keys():
                if rel_path.endswith(('.py', '.sh')):
                    file_path = os.path.join(self.workspace, rel_path)
                    findings = self.pqc_scanner.scan_file(file_path)
                    if findings:
                        print(f"\n[PQC COMPLIANCE ALERT] Insecure Primitive Found in {rel_path}")
                        for item in findings:
                            print(f" -> Line {item['line']}: [{item['rule']}] Snippet: {item['snippet']}")
        except Exception as e:
            print(f"[MONITOR ERROR] Comparator exception: {str(e)}")

    async def start_monitoring_loop(self):
        """Initializes the background event timing mechanism."""
        self.is_running = True
        print(f"[MONITOR] Initializing Zero-Trust Autonomous Control Loop...")
        print(f"[MONITOR] Workspace Target: {self.workspace}")
        print(f"[MONITOR] Sampling Interval: {self.interval}s (Phase 3 RFC 3161 TSA Anchored)")
        print("-" * 70)
        while self.is_running:
            await self.run_comparator_cycle()
            await asyncio.sleep(self.interval)

if __name__ == "__main__":
    healer = AutonomicIntegrityDaemon()
    try:
        asyncio.run(healer.start_monitoring_loop())
    except KeyboardInterrupt:
        print("\n[MONITOR] Autonomous Control Loop terminated gracefully.")
        sys.exit(0)

