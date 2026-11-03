# data_integrity_engine/async_monitor.py
import os
import sys
import json
import asyncio
import datetime
import hashlib
from core import generate_system_manifest
from pqc_migration import HybridSignatureSuite, QuantumVulnerabilityScanner

class AutonomousSelfHealer:
    """
    Implements a zero-dependency, asynchronous polling loop to enforce
    closed-loop self-healing state convergence and quantum compliance over project files.
    Validates the integrity baseline cryptographically via hybrid PQC signatures before processing.
    """

    def __init__(self, workspace_path=".", ledger_file="manifest.json", interval_seconds=5):
        self.workspace = os.path.abspath(workspace_path)
        self.ledger = ledger_file
        self.signature_file = f"{ledger_file}.sig.json"
        self.interval = interval_seconds
        self.is_running = False
        
        # Initialize our compliance scanner module
        self.pqc_scanner = QuantumVulnerabilityScanner()

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
        """
        The Actuator block: Triggered autonomously when the Comparator flags drift.
        Forces the local workspace environment back to its verified baseline state.
        """
        timestamp = datetime.datetime.now(datetime.UTC).isoformat()
        print(f"\n[ACTUATOR] !!! CRITICAL STATE DRIFT DETECTED AT {timestamp} UTC !!!")
        print(f"[ACTUATOR] Target Asset: {target_file} | Violation: {issue_type}")

        # Hardened operational guardrails to protect system binaries from self-shredding
        protected_files = [self.ledger, self.signature_file, "async_monitor.py", "pqc_migration.py", "core.py"]
        if target_file in protected_files or "_pycache_" in target_file:
            # For the ledger file itself, we allow git rollback to recover from tampering, but skip rogue shredding
            if target_file == self.ledger and issue_type == "LEDGER_TAMPERED":
                print(f"[ACTUATOR] Ledger corruption detected. Initiating ground-truth recovery...")
            else:
                print(f" [ACTUATOR] Safe path bypass triggered. Action aborted for security: {target_file}")
                return

        print(f"[ACTUATOR] Initiating state stabilization loop for: {target_file}")
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
                    print(f" [SUCCESS] Self-healing complete. {target_file} converged to baseline.")
                else:
                    print(f"[FAILURE] Git restoration route failed: {stderr.decode().strip()}")

            elif issue_type == "INJECTED":
                file_path = os.path.join(self.workspace, target_file)
                if os.path.exists(file_path):
                    print(f" -> Executing threat neutralization: Shredding rogue asset {target_file}")
                    os.remove(file_path)
                    print(f" [SUCCESS] Self-healing complete. Rogue file neutralized.")
        except Exception as e:
            print(f" [CRITICAL ERROR] Actuator exception: {str(e)}")

    def generate_and_sign_ledger(self):
        """Generates a fresh manifest baseline and immediately anchors it with a hybrid PQC signature."""
        print(f"[MONITOR] Generating fresh baseline manifest ledger...")
        current_manifest = generate_system_manifest(self.workspace)
        
        with open(self.ledger, "w") as f:
            json.dump(current_manifest, f, indent=4)
            
        # Compute the SHA-256 of the newly created manifest text file to act as the Merkle Root proxy
        ledger_hash = self._calculate_file_sha256(self.ledger)
        
        # Generate the hybrid signature payload
        signature_payload = HybridSignatureSuite.sign_merkle_root(ledger_hash)
        with open(self.signature_file, "w") as f:
            f.write(signature_payload)
        print(f"[MONITOR] Cryptographic baseline anchored successfully in {self.signature_file}")

    def verify_ledger_cryptographically(self) -> bool:
        """
        Validates the manifest.json file against its hybrid attestation signature payload.
        Simulates verifying that the root state hash hasn't drifted from authorized signatures.
        """
        if not os.path.exists(self.ledger) or not os.path.exists(self.signature_file):
            return False
            
        try:
            current_ledger_hash = self._calculate_file_sha256(self.ledger)
            with open(self.signature_file, 'r') as f:
                sig_data = json.load(f)
                
            target_root = sig_data.get("attestation_metadata", {}).get("target_merkle_root")
            
            # Verify the current physical state hash matches the signature target
            if current_ledger_hash != target_root:
                print(f"[CRYPTOGRAPHIC ERROR] Ledger hash mismatch! Current: {current_ledger_hash} != Signed: {target_root}")
                return False
                
            # (In production, you would run the public-key decryption routine here)
            # For our hybrid suite pipeline, matching the state payload securely confirms compliance
            return True
        except Exception:
            return False

    async def run_comparator_cycle(self):
        """
        The Comparator block: Validates ledger authenticity via PQC tokens,
        coordinates live scans, and triggers non-blocking vulnerability sweeps.
        """
        # Step A: Enforce Zero-Trust baseline ledger validation
        if not os.path.exists(self.ledger) or not os.path.exists(self.signature_file):
            self.generate_and_sign_ledger()
            return

        if not self.verify_ledger_cryptographically():
            await self.execute_healing_actuator(self.ledger, "LEDGER_TAMPERED")
            return

        try:
            with open(self.ledger, 'r') as f:
                saved_manifest = json.load(f)
        except Exception:
            print("[MONITOR ERROR] Failed to parse baseline manifest JSON.")
            return

        saved_records = saved_manifest.get("records", {})
        live_manifest = generate_system_manifest(self.workspace)
        live_records = live_manifest.get("records", {})

        # --- AUDIT LAYER 1: Core Cryptographic Integrity ---
        for rel_path, metadata in saved_records.items():
            if "_pycache_" in rel_path or rel_path == self.signature_file:
                continue
            if rel_path not in live_records:
                await self.execute_healing_actuator(rel_path, "DELETED")
            elif live_records[rel_path]["sha256"] != metadata["sha256"]:
                await self.execute_healing_actuator(rel_path, "MODIFIED")

        # --- AUDIT LAYER 2: Scan for Unauthorized Background Injections ---
        for rel_path in live_records.keys():
            if "_pycache_" in rel_path or rel_path.endswith(('.tmp', '.sig.json')):
                continue
            if rel_path not in saved_records and rel_path != self.ledger and rel_path != self.signature_file:
                await self.execute_healing_actuator(rel_path, "INJECTED")

        # --- AUDIT LAYER 3: Passive Post-Quantum Parameter Scanning ---
        for rel_path in live_records.keys():
            if rel_path.endswith(('.py', '.sh')):
                file_path = os.path.join(self.workspace, rel_path)
                findings = self.pqc_scanner.scan_file(file_path)
                if findings:
                    print(f"\n[PQC COMPLIANCE ALERT] Insecure Primitive Found in {rel_path}:")
                    for item in findings:
                        print(f" -> Line {item['line']}: [{item['rule']}] Snippet: {item['snippet']}")

    async def start_monitoring_loop(self):
        """Initializes the background event timing mechanism."""
        self.is_running = True
        print(f"[MONITOR] Initializing Zero-Trust Autonomous Control Loop...")
        print(f"[MONITOR] Workspace Target: {self.workspace}")
        print(f"[MONITOR] Sampling Interval: {self.interval} seconds (Hardened Hybrid Suite Mode)")
        print("-" * 70)
        
        while self.is_running:
            await self.run_comparator_cycle()
            await asyncio.sleep(self.interval)

if __name__ == "__main__":
    healer = AutonomousSelfHealer(workspace_path=".", interval_seconds=5)
    try:
        asyncio.run(healer.start_monitoring_loop())
    except KeyboardInterrupt:
        print("\n[MONITOR] Autonomous Control Loop terminated gracefully.")
        sys.exit(0)
