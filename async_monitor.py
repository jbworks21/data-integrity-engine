# data_integrity_engine/async_monitor.py

import os
import sys
import json
import asyncio
import datetime
from core import generate_system_manifest
# Dynamically import the static vulnerability checker from our Phase 4 module
from pqc_migration import QuantumVulnerabilityScanner

class AutonomousSelfHealer:
    """
    Implements a zero-dependency, asynchronous polling loop to enforce 
    closed-loop self-healing state convergence and quantum compliance over project files.
    """
    
    def __init__(self, workspace_path=".", ledger_file="manifest.json", interval_seconds=5):
        self.workspace = os.path.abspath(workspace_path)
        self.ledger = ledger_file
        self.interval = interval_seconds
        self.is_running = False
        # Initialize our compliance scanner module
        self.pqc_scanner = QuantumVulnerabilityScanner()

    async def execute_healing_actuator(self, target_file, issue_type):
        """
        The Actuator block: Triggered autonomously when the Comparator flags drift.
        Forces the local workspace environment back to its verified baseline state.
        """
        timestamp = datetime.datetime.now(datetime.UTC).isoformat()
        print(f"\n[ACTUATOR] !!! CRITICAL STATE DRIFT DETECTED AT {timestamp} UTC !!!")
        print(f"[ACTUATOR] Target Asset: {target_file} | Violation: {issue_type}")
        
        # Hardened operational guardrails to protect system binaries from self-shredding
        protected_files = [self.ledger, "async_monitor.py", "pqc_migration.py", "secure_vault.db"]
        if target_file in protected_files or "__pycache__" in target_file:
            print(f"[ACTUATOR] Safe path bypass triggered. Action aborted for: {target_file}")
            return

        print(f"[ACTUATOR] Initiating state stabilization loop for: {target_file}")
        
        try:
            if issue_type in ["MODIFIED", "DELETED"]:
                print(f" -> Executing system rollback: git checkout -- {target_file}")
                process = await asyncio.create_subprocess_exec(
                    'git', 'checkout', '--', target_file,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                
                if process.returncode == 0:
                    print(f"[SUCCESS] Self-healing complete. {target_file} convergence achieved.")
                else:
                    print(f"[FAILURE] Git restoration route failed: {stderr.decode().strip()}")
                    
            elif issue_type == "INJECTED":
                file_path = os.path.join(self.workspace, target_file)
                if os.path.exists(file_path):
                    print(f" -> Executing threat neutralization: Shredding rogue asset {target_file}")
                    os.remove(file_path)
                    print(f"[SUCCESS] Self-healing complete. Rogue file neutralized.")
                    
        except Exception as e:
            print(f"[CRITICAL ERROR] Actuator exception: {str(e)}")

    async def run_comparator_cycle(self):
        """
        The Comparator block: Coordinates live scans against the immutable 
        manifest, passing mutation vectors directly to the actuator.
        Also triggers the asynchronous quantum-vulnerability audit.
        """
        if not os.path.exists(self.ledger):
            print(f"[MONITOR] Base ledger {self.ledger} missing. Generating fresh baseline...")
            current_manifest = generate_system_manifest(self.workspace)
            with open(self.ledger, "w") as f:
                json.dump(current_manifest, f, indent=4)
            return

        try:
            with open(self.ledger, 'r') as f:
                saved_manifest = json.load(f)
        except Exception:
            print("[MONITOR ERROR] Failed to parse baseline manifest json.")
            return

        saved_records = saved_manifest.get("records", {})
        live_manifest = generate_system_manifest(self.workspace)
        live_records = live_manifest.get("records", {})

        # --- AUDIT LAYER 1: Core Cryptographic Integrity ---
        for rel_path, metadata in saved_records.items():
            if "__pycache__" in rel_path:
                continue
            if rel_path not in live_records:
                await self.execute_healing_actuator(rel_path, "DELETED")
            elif live_records[rel_path]["sha256"] != metadata["sha256"]:
                await self.execute_healing_actuator(rel_path, "MODIFIED")

        for rel_path in live_records.keys():
            if "__pycache__" in rel_path or rel_path.endswith('.tmp'):
                continue
            if rel_path not in saved_records and rel_path != self.ledger and rel_path != "async_monitor.py":
                await self.execute_healing_actuator(rel_path, "INJECTED")

        # --- AUDIT LAYER 2: Passive Post-Quantum Parameter Scanning ---
        # Runs non-blocking inspection across tracked project files
        for rel_path in live_records.keys():
            if rel_path.endswith(('.py', '.sh')):
                file_path = os.path.join(self.workspace, rel_path)
                findings = self.pqc_scanner.scan_file(file_path)
                if findings:
                    print(f"\n[PQC COMPLIANCE ALERT] Insecure Primitive Found in: {rel_path}")
                    for item in findings:
                        print(f"  -> Line {item['line']}: [{item['rule']}] Snippet: {item['snippet']}")

    async def start_monitoring_loop(self):
        """Initializes the background event timing mechanism."""
        self.is_running = True
        print(f"[MONITOR] Initializing Autonomous Control Loop...")
        print(f"[MONITOR] Workspace Target: {self.workspace}")
        # Bumping interval slightly to prevent loop saturation due to text processing overhead
        print(f"[MONITOR] Sampling Interval: {self.interval} seconds (Hardened Hybrid Suite)")
        print("---------------------------------------------------------------------")
        
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

