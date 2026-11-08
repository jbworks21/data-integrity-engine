# async_monitor.py
import os
import sys
import json
import asyncio
import datetime
import hashlib
import subprocess
from .core import generate_system_manifest
from .pqc_migration import HybridSignatureSuite, QuantumVulnerabilityScanner


class AutonomousSelfHealer:
    def __init__(self, workspace_path=".", ledger_file="manifest.json",
                 interval_seconds=5, public_key_path=None, private_key_path=None):
        self.workspace = os.path.abspath(workspace_path)
        self.ledger = ledger_file
        self.signature_file = f"{ledger_file}.sig.json"
        self.interval = interval_seconds
        self.is_running = False
        self.pqc_scanner = QuantumVulnerabilityScanner()
        # Trust anchor MUST live outside the workspace.
        self.public_key_path = public_key_path or os.path.expanduser("~/.sigma/public_key.pem")
        self.private_key_path = private_key_path or os.path.expanduser("~/.sigma/private_key.pem")

    def _calculate_file_sha256(self, file_path):
        try:
            h = hashlib.sha256()
            with open(file_path, 'rb') as f:
                while chunk := f.read(4096):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    def _is_git_repo(self):
        try:
            r = subprocess.run(
                ['git', 'rev-parse', '--is-inside-work-tree'],
                cwd=self.workspace, capture_output=True, timeout=5,
            )
            return r.returncode == 0 and r.stdout.strip() == b'true'
        except Exception:
            return False

    def _protected(self, target_file):
        basename = os.path.basename(target_file)
        protected = {
            os.path.basename(self.ledger),
            os.path.basename(self.signature_file),
            "async_monitor.py", "pqc_migration.py", "core.py",
            "sig_engine.py", "sig_engine_pqc.py",
        }
        return basename in protected or "__pycache__" in target_file

    async def execute_healing_actuator(self, target_file, issue_type):
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        print(f"\n[ACTUATOR] Drift {ts}: {target_file} ({issue_type})")

        if self._protected(target_file) and not (
            target_file == self.ledger and issue_type == "LEDGER_TAMPERED"
        ):
            print(f"[ACTUATOR] Protected path; skipped.")
            return

        if not self._is_git_repo():
            print(f"[ACTUATOR] Workspace is not a git repository; cannot heal.")
            return

        try:
            if issue_type in ("MODIFIED", "DELETED", "LEDGER_TAMPERED"):
                paths = [self.ledger, self.signature_file] \
                    if issue_type == "LEDGER_TAMPERED" else [target_file]
                for p in paths:
                    proc = await asyncio.create_subprocess_exec(
                        'git', 'checkout', '--', p, cwd=self.workspace,
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                    )
                    _, err = await proc.communicate()
                    if proc.returncode == 0:
                        print(f"[ACTUATOR] Restored {p}")
                    else:
                        print(f"[ACTUATOR] Restore failed for {p}: {err.decode().strip()}")
            elif issue_type == "INJECTED":
                fp = os.path.join(self.workspace, target_file)
                if os.path.exists(fp):
                    os.remove(fp)
                    print(f"[ACTUATOR] Removed rogue file: {target_file}")
        except Exception as e:
            print(f"[ACTUATOR ERROR] {e}")

    def _ensure_keys(self):
        have_priv = os.path.exists(self.private_key_path)
        have_pub = os.path.exists(self.public_key_path)
        if have_priv and have_pub:
            return True
        if not have_priv and not have_pub:
            from . import sig_engine
            os.makedirs(os.path.dirname(self.private_key_path), exist_ok=True)
            os.makedirs(os.path.dirname(self.public_key_path), exist_ok=True)
            sig_engine.generate_keys(self.private_key_path, self.public_key_path)
            print(f"[MONITOR] Generated new keypair. Public key is the trust anchor.")
            return True
        print(f"[MONITOR ERROR] Inconsistent key state "
              f"(priv={have_priv}, pub={have_pub}).")
        return False

    def generate_and_sign_ledger(self):
        if not self._ensure_keys():
            return
        manifest = generate_system_manifest(self.workspace, quiet=True)
        with open(self.ledger, "w") as f:
            json.dump(manifest, f, indent=4)
        ledger_hash = self._calculate_file_sha256(self.ledger)
        payload = HybridSignatureSuite.sign_merkle_root(ledger_hash, self.private_key_path)
        with open(self.signature_file, "w") as f:
            f.write(payload)
        print(f"[MONITOR] Ledger signed -> {self.signature_file}")

    def verify_ledger_cryptographically(self):
        if not os.path.exists(self.ledger) or not os.path.exists(self.signature_file):
            return False
        try:
            current = self._calculate_file_sha256(self.ledger)
            with open(self.signature_file) as f:
                payload = f.read()
            if not os.path.exists(self.public_key_path):
                print(f"[CRYPTO] Public key missing at {self.public_key_path}")
                return False
            return HybridSignatureSuite.verify_merkle_root(
                current, payload, self.public_key_path
            )
        except Exception as e:
            print(f"[CRYPTO ERROR] {e}")
            return False

    async def run_comparator_cycle(self):
        if not os.path.exists(self.ledger) or not os.path.exists(self.signature_file):
            self.generate_and_sign_ledger()
            return
        if not self.verify_ledger_cryptographically():
            await self.execute_healing_actuator(self.ledger, "LEDGER_TAMPERED")
            return
        try:
            with open(self.ledger) as f:
                saved = json.load(f)
        except Exception:
            print("[MONITOR ERROR] Cannot parse ledger.")
            return
        saved_records = saved.get("records", {})

        loop = asyncio.get_running_loop()
        live = await loop.run_in_executor(
            None, generate_system_manifest, self.workspace, True
        )
        live_records = live.get("records", {})

        for rel, meta in saved_records.items():
            if "__pycache__" in rel or rel == self.signature_file:
                continue
            if rel not in live_records:
                await self.execute_healing_actuator(rel, "DELETED")
            elif live_records[rel]["sha256"] != meta["sha256"]:
                await self.execute_healing_actuator(rel, "MODIFIED")

        for rel in live_records:
            if "__pycache__" in rel or rel.endswith(('.tmp', '.sig.json')):
                continue
            if rel not in saved_records and rel not in (self.ledger, self.signature_file):
                await self.execute_healing_actuator(rel, "INJECTED")

        for rel in live_records:
            if rel.endswith(('.py', '.sh')):
                found = self.pqc_scanner.scan_file(os.path.join(self.workspace, rel))
                if found:
                    print(f"\n[PQC COMPLIANCE] {rel}:")
                    for item in found:
                        print(f"  Line {item['line']}: [{item['rule']}] {item['snippet']}")

    async def start_monitoring_loop(self):
        self.is_running = True
        print(f"[MONITOR] Workspace: {self.workspace}")
        print(f"[MONITOR] Interval: {self.interval}s")
        print(f"[MONITOR] Trust anchor: {self.public_key_path}")
        print("-" * 70)
        while self.is_running:
            await self.run_comparator_cycle()
            await asyncio.sleep(self.interval)


if __name__ == "__main__":
    healer = AutonomousSelfHealer(workspace_path=".", interval_seconds=5)
    try:
        asyncio.run(healer.start_monitoring_loop())
    except KeyboardInterrupt:
        print("\n[MONITOR] Stopped.")
        sys.exit(0)
