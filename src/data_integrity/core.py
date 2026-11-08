# core.py
import hashlib
import os
import sys
import json
import datetime
from pathlib import Path

# Files that are never part of the integrity baseline (they *are* the baseline,
# or they're runtime artifacts that change on every invocation).
_EXCLUDED_NAMES = {"manifest.json", "manifest.json.sig.json", "directory_baseline.json"}
_EXCLUDED_EXTENSIONS = (".db",)
_EXCLUDED_DIRS = {".git", "__pycache__"}


def calculate_file_hash(file_path):
    """Chunked SHA-256 of a file's contents."""
    sha256_engine = hashlib.sha256()
    try:
        with open(file_path, 'rb') as target_file:
            while chunk := target_file.read(4096):
                sha256_engine.update(chunk)
        return sha256_engine.hexdigest()
    except FileNotFoundError:
        print(f"[ERROR] Target file not found at: {file_path}")
        return None
    except Exception as e:
        print(f"[ERROR] Security exception or read failure: {str(e)}")
        return None


def generate_system_manifest(target_directory, quiet=False):
    """Walk a directory and return a timestamped manifest of file hashes."""
    manifest = {
        "system_metadata": {
            "generated_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "target_path": os.path.abspath(target_directory),
        },
        "records": {},
    }
    if not quiet:
        print(f"[SYSTEM] Beginning integrity scan on: {target_directory}")

    for root, dirs, files in os.walk(target_directory):
        if any(d in Path(root).parts for d in _EXCLUDED_DIRS):
            continue
        for file_name in files:
            if file_name in _EXCLUDED_NAMES:
                continue
            if file_name.endswith(_EXCLUDED_EXTENSIONS):
                continue
            full_path = os.path.join(root, file_name)
            relative_path = os.path.relpath(full_path, target_directory)
            file_hash = calculate_file_hash(full_path)
            if file_hash:
                manifest["records"][relative_path] = {
                    "sha256": file_hash,
                    "size_bytes": os.path.getsize(full_path),
                }
                if not quiet:
                    print(f" -> Indexed: {relative_path}")
    return manifest


def verify_system_integrity(target_directory, manifest_file_path):
    """Compare live workspace against a saved manifest. Returns True if clean."""
    print(f"\n[AUDIT] Initiating delta verification using: {manifest_file_path}")
    try:
        with open(manifest_file_path, 'r') as f:
            saved_manifest = json.load(f)
    except FileNotFoundError:
        print(f"[AUDIT FAIL] Base ledger not found at: {manifest_file_path}")
        return False

    saved_records = saved_manifest.get("records", {})
    live_manifest = generate_system_manifest(target_directory, quiet=True)
    live_records = live_manifest.get("records", {})

    tampering_detected = False

    for relative_path, metadata in saved_records.items():
        if relative_path not in live_records:
            print(f"[ALERT - DELETED] {relative_path}")
            tampering_detected = True
        elif live_records[relative_path]["sha256"] != metadata["sha256"]:
            print(f"[ALERT - MODIFIED] {relative_path}")
            print(f"  -> Expected: {metadata['sha256'][:10]}...")
            print(f"  -> Found:    {live_records[relative_path]['sha256'][:10]}...")
            tampering_detected = True

    for relative_path in live_records:
        if relative_path not in saved_records:
            print(f"[ALERT - INJECTED] {relative_path}")
            tampering_detected = True

    if not tampering_detected:
        print("[AUDIT SUCCESS] 100% Integrity Match.")
    return not tampering_detected


if __name__ == "__main__":
    workspace = "."
    ledger = "manifest.json"
    if os.path.exists(ledger):
        ok = verify_system_integrity(workspace, ledger)
        sys.exit(0 if ok else 1)      # <-- lets audit.sh see the real result
    else:
        current_manifest = generate_system_manifest(workspace)
        with open(ledger, "w") as f:
            json.dump(current_manifest, f, indent=4)
        print(f"\n[SUCCESS] Fresh baseline ledger written to: {ledger}")
