# data_integrity_engine/tamper_detector.py

import os
import json
import sys
import base64
from pathlib import Path
from merkle import MerkleTree, hash_file
from crypto_log import save_log_entry, initialize_database

BASELINE_FILE = "directory_baseline.json"
DB_PATH = "secure_vault.db"

def create_baseline(directory_path):
    """Generates and saves a secure integrity baseline of the directory."""
    target = Path(directory_path)
    tree = MerkleTree(target)
    
    manifest = {}
    for root, _, filenames in os.walk(target):
        if '.git' in Path(root).parts or '__pycache__' in Path(root).parts:
            continue
        for filename in filenames:
            full_path = Path(root) / filename
            if full_path.is_file() and full_path.name != BASELINE_FILE:
                rel_path = str(full_path.relative_to(target))
                manifest[rel_path] = hash_file(full_path)
                
    data = {
        "root_hash": tree.root_hash,
        "manifest": manifest
    }
    
    with open(BASELINE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
        
    print(f"\033[92m[BASELINE CREATED] Root Hash: {tree.root_hash}\033[0m")
    print(f"[MANIFEST SECURED] {len(manifest)} files indexed into {BASELINE_FILE}")

def check_tampering(directory_path):
    """Verifies current directory state against baseline and logs discrepancies."""
    target = Path(directory_path)
    if not os.path.exists(BASELINE_FILE):
        print(f"\033[91m[ERROR] Baseline file {BASELINE_FILE} not found. Run 'init' first.\033[0m")
        return

    with open(BASELINE_FILE, "r", encoding="utf-8") as f:
        baseline = json.load(f)
        
    old_root = baseline["root_hash"]
    old_manifest = baseline["manifest"]
    
    # Compute current state via Merkle Tree
    current_tree = MerkleTree(target)
    new_root = current_tree.root_hash
    
    if old_root == new_root:
        print(f"\033[92m[INTEGRITY VERIFIED] Root hashes match perfectly. No tampering detected.\033[0m")
        return True
        
    print(f"\033[91m[ALERT] TAMPERING DETECTED! Root hash mismatch.\033[0m")
    print(f"  Baseline Root: {old_root}")
    print(f"  Current Root:  {new_root}")
    
    # Scan current files to isolate exact deltas
    current_manifest = {}
    for root, _, filenames in os.walk(target):
        if '.git' in Path(root).parts or '__pycache__' in Path(root).parts:
            continue
        for filename in filenames:
            full_path = Path(root) / filename
            if full_path.is_file() and full_path.name != BASELINE_FILE:
                rel_path = str(full_path.relative_to(target))
                current_manifest[rel_path] = hash_file(full_path)
                
    old_files = set(old_manifest.keys())
    new_files = set(current_manifest.keys())
    
    added = new_files - old_files
    removed = old_files - new_files
    common = old_files & new_files
    modified = [f for f in common if old_manifest[f] != current_manifest[f]]
    
    if added:
        print(f"  [ADDED FILES]: {list(added)}")
    if removed:
        print(f"  [REMOVED FILES]: {list(removed)}")
    if modified:
        print(f"  [MODIFIED FILES]: {modified}")
        
    # Log incident into Project Alpha encrypted vault
    initialize_database(DB_PATH)
    alert_msg = f"TAMPER ALERT: Added={len(added)}, Removed={len(removed)}, Modified={len(modified)}"
    encoded_payload = base64.b64encode(alert_msg.encode('utf-8')).decode('utf-8')
    save_log_entry(encoded_payload, DB_PATH)
    print(f"[SECURE VAULT] Tamper alert encrypted and logged to {DB_PATH}")
    return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python tamper_detector.py [init|check] [directory]")
        sys.exit(1)
        
    action = sys.argv[1]
    target_dir = sys.argv[2] if len(sys.argv) > 2 else "."
    
    if action == "init":
        create_baseline(target_dir)
    elif action == "check":
        check_tampering(target_dir)
    else:
        print("Unknown action. Use 'init' or 'check'.")

