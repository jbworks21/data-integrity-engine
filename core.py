# data_integrity_engine/core.py

import hashlib
import os
import json
import datetime

def calculate_file_hash(file_path):
    """
    Reads a file in binary mode and calculates its SHA-256 fingerprint.
    Processes data in chunks to handle files of any size efficiently.
    """
    sha256_engine = hashlib.sha256()
    
    try:
        # Open file in Read-Binary ('rb') mode to prevent format manipulation
        with open(file_path, 'rb') as target_file:
            # Read in 4096-byte blocks to preserve system memory
            while chunk := target_file.read(4096):
                sha256_engine.update(chunk)
                
        return sha256_engine.hexdigest()
        
    except FileNotFoundError:
        print(f"[ERROR] Target file not found at: {file_path}")
        return None
    except Exception as e:
        print(f"[ERROR] Security exception or read failure: {str(e)}")
        return None

def generate_system_manifest(target_directory):
    """
    Scans a directory, calculates hashes for all non-hidden files,
    and returns a structured, timestamped manifest dictionary.
    """
    manifest = {
        "system_metadata": {
            "generated_at_utc": datetime.datetime.utcnow().isoformat(),
            "target_path": os.path.abspath(target_directory)
        },
        "records": {}
    }
    
    print(f"[SYSTEM] Beginning integrity scan on: {target_directory}")
    
    # Walk through all directories and files recursively
    for root, dirs, files in os.walk(target_directory):
        # Prevent tracking hidden git configurations
        if '.git' in root:
            continue
            
        for file_name in files:
            full_path = os.path.join(root, file_name)
            relative_path = os.path.relpath(full_path, target_directory)
            
            # Calculate the unassailable hash using our hashing module
            file_hash = calculate_file_hash(full_path)
            
            if file_hash:
                manifest["records"][relative_path] = {
                    "sha256": file_hash,
                    "size_bytes": os.path.getsize(full_path)
                }
                print(f" -> Indexed: {relative_path}")
                
    return manifest

def verify_system_integrity(target_directory, manifest_file_path):
    """
    Compares the current live workspace against a saved manifest ledger.
    Flags additions, deletions, or modifications with absolute mathematical certainty.
    """
    print(f"\n[AUDIT] Initiating delta verification using: {manifest_file_path}")
    
    try:
        with open(manifest_file_path, 'r') as f:
            saved_manifest = json.load(f)
    except FileNotFoundError:
        print(f"[AUDIT FAIL] Base ledger snapshot not found at: {manifest_file_path}")
        return False

    saved_records = saved_manifest.get("records", {})
    
    # Generate a fresh live snapshot of the directory right now
    live_manifest = generate_system_manifest(target_directory)
    live_records = live_manifest.get("records", {})
    
    tampering_detected = False
    
    # Check 1: Scan for Modifications and Deletions
    for relative_path, metadata in saved_records.items():
        if relative_path not in live_records:
            print(f"[ALERT - DELETED] Saved asset is missing from workspace: {relative_path}")
            tampering_detected = True
        elif live_records[relative_path]["sha256"] != metadata["sha256"]:
            print(f"[ALERT - MODIFIED] Cryptographic hash mismatch on: {relative_path}")
            print(f"  -> Expected: {metadata['sha256'][:10]}...")
            print(f"  -> Found:    {live_records[relative_path]['sha256'][:10]}...")
            tampering_detected = True
            
    # Check 2: Scan for Injections (Untracked New Files)
    for relative_path in live_records.keys():
        if relative_path not in saved_records and relative_path != manifest_file_path:
            print(f"[ALERT - INJECTED] Unauthorized or untracked file detected: {relative_path}")
            tampering_detected = True
            
    if not tampering_detected:
        print("[AUDIT SUCCESS] 100% Integrity Match. No modifications, injections, or deletions detected.")
        
    return not tampering_detected

if __name__ == "__main__":
    workspace = "."
    ledger = "manifest.json"
    
    # Check if an existing ledger file exists
    if os.path.exists(ledger):
        # Run our audit program to check for tampering
        verify_system_integrity(workspace, ledger)
    else:
        # If no ledger exists, build one from scratch
        current_manifest = generate_system_manifest(workspace)
        with open(ledger, "w") as f:
            json.dump(current_manifest, f, indent=4)
        print(f"\n[SUCCESS] Fresh baseline ledger written to: {ledger}")

