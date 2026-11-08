# tamper_detector.py
import os
import json
import sys
import base64
from pathlib import Path
from merkle import MerkleTree, hash_file
from crypto_log import save_alert_entry, initialize_database

BASELINE_FILE = "directory_baseline.json"
DB_PATH = "secure_vault.db"
_EXCLUDED_EXTENSIONS = (".db",)
_EXCLUDED_NAMES = {BASELINE_FILE, "manifest.json", "manifest.json.sig.json"}
_EXCLUDED_DIRS = {".git", "__pycache__"}


def _skip(path_obj):
    return any(d in path_obj.parts for d in _EXCLUDED_DIRS)


def create_baseline(directory_path):
    target = Path(directory_path)
    tree = MerkleTree(target)
    manifest = {}
    for root, _, filenames in os.walk(target):
        if _skip(Path(root)):
            continue
        for filename in filenames:
            fp = Path(root) / filename
            if not fp.is_file() or fp.name in _EXCLUDED_NAMES:
                continue
            if fp.name.endswith(_EXCLUDED_EXTENSIONS):
                continue
            manifest[str(fp.relative_to(target))] = hash_file(fp)
    data = {"root_hash": tree.root_hash, "manifest": manifest}
    with open(BASELINE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    print(f"\033[92m[BASELINE] root={tree.root_hash} files={len(manifest)}\033[0m")


def check_tampering(directory_path):
    target = Path(directory_path)
    if not os.path.exists(BASELINE_FILE):
        print(f"\033[91m[ERROR] {BASELINE_FILE} not found. Run 'init' first.\033[0m")
        return False
    with open(BASELINE_FILE, encoding="utf-8") as f:
        baseline = json.load(f)
    old_root = baseline["root_hash"]
    old_manifest = baseline["manifest"]

    tree = MerkleTree(target)
    if old_root == tree.root_hash:
        print(f"\033[92m[INTEGRITY] Root hashes match.\033[0m")
        return True

    print(f"\033[91m[ALERT] Root mismatch.\033[0m")
    print(f"  Baseline: {old_root}")
    print(f"  Current:  {tree.root_hash}")

    current = {}
    for root, _, filenames in os.walk(target):
        if _skip(Path(root)):
            continue
        for filename in filenames:
            fp = Path(root) / filename
            if not fp.is_file() or fp.name in _EXCLUDED_NAMES:
                continue
            if fp.name.endswith(_EXCLUDED_EXTENSIONS):
                continue
            current[str(fp.relative_to(target))] = hash_file(fp)

    added = set(current) - set(old_manifest)
    removed = set(old_manifest) - set(current)
    common = set(current) & set(old_manifest)
    modified = [f for f in common if old_manifest[f] != current[f]]

    if added:    print(f"  [ADDED]:    {sorted(added)}")
    if removed:  print(f"  [REMOVED]:  {sorted(removed)}")
    if modified: print(f"  [MODIFIED]: {sorted(modified)}")

    initialize_database(DB_PATH)
    save_alert_entry(
        f"Tamper: added={len(added)}, removed={len(removed)}, modified={len(modified)}",
        severity="HIGH", source="tamper_detector", db_path=DB_PATH,
    )
    return False


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python tamper_detector.py [init|check] [directory]")
        sys.exit(1)
    action = sys.argv[1]
    target = sys.argv[2] if len(sys.argv) > 2 else "."
    ok = True
    if action == "init":
        create_baseline(target)
    elif action == "check":
        ok = check_tampering(target)
    else:
        print("Unknown action.")
        sys.exit(1)
    sys.exit(0 if ok else 1)
