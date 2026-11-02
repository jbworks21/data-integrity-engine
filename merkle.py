# data_integrity_engine/merkle.py

import os
import hashlib
from pathlib import Path

def hash_file(filepath, chunk_size=8192):
    """Computes SHA-256 hash of an individual file in binary chunks."""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(chunk_size):
            sha256.update(chunk)
    return sha256.hexdigest()

def hash_pair(left_hex, right_hex):
    """Combines two child node hashes into a parent node hash."""
    combined = left_hex + right_hex
    return hashlib.sha256(combined.encode('utf-8')).hexdigest()

class MerkleTree:
    def __init__(self, directory_path):
        self.directory_path = Path(directory_path)
        self.leaves = []
        self.tree = []
        self.root_hash = None
        self.build_tree()

    def _get_sorted_files(self):
        """Recursively retrieves and sorts all files in the directory for absolute determinism."""
        files = []
        if not self.directory_path.exists():
            raise FileNotFoundError(f"Directory not found: {self.directory_path}")
        
        for root, _, filenames in os.walk(self.directory_path):
            # Exclude version control directories for pure data state tracking
            if '.git' in Path(root).parts:
                continue
            for filename in filenames:
                full_path = Path(root) / filename
                if full_path.is_file():
                    files.append(full_path)
        
        # Sort paths lexicographically so tree construction is deterministic
        return sorted(files, key=lambda p: str(p.relative_to(self.directory_path)))

    def build_tree(self):
        file_paths = self._get_sorted_files()
        if not file_paths:
            self.root_hash = hashlib.sha256(b"empty_directory").hexdigest()
            return

        # 1. Generate leaf hashes from individual files
        self.leaves = [hash_file(fp) for fp in file_paths]
        current_level = self.leaves
        self.tree = [current_level]

        # 2. Build tree upwards level by level
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                # If odd number of nodes, duplicate the last node to balance the tree
                right = current_level[i+1] if i + 1 < len(current_level) else left
                parent = hash_pair(left, right)
                next_level.append(parent)
            current_level = next_level
            self.tree.append(current_level)

        # 3. Final single node is the Root Hash
        self.root_hash = current_level[0]

    def verify_state(self, other_directory):
        """Compares the current directory state against another directory via root hash."""
        target_tree = MerkleTree(other_directory)
        return target_tree.root_hash == self.root_hash

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"[MERKLE ENGINE] Scanning directory: {os.path.abspath(target)}")
    
    tree = MerkleTree(target)
    print(f"[FILES INDEXED]: {len(tree.leaves)}")
    print(f"\033[92m[MERKLE ROOT HASH]: {tree.root_hash}\033[0m")

