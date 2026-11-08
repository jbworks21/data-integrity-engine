# merkle.py
import os
import hashlib
from pathlib import Path


def hash_file(filepath, chunk_size=8192):
    """Plain SHA-256 of file contents (used outside the Merkle tree)."""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(chunk_size):
            sha256.update(chunk)
    return sha256.hexdigest()


def hash_leaf(filepath, chunk_size=8192):
    """Domain-separated leaf hash: SHA-256(0x00 || contents).
    The 0x00 prefix ensures no leaf can ever equal an internal node."""
    sha256 = hashlib.sha256()
    sha256.update(b"\x00")
    with open(filepath, 'rb') as f:
        while chunk := f.read(chunk_size):
            sha256.update(chunk)
    return sha256.hexdigest()


def hash_pair(left_hex, right_hex):
    """Domain-separated internal node: SHA-256(0x01 || left_bytes || right_bytes)."""
    combined = b"\x01" + bytes.fromhex(left_hex) + bytes.fromhex(right_hex)
    return hashlib.sha256(combined).hexdigest()


class MerkleTree:
    def __init__(self, directory_path):
        self.directory_path = Path(directory_path)
        self.leaves = []
        self.tree = []
        self.root_hash = None
        self.build_tree()

    def _get_sorted_files(self):
        files = []
        if not self.directory_path.exists():
            raise FileNotFoundError(f"Directory not found: {self.directory_path}")
        for root, _, filenames in os.walk(self.directory_path):
            if '.git' in Path(root).parts:
                continue
            for filename in filenames:
                fp = Path(root) / filename
                if fp.is_file():
                    files.append(fp)
        return sorted(files, key=lambda p: str(p.relative_to(self.directory_path)))

    def build_tree(self):
        file_paths = self._get_sorted_files()
        if not file_paths:
            self.root_hash = hashlib.sha256(b"empty_directory").hexdigest()
            return
        self.leaves = [hash_leaf(fp) for fp in file_paths]
        current_level = self.leaves
        self.tree = [current_level]
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                next_level.append(hash_pair(left, right))
            current_level = next_level
            self.tree.append(current_level)
        self.root_hash = current_level[0]

    def verify_state(self, other_directory):
        return MerkleTree(other_directory).root_hash == self.root_hash


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"[MERKLE] Scanning: {os.path.abspath(target)}")
    tree = MerkleTree(target)
    print(f"[FILES]: {len(tree.leaves)}")
    print(f"[ROOT HASH]: {tree.root_hash}")
