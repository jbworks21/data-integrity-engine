# data_integrity_engine/sig_engine.py

import os
import sys
import base64
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

def generate_keys(priv_path="private_key.pem", pub_path="public_key.pem"):
    """Generates an Ed25519 asymmetric key pair for cryptographic attestation."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    # Save private key in PEM format (Keep secret / off public repositories)
    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
        
    # Save public key in PEM format (Safe to share/publish for verification)
    with open(pub_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        
    print(f"[SIGMA] Key pair successfully generated:\n  -> Private Key: {priv_path}\n  -> Public Key:  {pub_path}")

def sign_merkle_root(merkle_root: str, priv_path="private_key.pem") -> bytes:
    """Signs a Merkle root string using the local private key."""
    if not os.path.exists(priv_path):
        raise FileNotFoundError(f"[ERROR] Private key not found at {priv_path}. Run 'generate' first.")
        
    with open(priv_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
        
    signature = private_key.sign(merkle_root.encode())
    return signature

def verify_merkle_root(merkle_root: str, signature_b64: str, pub_path="public_key.pem") -> bool:
    """Verifies an Ed25519 signature against a Merkle root, handling any shell-stripped Base64 padding."""
    try:
        if not os.path.exists(pub_path):
            print(f"[ERROR] Public key not found at {pub_path}.")
            return False
            
        with open(pub_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
            
        # Clean string and automatically fix missing Base64 padding caused by shell input
        sig_clean = signature_b64.strip()
        padding_needed = len(sig_clean) % 4
        if padding_needed:
            sig_clean += '=' * (4 - padding_needed)
            
        signature = base64.b64decode(sig_clean)
        public_key.verify(signature, merkle_root.encode())
        return True
    except Exception as e:
        print(f"[VERIFY ERROR] Signature validation failed: {str(e)}")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("\n[USAGE ERROR] Project Sigma Execution Routes:")
        print("  Generate Keys: python sig_engine.py generate")
        print("  Sign Root:     python sig_engine.py sign '<merkle_root>'")
        print("  Verify Root:   python sig_engine.py verify '<merkle_root>' '<base64_sig>'")
        sys.exit(1)
        
    action = sys.argv[1].lower()
    
    if action == "generate":
        generate_keys()
    elif action == "sign":
        if len(sys.argv) < 3:
            print("[ERROR] Merkle root argument missing.")
            sys.exit(1)
        root_arg = sys.argv[2]
        try:
            sig_bytes = sign_merkle_root(root_arg)
            sig_encoded = base64.b64encode(sig_bytes).decode()
            print(f"\n[CRYPTOGRAPHIC SIGNATURE (Base64)]:\n{sig_encoded}")
        except Exception as e:
            print(str(e))
            sys.exit(1)
    elif action == "verify":
        if len(sys.argv) < 4:
            print("[ERROR] Merkle root or signature argument missing.")
            sys.exit(1)
        root_arg = sys.argv[2]
        sig_arg = sys.argv[3]
        is_valid = verify_merkle_root(root_arg, sig_arg)
        if is_valid:
            print("\n[SUCCESS] Signature is VALID. Non-repudiation confirmed.")
            sys.exit(0)
        else:
            print("\n[ALERT] Signature is INVALID. Tampering or spoofing detected.")
            sys.exit(1)
    else:
        print(f"[ERROR] Unknown instruction protocol: {action}")
        sys.exit(1)
