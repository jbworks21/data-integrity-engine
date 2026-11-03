# data_integrity_engine/sig_engine_pqc.py

import os
import base64
from cryptography.hazmat.primitives.asymmetric import mldsa

def generate_pqc_key_pair():
    """
    Generates a post-quantum cryptographic key pair using the ML-DSA-65 
    module-lattice algorithm (FIPS 204 / NIST Security Category 3).
    
    Returns:
        tuple: (private_key, public_key) objects configured for post-quantum operations.
    """
    private_key = mldsa.MLDSA65PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def sign_merkle_root_pqc(merkle_root: str, private_key) -> str:
    """
    Accepts a hexadecimal Merkle tree root string, signs it using the post-quantum 
    private key, and encodes the resulting raw signature bytes into a safe Base64 string.
    
    Parameters:
        merkle_root (str): The 64-character SHA-256 Merkle root hash string.
        private_key: The ML-DSA private key object used for signing.
        
    Returns:
        str: Base64-encoded string representation of the post-quantum signature.
    """
    # Generate the raw post-quantum signature bytes from the message string
    signature_bytes = private_key.sign(merkle_root.encode('utf-8'))
    
    # Encode into Base64 for clean text-based storage and transmission
    encoded_signature = base64.b64encode(signature_bytes).decode('utf-8')
    return encoded_signature

def verify_merkle_root_pqc(merkle_root: str, signature_b64: str, public_key) -> bool:
    """
    Verifies a post-quantum ML-DSA signature against a Merkle root string using the 
    corresponding public key. Includes automatic Base64 padding correction to protect 
    against CLI or text truncation anomalies.
    
    Parameters:
        merkle_root (str): The original Merkle root hash string to verify against.
        signature_b64 (str): The Base64-encoded signature string.
        public_key: The ML-DSA public key object used for verification.
        
    Returns:
        bool: True if the signature is mathematically valid, False otherwise.
    """
    try:
        # Sanitize whitespace from the signature string
        sig_clean = signature_b64.strip()
        
        # Automatically compute and append missing Base64 padding characters if needed
        padding_needed = len(sig_clean) % 4
        if padding_needed:
            sig_clean += '=' * (4 - padding_needed)
            
        # Decode the cleaned string back into raw byte format
        signature_bytes = base64.b64decode(sig_clean)
        
        # Perform cryptographic verification against the public key
        public_key.verify(signature_bytes, merkle_root.encode('utf-8'))
        return True
        
    except Exception as e:
        # Any mathematical mismatch or malformed structure safely falls back to False
        print(f"[PQC VERIFICATION ERROR]: {str(e)}")
        return False
