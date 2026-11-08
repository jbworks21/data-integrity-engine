# sig_engine_pqc.py
import os
import base64

try:
    from cryptography.hazmat.primitives.asymmetric import mldsa
    _MLDSA_AVAILABLE = True
except (ImportError, AttributeError):
    _MLDSA_AVAILABLE = False


def generate_pqc_key_pair():
    """ML-DSA-65 keypair. Requires cryptography >= 44 (or a build with ML-DSA)."""
    if not _MLDSA_AVAILABLE:
        raise ImportError(
            "ML-DSA is not available in the installed cryptography version. "
            "Upgrade to cryptography >= 44 or use liboqs-python."
        )
    private_key = mldsa.MLDSA65PrivateKey.generate()
    return private_key, private_key.public_key()


def sign_merkle_root_pqc(merkle_root: str, private_key) -> str:
    signature_bytes = private_key.sign(merkle_root.encode('utf-8'))
    return base64.b64encode(signature_bytes).decode('utf-8')


def verify_merkle_root_pqc(merkle_root: str, signature_b64: str, public_key) -> bool:
    try:
        sig_clean = signature_b64.strip()
        pad = len(sig_clean) % 4
        if pad:
            sig_clean += '=' * (4 - pad)
        signature_bytes = base64.b64decode(sig_clean)
        public_key.verify(signature_bytes, merkle_root.encode('utf-8'))
        return True
    except Exception as e:
        print(f"[PQC VERIFICATION ERROR]: {e}")
        return False
