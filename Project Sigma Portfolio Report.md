# PROJECT SIGMA: ADVANCED CRYPTOGRAPHIC INTEGRITY & TRANSPARENCY ENGINE
**Repository:** `jbworks21/data-integrity-engine`  
**Status:** PRODUCTION-HARDENED / STABLE / RESTORED (Commit `f5f1792`)  
**Environment:** Termux / Python 3.13 / GitHub Actions CI/CD  

---

## 1. Executive Summary & Architecture Overview
Project Sigma has evolved from a local cryptographic state monitor into an enterprise-grade, autonomic data integrity daemon. Designed to eliminate subjective gatekeeping through immutable mathematical proof, the engine combines classical and post-quantum cryptographic primitives, chronological SQLite ledgering, and external transparency anchoring via RFC 3161 Trusted Timestamping Authorities (TSAs).

The entire system is modularly structured under a clean package layout, fully covered by automated unit test suites, and continuously integrated via GitHub Actions CI/CD pipelines.

---

## 2. Core Technical Modules & Implementation

### A. Core Integrity Engine (`data_integrity/core.py`)
* **Chunked SHA-256 Hashing:** Reads target assets in memory-efficient 4096-byte binary blocks (`'rb'`) to compute unassailable digital fingerprints without risking memory overflows on large datasets.
* **Recursive Directory Scanning:** Automatically crawls workspace directory trees while safely ignoring version control internals (`.git/`) and compiled database artifacts.
* **Delta Auditor & Manifests:** Generates structured JSON snapshot ledgers (`manifest.json`) and cross-references live environments to instantly flag modified, deleted, or injected files.

### B. Cryptographic Storage Vault (`data_integrity/crypto_log.py`)
* **AES-256 GCM Encryption:** Implements authenticated symmetric encryption backed by PBKDF2HMAC key derivation (100,000 iterations of SHA-256) with dynamic CLI argument interfaces (`sys.argv`).
* **SQLite Persistence:** Binds encrypted payloads directly into local SQLite vault tables (`secure_vault.db`) with UTC timestamping rows.

### C. Post-Quantum Cryptography & Sigchain Ledger (`data_integrity/pqc_migration.py`)
* **Hybrid Signature Suite (`HybridSignatureSuite`):** Combines classical Ed25519 signatures with post-quantum ML-DSA-65 (Dilithium) payloads to ensure future-proof cryptographic security against quantum decryption attacks.
* **Chronological Sigchain Database:** Binds attestation blocks sequentially into SQLite, linking each cryptographic block directly to its predecessor's signature and Merkle root.

### D. External Transparency Anchoring (RFC 3161)
* **TSA Client Integration (`RFC3161TimestampAuthorityClient`):** Dispatches binary query payloads directly to independent public Timestamping Authorities (e.g., FreeTSA) and embeds base64-encoded response tokens into the sigchain block to prevent local system clock manipulation.

---

## 3. Version Control & Repository Inventory

| File Path | Component State | Technical Function |
| :--- | :--- | :--- |
| `data_integrity/core.py` | ACTIVE | SHA-256 hashing, directory crawling, and delta verification. |
| `data_integrity/crypto_log.py` | ACTIVE | AES-256 GCM encryption and SQLite vault management. |
| `data_integrity/pqc_migration.py` | ACTIVE | Post-quantum hybrid signatures and RFC 3161 TSA client. |
| `data_integrity/scraper_engine.py` | ACTIVE | Automated urllib data stream parser and JSON archiving. |
| `data_integrity/network_monitor.py` | ACTIVE | Access log regex parser and threat anomaly detector. |
| `tests/test_engine.py` | ACTIVE | Comprehensive unit test suite covering all modules. |
| `.github/workflows/ci.yml` | ACTIVE | Automated Ubuntu runner CI/CD test execution pipeline. |
| `audit.sh` | HARDENED | Termux shell wrapper and test automation alias (`runtests`). |
| `LICENSE` | VERIFIED | Open-source MIT compliance legal shield. |

---

## 4. Verification & Testing Pipeline
To maintain zero-tolerance quality control, the repository enforces a mandatory verification workflow:

```bash
# 1. Inspect repository status
git status

# 2. Execute unified unit test suite
python -m unittest tests/test_engine.py
# (Or using the global Termux shortcut configured in ~/.bashrc:)
runtests

# 3. Execute system security and integrity audit wrapper
./audit.sh
```

### Expected Output Summary
```text
[CRITICAL] RUNNING AUTOMATED INTEGRITY SCAN
====================================================
[SYSTEM] Beginning integrity scan on: .
-> Indexed: data_integrity/core.py (SHA-256: 393a1931c...)
-> Indexed: data_integrity/crypto_log.py (SHA-256: c9992eee8...)
[AUDIT SUCCESS] 100% Integrity Match. No modifications, injections, or deletions detected.
====================================================
[STATUS] ENVIRONMENT VERIFIED & SECURE
```

---

## 5. Next Recommended Roadmap Phase
* **Phase 4 Target: Hardware Security Module (HSM) & TPM Integration**  
  Offloading key generation and signature creation directly to physical or virtual Trusted Platform Modules (TPMs) to ensure signing keys remain strictly non-exportable under full host OS compromise and bind attestation states to hardware Platform Configuration Registers (PCRs).

---
*Maintained under MIT License. Publicly verifiable via GitHub repository [jbworks21/data-integrity-engine](https://github.com/jbworks21/data-integrity-engine).*