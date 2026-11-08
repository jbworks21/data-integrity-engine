...paste everything between the fences below...
# ARCHITECTURAL REPORT: AUTONOMIC DATA INTEGRITY AND CRYPTOGRAPHIC ATTESTATION SYSTEMS

**Document classification:** Graduate portfolio / systems architecture baseline
**Systems ledger:** https://github.com (replace with real repo URL)
**Execution environment:** Python 3.9+, Linux, Termux-compatible

---

## 1. ABSTRACT & SCOPE

This report documents the architecture of a data integrity engine and
cryptographic attestation suite. The system combines SHA-256 file-tree
manifests, a deterministic Merkle tree for whole-directory state tracking,
an AES-256-GCM encrypted log vault, Ed25519 asymmetric attestation, and an
asynchronous self-monitoring daemon that detects workspace drift.

**Scope note on post-quantum cryptography.** The ML-DSA component in
`pqc_migration.py` is a *simulation stub*, not a working post-quantum
signature. Its purpose is to demonstrate the shape of a hybrid attestation
payload and to reserve the integration point for a real ML-DSA library.
It provides no post-quantum security today. Section 3 states precisely what
it does and does not do; Section 7 gives the integration path to make it real.

The system is written in pure Python and depends on the `cryptography`
library for all symmetric and asymmetric primitives. It does not implement
cryptography from scratch.

---

## 2. SUBSYSTEM MATRIX

| Subsystem / module | Status | Mechanism | Known limitations |
| :--- | :--- | :--- | :--- |
| **Core Engine**<br>`core.py`, `audit.sh` | Prototype | 4096-byte chunked SHA-256 streaming, recursive tree walk, JSON delta ledger (`manifest.json`). | `audit.sh` exit code does not reflect tampering yet; needs `sys.exit(0/1)` in `core.py`. |
| **Project Alpha**<br>`crypto_log.py` | Working | Authenticated AES-256-GCM with PBKDF2-HMAC-SHA-256 key derivation, persisted to `secure_vault.db`. | PBKDF2 iterations currently 100,000; OWASP 2023 guidance is 600,000+. Upgrade planned. |
| **Project Beta**<br>`scraper_engine.py` | Working (partial) | Asynchronous non-blocking HTTP via `urllib.request` in `run_in_executor`, UTC audit headers, vault persistence. | Persistence target table `project_beta_feeds` is not created by `initialize_database`; writes currently fail and fall through to the error branch. |
| **Project Gamma**<br>`network_monitor.py` | Demonstrated | Regex parsing of structured access-log lines; anomaly detection on repeated 401/403 status codes. | Operates on a self-written sample log in `__main__`; not yet wired to a live syslog stream. |
| **Project Sigma**<br>`sig_engine.py`, `pqc_migration.py`, `async_monitor.py` | Prototype | Ed25519 signing (verification path implemented in `sig_engine.py`) plus a documented ML-DSA simulation stub; asynchronous polling and healing daemon. | The signing routine in `pqc_migration.py` uses an ephemeral key that is discarded, so its signatures are not independently verifiable. `async_monitor.py` performs a hash-equality check on the ledger, not a signature check (see §4). |
| **Merkle Engine**<br>`merkle.py` | Working | Deterministic sorted-leaf Merkle tree over a directory; root hash comparison for state verification. | No leaf/node domain separation; odd-node duplication introduces a theoretical second-preimage ambiguity. Fix planned. |
| **Tamper Detector**<br>`tamper_detector.py` | Working | One-shot baseline creation and comparison; logs discrepancies to the vault. | Uses a separate baseline (`directory_baseline.json`) from `manifest.json`; the two baselines are not reconciled. |

---

## 3. HYBRID ATTESTATION: CURRENT STATE AND HONEST BOUNDS

The attestation layer is intended to produce a composite signature over a
ledger hash $H_M = \text{SHA-256}(M)$, combining a classical Ed25519
signature with a post-quantum ML-DSA-65 signature.

**Classical half (Ed25519).** Implemented correctly in `sig_engine.py`:
keypair generation, PEM persistence, signing, and verification all work.
The `verify_merkle_root()` function performs a real
`public_key.verify(signature, message)` call. This half provides genuine
classical non-repudiation when the caller uses the persistent keypair.

**Post-quantum half (ML-DSA-65).** Currently a simulation:

$$
\text{stub}(H_M) = \text{SHA-256}(H_M \parallel \texttt{"ML-DSA-65\_LATTICE\_PARAMETER"}) \parallel \text{random}_{32}
$$

This construction has no key, no verification relation, and no hardness
assumption. It is emitted into the attestation JSON but **nothing reads it**.
It does not provide quantum resistance, and it must not be described as a
post-quantum signature until a real implementation replaces it.

**Behavior of the composite payload today.** `pqc_migration.sign_merkle_root()`
generates a fresh ephemeral Ed25519 key, signs, then discards the key. The
resulting payload therefore has no corresponding public key that a verifier
could use. `sig_engine.py` (which uses a persistent keypair) is the correct
pattern; the composite payload function should be refactored to call it.

**What the current system actually guarantees:**

1. File contents are hashed with SHA-256 (collision resistance ~2^128).
2. A Merkle root commits to the exact set and contents of files in a
   directory, deterministically.
3. AES-256-GCM provides authenticated encryption with tamper detection on
   the ciphertext.
4. Ed25519 provides classical signature security when `sig_engine.py` is
   used with a persistent keypair.

It does **not** currently guarantee post-quantum security, and it does not
currently verify any signature inside the monitoring loop.

---

## 4. CYBERNETIC CONTROL LOOP: WHAT IS IMPLEMENTED

The monitor in `async_monitor.py` runs a polling loop at interval τ = 5 s.

1. **Sensor.** `generate_system_manifest()` walks the workspace and computes
   SHA-256 per file. This is a synchronous call; it runs in the event-loop
   thread and therefore *does* block the loop for its duration. Moving it to
   `loop.run_in_executor()` is a pending optimization.
2. **Comparator.** The monitor reads `manifest.json`, computes its SHA-256,
   and compares it to `target_merkle_root` stored in
   `manifest.json.sig.json`. **This is a hash-equality check between two
   files inside the workspace, not a signature verification.** An attacker
   who can rewrite `manifest.json` can also rewrite the adjacent `.sig.json`
   to match; the code does not detect that. Real tamper detection requires
   persisting the Ed25519 public key *outside* the workspace and calling
   `public_key.verify()` inside the comparator. This integration is pending.
3. **Actuator.** On a flagged delta the actuator issues
   `git checkout -- <path>` for modified/deleted files, and `os.remove()` for
   files not in the baseline. This requires the workspace to be a git
   repository with the target tracked; the precondition is not checked.
   Destructive action on "injected" files is aggressive and should be gated
   behind an explicit opt-in flag before production use.

The loop implements real convergence behavior when git is present and the
files are tracked. It does not implement cryptographic attestation of the
ledger as described in earlier drafts of this report.

---

## 5. STATIC SCANNER: FALSE-POSITIVE MITIGATION

`QuantumVulnerabilityScanner` uses lookaround-anchored regular expressions
to flag legacy primitives (`rsa`, `dsa`, `md5`, `sha1`, `nistp256`,
`secp256k1`) without tripping on safe labels such as `ML-DSA`, `SLH-DSA`,
or internal rule keys.

**Disclosed limitation.** The scanner explicitly skips `async_monitor.py`
and `pqc_migration.py` to avoid self-flagging. This means the crypto module
itself is not audited by its own scanner. A reviewer should treat the scan
output as covering only the rest of the workspace.

---

## 6. DEVELOPMENT TIMELINE

Selected commits from `git log`, presented as a functional build-up:

- `cdfd1fc` — Project Alpha AES-256-GCM engine initialized.
- `3ae3e77` — `crypto_log.py` CLI parameter interface.
- `d4e6d33` — SQLite persistence layer integrated.
- `40adf4b` — Project Beta asynchronous scraper initialized.
- `f0310f6` — Project Gamma network log analyzer added.
- `406d5a2` — Automated unittest suite and CI/CD workflow.
- `b0591b4` — Ed25519 attestation engine (`sig_engine.py`).
- `c577803` — Merkle tree module.
- `846dcb8` — Tamper detector with Merkle root comparison.
- `ec4f43e` — Mock log quote-format correction for test parity.
- `00f1b21` — Rollback of Docker/firewall additions to pure-Python daemon.
- `81516c7` — Hybrid PQC payload scaffold (simulation).
- `920c85b` — PQC regex filters and hardened monitor daemon.
- `eacd5be` — Async monitor daemon and scanner refinements.
- `deadabf` — PQC pre-flight hook added to monitor loop.
- `65e2432` — Asyncio scraper engine refinement.
- `bb85a86` — This report.
- `f8693fd` — Package layout refactor. **Note:** this commit reduced
  `tests/test_engine.py` from 142 to 94 lines; the suite has not yet been
  re-expanded to cover the moved modules.
- `f5f1792` — Passphrase-derived AES-256-GCM vault key work and hardware
  keystore stubs.

The timeline is included for orientation, not as an audit claim.

---

## 7. KNOWN LIMITATIONS AND INTEGRATION ROADMAP

**Immediate (honesty/correctness):**

1. Wire `sig_engine.verify_merkle_root()` into `async_monitor`'s comparator
   so the ledger check is a real signature verification.
2. Persist the Ed25519 public key outside the workspace so the verifier is
   not co-located with the data it is verifying.
3. Make `core.py` exit nonzero on tamper so `audit.sh` reports the true
   result.
4. Create the `project_beta_feeds` table in `initialize_database`, or route
   scraper persistence through the existing `encrypted_logs` schema.
5. Complete the package refactor: move the remaining modules under
   `data_integrity/` and update absolute imports.
6. Raise PBKDF2 iterations to 600,000 (OWASP 2023).

**Medium-term (security):**

7. Replace the ML-DSA stub with a real library: `liboqs-python`, or the
   ML-DSA support in recent `cryptography` releases. Verify that the import
   used in `sig_engine_pqc.py` resolves on the target version before relying
   on it.
8. Add leaf/node domain separation in `merkle.py` (`\x00` for leaves,
   `\x01` for internal nodes) to eliminate the odd-node ambiguity.
9. Gate the "INJECTED" deletion path behind an explicit `--enforce` flag and
   normalize paths before the protected-files comparison.
10. Add per-IP cooldown in `daemon.py` so a sustained attack cannot flood the
    vault.

**Long-term (research extensions):**

11. Zero-knowledge attestation over the Merkle root (SNARK or STARK) so
    proofs can be verified without revealing file contents.
12. Byzantine-fault-tolerant threshold signing for the ledger, so no single
    key compromise can forge a baseline.

---

## 8. DEPENDENCIES

- Python standard library (`hashlib`, `os`, `json`, `sqlite3`, `asyncio`,
  `urllib`, `datetime`, `secrets`, `unittest`, `re`, `base64`)
- `cryptography` (Ed25519, AES-GCM, PBKDF2; and ML-DSA if available in the
  installed version)

The claim that the suite is "zero-dependency" is not accurate; it depends on
`cryptography` and is otherwise standard-library-only.

---

## 9. CONCLUSION

The system demonstrates working implementations of SHA-256 manifest
tracking, Merkle root commitment, AES-256-GCM encryption with authenticated
tamper detection, and Ed25519 signing and verification. It also contains a
documented ML-DSA simulation stub, an asynchronous drift-detection loop with
a git-based actuator, and a static scanner for legacy cryptographic
primitives.

The security guarantees currently delivered are classical: SHA-256
collision resistance, AES-GCM authenticated encryption, and Ed25519
signature unforgeability. Post-quantum resistance is not yet delivered and
is stated here as a roadmap item rather than a capability. The control loop
detects drift via hash comparison and heals via git; cryptographic
attestation of the ledger is the next integration step.

All claims in this document are intended to be checkable against the source
tree. Where the implementation does not yet match the design, that gap is
stated explicitly rather than papered over.
