# 1. Remove the orphaned package (log shows imports expect root-level modules)
rm -rf data_integrity/

# 2. Install / verify dependencies
pip install --upgrade cryptography
python -c "import cryptography; print(cryptography.__version__)"

# 3. Regenerate baselines — Merkle leaf format changed (0x00 prefix),
#    so old directory_baseline.json and manifest.json are invalid.
rm -f directory_baseline.json manifest.json manifest.json.sig.json

# 4. Create the trust anchor OUTSIDE the workspace
mkdir -p ~/.sigma
python -c "import sig_engine; sig_engine.generate_keys('/root/.sigma/private_key.pem', '/root/.sigma/public_key.pem')"  # adjust $HOME
# Termux: use $HOME/.sigma, e.g. /data/data/com.termux/files/home/.sigma

# 5. Build first manifest + baseline
python core.py
python tamper_detector.py init .

# 6. Run tests
python -m unittest test_engine -v

# 7. Sanity-check audit.sh now reflects true state
./audit.sh
echo "exit=$?"

# 8. Commit
git add -A
git commit -m "fix: exit codes, scrambler table, PBKDF2 600k, real Ed25519 verification, Merkle domain separation"
