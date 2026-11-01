#!/bin/bash

# --- SYSTEM AUTOMATION & HARDENING WRAPPER ---
# Objective: Instantly verify environment state and minimize user visibility.

clear
echo "============================================="
echo "[CRITICAL] RUNNING AUTOMATED INTEGRITY SCAN"
echo "============================================="

# 1. Execute the core verification python engine
python core.py

# 2. Capture the exact system exit code
# (0 means success/no modifications; anything else means warning/error)
SCAN_RESULT=$?

echo "============================================="
if [ $SCAN_RESULT -eq 0 ]; then
    echo "[STATUS] ENVIRONMENT VERIFIED & SECURE"
else
    echo "[WARNING] DRIFT OR ALTERATION DETECTED"
fi
echo "============================================="

