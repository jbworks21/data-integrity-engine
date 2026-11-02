# data_integrity_engine/daemon.py

import time
import os
import re
import base64
from collections import defaultdict, deque
from crypto_log import save_log_entry, initialize_database

# Configuration thresholds
THRESHOLD_ATTEMPTS = 3
TIME_WINDOW_SECONDS = 30
DB_PATH = "secure_vault.db"

# Regular expression matching incoming failed authentication telemetry
FAILED_LOGIN_REGEX = re.compile(
    r'(?P<timestamp>\S+ \S+ \S+) .* Failed password for .* from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
)

class NetworkDefenseDaemon:
    def __init__(self, log_file_path):
        self.log_file_path = log_file_path
        self.attack_tracker = defaultdict(deque)
        initialize_database(DB_PATH)

    def analyze_line(self, line):
        match = FAILED_LOGIN_REGEX.search(line)
        if match:
            ip = match.group("ip")
            current_time = time.time()
            
            # Record timestamp of attempt
            timestamps = self.attack_tracker[ip]
            timestamps.append(current_time)
            
            # Prune old attempts outside the sliding window
            while timestamps and current_time - timestamps[0] > TIME_WINDOW_SECONDS:
                timestamps.popleft()
            
            # Check if attack frequency breaches threshold
            if len(timestamps) >= THRESHOLD_ATTEMPTS:
                self.trigger_countermeasure(ip, len(timestamps))

    def trigger_countermeasure(self, ip_address, attempt_count):
        alert_msg = f"[DEFENSE TRIGGER] Brute-force threshold breached by IP {ip_address}: {attempt_count} rapid failures detected."
        print(f"\033[91m{alert_msg}\033[0m")
        
        # Encrypt and secure threat record into Project Alpha's encrypted SQLite vault
        encoded_payload = base64.b64encode(alert_msg.encode('utf-8')).decode('utf-8')
        save_log_entry(encoded_payload, DB_PATH)
        print(f"[SECURE VAULT] Threat telemetry locked into encrypted database: {DB_PATH}")

    def tail_log_stream(self):
        if not os.path.exists(self.log_file_path):
            print(f"[DAEMON] Log file target {self.log_file_path} not found. Initializing empty stream...")
            with open(self.log_file_path, "w", encoding="utf-8") as f:
                f.write("# Project Delta live telemetry stream initialized.\n")

        print(f"\033[92m[DAEMON ACTIVE] Monitoring live telemetry stream on: {self.log_file_path}\033[0m")
        with open(self.log_file_path, "r", encoding="utf-8") as f:
            # Seek to end of file to tail incoming live writes
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.4)
                    continue
                self.analyze_line(line.strip())

if __name__ == "__main__":
    target_log = "active_auth.log"
    daemon = NetworkDefenseDaemon(target_log)
    try:
        daemon.tail_log_stream()
    except KeyboardInterrupt:
        print("\n[DAEMON STOPPED] Network Defense Daemon gracefully terminated.")

