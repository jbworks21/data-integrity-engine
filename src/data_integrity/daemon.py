# daemon.py
import time
import os
import re
from collections import defaultdict, deque
from .crypto_log import save_alert_entry, initialize_database

THRESHOLD_ATTEMPTS = 3
TIME_WINDOW_SECONDS = 30
COOLDOWN_SECONDS = 60
DB_PATH = "secure_vault.db"

FAILED_LOGIN_REGEX = re.compile(
    r'(?P<timestamp>\S+ \S+ \S+) .* Failed password for .* from '
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
)


class NetworkDefenseDaemon:
    def __init__(self, log_file_path):
        self.log_file_path = log_file_path
        self.attack_tracker = defaultdict(deque)
        self.last_alert = {}
        initialize_database(DB_PATH)

    def analyze_line(self, line):
        match = FAILED_LOGIN_REGEX.search(line)
        if not match:
            return
        ip = match.group("ip")
        now = time.time()
        stamps = self.attack_tracker[ip]
        stamps.append(now)
        while stamps and now - stamps[0] > TIME_WINDOW_SECONDS:
            stamps.popleft()
        if len(stamps) >= THRESHOLD_ATTEMPTS:
            if now - self.last_alert.get(ip, 0) >= COOLDOWN_SECONDS:
                self.last_alert[ip] = now
                self.trigger_countermeasure(ip, len(stamps))

    def trigger_countermeasure(self, ip_address, attempt_count):
        msg = (f"Brute-force threshold breached by {ip_address}: "
               f"{attempt_count} rapid failures detected.")
        print(f"\033[91m[DEFENSE] {msg}\033[0m")
        save_alert_entry(msg, severity="HIGH", source="auth-log", db_path=DB_PATH)

    def tail_log_stream(self):
        if not os.path.exists(self.log_file_path):
            with open(self.log_file_path, "w", encoding="utf-8") as f:
                f.write("# telemetry stream initialized\n")
        print(f"\033[92m[DAEMON ACTIVE] {self.log_file_path}\033[0m")
        with open(self.log_file_path, "r", encoding="utf-8") as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.4)
                    continue
                self.analyze_line(line.strip())


if __name__ == "__main__":
    daemon = NetworkDefenseDaemon("active_auth.log")
    try:
        daemon.tail_log_stream()
    except KeyboardInterrupt:
        print("\n[DAEMON STOPPED]")
