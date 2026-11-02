# data_integrity_engine/network_monitor.py

import re
import sys
import json
import datetime
import os

# Simulated raw network logs for telemetry and anomaly analysis
SAMPLE_LOGS = [
    "192.168.1.10 - - [2026-11-01T21:00:00] 'GET /api/v1/status HTTP/1.1' 200 512",
    "10.0.0.45 - - [2026-11-01T21:01:15] 'POST /api/v1/auth/login HTTP/1.1' 401 128",
    "10.0.0.45 - - [2026-11-01T21:01:18] 'POST /api/v1/auth/login HTTP/1.1' 401 128",
    "10.0.0.45 - - [2026-11-01T21:01:22] 'POST /api/v1/auth/login HTTP/1.1' 401 128",
    "192.168.1.104 - - [2026-11-01T21:02:00] 'GET /admin/config/override HTTP/1.1' 403 64",
    "192.168.1.10 - - [2026-11-01T21:03:10] 'GET /api/v1/data HTTP/1.1' 200 1024"
]

def parse_and_analyze_logs(log_lines):
    """
    Parses raw network stream logs using regular expressions, 
    extracts telemetry, and detects anomalous security patterns.
    """
    # Regex pattern to match standard structured access logs
    log_pattern = re.compile(
        r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<endpoint>\S+) \S+" (?P<status>\d+) (?P<size>\d+)'
    )
    
    analyzed_records = []
    ip_failure_counts = {}
    unauthorized_access_flags = []

    print("[ANALYTICS] Parsing network packet stream and log vectors...")

    for line in log_lines:
        match = log_pattern.match(line)
        if match:
            data = match.groupdict()
            status_code = int(data['status'])
            ip = data['ip']
            
            # Track failed authentication or forbidden access attempts (anomaly threshold)
            if status_code in [401, 403]:
                ip_failure_counts[ip] = ip_failure_counts.get(ip, 0) + 1
                if ip_failure_counts[ip] >= 2:
                    unauthorized_access_flags.append({
                        "ip_address": ip,
                        "triggered_at": data['timestamp'],
                        "reason": f"Repeated unauthorized/forbidden status code: {status_code}"
                    })
            
            analyzed_records.append(data)

    report = {
        "scan_timestamp_utc": datetime.datetime.utcnow().isoformat(),
        "total_packets_analyzed": len(analyzed_records),
        "anomalies_detected": len(unauthorized_access_flags),
        "threat_ledger": unauthorized_access_flags
    }
    
    return report

if __name__ == "__main__":
    log_filename = "network_traffic.log"
    
    # Write a sample log file for local verification
    with open(log_filename, "w", encoding="utf-8") as f:
        for log in SAMPLE_LOGS:
            f.write(log + "\n")
            
    with open(log_filename, "r", encoding="utf-8") as f:
        lines = f.readlines()
        
    security_report = parse_and_analyze_logs([l.strip() for l in lines])
    
    print("\n--- Network Security Telemetry Report ---")
    print(json.dumps(security_report, indent=4))
    
    if security_report["anomalies_detected"] > 0:
        print("\n[ALERT] Anomalous network traffic spikes or intrusion vectors isolated.")
    else:
        print("\n[STATUS] Network stream clean. No anomalous spikes detected.")
