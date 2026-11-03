# data_integrity_engine/scraper_engine.py
import os
import sys
import re
import json
import urllib.request
import urllib.error
import hashlib
import sqlite3
import datetime
import asyncio

class ProgrammaticScraperEngine:
    """
    Implements a zero-dependency, asynchronous web ingestion pipeline.
    Parses programmatic data streams using native standard libraries,
    enforces absolute UTC audit tracking headers, and records snapshots securely.
    """

    def __init__(self, db_path="secure_vault.db"):
        self.db_path = db_path
        # User-Agent representing compliance and identification profiles
        self.user_agent = "DataIntegrityEngine-Crawler/2.0 (+https://github.com)"
        
    def _calculate_sha256(self, data: bytes) -> str:
        """Computes a strict cryptographic hash over raw ingested content."""
        return hashlib.sha256(data).hexdigest()

    def _log_to_vault(self, url: str, status: int, content: str, checksum: str):
        """Persists crawled metrics cleanly inside the secure relational vault database."""
        timestamp = datetime.datetime.now(datetime.UTC).isoformat()
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO project_beta_feeds (timestamp, source_url, http_status_code, payload_content, sha256_checksum)
                VALUES (?, ?, ?, ?, ?)
            """, (timestamp, url, status, content, checksum))
            conn.commit()
            conn.close()
            print(f"[VAULT LOG] Successfully anchored ingestion footprint for: {url}")
        except Exception as e:
            print(f"[VAULT ERROR] Failed to record footprint inside database: {str(e)}")

    async def fetch_target_stream(self, url: str) -> dict:
        """
        Executes a non-blocking network request using native urllib bindings wrapped in an asyncio thread pool.
        """
        print(f"\n[HTTP REQUEST] Dispaching egress worker to target: {url}")
        
        req = urllib.request.Request(url)
        req.add_header("User-Agent", self.user_agent)
        req.add_header("Accept-Encoding", "identity")
        req.add_header("X-Audit-Tracking-UTC", datetime.datetime.now(datetime.UTC).isoformat())

        # Execute blocking urllib call within a default executor pool to prevent blocking the async loop
        loop = asyncio.get_running_loop()
        
        def _execute_network_call():
            try:
                with urllib.request.urlopen(req, timeout=10) as response:
                    status = response.getcode()
                    raw_payload = response.read()
                    return status, raw_payload
            except urllib.error.HTTPError as e:
                return e.code, str(e.reason).encode('utf-8')
            except urllib.error.URLError as e:
                return 599, str(e.reason).encode('utf-8')
            except Exception as e:
                return 500, str(e).encode('utf-8')

        status_code, raw_bytes = await loop.run_in_executor(None, _execute_network_call)
        
        # Process and validate the response payload
        checksum = self._calculate_sha256(raw_bytes)
        decoded_content = raw_bytes.decode('utf-8', errors='ignore')
        
        print(f"[HTTP RESPONSE] Code: {status_code} | Payload Checksum: {checksum}")
        
        # Commit footprint immediately to database tracking tables
        self._log_to_vault(url, status_code, decoded_content, checksum)
        
        return {
            "url": url,
            "status": status_code,
            "sha256": checksum,
            "content_snippet": decoded_content[:150].strip().replace('\n', ' ')
        }

    async def execute_batch_harvest(self, target_urls: list):
        """Coordinates concurrent network ingestion matrix execution across worker clusters."""
        print(f"=============================================================")
        print("          PROJECT BETA: DATA INGESTION ENGINE ACTIVE         ")
        print("=============================================================")
        
        tasks = [self.fetch_target_stream(url) for url in target_urls]
        results = await asyncio.gather(*tasks)
        
        print("\n=============================================================")
        print("                BATCH HARVEST SUMMARY PROFILE                 ")
        print("=============================================================")
        for res in results:
            print(f"URL   : {res['url']}")
            print(f"Status: {res['status']} | Hash: {res['sha256']}")
            print(f"Data  : {res['content_snippet']}...")
            print("-" * 70)

if __name__ == "__main__":
    # Test suite targets (Using public configuration end points)
    sample_targets = [
        "https://httpbin.org",
        "https://httpbin.org"
    ]
    
    scraper = ProgrammaticScraperEngine()
    try:
        asyncio.run(scraper.execute_batch_harvest(sample_targets))
    except KeyboardInterrupt:
        print("\n[SCRAPER] Ingestion sequence terminated via user control interrupt.")
        sys.exit(0)
