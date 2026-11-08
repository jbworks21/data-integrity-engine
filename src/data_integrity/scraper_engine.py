# scraper_engine.py
import sys
import urllib.request
import urllib.error
import hashlib
import sqlite3
import datetime
import asyncio

from .crypto_log import initialize_database


class ProgrammaticScraperEngine:
    """
    Asynchronous web ingestion pipeline. Uses the stdlib only (no aiohttp),
    wraps the blocking urllib call in a thread pool, and persists each
    footprint to the secure_vault.db project_beta_feeds table.
    """

    def __init__(self, db_path="secure_vault.db", timeout_seconds=10):
        self.db_path = db_path
        self.timeout = timeout_seconds
        self.user_agent = "DataIntegrityEngine-Crawler/2.0 (+https://github.com)"
        # Ensure project_beta_feeds (and the other tables) exist before we
        # attempt any INSERT. Without this, persistence fails silently.
        initialize_database(db_path)

    def _calculate_sha256(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def _log_to_vault(self, url: str, status: int, content: str, checksum: str):
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute(
                "INSERT INTO project_beta_feeds "
                "(timestamp, source_url, http_status_code, payload_content, sha256_checksum) "
                "VALUES (?, ?, ?, ?, ?)",
                (timestamp, url, status, content, checksum),
            )
            conn.commit()
            conn.close()
            print(f"[VAULT LOG] Anchored ingestion footprint for: {url}")
        except Exception as e:
            print(f"[VAULT ERROR] Failed to record footprint: {e}")

    def _blocking_fetch(self, url: str) -> tuple:
        """Runs in a thread-pool worker. Returns (status_code, raw_bytes)."""
        req = urllib.request.Request(url)
        req.add_header("User-Agent", self.user_agent)
        req.add_header("Accept-Encoding", "identity")
        req.add_header(
            "X-Audit-Tracking-UTC",
            datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                return response.getcode(), response.read()
        except urllib.error.HTTPError as e:
            return e.code, str(e.reason).encode("utf-8", errors="ignore")
        except urllib.error.URLError as e:
            return 599, str(e.reason).encode("utf-8", errors="ignore")
        except Exception as e:
            return 500, str(e).encode("utf-8", errors="ignore")

    async def fetch_target_stream(self, url: str) -> dict:
        print(f"\n[HTTP REQUEST] Dispatching egress worker to: {url}")
        loop = asyncio.get_running_loop()
        status_code, raw_bytes = await loop.run_in_executor(
            None, self._blocking_fetch, url
        )
        checksum = self._calculate_sha256(raw_bytes)
        decoded = raw_bytes.decode("utf-8", errors="ignore")
        print(f"[HTTP RESPONSE] Code: {status_code} | Checksum: {checksum}")
        self._log_to_vault(url, status_code, decoded, checksum)
        return {
            "url": url,
            "status": status_code,
            "sha256": checksum,
            "content_snippet": decoded[:150].strip().replace("\n", " "),
        }

    async def execute_batch_harvest(self, target_urls: list):
        print("=" * 70)
        print("         PROJECT BETA: DATA INGESTION ENGINE ACTIVE")
        print("=" * 70)
        tasks = [self.fetch_target_stream(u) for u in target_urls]
        results = await asyncio.gather(*tasks)
        print("\n" + "=" * 70)
        print("                BATCH HARVEST SUMMARY")
        print("=" * 70)
        for res in results:
            print(f"URL    : {res['url']}")
            print(f"Status : {res['status']} | Hash: {res['sha256']}")
            print(f"Data   : {res['content_snippet']}...")
            print("-" * 70)


if __name__ == "__main__":
    # Public, stable, unauthenticated test endpoints.
    # jsonplaceholder matches the source used by archive_data.json.
    sample_targets = [
        "https://jsonplaceholder.typicode.com/todos/1",
        "https://jsonplaceholder.typicode.com/users/1",
    ]
    scraper = ProgrammaticScraperEngine()
    try:
        asyncio.run(scraper.execute_batch_harvest(sample_targets))
    except KeyboardInterrupt:
        print("\n[SCRAPER] Ingestion sequence terminated by user.")
        sys.exit(0)
