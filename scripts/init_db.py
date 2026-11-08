# init_db.py
import sqlite3

def initialize_secure_vault(db_path="secure_vault.db"):
    """Initializes the secure SQLite vault schema for Project Beta and Project Sigma."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Project Beta: Programmatic Web Feed Ingestion Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS project_beta_feeds (
        feed_id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        source_url TEXT NOT NULL,
        http_status_code INTEGER,
        payload_content TEXT,
        sha256_checksum TEXT NOT NULL
    );
    """)
    
    # Project Sigma: Chronological Append-Only Sigchain Table (Phase 2)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sigma_attestations (
        sequence_id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        merkle_root TEXT NOT NULL,
        signature TEXT NOT NULL,
        previous_signature TEXT
    );
    """)
    
    conn.commit()
    conn.close()
    print(f"[VAULT] secure_vault.db successfully initialized with sigma_attestations & project_beta_feeds.")

if __name__ == "__main__":
    initialize_secure_vault()

