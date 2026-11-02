# data_integrity_engine/scraper_engine.py

import os
import sys
import json
import urllib.request
import urllib.error
import datetime

def fetch_and_aggregate_data(target_url: str, output_file: str = "archive_data.json"):
    """
    Programmatically fetches raw data from a targeted endpoint, 
    parses and sanitizes the payload, and structures it into a JSON archive.
    """
    print(f"[NETWORK] Initiating secure data request to: {target_url}")
    
    headers = {'User-Agent': 'DataIntegrityEngine-Agent/1.0'}
    
    try:
        req = urllib.request.Request(target_url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as response:
            raw_content = response.read().decode('utf-8')
            
        # Parse raw payload into a structured python object
        parsed_data = json.loads(raw_content)
        
        # Build structured archive package with system metadata
        archive_payload = {
            "ingestion_metadata": {
                "source_url": target_url,
                "ingested_at_utc": datetime.datetime.utcnow().isoformat(),
                "status": "SUCCESS"
            },
            "record_count": len(parsed_data) if isinstance(parsed_data, list) else 1,
            "payload": parsed_data
        }
        
        # Write structured profile to local archive
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(archive_payload, f, indent=4)
            
        print(f"[ARCHIVE] Successfully aggregated and structured data into: {output_file}")
        return True

    except urllib.error.URLError as e:
        print(f"[ERROR] Network connection failed: {e.reason}")
        return False
    except json.JSONDecodeError:
        print("[ERROR] Failed to parse response into JSON. Invalid payload format.")
        return False
    except Exception as e:
        print(f"[ERROR] Unexpected execution failure: {str(e)}")
        return False

if __name__ == "__main__":
    # Target a reliable public JSON endpoint for initial architecture verification
    target_endpoint = "https://jsonplaceholder.typicode.com/todos?_limit=5"
    destination_archive = "archive_data.json"
    
    success = fetch_and_aggregate_data(target_endpoint, destination_archive)
    if not success:
        sys.exit(1)
