import hashlib
import os
import json
import datetime


def calculate_file_hash(file_path):
    """
    Reads a file in binary mode and calculates its SHA-256 fingerprint 
    Processes data in chunks to handle files of any size efficiwntly.
    
    """
    # Initialize the SHA-256 hashing engine
    sha256_engine = hashlib.sha256()

    try:
        # Open file in Read-Binary ('rb') mode to prevent format manipulation.
        with open(file_path, 'rb') as target_file:
            # Read in 4096-byte blocks to preserce system memory
            while chunk := target_file.read(4096):
                sha256_engine.update(chunk)

        
        # Return the final hexadecimal 64-character fingerprint
        return sha256_engine.hexdigest()


    except FileNotFoundError:
	    print(f"[ERROR] Target file not found at: {file_path}")
	    return None
    except Exception as e:
	    print(f"[ERROR] Security exception or readfailure: {str(e)}")
	    return None


def generate_system_manifest(target_directory):
    """
    Scans a directory, calculates hashes for all non-hidden files,
    and returns a structured, timestamped manifest dictionary.
    """

    manifest = {
        "system_metadata": {
            "generated_at_utc": datetime.datetime.utcnow().isoformat(),
            "target_path": os.path.abspath(target_directory)
        },
        "records": {}
    }
    
    
    print(f"[SYSTEM] Beginning integrity scan on: {target_directory}")
    
    
    # Walk through all directories and files recursively
    for root, dirs, files in os.walk(target_directory):
        # Prevent tracking hidden git configurations
        if 'git' in root:
            continue
            
            
        for file_name in files:
            full_path = os.path.join(root, file_name)
            relative_path = os.path.relpath(full_path, target_directory)
        
        
            # Calculate the unassailable hash using our lesson 2 module
            file_hash = calculate_file_hash(full_path)
        
            if file_hash:
                manifest["records"][relative_path] = {
                    "sha256": file_hash,
                    "size_bytes": os.path.getsize(full_path)
                }
                print(f" -> Indexed: {relative_path}")
            
            
    return manifest    


if __name__ == "__main__":
    # Test the module on itself to verify execution
    current_file = __file__
    print(f"[SYSTEM] Hashing execution path: {current_file}")

    resulting_hash = calculate_file_hash(current_file)
    if resulting_hash:
    	print(f"[RESULT] Verification Fingerprint:\n-> {resulting_hash}")

    # Define tge current workspace directory 
    workspace = "."


    # Generate the complete dataset profile
    current_manifest = generate_system_manifest(workspace)


    # Save the manifest as an immutable local record
    output_file = "manifest.json"
    with open(output_file, "w") as f:
        json.dump(current_manifest, f, indent=4)

    print(f"\n[SUCCESS] Integrity Ledger written to: {output_file}")
