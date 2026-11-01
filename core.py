import hashlib
import os

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


if __name__ == "__main__":
    # Test the module on itself to verify execution
    current_file = __file__
    print(f"[SYSTEM] Hashing execution path: {current_file}")

    resulting_hash = calculate_file_hash(current_file)
    if resulting_hash:
    	print(f"[RESULT] Verification Fingerprint:\n-> {resulting_hash}")
