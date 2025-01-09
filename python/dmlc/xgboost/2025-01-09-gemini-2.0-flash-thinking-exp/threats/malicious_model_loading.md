```python
# This is a conceptual example and not directly executable.
# It demonstrates the principles of integrity checks.

import hashlib
import os

# --- Configuration ---
MODEL_STORAGE_PATH = "/path/to/model/storage"  # Replace with actual path
EXPECTED_MODEL_HASHES = {
    "model_v1.bin": "your_known_good_hash_for_v1",
    "model_v2.bin": "your_known_good_hash_for_v2",
    # ... add hashes for all legitimate models
}

def calculate_file_hash(filepath):
    """Calculates the SHA-256 hash of a file."""
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as file:
        while True:
            chunk = file.read(4096)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()

def load_model_with_integrity_check(model_filename):
    """Loads an XGBoost model with integrity verification."""
    model_path = os.path.join(MODEL_STORAGE_PATH, model_filename)

    if model_filename not in EXPECTED_MODEL_HASHES:
        print(f"Error: Unknown model file: {model_filename}")
        return None  # Or raise an exception

    expected_hash = EXPECTED_MODEL_HASHES[model_filename]
    calculated_hash = calculate_file_hash(model_path)

    if calculated_hash == expected_hash:
        print(f"Integrity check passed for {model_filename}")
        try:
            import xgboost as xgb
            bst = xgb.Booster()
            bst.load_model(model_path)
            return bst
        except Exception as e:
            print(f"Error loading model: {e}")
            return None
    else:
        print(f"Error: Integrity check failed for {model_filename}! "
              f"Expected hash: {expected_hash}, Calculated hash: {calculated_hash}")
        # Handle the failure appropriately:
        # - Log the incident
        # - Alert security team
        # - Potentially refuse to load the model or use a fallback
        return None

# --- Example Usage ---
model_to_load = "model_v1.bin"
loaded_model = load_model_with_integrity_check(model_to_load)

if loaded_model:
    print(f"Model '{model_to_load}' loaded successfully and is verified.")
    # Proceed with using the loaded model
else:
    print(f"Failed to load model '{model_to_load}' due to integrity issues.")

# --- Example of scanning for unauthorized modifications (Conceptual) ---
def scan_model_storage():
    """Scans the model storage for unauthorized modifications."""
    print("Scanning model storage for unauthorized modifications...")
    for filename in os.listdir(MODEL_STORAGE_PATH):
        if filename.endswith(".bin"): # Assuming model files have .bin extension
            filepath = os.path.join(MODEL_STORAGE_PATH, filename)
            calculated_hash = calculate_file_hash(filepath)
            if filename in EXPECTED_MODEL_HASHES:
                if calculated_hash != EXPECTED_MODEL_HASHES[filename]:
                    print(f"WARNING: Model '{filename}' has been modified! "
                          f"Expected hash: {EXPECTED_MODEL_HASHES[filename]}, Calculated hash: {calculated_hash}")
                    # Implement alerting and incident response here
            else:
                print(f"WARNING: Unauthorized model file found: {filename} (Hash: {calculated_hash})")
                # Implement alerting and incident response here

# Example of running the scan periodically
# scan_model_storage()
```