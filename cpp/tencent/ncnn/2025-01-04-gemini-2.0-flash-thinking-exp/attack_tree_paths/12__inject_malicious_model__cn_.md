```python
import hashlib
import requests
import os

# --- Configuration (Should be securely managed) ---
MODEL_URL = "https://example.com/legitimate_model.bin"  # Replace with actual URL
EXPECTED_HASH = "your_expected_sha256_hash_here"  # Replace with the SHA256 hash of the legitimate model
MODEL_FILE_PATH = "model.bin"

def download_model():
    """Downloads the model file."""
    try:
        response = requests.get(MODEL_URL, stream=True)
        response.raise_for_status()  # Raise an exception for bad status codes

        with open(MODEL_FILE_PATH, 'wb') as file:
            for chunk in response.iter_content(chunk_size=8192):
                file.write(chunk)
        print(f"Model downloaded successfully to {MODEL_FILE_PATH}")
        return True
    except requests.exceptions.RequestException as e:
        print(f"Error downloading model: {e}")
        return False

def verify_model_integrity():
    """Verifies the integrity of the downloaded model using SHA256."""
    if not os.path.exists(MODEL_FILE_PATH):
        print("Model file not found. Cannot verify integrity.")
        return False

    hasher = hashlib.sha256()
    try:
        with open(MODEL_FILE_PATH, 'rb') as file:
            while chunk := file.read(4096):
                hasher.update(chunk)
        calculated_hash = hasher.hexdigest()
        if calculated_hash == EXPECTED_HASH:
            print("Model integrity verified successfully.")
            return True
        else:
            print(f"Model integrity check failed! Calculated hash: {calculated_hash}, Expected hash: {EXPECTED_HASH}")
            return False
    except Exception as e:
        print(f"Error calculating hash: {e}")
        return False

def load_and_execute_model():
    """Loads and executes the model using ncnn (placeholder)."""
    print("Attempting to load and execute the model...")
    # --- ncnn specific code would go here ---
    # Example:
    # import ncnn
    # net = ncnn.Net()
    # net.load_param('model.param')
    # net.load_model('model.bin')
    # ... perform inference ...
    print("Model loaded and executed (placeholder).")
    return True

def main():
    """Main function to demonstrate the vulnerability and mitigation."""
    print("Starting application...")

    # Simulate downloading the model (vulnerable step)
    if download_model():
        # Simulate the vulnerability: Lack of integrity check
        print("\n--- Vulnerable Scenario: Without Integrity Check ---")
        load_and_execute_model() # Application loads whatever is present

        # --- Mitigation: Implementing Integrity Check ---
        print("\n--- Mitigated Scenario: With Integrity Check ---")
        if verify_model_integrity():
            load_and_execute_model()
        else:
            print("Model integrity check failed. Aborting model loading.")
    else:
        print("Application startup failed due to model download issue.")

if __name__ == "__main__":
    main()
```