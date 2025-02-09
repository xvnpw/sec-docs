# Mitigation Strategies Analysis for tencent/mmkv

## Mitigation Strategy: [Layered Encryption (with MMKV Interaction)](./mitigation_strategies/layered_encryption__with_mmkv_interaction_.md)

**Description:**
1.  **Key Derivation:** (As before - this is *preparation* for using MMKV, but not directly interacting with it). Derive a strong encryption key using a KDF like Argon2id, a secret, and a salt.
2.  **Encryption:** Before calling `MMKV.set()` (or equivalent), encrypt the data using AES-256-GCM with the derived key and a unique IV/nonce.
3.  **MMKV Storage:** Call `MMKV.set(key, encryptedData)` to store the *ciphertext*, IV/nonce, and (separately) the salt.  You might use different MMKV instances or keys to separate these components.
4.  **MMKV Retrieval:** When retrieving, call `MMKV.get(key)` to retrieve the ciphertext, IV/nonce, and salt.
5.  **Key Re-derivation:** (As before). Re-derive the encryption key.
6.  **Decryption:** Decrypt the ciphertext using the re-derived key and the retrieved IV/nonce. Verify the authentication tag.

**Threats Mitigated:**
*   **Data Breach via File System Access (High Severity):** MMKV files contain only encrypted data.
*   **Brute-Force Attacks on MMKV's Built-in Encryption (Medium Severity):** Adds a layer of protection.
*   **Weak Key Vulnerabilities (High Severity):** Addressed by the KDF.
*   **Replay Attacks (Medium Severity):** Prevented by unique IV/nonces.

**Impact:**
*   **Data Breach via File System Access:** Risk reduced from High to Very Low.
*   **Brute-Force Attacks:** Risk reduced from Medium to Low.
*   **Weak Key Vulnerabilities:** Risk reduced from High to Low.
*   **Replay Attacks:** Risk reduced from Medium to Very Low.

**Currently Implemented:** Partially. Encryption before `MMKV.set()` for user credentials in `auth.cpp`.

**Missing Implementation:** Encryption missing before `MMKV.set()` for application settings in `settings.cpp`. Need to standardize on AES-256-GCM and Argon2id. Consistent IV/nonce handling.

## Mitigation Strategy: [HMAC-Based Integrity Check (with MMKV Interaction)](./mitigation_strategies/hmac-based_integrity_check__with_mmkv_interaction_.md)

**Description:**
1.  **Key Generation:** (Preparation - not direct MMKV interaction). Generate a separate secret HMAC key.
2.  **HMAC Calculation:** Before calling `MMKV.set()`, calculate an HMAC-SHA256 of the data (plaintext or ciphertext).
3.  **MMKV Storage:** Call `MMKV.set(key, data)` and `MMKV.set(hmacKey, hmacValue)` to store *both* the data and the calculated HMAC. Use a separate key for the HMAC.
4.  **MMKV Retrieval:** When retrieving, call `MMKV.get(key)` to get the data and `MMKV.get(hmacKey)` to get the HMAC.
5.  **HMAC Verification:** Re-calculate the HMAC of the retrieved data.
6.  **Comparison:** Compare the calculated HMAC with the retrieved HMAC from MMKV.

**Threats Mitigated:**
*   **Data Tampering via File System Access (High Severity):** Prevents undetected modification of data in MMKV files.
*   **Bypass of MMKV's CRC32 Check (Medium Severity):** Provides cryptographically strong integrity.

**Impact:**
*   **Data Tampering via File System Access:** Risk reduced from High to Very Low.
*   **Bypass of MMKV's CRC32 Check:** Risk reduced from Medium to Very Low.

**Currently Implemented:** Not implemented.

**Missing Implementation:** HMAC calculation/verification missing for all `MMKV.set()` and `MMKV.get()` calls.

## Mitigation Strategy: [Secure File Storage and Permissions (MMKV Configuration)](./mitigation_strategies/secure_file_storage_and_permissions__mmkv_configuration_.md)

**Description:**
1.  **Platform-Specific Path:** During MMKV initialization, specify a secure, application-specific directory for MMKV files. This is done *when creating the MMKV instance*.
    *   **Android:** Use `Context.getFilesDir().getAbsolutePath()` as the base path.
    *   **iOS:** Use the appropriate sandboxed directory path.
    *   **Other Platforms:** Use the platform-recommended secure storage location.
2.  **MMKV Initialization:** Pass this secure path to the MMKV initialization function (e.g., `MMKV.initialize()` or equivalent). This ensures MMKV stores its files in the designated secure location.
3. **Least Privilege:** (Not directly MMKV, but related) Ensure the application runs with minimum privileges.

**Threats Mitigated:**
*   **Unauthorized Access by Other Applications (High Severity):** Limits access to MMKV files.
*   **Unauthorized Access by Other Users (Medium Severity):** On multi-user systems.

**Impact:**
*   **Unauthorized Access by Other Applications:** Risk reduced from High to Very Low (on sandboxed platforms).
*   **Unauthorized Access by Other Users:** Risk reduced from Medium to Low.

**Currently Implemented:** Partially. Correct paths used during MMKV initialization on Android and iOS.

**Missing Implementation:** Explicit path configuration missing for desktop platforms during MMKV initialization.

## Mitigation Strategy: [Input Validation and Sanitization (Before MMKV Interaction)](./mitigation_strategies/input_validation_and_sanitization__before_mmkv_interaction_.md)

**Description:**
1.  **Key Validation:** *Before* calling `MMKV.set(key, value)`, validate the `key`:
    *   Define a strict format (e.g., alphanumeric, limited length, specific prefixes).
    *   Reject keys that don't conform.
2.  **Value Sanitization:** *Before* calling `MMKV.set(key, value)`, if the `value` will be used in a security-sensitive context (HTML, JavaScript, SQL), sanitize it appropriately for that context.

**Threats Mitigated:**
*   **Injection Attacks (High Severity):** Prevents storing data that could lead to XSS, SQLi, etc., *if* that data is later used unsafely.
*   **Unexpected Behavior (Low Severity):** Due to malformed keys.

**Impact:**
*   **Injection Attacks:** Risk reduced from High to Very Low (dependent on correct sanitization elsewhere).
*   **Unexpected Behavior:** Risk reduced from Low to Very Low.

**Currently Implemented:** Partially. Basic key length checks before some `MMKV.set()` calls.

**Missing Implementation:** Comprehensive key format validation before all `MMKV.set()` calls. Consistent value sanitization before `MMKV.set()` where appropriate.

## Mitigation Strategy: [Monitoring and Auditing (Wrapper Functions)](./mitigation_strategies/monitoring_and_auditing__wrapper_functions_.md)

**Description:**
1.  **Wrapper Functions:** Create custom functions, e.g., `my_mmkv_set(key, value)` and `my_mmkv_get(key)`, that wrap MMKV's `set()` and `get()` methods.
2.  **Logging (Inside Wrappers):**  Within `my_mmkv_set` and `my_mmkv_get`, *before* and *after* calling the actual MMKV functions, log:
    *   Timestamp
    *   Key being accessed
    *   Operation (set or get)
    *   Success/failure
    *   (If possible) User/context ID
3. **Call Wrappers:** Always use `my_mmkv_set` and `my_mmkv_get` instead of directly calling MMKV's methods.

**Threats Mitigated:**
*   **Detection of Unauthorized Access (Medium Severity):** Helps detect suspicious activity.
*   **Incident Response (Medium Severity):** Provides audit trails.

**Impact:**
*   **Detection of Unauthorized Access:** Risk reduced from Medium to Low (with effective monitoring).
*   **Incident Response:** Improved ability to investigate incidents.

**Currently Implemented:** Not implemented.

**Missing Implementation:** Wrapper functions and logging around MMKV calls are completely absent.

