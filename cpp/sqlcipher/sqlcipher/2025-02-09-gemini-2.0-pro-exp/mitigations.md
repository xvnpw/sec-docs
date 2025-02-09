# Mitigation Strategies Analysis for sqlcipher/sqlcipher

## Mitigation Strategy: [Secure Key Derivation and SQLCipher Rekeying](./mitigation_strategies/secure_key_derivation_and_sqlcipher_rekeying.md)

1.  **Key Derivation (Initial Setup):**
    *   Use a robust KDF (PBKDF2, Argon2id, scrypt) supported by SQLCipher.
    *   Generate a cryptographically secure random salt.
    *   Set a *high* iteration count/work factor for the KDF. This is crucial and directly impacts SQLCipher's security.
    *   Use the derived key with SQLCipher's `PRAGMA key = 'your_derived_key';` command *immediately* after opening the database connection.  This is the *only* way to set the initial encryption key.
2.  **Key Rotation (Rekeying):**
    *   Implement a mechanism to periodically change the encryption key.
    *   Generate a *new* key using the same secure KDF process (with a new salt, ideally).
    *   Use SQLCipher's `PRAGMA rekey = 'new_derived_key';` command to re-encrypt the entire database with the new key.  This is an atomic operation provided by SQLCipher.  Ensure you have a reliable connection and sufficient resources (disk space, time) for this operation.
    *   *Important:* The `rekey` pragma *must* be the *first* operation performed on the database after opening it with the *old* key.  You open with the old key, immediately `PRAGMA rekey`, and then close and reopen with the new key.
3. **Key Consistency Check:**
    * After setting the key (either initially or after rekeying), immediately execute a simple query (e.g., `SELECT 1;`) to verify that the key is correct and the database is accessible. This catches errors early.

    **List of Threats Mitigated:**
        *   **Brute-Force Attacks on Passphrase:** (Severity: High) - High KDF iteration count directly mitigates this.
        *   **Dictionary Attacks on Passphrase:** (Severity: High) - Salt usage, combined with the KDF, mitigates this.
        *   **Data Breach After Key Compromise:** (Severity: Critical) - `PRAGMA rekey` limits the exposure window.
        *   **Incorrect Key Usage:** (Severity: Critical) - Immediate query after key setting verifies correct operation.

    **Impact:**
        *   **Brute-Force/Dictionary Attacks:** Significantly reduced attack success probability.
        *   **Data Breach After Key Compromise:** Limits the amount of data exposed.
        *   **Incorrect Key:** Prevents proceeding with an invalid key, avoiding data corruption or inaccessibility.

    **Currently Implemented:**
        *   Key Derivation: Partially. PBKDF2 is used, but the iteration count is too low. Salt is generated securely. `PRAGMA key` is used.
        *   Key Rotation: Not implemented. `PRAGMA rekey` is not used.
        *   Key Consistency Check: Not implemented.

    **Missing Implementation:**
        *   Key Derivation: Increase PBKDF2 iteration count to at least 100,000.
        *   Key Rotation: Implement the `PRAGMA rekey` logic and a scheduling mechanism.
        *   Key Consistency Check: Add a simple query after setting the key.

## Mitigation Strategy: [Correct SQLCipher Configuration (Pragmas)](./mitigation_strategies/correct_sqlcipher_configuration__pragmas_.md)

1.  **Cipher Algorithm:**
    *   Explicitly set the cipher using `PRAGMA cipher = 'aes-256-cbc';` (or another secure, supported cipher).  Don't rely solely on the default, explicitly configure it.
2.  **HMAC Verification:**
    *   Explicitly enable HMAC using `PRAGMA cipher_use_hmac = ON;`.  This is usually the default, but confirm it.  This prevents tampering.
3.  **KDF Iteration Count (Pragma):**
    *   Set the KDF iteration count using `PRAGMA kdf_iter = 100000;` (or the chosen high value).  This *must* match the iteration count used in your key derivation code. This pragma tells SQLCipher how many iterations *it* should use internally for certain operations.
4.  **Page Size:**
    *   Set the page size using `PRAGMA page_size = 4096;` (or another appropriate size).  The default is usually fine, but be explicit.
5.  **Secure Delete:**
    *   Consider enabling secure delete using `PRAGMA secure_delete = ON;`.  Evaluate the performance impact.
6. **WAL Mode (Confirmation):**
    * If using WAL mode, ensure it's correctly configured. SQLCipher handles WAL encryption automatically if the main database is encrypted, but verify with `PRAGMA journal_mode;`.
7. **Compatibility:**
    * If you need to maintain compatibility with older versions of SQLCipher, use `PRAGMA cipher_compatibility = X;` where X is the version number. Be very careful with this, as it can weaken security.
8. **Execute all PRAGMAs immediately after opening the database connection and setting the key, and *before* any other SQL operations.**

    **List of Threats Mitigated:**
        *   **Weak Cipher Usage:** (Severity: High) - Explicitly setting a strong cipher prevents using a weaker default.
        *   **Data Tampering:** (Severity: High) - `PRAGMA cipher_use_hmac = ON` prevents undetected modifications.
        *   **Inconsistent KDF Settings:** (Severity: Critical) - `PRAGMA kdf_iter` ensures consistency between key derivation and SQLCipher's internal operations.
        *   **Data Recovery from Deleted Records:** (Severity: Medium) - `PRAGMA secure_delete = ON` makes recovery harder.
        *   **Compatibility Issues:** (Severity: Variable) - `PRAGMA cipher_compatibility` allows controlled compatibility, but should be used with extreme caution.

    **Impact:**
        *   **Weak Cipher/Data Tampering:** Risk eliminated by correct pragma settings.
        *   **Inconsistent KDF:** Prevents operational errors.
        *   **Data Recovery:** Reduces the risk.
        * **Compatibility Issues:** Provides a controlled way to manage compatibility, but with potential security trade-offs.

    **Currently Implemented:**
        *   `PRAGMA cipher`: Set to 'aes-256-cbc'.
        *   `PRAGMA cipher_use_hmac`: Set to ON.
        *   `PRAGMA kdf_iter`: Set, but the value needs to be increased to match the updated key derivation.
        *   `PRAGMA page_size`: Set to the default (4096).
        *   `PRAGMA secure_delete`: Not set.
        *   `PRAGMA journal_mode`: Set to WAL.
        *   `PRAGMA cipher_compatibility`: Not set.

    **Missing Implementation:**
        *   `PRAGMA kdf_iter`: Update the value to match the increased iteration count in key derivation.
        *   `PRAGMA secure_delete`: Evaluate and potentially enable.
        *   **Ordering:** Ensure all pragmas are executed in the correct order, immediately after opening the database and setting the key.

