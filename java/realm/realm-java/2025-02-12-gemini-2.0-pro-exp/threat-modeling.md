# Threat Model Analysis for realm/realm-java

## Threat: [Unauthorized Data Access via File System (Unencrypted Realm)](./threats/unauthorized_data_access_via_file_system__unencrypted_realm_.md)

*   **Description:** An attacker gains access to the device's file system and reads the *unencrypted* `.realm` file directly. This bypasses any application-level security if Realm's encryption is not used.
    *   **Impact:** Complete exposure of all data stored in the Realm database. This is a direct compromise of the data managed by Realm.
    *   **Affected Component:** Realm Core Database Engine (storage layer), `.realm` file.
    *   **Risk Severity:** Critical.
    *   **Mitigation Strategies:**
        *   **Encryption (Mandatory):** *Always* encrypt the Realm database using Realm's built-in encryption. This is the *primary* defense against this threat.

## Threat: [Weak Encryption Key Compromise](./threats/weak_encryption_key_compromise.md)

*   **Description:** An attacker obtains the encryption key used by Realm. This could be through reverse engineering if the key is poorly protected *within the application's interaction with Realm*, or through vulnerabilities in how the application retrieves or uses the key with the Realm API. This is distinct from a general Keystore compromise; it focuses on the application's *use* of the key with Realm.
    *   **Impact:** Complete exposure of all encrypted data in the Realm database. The Realm encryption is rendered useless.
    *   **Affected Component:** Realm Encryption Module, Key Management Logic *as it interacts with Realm APIs*.
    *   **Risk Severity:** Critical.
    *   **Mitigation Strategies:**
        *   **Secure Key Generation:** Use a cryptographically secure random number generator (CSPRNG) to generate the encryption key *before passing it to Realm*.
        *   **Android Keystore/iOS Keychain:** Use the platform's secure key storage *and ensure the application correctly retrieves and uses the key with Realm APIs*.
        *   **Key Derivation (Optional):** If using a KDF, ensure it's implemented correctly and the derived key is securely passed to Realm.
        *   **Code Obfuscation:** Obfuscate code that interacts with Realm's encryption APIs to make reverse engineering harder.
        *   **Native Code (Optional):** Consider native code for the logic that passes the key to Realm's encryption functions.

## Threat: [Unauthorized Data Modification](./threats/unauthorized_data_modification.md)

*   **Description:** An attacker gains write access to the Realm file and modifies the data. This directly impacts the integrity of the data managed by Realm. The focus here is on the *Realm file* itself being modified, not general application logic flaws.
    *   **Impact:** Data corruption, application instability, and compromise of data integrity within the Realm database.
    *   **Affected Component:** Realm Core Database Engine (storage and transaction layers), `.realm` file.
    *   **Risk Severity:** High.
    *   **Mitigation Strategies:**
        *   **Encryption:** Encryption (as described above) is crucial to prevent unauthorized modification.
        *   **Restrictive File Permissions:** Ensure the Realm file has the most restrictive file system permissions (Realm's default behavior is generally secure, but verification is important).

## Threat: [Data Deletion](./threats/data_deletion.md)

*    **Description:** An attacker with write access to the Realm file deletes the entire database or specific objects within it.
    *    **Impact:** Complete or partial data loss, leading to application malfunction or loss of user data.
    *    **Affected Component:** Realm Core Database Engine (storage layer), `.realm` file.
    *    **Risk Severity:** High.
    *    **Mitigation Strategies:**
        *    **Same as Unauthorized Data Access and Modification:** Encryption, secure key storage, restrictive file permissions.

