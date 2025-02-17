# Mitigation Strategies Analysis for realm/realm-cocoa

## Mitigation Strategy: [Secure Encryption Key Management (Realm API Usage)](./mitigation_strategies/secure_encryption_key_management__realm_api_usage_.md)

**Description:**
1.  **Obtain the 64-byte Encryption Key:** This key *must* be securely managed (see previous responses for secure generation and storage). This step focuses on *how* you use the key with Realm.
2.  **Realm Configuration:** When opening an encrypted Realm, create a `Realm.Configuration` object.
3.  **Set the `encryptionKey` Property:** Set the `encryptionKey` property of the `Realm.Configuration` to your 64-byte key (as a `Data` object).  Example (Swift):
    ```swift
    var config = Realm.Configuration()
    config.encryptionKey = my64ByteKeyData // my64ByteKeyData is a Data object
    ```
4.  **Open the Realm:** Use the configured `Realm.Configuration` when opening the Realm:
    ```swift
    let realm = try! Realm(configuration: config)
    ```
5.  **Key Rotation (Realm API):** If you need to change the encryption key, use Realm's `writeCopyTo(path:encryptionKey:)` method.  This creates a *new* copy of the Realm file, re-encrypted with the new key.  You are responsible for:
    *   Generating the new key securely.
    *   Managing the old and new key securely.
    *   Replacing the old Realm file with the new one.
    *   Handling any errors during the copy process.
    * Example:
    ```swift
    let newKey = //... generate new 64-byte key
    let newPath = //... path for the new encrypted file
    try! realm.writeCopy(toFile: newPath, encryptionKey: newKey)
    // Safely replace the old file with the new file
    ```
6. **Zeroize Key in Memory:** After using the key with Realm (opening or copying), immediately overwrite the `Data` object containing the key with zeros. This is crucial to prevent the key from lingering in memory. This is *not* handled by Realm itself; you must do this manually.
    ```swift
    my64ByteKeyData.withUnsafeMutableBytes { bytes in
        memset(bytes.baseAddress, 0, bytes.count)
    }
    ```

**Threats Mitigated:**
*   **Incorrect Key Usage with Realm API (Severity: Critical):** Ensures the key is correctly provided to Realm for encryption/decryption.
*   **Key Exposure During Realm Operations (Severity: High):** Reduced by zeroizing the key in memory after use.
*   **Improper Key Rotation (Severity: High):** Provides the correct Realm API usage for key rotation, although secure key management is still your responsibility.

**Impact:**
*   **Incorrect Key Usage:** Risk reduced to 0% (assuming correct key management).
*   **Key Exposure During Realm Operations:** Risk significantly reduced.
*   **Improper Key Rotation:** Risk of data loss or corruption due to incorrect key rotation is reduced.

**Currently Implemented:**
*   Correct `encryptionKey` usage in `Realm.Configuration` is implemented in `RealmManager.swift`.

**Missing Implementation:**
*   Zeroization of the `Data` object containing the key after use is *not* implemented in `RealmManager.swift`. This is a critical missing piece.
*   Key rotation functionality is not yet implemented.

## Mitigation Strategy: [Use Parameterized Queries (Realm API)](./mitigation_strategies/use_parameterized_queries__realm_api_.md)

**Description:**
1.  **`NSPredicate` with Format Specifiers:** When using `NSPredicate` for Realm queries, *always* use format specifiers (`%@`, `%d`, `%K`, etc.) and provide user input as separate arguments.  *Never* concatenate user input directly into the predicate string.
    *   **Vulnerable:** `NSPredicate(format: "name = '\(userInput)'")`
    *   **Safe:** `NSPredicate(format: "name = %@", userInput)`
2.  **Realm Swift Query Builder (Strongly Recommended):** If using Swift, use Realm's type-safe query builder (introduced in later versions of Realm Swift). This provides compile-time safety and eliminates the possibility of string-based injection. Example:
    ```swift
    // Assuming a 'Person' object with a 'name' property
    let results = realm.objects(Person.self).where {
        $0.name == userInput // userInput is a String
    }
    ```
3. **Avoid `filter(_:)` with string based predicates if user input is involved.** Use the other options instead.

**Threats Mitigated:**
*   **Realm Query Injection (Severity: Medium):** Directly mitigated by using parameterized queries or the type-safe query builder.

**Impact:**
*   **Realm Query Injection:** Risk reduced to near 0%.

**Currently Implemented:**
*   All `NSPredicate`-based queries in `DataService.swift` use format specifiers.

**Missing Implementation:**
*   Migration to the Realm Swift query builder is planned but not yet started.

## Mitigation Strategy: [Correct Realm File Path Configuration](./mitigation_strategies/correct_realm_file_path_configuration.md)

**Description:**
1.  **Avoid Default Path:** Do *not* rely on the default Realm file path. Explicitly set the `fileURL` property of your `Realm.Configuration`.
2.  **Secure Location:** Construct the `fileURL` to point to a secure location within your application's sandbox (e.g., the Documents directory).  See previous responses for details on obtaining this path.
3. **Custom File Name:** Use a custom file name instead of the default `default.realm`.
4.  **Example (Swift):**
    ```swift
    var config = Realm.Configuration()
    if let documentsURL = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first {
        config.fileURL = documentsURL.appendingPathComponent("myCustomRealm.realm")
    }
    ```

**Threats Mitigated:**
*   **Incorrect Realm File Location (Severity: High):** Ensures the Realm file is stored in a secure, sandboxed location.

**Impact:**
*   **Incorrect Realm File Location:** Risk reduced to near 0% (assuming correct sandboxing by the OS).

**Currently Implemented:**
*   `fileURL` is explicitly set to a location within the Documents directory in `RealmManager.swift`.
* Custom file name is used.

**Missing Implementation:**
*   None.

