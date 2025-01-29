# Attack Surface Analysis for realm/realm-java

## Attack Surface: [1. Insecure Realm File Permissions](./attack_surfaces/1__insecure_realm_file_permissions.md)

*   **Description:** Realm files are stored with overly permissive file system permissions, allowing unauthorized access from other applications or users on the device.
*   **Realm-Java Contribution:** `realm-java` is responsible for creating and managing the Realm file. If the application doesn't explicitly configure restrictive permissions during Realm initialization, default permissions might be insecure.
*   **Example:** An Android application using `realm-java` stores a Realm database with world-readable permissions. A malicious application installed on the same device can read this Realm file and access sensitive user data stored within.
*   **Impact:** Confidentiality breach, data leakage, unauthorized access to sensitive data.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Restrict File Permissions:**  When initializing Realm configuration, explicitly set file permissions to be as restrictive as possible. On Android, use `Context.MODE_PRIVATE` when creating the Realm configuration to ensure only the application can access the file.
    *   **Regular Audits:** Periodically review the file permissions of the Realm file in deployed applications to verify they remain secure and haven't been inadvertently changed.

## Attack Surface: [2. Path Traversal to Realm File](./attack_surfaces/2__path_traversal_to_realm_file.md)

*   **Description:** User-controlled input is used to construct the Realm file path without proper sanitization, enabling attackers to access or manipulate Realm files outside the intended application directory.
*   **Realm-Java Contribution:** `realm-java` allows developers to specify the Realm file path during configuration. If this path is built using unsanitized user input, it becomes susceptible to path traversal attacks.
*   **Example:** An application allows users to name their database. This user-provided name is directly incorporated into the Realm file path like `/data/data/com.example.exampleapp/files/realms/{user_database_name}.realm`. An attacker provides a malicious database name like `../../../../sensitive_data` to attempt accessing or overwriting files outside the intended Realm storage location.
*   **Impact:** Data breach, data corruption, unauthorized access to other application data or potentially system files.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Input Sanitization and Validation:**  Strictly sanitize and validate any user input that is used to construct the Realm file path. Implement whitelisting of allowed characters and reject any path traversal sequences (e.g., `..`, `/`).
    *   **Fixed Realm File Path:**  Prefer using a fixed, predefined path within the application's private storage for the Realm file, avoiding user-controlled input in path construction altogether.

## Attack Surface: [3. Weak Realm File Encryption](./attack_surfaces/3__weak_realm_file_encryption.md)

*   **Description:** Realm's file encryption implementation utilizes weak or outdated encryption algorithms, or contains flaws, making the encrypted data vulnerable to decryption.
*   **Realm-Java Contribution:** `realm-java` provides built-in encryption for Realm files. The security of this feature directly depends on the strength and correctness of the encryption algorithms and their implementation within the library.
*   **Example:** An application uses an older version of `realm-java` that might employ a less robust encryption algorithm with known weaknesses. An attacker with physical access to the device could attempt to exploit these weaknesses to decrypt the Realm file and access sensitive data at rest.
*   **Impact:** Confidentiality breach, data leakage, exposure of sensitive data stored in the Realm file.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Use Strong Encryption:** Always enable Realm's encryption feature when storing sensitive data. Ensure you are using the latest version of `realm-java` which typically employs strong and up-to-date encryption algorithms (like AES-256).
    *   **Regular Updates:** Keep `realm-java` updated to the latest version to benefit from security patches, improvements in encryption implementation, and stronger algorithms if they are introduced.

## Attack Surface: [4. Insecure Realm Encryption Key Storage](./attack_surfaces/4__insecure_realm_encryption_key_storage.md)

*   **Description:** The encryption key used to protect the Realm file is stored insecurely, making it easily accessible to attackers and rendering the encryption ineffective.
*   **Realm-Java Contribution:** `realm-java` requires an encryption key to be provided during Realm configuration to enable encryption. The library itself does not enforce secure key storage, making it the developer's responsibility to handle the key securely.
*   **Example:** The Realm encryption key is hardcoded directly into the application's source code or stored in shared preferences without any additional protection. An attacker decompiling the application or gaining access to shared preferences can easily retrieve the key and decrypt the Realm file, bypassing the encryption.
*   **Impact:** Confidentiality breach, data leakage, complete bypass of Realm file encryption.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Avoid Hardcoding Keys:** Never hardcode encryption keys directly in the application source code.
    *   **Secure Key Storage Mechanisms:** Utilize secure key storage mechanisms provided by the operating system, such as Android Keystore or iOS Keychain, to store the encryption key securely. These systems are designed to protect keys from unauthorized access.
    *   **Key Derivation (Advanced):** Consider deriving the encryption key from a more secure source, such as user credentials combined with device-specific secrets, using robust key derivation functions (KDFs). This adds a layer of complexity for attackers.

## Attack Surface: [5. RQL Injection](./attack_surfaces/5__rql_injection.md)

*   **Description:** User-provided input is directly incorporated into Realm Query Language (RQL) queries without proper sanitization or parameterization, leading to malicious query injection attacks.
*   **Realm-Java Contribution:** `realm-java` uses RQL for querying data. If developers construct RQL queries by directly concatenating user input into query strings, the application becomes vulnerable to RQL injection.
*   **Example:** An application searches for products by name. The RQL query is built as `realm.where(Product.class).equalTo("name", userInput).findAll()`. If `userInput` is maliciously crafted as `'" OR \'1\'='1"'` , the query becomes `realm.where(Product.class).equalTo("name", '" OR \'1\'='1"').findAll()`, potentially returning all products instead of just those matching the intended name. More sophisticated injections could modify or delete data.
*   **Impact:** Data exfiltration, data modification or deletion, bypass of application logic and access controls, unauthorized data access.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Parameterized Queries (Realm Query API):**  Utilize Realm's query building API in a way that avoids direct string concatenation of user input into query strings. Use methods like `equalTo()`, `contains()`, `beginsWith()` with user input as parameters. This approach prevents direct injection of malicious RQL code.
    *   **Input Validation and Sanitization:**  Validate and sanitize user input before using it in Realm queries. Enforce input length limits, character whitelists, and escape special characters if absolutely necessary (though parameterized approach is strongly preferred).
    *   **Principle of Least Privilege (Data Access):** Design application logic and Realm schema to minimize the potential impact of RQL injection. Avoid storing highly sensitive data in fields that are frequently queried based on user input if possible.

## Attack Surface: [6. API Misuse and Logic Errors Related to Realm API](./attack_surfaces/6__api_misuse_and_logic_errors_related_to_realm_api.md)

*   **Description:** Incorrect or insecure usage of the `realm-java` API, or logic errors in application code when interacting with Realm, can introduce security vulnerabilities.
*   **Realm-Java Contribution:** The complexity of the `realm-java` API and the need for careful data handling can lead to developer errors that inadvertently create security weaknesses.
*   **Example:** Developers might misunderstand Realm's access control mechanisms and incorrectly implement user permissions, unintentionally granting unauthorized users access to sensitive data through Realm queries or API calls. Or, improper handling of Realm object lifecycles or transactions could lead to data corruption or unexpected application behavior that can be exploited.
*   **Impact:** Data breach, data corruption, application instability, unauthorized access to data or functionalities.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Thorough Code Reviews:** Conduct rigorous code reviews, specifically focusing on code sections that interact with the `realm-java` API and handle sensitive data. Pay close attention to data access patterns, transaction management, and object lifecycle handling.
    *   **Security Testing:** Perform comprehensive security testing, including penetration testing and static/dynamic code analysis, to identify potential API misuse and logic errors related to Realm usage.
    *   **Developer Training:** Provide developers with thorough training on secure coding practices and the correct and secure usage of the `realm-java` API, emphasizing security considerations and common pitfalls.
    *   **Principle of Least Privilege (Data Access):** Design application logic and Realm schema to adhere to the principle of least privilege, ensuring users and application components only have access to the data and functionalities they absolutely require.

