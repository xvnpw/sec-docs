# Attack Surface Analysis for isar/isar

## Attack Surface: [Unencrypted Local Data Storage](./attack_surfaces/unencrypted_local_data_storage.md)

* **Description:** Sensitive data stored by the application is persisted locally on the device's file system without encryption.
    * **How Isar Contributes to the Attack Surface:** Isar, by default, stores data in a local database file without providing built-in encryption at rest. This makes the raw data directly accessible if the device's file system is compromised.
    * **Example:** A user's personal information (name, address, financial details) stored in an Isar collection is directly readable from the database file if an attacker gains access to the device's storage.
    * **Impact:** Confidentiality breach, potential identity theft, financial loss, regulatory non-compliance.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **Implement Encryption at Rest:** Utilize platform-specific encryption APIs (e.g., `flutter_secure_storage` in Flutter) or third-party libraries to encrypt the Isar database file before or after its creation.
        * **Encrypt Sensitive Fields:** If full database encryption is not feasible, encrypt individual sensitive fields before storing them in Isar.

## Attack Surface: [Query Injection Vulnerabilities](./attack_surfaces/query_injection_vulnerabilities.md)

* **Description:**  Maliciously crafted input can be injected into Isar queries, allowing attackers to access or manipulate data beyond their intended scope.
    * **How Isar Contributes to the Attack Surface:** If the application constructs Isar queries by directly concatenating user-provided input without proper sanitization or parameterization, it becomes vulnerable to query injection.
    * **Example:** An application allows users to search for items by name. If the search term is directly embedded in the Isar query like `isar.collection<Item>().filter().nameEqualTo('${userInput}').findAll()`, an attacker could input `' OR 1=1 -- ` to potentially retrieve all items.
    * **Impact:** Data breach, unauthorized data modification, potential denial of service.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **Use Parameterized Queries/Filters:** Leverage Isar's built-in filtering mechanisms and avoid string concatenation of user input directly into query conditions. Isar's filter builders help prevent this.
        * **Input Validation and Sanitization:**  Thoroughly validate and sanitize all user input before using it in any part of the Isar query construction.

