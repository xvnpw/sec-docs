# Attack Surface Analysis for realm/realm-kotlin

## Attack Surface: [Unencrypted Local Data Storage](./attack_surfaces/unencrypted_local_data_storage.md)

*   **Description:** Realm database files stored on the device without encryption are vulnerable to unauthorized access.
*   **How `realm-kotlin` Contributes:** Realm provides the *capability* to store data locally, but encryption is an opt-in feature. The default behavior (no encryption) increases the attack surface if developers don't explicitly enable it. This is a *direct* responsibility of how the developer uses the library.
*   **Example:** An attacker gains access to a lost or stolen phone and uses Realm Studio to open the unencrypted `.realm` file, extracting sensitive user data.
*   **Impact:** Direct exposure of sensitive data, potentially leading to identity theft, financial loss, or privacy violations.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developer:** *Always* enable Realm encryption using `RealmConfiguration.Builder.encryptionKey()`. Use a strong, 64-byte key generated securely.
    *   **Developer:** Store the encryption key securely using platform-specific key management (Android Keystore, iOS Keychain).  *Never* hardcode the key.
    *   **Developer:** Consider using a Key Derivation Function (KDF) like Argon2id.

## Attack Surface: [Weak Encryption Key Management](./attack_surfaces/weak_encryption_key_management.md)

*   **Description:** Even with encryption enabled, a weak or improperly managed encryption key compromises the security.
*   **How `realm-kotlin` Contributes:** Realm *relies* on the developer to provide and manage the encryption key correctly. The library provides the *mechanism* for encryption, but the security hinges on proper key management, a *direct* developer responsibility.
*   **Example:** A developer hardcodes a short key in the application code. An attacker reverse-engineers the app, extracts the key, and decrypts the Realm file.
*   **Impact:**  Complete compromise of the encrypted Realm data.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developer:** Use a strong, randomly generated 64-byte key.
    *   **Developer:** Leverage platform-specific secure key storage (Android Keystore, iOS Keychain).
    *   **Developer:** Implement key rotation policies.
    *   **Developer:** Use a KDF (Argon2id recommended) with a strong salt and high iteration count.

## Attack Surface: [Compromised Realm Sync Server (if used)](./attack_surfaces/compromised_realm_sync_server__if_used_.md)

*   **Description:** If using Realm Sync, a compromised server exposes all synchronized data.
*   **How `realm-kotlin` Contributes:** The `realm-kotlin` library provides the *client-side functionality* for Realm Sync. While the server itself isn't part of `realm-kotlin`, the library's *purpose* is to interact with this server, making the server's security a *direct* concern for applications using the sync feature.
*   **Example:** An attacker exploits a vulnerability in the Realm Object Server, gaining access and downloading all user data.
*   **Impact:**  Massive data breach affecting all users.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Developer (Self-hosted ROS):** Keep the server software up-to-date, implement strong access controls, monitor logs, and use strong passwords/MFA.
    *   **Developer (Atlas Device Sync):** Follow MongoDB Atlas's security best practices, use strong authentication/authorization, and enable auditing.
    *   **Developer (Both):** Consider end-to-end encryption (E2EE) *in addition to* Realm Sync's transport encryption. (Requires a separate implementation, as Realm Sync doesn't provide E2EE natively).

## Attack Surface: [Weak Server-Side Authentication/Authorization (Sync)](./attack_surfaces/weak_server-side_authenticationauthorization__sync_.md)

*   **Description:** Insufficient authentication/authorization on the Realm Sync server allows unauthorized access.
*   **How `realm-kotlin` Contributes:** `realm-kotlin` handles the *client-side* authentication process (e.g., passing credentials).  However, the *enforcement* of authentication and authorization rules is a server-side responsibility, directly impacting the security of data accessed via the `realm-kotlin` sync functionality.
*   **Example:** An attacker uses a brute-force attack to guess a user's password and gains access to their synchronized Realm data.
*   **Impact:** Unauthorized access to a user's data.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developer:** Implement strong password policies.
    *   **Developer:** Enforce multi-factor authentication (MFA).
    *   **Developer:** Use fine-grained authorization rules (principle of least privilege).
    *   **Developer:** Regularly audit user accounts and permissions.

