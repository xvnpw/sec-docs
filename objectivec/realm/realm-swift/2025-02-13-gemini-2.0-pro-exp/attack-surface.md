# Attack Surface Analysis for realm/realm-swift

## Attack Surface: [Unauthorized Realm File Access](./attack_surfaces/unauthorized_realm_file_access.md)

*   **Description:** Attackers gain direct access to the `.realm` database file stored on the device's file system.
*   **How `realm-swift` Contributes:** Realm stores data in a `.realm` file, which, if unencrypted or improperly protected, becomes a target. This is the *core* function of Realm.
*   **Example:** An attacker gains physical access to an unlocked, jailbroken iOS device and copies the application's `.realm` file.
*   **Impact:** Complete data breach; exposure of all information stored in the Realm database.
*   **Risk Severity:** **Critical** (if unencrypted), **High** (if encrypted, but key management is weak).
*   **Mitigation Strategies:**
    *   **Encryption at Rest (Mandatory):**  Enable Realm's built-in encryption using a strong, randomly generated key.  *This is non-negotiable for sensitive data.* This is a direct Realm feature.
    *   **Secure Key Storage:** Store the encryption key securely using the platform's secure element (Keychain on iOS, Keystore on Android).  *Never* hardcode the key.
    *   **Jailbreak/Root Detection:** Implement robust jailbreak/root detection (with awareness of its limitations). Consider data wiping.
    *   **Secure Backup Practices:** Ensure device backups are encrypted. Exclude the Realm file from backups if possible.
    * **File Path Obfuscation:** Avoid exposing the file path.

## Attack Surface: [Weak or Compromised Encryption Key](./attack_surfaces/weak_or_compromised_encryption_key.md)

*   **Description:** The encryption key used to protect the Realm file is weak, improperly stored, or otherwise compromised.
*   **How `realm-swift` Contributes:** Realm's encryption *entirely* depends on the security of the key provided to the `realm-swift` API. This is a direct dependency.
*   **Example:** The application uses a hardcoded, short string as the encryption key, discovered through reverse engineering.
*   **Impact:**  Renders encryption useless; attacker can decrypt the Realm file.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Strong Key Generation:** Use a cryptographically secure random number generator to create a 64-byte key (Realm's requirement).
    *   **Secure Key Storage (Mandatory):** Use the platform's secure key storage (Keychain/Keystore).  *Never* store the key in plain text.
    *   **Key Rotation (Recommended):** Implement a key rotation strategy, periodically generating a new key and re-encrypting the Realm (using Realm's API).
    *   **Consider Key Derivation Functions (KDFs):** Use a strong KDF (PBKDF2, Argon2) if deriving the key from a password.

## Attack Surface: [Realm Sync: Man-in-the-Middle (MitM) Attack](./attack_surfaces/realm_sync_man-in-the-middle__mitm__attack.md)

*   **Description:** An attacker intercepts network communication between the client and the Realm Object Server when using Realm Sync.
*   **How `realm-swift` Contributes:** Realm Sync, a *core feature* of `realm-swift` (when enabled), transmits data over the network.
*   **Example:** An attacker on the same Wi-Fi network intercepts the TLS connection, presenting a fake certificate.
*   **Impact:**  Data exposure and potential modification of synchronized data.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **TLS with Certificate Pinning (Mandatory):** Use TLS and implement certificate pinning to verify the server's certificate. This is *crucial* and directly interacts with how `realm-swift` handles network communication for Sync.

## Attack Surface: [Realm Sync: Authentication Bypass](./attack_surfaces/realm_sync_authentication_bypass.md)

*   **Description:** An attacker bypasses Realm Sync's authentication, gaining unauthorized access.
*   **How `realm-swift` Contributes:** Realm Sync, a feature of `realm-swift`, relies on authentication to control data access. The authentication mechanisms are integrated with the `realm-swift` SDK.
*   **Example:** A weak password or a vulnerability in the authentication flow allows unauthorized access.
*   **Impact:** Unauthorized access to synchronized data; potential modification/deletion.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Strong Authentication:** Use robust authentication (JWT, OAuth 2.0) with strong password policies. Consider MFA. This directly involves configuring `realm-swift`'s authentication providers.
    *   **Secure Authentication Flow:** Ensure the authentication flow itself is secure.

## Attack Surface: [Realm Sync: Server-Side Vulnerabilities](./attack_surfaces/realm_sync_server-side_vulnerabilities.md)

*   **Description:** Vulnerabilities in the Realm Object Server or MongoDB are exploited.
*   **How `realm-swift` Contributes:** Realm Sync, a feature of `realm-swift`, requires a server-side component (Realm Object Server or MongoDB Realm Sync). While the vulnerability isn't *in* `realm-swift` itself, the client's use of Realm Sync directly exposes it to this risk.
*   **Example:** A known MongoDB vulnerability is exploited to access the database.
*   **Impact:** Potential data breach of all synchronized data; server compromise.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Regular Server Updates (Mandatory):** Keep the Realm Object Server and MongoDB updated.
    *   **Server Hardening:** Follow best practices for securing MongoDB and the server.
    *   **Principle of Least Privilege (Server-Side):** Configure the server with minimal privileges.
    *   **Monitoring and Auditing:** Implement robust monitoring and auditing.

