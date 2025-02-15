# Threat Model Analysis for borgbackup/borg

## Threat: [Unauthorized Repository Access and Decryption](./threats/unauthorized_repository_access_and_decryption.md)

*   **Description:** An attacker gains access to the Borg repository credentials (repository URL, passphrase, and/or SSH key). They use these credentials to connect to the repository and decrypt the backups using a legitimate or modified Borg client.
    *   **Impact:** Complete compromise of all backed-up data. The attacker can read, modify, or delete the data. This could lead to data breaches, data loss, and reputational damage.
    *   **Borg Component Affected:** Repository access mechanisms (authentication, encryption), `borg create`, `borg extract`, `borg list`, `borg mount`. Primarily affects the overall repository security, not a specific *code* component.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Strong Passphrases:** Use a long, complex, and randomly generated passphrase.
        *   **Secrets Management:** Store credentials in a secure secrets management solution. *Never* hardcode credentials.
        *   **Key Rotation:** Regularly rotate the passphrase and SSH keys.
        *   **Access Control:** Implement strict access controls on the repository server.
        *   **Two-Factor Authentication (2FA):** Enable 2FA for SSH access if supported.
        *   **Monitoring:** Monitor repository access logs.
        *   **Keyfiles:** Consider using and securely managing keyfiles.

## Threat: [Malicious Borg Binary Replacement](./threats/malicious_borg_binary_replacement.md)

*   **Description:** An attacker gains write access to the application server and replaces the legitimate `borg` binary with a malicious version. This malicious binary could intercept data, steal credentials, or perform other malicious actions.
    *   **Impact:** Potential data compromise, credential theft, and arbitrary code execution on the application server. The attacker could gain control of the backup process and potentially the entire server.
    *   **Borg Component Affected:** The `borg` executable itself.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **File Integrity Monitoring:** Implement file integrity monitoring to detect unauthorized changes.
        *   **Package Manager Verification:** Verify the integrity of the installed Borg package.
        *   **Restricted Permissions:** Ensure only authorized users have write access to the `borg` binary's directory.
        *   **Code Signing (If Building from Source):** Consider code signing.
        *   **Sandboxing/Containerization:** Run Borg within a container.

## Threat: [Remote Repository Data Tampering](./threats/remote_repository_data_tampering.md)

*   **Description:** An attacker gains write access to the remote Borg repository (but *without* the passphrase). They modify or delete existing archives or archive segments.
    *   **Impact:** Data loss or corruption. Restoring from a tampered backup could result in incomplete/incorrect data, or even execution of malicious code.
    *   **Borg Component Affected:** Repository data integrity mechanisms. Affects `borg check`, `borg extract`, and potentially `borg create`.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Append-Only Repositories:** Use `borg init --append-only`.
        *   **Regular `borg check --verify-data`:** Run regularly to verify repository integrity.
        *   **Strong Access Controls:** Implement strong access controls on the remote repository server.
        *   **Replication/Redundancy:** Maintain multiple, independent copies of the repository.
        *   **Object Storage Immutability:** Use features like object versioning and immutability.

## Threat: [Passphrase Leakage via Logging or Error Messages](./threats/passphrase_leakage_via_logging_or_error_messages.md)

*   **Description:** The application inadvertently logs the Borg passphrase in plain text. An attacker who gains access to these logs can decrypt the backups.
    *   **Impact:** Complete compromise of all backed-up data.
    *   **Borg Component Affected:** Not a specific Borg component, but how the application *uses* Borg.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Never Log Sensitive Data:** Ensure the application *never* logs the passphrase.
        *   **Input Sanitization:** Sanitize input and output to prevent accidental inclusion.
        *   **Secrets Management:** Use a secrets management solution.
        *   **Code Review:** Conduct thorough code reviews.
        *   **Automated Scanning:** Use tools to scan for potential secrets exposure.

## Threat: [Elevation of Privilege via Borg Running as Root](./threats/elevation_of_privilege_via_borg_running_as_root.md)

*   **Description:** Borg is run as the `root` user. If compromised, the attacker could gain full root access to the system.
    *   **Impact:** Complete system compromise.
    *   **Borg Component Affected:** The entire `borg` process.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Principle of Least Privilege:** Run Borg as a dedicated, non-root user.
        *   **`sudo` (Carefully):** Use with extreme caution and restrict commands.
        *   **Containerization:** Run Borg within a container.

## Threat: [Unpatched Borg Vulnerability (High/Critical Impact)](./threats/unpatched_borg_vulnerability__highcritical_impact_.md)

*   **Description:** A *high or critical* vulnerability is discovered in Borg. An attacker exploits this to gain unauthorized access, modify data, or cause a denial of service.  This entry specifically focuses on vulnerabilities with a high or critical impact.
    *   **Impact:** Varies depending on the vulnerability, but *by definition* in this list, it would be High or Critical (e.g., data breach, system compromise).
    *   **Borg Component Affected:** Potentially any part of the Borg codebase.
    *   **Risk Severity:** High or Critical (depending on the specific vulnerability)
    *   **Mitigation Strategies:**
        *   **Keep Borg Updated:** Regularly update Borg to the latest stable version. This is the *primary* mitigation.
        *   **Monitor Security Advisories:** Subscribe to Borg's security announcements.
        *   **Vulnerability Scanning:** Consider using vulnerability scanning tools.
        *   **Containerization (Partial Mitigation):** Can help limit the impact, but isn't a complete solution.

