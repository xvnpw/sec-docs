# Attack Surface Analysis for borgbackup/borg

## Attack Surface: [1. Unauthorized Repository Access (Borg-Specific Aspects)](./attack_surfaces/1__unauthorized_repository_access__borg-specific_aspects_.md)

*   **Description:** An attacker gains read, write, or delete access to the Borg backup repository *by exploiting weaknesses related to Borg's authentication or authorization mechanisms*.
*   **How Borg Contributes:** This is *directly* related to Borg's core function: managing access to the encrypted repository. Weaknesses in Borg's handling of passwords, keys, or network protocols are the primary concern.
*   **Example:** An attacker exploits a vulnerability in Borg's `borg serve` implementation to bypass authentication and gain access to the repository.  Or, an attacker discovers a flaw in Borg's key derivation function that allows them to brute-force a weak passphrase more easily.
*   **Impact:** Complete data breach (confidentiality loss), data loss (availability loss), potential data tampering (integrity loss). Restoration of tampered backups could introduce malware.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Strong Passphrases/Key Management:** Use strong, unique passphrases. Securely store and manage encryption keys (offline, HSM). Implement key rotation.
    *   **Secure `borg serve` Configuration:** *Always* use strong authentication with `borg serve`.  Restrict network access using firewall rules.  Avoid exposing `borg serve` directly to the internet.
    *   **Use Authenticated Encryption:**  *Always* use Borg's authenticated encryption modes (e.g., `repokey-blake2`, `keyfile-blake2`). Never use unencrypted modes.
    *   **Keep Borg Updated:**  Apply security patches promptly. This is *crucial* to address any discovered vulnerabilities in Borg's authentication or authorization logic.
    *   **Avoid `BORG_PASSPHRASE`:** Do not use the `BORG_PASSPHRASE` environment variable. Use `BORG_PASSCOMMAND` with a *secure* command or a keyfile.
    *   **Secure `BORG_PASSCOMMAND`:** If using `BORG_PASSCOMMAND`, ensure the command itself is secure and not vulnerable to injection or leakage.

## Attack Surface: [2. Repository Tampering/Corruption (Borg-Specific Aspects)](./attack_surfaces/2__repository_tamperingcorruption__borg-specific_aspects_.md)

*   **Description:** An attacker modifies the Borg repository *by exploiting vulnerabilities in Borg's repository handling or integrity checks*.
*   **How Borg Contributes:** Borg has built-in integrity checks, but vulnerabilities in these checks or in the repository format handling could allow for targeted corruption.
*   **Example:** An attacker discovers a flaw in Borg's deduplication logic that allows them to inject malicious data into the repository without triggering integrity checks.  Or, a vulnerability in Borg's handling of corrupted archive headers allows an attacker to cause a denial-of-service during restoration.
*   **Impact:** Data loss (availability loss), data corruption (integrity loss), potential system compromise upon restoration (if malicious data is injected).
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Regular Integrity Checks:** Use `borg check --verify-data` regularly and *automate* this process. This relies on Borg's internal checks, so keeping Borg updated is vital.
    *   **Keep Borg Updated:**  Apply security patches promptly to address any vulnerabilities in Borg's repository handling or integrity checks.
    *   **Understand Append-Only Limitations:**  Append-only mode helps, but it doesn't prevent *adding* malicious archives.  It's a layer of defense, not a complete solution.

## Attack Surface: [3. Key Compromise (Direct Borg Handling)](./attack_surfaces/3__key_compromise__direct_borg_handling_.md)

*   **Description:** The encryption key is compromised *due to weaknesses in how Borg handles or stores the key*. This excludes general key management best practices.
*   **How Borg Contributes:**  While Borg doesn't *store* the key persistently unless configured to do so (e.g., with `repokey` mode), vulnerabilities in how Borg *uses* the key in memory or during key derivation could lead to compromise.
*   **Example:** A vulnerability in Borg's key derivation function (KDF) makes it susceptible to a side-channel attack, allowing an attacker to extract the key from memory. Or, a flaw in Borg's handling of the passphrase during input could expose it to other processes.
*   **Impact:** Complete data breach (confidentiality loss).
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Strong Passphrases:** Use long, complex passphrases to make brute-force and dictionary attacks more difficult.
    *   **Keep Borg Updated:**  Apply security patches to address any vulnerabilities in Borg's key handling or KDF.
    *   **Avoid `BORG_PASSPHRASE`:** As mentioned before, do not use this environment variable.
    *   **Secure `BORG_PASSCOMMAND`:** Ensure the command used with `BORG_PASSCOMMAND` is secure.

## Attack Surface: [4. Exploiting Borg Client/Server Vulnerabilities (Direct Code Issues)](./attack_surfaces/4__exploiting_borg_clientserver_vulnerabilities__direct_code_issues_.md)

*   **Description:**  Exploiting vulnerabilities *within the Borg codebase itself* (client or `borg serve`) to gain unauthorized access, execute code, or cause a denial of service.
*   **How Borg Contributes:** This is entirely dependent on the presence of bugs in Borg's code.
*   **Example:** A buffer overflow vulnerability in Borg's parsing of a malformed archive allows an attacker to execute arbitrary code on the client machine. Or, a denial-of-service vulnerability in `borg serve` allows an attacker to crash the server.
*   **Impact:** Varies depending on the vulnerability; could range from denial of service to complete system compromise (client or server).
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Keep Borg Updated:** This is the *primary* mitigation.  Apply security patches promptly.
    *   **Code Audits (if feasible):**  For highly sensitive deployments, consider independent security audits of the Borg codebase.

