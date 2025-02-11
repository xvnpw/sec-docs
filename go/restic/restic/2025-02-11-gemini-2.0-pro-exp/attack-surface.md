# Attack Surface Analysis for restic/restic

## Attack Surface: [Compromised Repository Credentials](./attack_surfaces/compromised_repository_credentials.md)

**Description:** Unauthorized access to the backup repository due to stolen, leaked, or weak credentials used for backend access.

**Restic's Contribution:** Restic *requires* credentials (passwords, API keys, etc.) to authenticate with various backend storage providers (S3, SFTP, etc.). The security of these credentials is the primary defense against unauthorized repository access.

**Example:** An attacker obtains the Backblaze B2 application key and key ID used by restic to access a backup repository.

**Impact:** Complete data breach (confidentiality), data tampering (integrity), and data destruction (availability).

**Risk Severity:** Critical

**Mitigation Strategies:**
    *   **Strong, Unique Credentials:** Use a password manager to generate and store strong, unique passwords or API keys for *each* repository.
    *   **Secure Storage:** Never hardcode credentials. Use environment variables, secrets management systems (e.g., HashiCorp Vault, AWS Secrets Manager, Azure Key Vault), or secure configuration files with appropriate permissions.
    *   **Least Privilege:** Configure backend access with the minimum necessary permissions.  Restic should only have the permissions it needs (read, write, list) and no more.
    *   **Credential Rotation:** Regularly rotate credentials according to a defined schedule and security policy.
    *   **Two-Factor Authentication (2FA):** Enable 2FA for the backend storage provider whenever possible.
    *   **Monitoring:** Monitor access logs for the backend storage provider for suspicious activity.

## Attack Surface: [Weak Repository Password](./attack_surfaces/weak_repository_password.md)

**Description:** The repository password used by restic to encrypt the backup data is easily guessable or crackable.

**Restic's Contribution:** Restic *directly* uses a user-provided password to derive the encryption key for the repository.  The strength of this password is the *sole* factor determining the cryptographic security of the stored data.

**Example:** An attacker uses a dictionary attack or brute-force tool to guess a weak repository password like "backup2023".

**Impact:** Complete data breach (confidentiality). The attacker can decrypt the entire repository.

**Risk Severity:** Critical

**Mitigation Strategies:**
    *   **Strong Password:** Use a long (at least 20 characters), randomly generated password. Avoid dictionary words, personal information, and common patterns.
    *   **Password Manager:** Use a password manager to generate and securely store the repository password.

## Attack Surface: [Vulnerabilities in Restic or its Dependencies](./attack_surfaces/vulnerabilities_in_restic_or_its_dependencies.md)

**Description:** Exploitable flaws in the `restic` binary itself or in one of its *compiled-in* dependencies.

**Restic's Contribution:** Restic, as a compiled program, can contain vulnerabilities.  Vulnerabilities in its *statically linked* dependencies are directly part of the `restic` binary's attack surface.

**Example:** A buffer overflow vulnerability is discovered in the cryptographic library statically linked into `restic`. An attacker could craft a malicious input to trigger the vulnerability and potentially gain code execution.

**Impact:** Varies depending on the vulnerability. Could range from denial-of-service to arbitrary code execution on the system running `restic`.

**Risk Severity:** High (potentially Critical, depending on the vulnerability)

**Mitigation Strategies:**
    *   **Keep Restic Updated:** Regularly update `restic` to the latest version to receive security patches. This is the *most important* mitigation.
    *   **Sandboxing/Containerization:** Consider running `restic` in a sandboxed environment or container to limit the impact of potential exploits.
    *   **Least Privilege:** Run `restic` with the minimum necessary privileges (avoid running as root if possible).

## Attack Surface: [Unauthorized `forget` or `prune` Operations](./attack_surfaces/unauthorized__forget__or__prune__operations.md)

**Description:** An attacker with access to run `restic` commands maliciously deletes snapshots or data within the repository.

**Restic's Contribution:** Restic *provides* the `forget` and `prune` commands, which are powerful tools for managing repository data.  These commands, if misused, can lead to irreversible data loss.

**Example:** An attacker gains access to a system where `restic` is configured and runs `restic forget --prune --keep-last 0` to delete all but the most recent snapshot, then deletes that one too.

**Impact:** Loss of data availability. Important backups could be permanently deleted.

**Risk Severity:** High

**Mitigation Strategies:**
    *   **Restricted Access:** Limit access to the `restic` binary and repository credentials *strictly* to authorized users and systems. This is the primary mitigation.
    *   **Authentication and Authorization:** Implement strong authentication and authorization controls for systems where `restic` is used.
    *   **Monitoring:** Monitor for unauthorized use of `forget` and `prune` commands (e.g., through audit logs, if possible, by wrapping the restic calls in a script that logs the commands).
    *   **Append-Only Backends:** If supported by the backend, consider using append-only storage (e.g., AWS S3 Object Lock in Governance mode) to prevent data deletion, even by authorized users. This is a *very strong* mitigation, but may not be compatible with all workflows.

