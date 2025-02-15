# Mitigation Strategies Analysis for borgbackup/borg

## Mitigation Strategy: [Secure Repository Access and Key Management (Borg-Specific)](./mitigation_strategies/secure_repository_access_and_key_management__borg-specific_.md)

1.  **Key Management (Borg Commands):**
    *   **Secure Passphrase Handling:** When running Borg commands that require the passphrase (e.g., `borg create`, `borg extract`, `borg list`), avoid storing the passphrase directly in scripts. Use one of the following:
        *   **Environment Variable:** Set the `BORG_PASSPHRASE` environment variable before running the command.  Be mindful of environment variable security.
        *   **Passphrase File:** Use the `--passphrase-file` option, pointing to a file containing *only* the passphrase.  Ensure this file has extremely restrictive permissions (e.g., `chmod 600`).
        *   **Interactive Prompt:** Allow Borg to prompt for the passphrase interactively. This is the most secure option for manual operations.
        *   **`BORG_PASSCOMMAND`:** Use a command that outputs the passphrase to stdout. This allows for integration with password managers or other secure key retrieval mechanisms. Example: `BORG_PASSCOMMAND="pass show my-borg-passphrase"`.
    *   **Key Rotation:** Regularly use the `borg key change-passphrase` command to change the repository's encryption key.  This command re-encrypts the repository metadata with the new key.  Remember to securely store the new passphrase.
2.  **Append-Only Mode (Borg Flag):**
    *   When creating the repository, use the `--append-only` flag: `borg init --append-only ...`.  This prevents modification or deletion of existing archives.
    *   *Alternatively*, if the repository already exists, you can change it to append-only mode using a separate, highly privileged process (e.g., a dedicated script run with elevated permissions). This requires careful planning and execution.
3.  **Separate Keys (Borg Practice):**
    *   When creating multiple repositories (e.g., for different datasets or clients), use a *different* encryption key for each repository.  This is a best practice enforced through careful use of Borg commands and key management, not a specific Borg command itself.

**Threats Mitigated:**
*   **Unauthorized Repository Access (Severity: Critical):** Secure passphrase handling prevents attackers from easily obtaining the key.
*   **Encryption Key Compromise (Severity: Critical):** Key rotation limits the impact of a compromised key. Separate keys isolate the damage.
*   **Ransomware/Malicious Deletion (Severity: High):** Append-only mode prevents modification/deletion of existing archives.

**Impact:**
*   **Unauthorized Repository Access:** Risk significantly reduced.
*   **Encryption Key Compromise:** Impact limited by key rotation and use of separate keys.
*   **Ransomware/Malicious Deletion:** Strong protection against modification/deletion of *existing* archives (with append-only).

**Currently Implemented:** (Example - Needs to be filled in based on the project)
*   The encryption key is provided via an environment variable.

**Missing Implementation:** (Example - Needs to be filled in based on the project)
*   Key rotation is not implemented (`borg key change-passphrase` is not used).
*   Append-only mode is not used (`--append-only` flag was not used).
*   Separate keys are not used for different repositories.

## Mitigation Strategy: [Data Corruption Detection (Borg-Specific)](./mitigation_strategies/data_corruption_detection__borg-specific_.md)

1.  **Regular `borg check`:**
    *   Regularly run the `borg check --verify-data` command. This verifies the integrity of both the repository metadata *and* the data chunks.  This is *crucial* for early detection of corruption.
    *   Automate this process (e.g., using a scheduled script).
    *   Capture and monitor the output of `borg check` for any errors. Implement alerting if errors are detected.

**Threats Mitigated:**
*   **Data Corruption (Severity: High):** Enables early detection of data corruption within the Borg repository.

**Impact:**
*   **Data Corruption:** Significantly reduces the risk of undetected data corruption, allowing for timely intervention.

**Currently Implemented:** (Example)
*   None.

**Missing Implementation:** (Example)
*   `borg check --verify-data` is not run regularly or automated.

## Mitigation Strategy: [Secure Remote Access with `borg serve` (Borg-Specific)](./mitigation_strategies/secure_remote_access_with__borg_serve___borg-specific_.md)

1.  **Read-Only Access (Borg Option):**
    *   If clients only need to *read* from the repository (e.g., for restoring data), start `borg serve` with the `--read-only` option: `borg serve --read-only ...`. This prevents any modification of the repository.
2. **Restrict to repository:**
    * Use `--restrict-to-repository` to limit access to a single repository.
3. **Restrict to paths:**
     * Use `--restrict-to-path` to limit access to a specific path within a repository.

**Threats Mitigated:**
*   **Unauthorized Repository Modification (Severity: High):** `--read-only` prevents clients from writing to the repository.
*  **Repository access outside of allowed scope (Severity: High):** `--restrict-to-repository` and `--restrict-to-path` prevent clients from accessing data they should not.

**Impact:**
*   **Unauthorized Modification:** Eliminates the risk of clients modifying the repository when read-only access is sufficient.
* **Unauthorized Access:** Limits the risk of clients accessing data they should not.

**Currently Implemented:** (Example)
*   None

**Missing Implementation:** (Example)
*   `borg serve` is not used with the `--read-only` option, even for read-only clients.
* `--restrict-to-repository` and `--restrict-to-path` are not used.

