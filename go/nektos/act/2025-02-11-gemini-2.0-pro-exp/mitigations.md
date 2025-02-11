# Mitigation Strategies Analysis for nektos/act

## Mitigation Strategy: [Use Official or Verified Runner Images (via `act` configuration)](./mitigation_strategies/use_official_or_verified_runner_images__via__act__configuration_.md)

**Mitigation Strategy:** Use Official or Verified Runner Images (via `act` configuration)

*   **Description:**
    1.  **Identify Trusted Sources:**  Determine the official `nektos/act` images or images from trusted providers.
    2.  **Pull Images:** Use `docker pull` to download the chosen images (e.g., `docker pull nektos/act:latest-ubuntu-22.04`).
    3.  **Configure `act` with `-P` or `--platform`:**  When running `act`, use the `-P` or `--platform` flag to *explicitly* specify the image to use.  This overrides `act`'s default image selection logic.  Example: `act -P ubuntu-latest=nektos/act:latest-ubuntu-22.04`.  This ensures that even if `act`'s default behavior changes, you're still using the image you intend.  You can specify multiple platforms if your workflow runs on different operating systems.
    4. **.actrc file (optional):** You can make this configuration persistent by adding platform mappings to an `.actrc` file in your project's root directory or your home directory. Example `.actrc` content:
        ```
        -P ubuntu-latest=nektos/act:latest-ubuntu-22.04
        -P ubuntu-20.04=nektos/act:latest-ubuntu-20.04
        ```

*   **Threats Mitigated:**
    *   **Compromised Docker Images (Runner Images):** (Severity: **Critical**) - Ensures `act` uses a specific, trusted image, preventing it from accidentally using a malicious or vulnerable image.
    *   **Vulnerable Software in Images:** (Severity: **High**) - By explicitly choosing a well-maintained image, you reduce the risk of using an image with outdated and vulnerable software.

*   **Impact:**
    *   **Compromised Docker Images:** Risk reduction: **High**.
    *   **Vulnerable Software in Images:** Risk reduction: **Medium-High**.

*   **Currently Implemented:** (Hypothetical) Partially implemented.  `-P` flag is used sometimes, but not consistently.

*   **Missing Implementation:** (Hypothetical) No `.actrc` file is used.  The `-P` flag is not used for all `act` invocations.

## Mitigation Strategy: [Use Secret Files for Sensitive Information (via `act`'s `-s` or `--secret-file` option)](./mitigation_strategies/use_secret_files_for_sensitive_information__via__act_'s__-s__or__--secret-file__option_.md)

**Mitigation Strategy:** Use Secret Files for Sensitive Information (via `act`'s `-s` or `--secret-file` option)

*   **Description:**
    1.  **Create a Secret File:** Create a text file (e.g., `secrets.txt`) to store secrets, one per line, in `KEY=VALUE` format.
    2.  **Secure the File:**  Set appropriate file permissions (e.g., `chmod 600 secrets.txt`).
    3.  **Use `-s` or `--secret-file`:**  When running `act`, use the `-s` option to specify individual secrets directly on the command line (less secure, but useful for testing), or, preferably, use the `--secret-file` option to provide the path to your secrets file.  Example: `act --secret-file secrets.txt`.  This tells `act` to load secrets from the specified file.
    4. **Avoid -s for production:** Avoid using -s option in production or scripts.

*   **Threats Mitigated:**
    *   **Exposure of Secrets:** (Severity: **High**) - Prevents secrets from being hardcoded in workflow files or passed as environment variables (which can be logged or accidentally exposed).
    *   **Unauthorized Access to Secrets:** (Severity: **High**) - Relies on file system permissions to protect the secrets file.

*   **Impact:**
    *   **Exposure of Secrets:** Risk reduction: **High**.
    *   **Unauthorized Access to Secrets:** Risk reduction: **High**.

*   **Currently Implemented:** (Hypothetical) Fully implemented.  `--secret-file` is used consistently.

*   **Missing Implementation:** (Hypothetical) None.

## Mitigation Strategy: [Use `--bind` option](./mitigation_strategies/use__--bind__option.md)

**Mitigation Strategy:** Use `--bind` option

*   **Description:**
    1.  **Understand the Risk:** By default, `act` mounts your project directory into the container.  If a workflow is compromised, it could potentially modify files in your project directory.
    2.  **Use `--bind`:** Use the `--bind` flag when running `act`. This mounts the project directory as read-only within the container.  Example: `act --bind`. This prevents the workflow from writing to your project directory, limiting the impact of a potential compromise.

*   **Threats Mitigated:**
    *   **Workflow Code Execution in a Privileged Context (Limited Scope):** (Severity: **Medium**) - While it doesn't prevent all privileged context issues, it specifically mitigates the risk of the workflow modifying your source code or other files in the project directory.
    *   **Accidental File Modification/Deletion:** (Severity: **Medium**) - Prevents the workflow from accidentally (or maliciously) changing or deleting files in your project.

*   **Impact:**
    *   **Workflow Code Execution in a Privileged Context (Limited Scope):** Risk reduction: **Medium**.
    *   **Accidental File Modification/Deletion:** Risk reduction: **High**.

*   **Currently Implemented:** (Hypothetical) Not implemented.

*   **Missing Implementation:** (Hypothetical) `act` is run without the `--bind` flag, allowing workflows to potentially modify the project directory.

