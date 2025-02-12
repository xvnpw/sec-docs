# Attack Surface Analysis for dominictarr/rc

## Attack Surface: [Environment Variable Injection](./attack_surfaces/environment_variable_injection.md)

*   **Description:** Attackers manipulate environment variables to inject malicious configuration values.
    *   **How `rc` Contributes:** `rc` *directly* loads configuration from environment variables, making them a primary and direct attack vector.
    *   **Example:**
        *   Attacker sets `DATABASE_URL=postgres://attacker:password@malicious-host:5432/database` in a containerized environment to redirect database connections.
        *   Attacker sets `DISABLE_AUTH=true` to bypass authentication if the application uses this environment variable.
    *   **Impact:** Data breaches, complete application compromise, denial of service, data manipulation.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Strict Environment Control:** Secure the environment (containers, servers) using least privilege.  Limit access to environment variable modification.
        *   **Post-Load Validation:** Validate *all* environment variables loaded by `rc` using a schema (e.g., Joi).  Enforce data types, allowed values, and lengths.  This is *crucial* because `rc` provides no built-in validation.
        *   **Secrets Management:** Use dedicated secrets management services (Vault, AWS Secrets Manager) for sensitive data instead of environment variables.

## Attack Surface: [Command-Line Argument Override](./attack_surfaces/command-line_argument_override.md)

*   **Description:** Attackers inject malicious configuration values via command-line arguments.
    *   **How `rc` Contributes:** `rc` *directly* parses command-line arguments, allowing attackers to override configurations. This is a direct feature of `rc`.
    *   **Example:**
        *   Attacker runs the application with `--database.host=malicious-host` to redirect database connections.
        *   Attacker uses `--featureFlags.disableSecurity=true` to disable a security feature.
    *   **Impact:** Similar to environment variable injection: data breaches, application compromise, denial of service.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Post-Load Argument Validation:** Validate command-line arguments *after* `rc` processing, using a schema or a dedicated argument parsing library.  Define expected arguments and their types strictly. `rc` itself does not validate argument types or values.
        *   **Restrict Argument Sources:** Limit how command-line arguments are provided.  Avoid accepting them from untrusted sources.
        *   **Whitelisting:** Only allow known, safe command-line arguments. Reject any unexpected arguments.

## Attack Surface: [Configuration File Poisoning](./attack_surfaces/configuration_file_poisoning.md)

*   **Description:** Attackers modify configuration files read by `rc` to inject malicious settings.
    *   **How `rc` Contributes:** `rc` *directly* loads configuration from files in standard locations (e.g., `/etc/myapprc`, `$HOME/.myapprc`, `./.myapprc`). The file loading mechanism is a core feature of `rc`.
    *   **Example:**
        *   Attacker gains write access to `/etc/myapprc` and changes `apiKey` to a key they control.
        *   Attacker creates a malicious `.myapprc` file in a parent directory of the application's execution path.
    *   **Impact:** Application compromise, data breaches, denial of service.
    *   **Risk Severity:** High (if write access is possible)
    *   **Mitigation Strategies:**
        *   **Strict File Permissions:** Enforce the most restrictive file permissions possible.  Only the application's user should have read access; no one should have write access except administrators.
        *   **File Integrity Monitoring:** Use tools like AIDE or Tripwire to detect unauthorized file modifications.
        *   **Post-Load File Content Validation:** Validate the *content* of configuration files after loading by `rc`, using a schema. This is essential because `rc` does not validate the content beyond basic JSON parsing.
        *   **Read-Only Filesystem:** Mount the configuration directory as read-only if possible.
        * **Avoid Default Locations:** If possible, use a custom location for configuration files.

