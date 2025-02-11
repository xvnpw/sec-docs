# Attack Surface Analysis for spf13/viper

## Attack Surface: [1. Configuration File Path Traversal](./attack_surfaces/1__configuration_file_path_traversal.md)

*   **Description:**  An attacker manipulates the file path used by Viper to load a configuration file, causing the application to load a malicious configuration from an unintended location.
*   **How Viper Contributes:** Viper's `SetConfigFile()` and `AddConfigPath()` functions accept file paths, which can be vulnerable if they are influenced by untrusted input.  This is *direct* Viper functionality.
*   **Example:**  An application allows users to specify a "theme" which is used to construct a configuration file path: `/config/themes/{user_input}.yaml`.  An attacker provides `../../../../etc/passwd` as the theme.
*   **Impact:**  Loading of attacker-controlled configuration, leading to arbitrary code execution, data breaches, or denial of service.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strict Input Validation:**  Validate and sanitize any user-supplied input. Use a whitelist.
    *   **Hardcoded Paths:**  Prefer absolute, hardcoded paths.
    *   **Read-Only Configuration Directory:**  Store configuration files in a read-only directory for the application user.
    *   **Avoid User Input in Paths:** Do not directly use user input in file paths.

## Attack Surface: [2. Configuration File Content Injection](./attack_surfaces/2__configuration_file_content_injection.md)

*   **Description:** An attacker gains write access to a legitimate configuration file used by Viper and modifies its contents.
*   **How Viper Contributes:** Viper reads and parses configuration files; if an attacker can modify these files, they control the application's configuration. This is a direct consequence of Viper's core purpose.
*   **Example:** An attacker modifies `config.yaml` to change the database connection string to a malicious server.
*   **Impact:**  Complete application compromise, data breaches, denial of service.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **File System Permissions:**  Enforce strict file system permissions (read-only for the application user).
    *   **File Integrity Monitoring (FIM):**  Implement FIM to detect unauthorized changes.
    *   **Digital Signatures:**  Digitally sign configuration files and verify the signature.
    *   **Configuration Auditing:** Regularly audit configuration files.

## Attack Surface: [3. Environment Variable Injection](./attack_surfaces/3__environment_variable_injection.md)

*   **Description:** An attacker manipulates environment variables that Viper reads, overriding intended settings.
*   **How Viper Contributes:** Viper's `AutomaticEnv()` and `BindEnv()` functions *directly* enable this attack surface. This is a core feature of Viper.
*   **Example:**  An application uses `viper.AutomaticEnv()`. An attacker sets `APP_ADMIN_ENABLED=true` to gain admin privileges.
*   **Impact:**  Bypassing security controls, privilege escalation, data breaches.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Minimize `AutomaticEnv()`:**  Avoid using `AutomaticEnv()` in untrusted environments.
    *   **Explicit Binding:**  Use `viper.BindEnv()` with specific key-value pairs.
    *   **Environment Variable Prefixing:**  Use `viper.SetEnvPrefix()`.
    *   **Environment Hardening:** Secure the application's environment.

## Attack Surface: [4. Remote Configuration Store Compromise](./attack_surfaces/4__remote_configuration_store_compromise.md)

*   **Description:** An attacker gains access to the remote configuration store (etcd, Consul) used by Viper.
*   **How Viper Contributes:** Viper *directly* supports fetching configuration from remote stores, making the security of the store a Viper-related concern.
*   **Example:** An attacker compromises etcd and modifies the database connection string.
*   **Impact:**  Complete application compromise, data breaches, denial of service.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Secure Remote Store:**  Secure the remote store with strong authentication and authorization.
    *   **TLS Communication:**  Use TLS (HTTPS) for all communication.
    *   **Monitoring and Alerting:**  Implement monitoring and alerting for the configuration store.
    *   **Key Rotation:** Regularly rotate access keys.

## Attack Surface: [5. Nested Key Manipulation (Key Delimiter Confusion)](./attack_surfaces/5__nested_key_manipulation__key_delimiter_confusion_.md)

*   **Description:** An attacker manipulates a portion of a nested configuration key to access or modify unintended values.
*   **How Viper Contributes:** Viper's use of a key delimiter (default `.`) for nested keys, combined with user input influencing part of a key, *directly* creates this vulnerability.
*   **Example:** An application uses `user_settings.{username}.theme`. An attacker provides `admin.theme` as the username.
*   **Impact:** Unauthorized access to or modification of configuration, potentially leading to privilege escalation.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Input Sanitization:** Sanitize and validate user input used in keys.
    *   **Key Delimiter Escaping:** Properly escape the key delimiter.
    *   **Avoid User Input in Keys:** Avoid directly incorporating user input into configuration keys.
    *   **Alternative Delimiters:** Consider using a different key delimiter.

