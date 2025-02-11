# Mitigation Strategies Analysis for spf13/viper

## Mitigation Strategy: [Secret Management via Environment Variable Binding](./mitigation_strategies/secret_management_via_environment_variable_binding.md)

**Mitigation Strategy:** Use `viper.BindEnv()` to read secrets from environment variables.

**Description:**
1.  **Identify Secrets:** List all sensitive configuration values.
2.  **Define Environment Variables:** For each secret, define a corresponding environment variable (e.g., `DB_PASSWORD`, `API_TOKEN`).
3.  **Bind with `viper.BindEnv()`:** In your Go code, use `viper.BindEnv()` to bind each environment variable to a Viper key.  Crucially, do this *before* reading any configuration files.  Example:
    ```go
    viper.BindEnv("DB_PASSWORD")
    viper.BindEnv("API_TOKEN", "MY_APP_API_TOKEN") // Optional: Map to a different Viper key
    ```
    The second example shows how to map an environment variable (`MY_APP_API_TOKEN`) to a different Viper key (`API_TOKEN`).
4.  **Retrieve with Type-Safe Getters:** Use Viper's type-safe getters (e.g., `viper.GetString("DB_PASSWORD")`) to retrieve the values.
5.  **Secure Environment Variable Setup:** Ensure the environment variables are set securely in your deployment environment (container orchestration, systemd, etc.). *Never* commit them to source control.

**Threats Mitigated:**
*   **Secret Exposure in Source Control (Severity: Critical):** Prevents hardcoding secrets in configuration files that might be committed.
*   **Secret Exposure in Backups (Severity: High):** Reduces the risk of secrets being exposed in backups of configuration files.
*   **Accidental Secret Sharing (Severity: High):** Makes it less likely developers will accidentally share configuration files containing secrets.

**Impact:**
*   **Secret Exposure in Source Control:** Risk significantly reduced (secrets are not in the codebase).
*   **Secret Exposure in Backups:** Risk reduced (secrets are not in backed-up files).
*   **Accidental Secret Sharing:** Risk reduced.

**Currently Implemented:** (Example) Partially implemented. `DATABASE_URL` is read from an environment variable, but other secrets are not.

**Missing Implementation:** (Example) API keys and other sensitive values need to be moved to environment variables and bound using `viper.BindEnv()`.

## Mitigation Strategy: [Configuration Change Monitoring with `viper.WatchConfig()`](./mitigation_strategies/configuration_change_monitoring_with__viper_watchconfig___.md)

**Mitigation Strategy:** Use `viper.WatchConfig()` and `viper.OnConfigChange()` to detect and react to configuration file changes.

**Description:**
1.  **Enable Watching:** After loading your configuration, call `viper.WatchConfig()`:
    ```go
    viper.WatchConfig()
    ```
2.  **Register a Callback:** Use `viper.OnConfigChange()` to register a function that will be executed whenever the configuration file changes:
    ```go
    viper.OnConfigChange(func(e fsnotify.Event) {
        fmt.Println("Config file changed:", e.Name)
        // 1. Re-validate the configuration (see Input Validation below).
        // 2. Log the change (including timestamp and potentially the changed values).
        // 3. (Optional) Alert administrators if critical values have changed.
        // 4. (Optional) Implement graceful reloading of services if necessary.
    })
    ```
3.  **Handle Changes:** Inside the callback function:
    *   **Re-validate:**  Re-check the configuration values to ensure they are still valid and secure (especially important if the configuration file is not under your direct control).
    *   **Log:** Record the change event, including the filename, timestamp, and potentially the specific values that changed.
    *   **Alert:**  If critical configuration values have changed (especially unexpectedly), consider sending alerts to administrators.
    *   **Reload (Optional):**  If your application can handle it, implement graceful reloading of services or components that depend on the changed configuration.
4. **Error Handling:** Ensure your application handles the case where `viper.WatchConfig()` might fail (e.g., due to file system issues).

**Threats Mitigated:**
*   **Unauthorized Configuration Changes (Severity: High):** Helps detect unauthorized modifications to configuration files.
*   **Configuration Errors (Severity: Medium):** Helps detect accidental or unintentional changes that could disrupt the application.

**Impact:**
*   **Unauthorized Configuration Changes:** Improves detection and response capabilities.
*   **Configuration Errors:** Enables faster detection and recovery.

**Currently Implemented:** (Example) `viper.WatchConfig()` is called, but the callback function only logs the change; no re-validation or alerting is implemented.

**Missing Implementation:** (Example) The callback function needs to be expanded to include re-validation of configuration values and potentially alerting.

## Mitigation Strategy: [Remote Configuration with Secure Options (Consul, etcd)](./mitigation_strategies/remote_configuration_with_secure_options__consul__etcd_.md)

**Mitigation Strategy:**  Use Viper's built-in support for secure communication with remote configuration stores (Consul, etcd).

**Description:**
1.  **Choose a Remote Store:** Select a supported remote configuration store (Consul, etcd).
2.  **Configure Viper:** Use Viper's configuration options to specify the connection details for the remote store.  *Crucially*, use the options that enable secure communication:
    *   **TLS/SSL:**  Use the `scheme` option to specify `https` (e.g., `viper.Set("consul.scheme", "https")`).  Provide paths to the necessary TLS certificates and keys using the appropriate Viper options (these vary depending on the specific store).
    *   **Authentication:**  Provide authentication credentials (tokens, client certificates) using the relevant Viper options for the chosen store.  Refer to the Viper documentation for the specific options for Consul and etcd.
3.  **Example (Conceptual - Consul):**
    ```go
    viper.SetConfigType("yaml")
    viper.AddRemoteProvider("consul", "localhost:8500", "my-app/config")
    viper.Set("consul.scheme", "https") // Enable TLS
    viper.Set("consul.token", "your-consul-token") // Authentication token
    // ... (configure TLS certificate paths if needed) ...
    err := viper.ReadRemoteConfig()
    if err != nil { /* handle error */ }
    ```
4. **Error Handling:** Ensure your application handles errors when connecting to or reading from the remote configuration store.

**Threats Mitigated:**
*   **Man-in-the-Middle (MitM) Attacks (Severity: High):** Prevents attackers from intercepting and modifying configuration data in transit.
*   **Unauthorized Configuration Access (Severity: High):** Prevents unauthorized access to the configuration store.

**Impact:**
*   **MitM Attacks:** Risk eliminated (communication is encrypted).
*   **Unauthorized Configuration Access:** Risk significantly reduced (authentication is required).

**Currently Implemented:** (Example) Viper is configured to read from Consul, but TLS is not enabled, and a weak, shared token is used.

**Missing Implementation:** (Example) We need to enable TLS (set `consul.scheme` to `https` and configure certificates) and use a stronger, per-application authentication token.

## Mitigation Strategy: [Type-Safe Configuration Retrieval](./mitigation_strategies/type-safe_configuration_retrieval.md)

**Mitigation Strategy:** Use Viper's type-specific getters (e.g., `GetInt()`, `GetString()`, `GetBool()`, `GetDuration()`, etc.) instead of `Get()`.

**Description:**
1.  **Identify Configuration Types:** Determine the expected data type of each configuration value (integer, string, boolean, duration, etc.).
2.  **Use Type-Specific Getters:**  Instead of using the generic `viper.Get()` method, use the appropriate type-specific getter:
    *   `viper.GetInt()` for integers
    *   `viper.GetString()` for strings
    *   `viper.GetBool()` for booleans
    *   `viper.GetDuration()` for time durations
    *   `viper.GetFloat64()` for floating-point numbers
    *   `viper.GetIntSlice()`, `viper.GetStringSlice()`, etc. for slices
3.  **Handle Default Values:**  Be mindful of the default values returned by these functions if the key is not found. Consider using `viper.IsSet()` to check if a key exists before retrieving its value.

**Threats Mitigated:**
*   **Type Confusion Errors (Severity: Medium):** Reduces the risk of unexpected behavior due to incorrect type assumptions. While not a direct security vulnerability in itself, type confusion can lead to logic errors that *could* be exploited.
*   **Improved Code Robustness (Severity: Low):** Makes the code more robust and less prone to errors.

**Impact:**
*   **Type Confusion Errors:** Risk reduced.
*   **Improved Code Robustness:**  Code is more maintainable and less likely to break due to unexpected configuration values.

**Currently Implemented:** (Example) Mostly implemented. Most configuration values are retrieved using type-specific getters.

**Missing Implementation:** (Example) A few places still use `viper.Get()`. These need to be updated to use the appropriate type-specific getters.

