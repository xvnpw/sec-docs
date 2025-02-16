# Mitigation Strategies Analysis for puppetlabs/puppet

## Mitigation Strategy: [Strict Code Review and Version Control (Puppet Code)](./mitigation_strategies/strict_code_review_and_version_control__puppet_code_.md)

1.  **Git Repository:** All Puppet code (manifests, modules, Hiera data) *must* reside in a Git repository.
2.  **Branching Strategy:** Use a branching strategy (e.g., Gitflow). Developers work on feature branches.
3.  **Pull Requests:** All changes *must* be submitted via pull requests (PRs).
4.  **Mandatory Code Review:** Each PR *must* be reviewed by at least one other team member, focusing on:
    *   Puppet-specific vulnerabilities (e.g., insecure `exec` resources, improper file permissions within modules, unsafe handling of facts).
    *   Adherence to Puppet coding style and best practices (using the Puppet Development Kit (PDK) recommendations).
    *   Correct use of Puppet data types and functions.
    *   Proper parameterization and validation.
5.  **Approval Requirements:** Require approvals before merging.
6.  **Automated Checks (Puppet-Specific):** Integrate `puppet-lint` and PDK validation into the CI/CD pipeline. This automatically checks for style issues, potential errors, and deprecated features *specific to Puppet*.
7.  **Audit Trail:** Git provides the audit trail.

## Mitigation Strategy: [Secure Hiera Configuration](./mitigation_strategies/secure_hiera_configuration.md)

1.  **Secrets Management (Puppet-Integrated):**
    *   **Choose a Backend:** Select a secure backend *supported by Hiera* (e.g., HashiCorp Vault with the `hiera-vault` backend, AWS Secrets Manager with a custom backend, or `eyaml`).
    *   **Hiera Integration:** Configure Hiera (via `hiera.yaml`) to use the chosen backend. This involves installing the appropriate Hiera backend gem/plugin and configuring the connection details.  This is a *Puppet-specific* configuration.
    *   **Access Control (Backend-Specific):** Configure access control within the chosen backend (e.g., Vault policies).
2.  **`eyaml` (if used - Puppet-Specific):**
    *   **Secure Key Storage:** Store the `eyaml` private key *outside* the Puppet codebase, ideally in the chosen secrets management solution.
    *   **Regular Key Rotation:** Rotate the `eyaml` keys.
3.  **Hiera Data File Permissions:** Restrict access to Hiera data files (YAML files) using standard OS permissions. This is less Puppet-specific, but important.
4.  **Hiera Hierarchy (Puppet-Specific):** Design the Hiera hierarchy (`hiera.yaml`) to minimize data exposure. Use node-specific or role-specific data sources.  The *hierarchy itself* is a core Puppet concept.

## Mitigation Strategy: [Module Signing and Verification](./mitigation_strategies/module_signing_and_verification.md)

1.  **Signing (Module Authors):**
    *   **Private Key:** Generate a private key for signing modules.
    *   **`puppet module build`:** Use the `puppet module build` command, which includes signing functionality.
    *   **Publish to Forge (or Internal Repo):** Publish the signed module.
2.  **Verification (Puppet Agents):**
    *   **`puppet agent --test` (or regular runs):** Configure Puppet agents to *verify* module signatures. This is done via settings in `puppet.conf`, specifically the `module_repository` and related settings. This is a *Puppet-specific* configuration.
    *   **Trusted Certificate Authority:** Ensure agents trust the CA that issued the signing certificate. This might involve distributing the CA certificate to agents.
3. **Internal Module Repository (Optional):** If using an internal repository, configure it to support signed modules.

## Mitigation Strategy: [Regular Expression Validation for External Input (Within Puppet Code)](./mitigation_strategies/regular_expression_validation_for_external_input__within_puppet_code_.md)

1.  **Identify Input Sources:** Identify all places in Puppet code where external data is used:
    *   Facts (especially custom facts).
    *   Parameters passed to classes or defined types.
    *   Data looked up from external sources (e.g., using `lookup()` function).
2.  **Whitelisting:** Use *whitelisting* with regular expressions. Define *allowed* patterns, rather than trying to block specific malicious patterns.
3.  **Puppet Data Types:** Use Puppet's data types (e.g., `String`, `Integer`, `Enum`, `Pattern`) to enforce basic type validation.
4.  **`validate_re` (Deprecated) / `assert_type` (Recommended):**
    *   Use the `assert_type` function (or the older `validate_re` function if using an older Puppet version) to validate input against regular expressions *within Puppet code*. This is a *Puppet-specific* validation mechanism.
    *   Example: `assert_type(Pattern[/^[a-zA-Z0-9_\-]+$/], $hostname, 'Invalid hostname format')`
5.  **Avoid `exec` with Untrusted Input:** Be *extremely* cautious when using the `exec` resource with any external input.  If possible, avoid it entirely. If unavoidable, sanitize and validate the input *very* thoroughly.

## Mitigation Strategy: [Disable Unnecessary Features (Puppet Server/Agent)](./mitigation_strategies/disable_unnecessary_features__puppet_serveragent_.md)

1.  **Review `puppet.conf`:** Examine the `puppet.conf` file on both the Puppet Server and agents.
2.  **Identify Unused Settings:** Identify any settings or features that are not actively used.
3.  **Disable/Remove:**
    *   Comment out or remove unnecessary settings from `puppet.conf`.
    *   If a feature is provided by a separate module, uninstall the module if it's not needed.
    *   Examples:
        *   If not using PuppetDB, disable the `storeconfigs` and `storeconfigs_backend` settings.
        *   If not using the legacy reports system, disable it.
        *   If not using a specific ENC (External Node Classifier), disable the related configuration.
4. **Restart Services:** Restart the Puppet Server and Agent services after making changes to `puppet.conf`.

## Mitigation Strategy: [Data Leakage Prevention using Puppet's `Sensitive` Data Type](./mitigation_strategies/data_leakage_prevention_using_puppet's__sensitive__data_type.md)

1.  **Identify Sensitive Values:** Identify all variables and parameters within your Puppet code that contain sensitive information (passwords, API keys, etc.).
2.  **Wrap with `Sensitive`:** Wrap these values using the `Sensitive` data type.  This is a *Puppet-specific* feature.
    *   Example: `$password = Sensitive('mysecretpassword')`
3.  **Use in Resources:** Use the `Sensitive`-wrapped variables within your Puppet resources as you normally would. Puppet will automatically handle the masking.
4.  **Avoid String Interpolation:** Do *not* directly interpolate `Sensitive` values into strings.  Puppet's resource providers should handle `Sensitive` values correctly.
5. **Test:** Thoroughly test your code to ensure that sensitive values are not being leaked in logs, reports, or error messages.

## Mitigation Strategy: [Secure Report Processor Configuration](./mitigation_strategies/secure_report_processor_configuration.md)

1.  **Review `puppet.conf` (Server):** Examine the `reports` setting in the `[master]` section of `puppet.conf` on the Puppet Server.
2.  **Choose Secure Processors:**
    *   Use report processors that are known to be secure and handle sensitive data appropriately. Avoid custom or poorly-maintained processors.
    *   The `http` and `https` report processors are generally preferred for sending reports to external systems, *provided* TLS is properly configured.
    *   The `store` report processor simply stores reports locally; ensure appropriate file permissions are set.
3.  **Configure Encryption (if applicable):** If using a report processor that transmits data over the network (e.g., `http`, `https`), ensure that TLS encryption is enabled and properly configured.
4.  **Avoid Storing Sensitive Data:** Configure report processors to *avoid* storing or transmitting sensitive information unnecessarily.  The `Sensitive` data type helps with this.
5. **Review Custom Report Processors:** If using any custom report processors, thoroughly review their code for security vulnerabilities, especially regarding data handling and transmission.

## Mitigation Strategy: [Careful Parameter Handling within Puppet Modules](./mitigation_strategies/careful_parameter_handling_within_puppet_modules.md)

1.  **Parameterized Classes and Defined Types:** Use parameterized classes and defined types to define the inputs (parameters) that your modules accept.
2.  **Data Type Validation:** Use Puppet's data types (e.g., `String`, `Integer`, `Boolean`, `Array`, `Hash`, `Enum`, `Pattern`) to enforce type checking for all parameters. This is a core *Puppet-specific* feature.
3.  **`assert_type`:** Use the `assert_type` function to perform more complex validation, including regular expression checks, within your module code.
4.  **Default Values:** Provide sensible default values for parameters whenever possible.
5.  **Documentation:** Clearly document the expected data types and allowed values for all parameters in your module's README.
6.  **Avoid `exec` with Untrusted Input:** Minimize the use of the `exec` resource, and *never* use it with unsanitized external input.

