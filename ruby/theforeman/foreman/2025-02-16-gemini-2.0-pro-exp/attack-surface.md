# Attack Surface Analysis for theforeman/foreman

## Attack Surface: [Remote Code Execution (RCE) via Provisioning Templates](./attack_surfaces/remote_code_execution__rce__via_provisioning_templates.md)

*   **Description:** Exploitation of vulnerabilities in provisioning templates to execute arbitrary code on the Foreman server or managed hosts.
    *   **How Foreman Contributes:** Foreman uses templates (ERB, MCollective, etc.) extensively for provisioning and configuration management. These templates are executed with elevated privileges *by Foreman*.
    *   **Example:** An attacker injects a malicious ERB command (`<%= system('rm -rf /') %>`) into a provisioning template, which is then executed on a newly provisioned host *by Foreman's provisioning process*.
    *   **Impact:** Complete system compromise (Foreman server or managed host), data loss, data exfiltration.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Input Validation:** Strictly validate and sanitize all user-supplied input that is used in templates. Use a whitelist approach.
        *   **Template Sandboxing:** Explore sandboxing techniques to limit template engine capabilities (custom Foreman plugin development may be needed).
        *   **Least Privilege:** Run Foreman and its processes with the least necessary privileges. Avoid root for provisioning.
        *   **Regular Audits:** Audit provisioning templates for vulnerabilities.
        *   **Principle of Least Privilege for Template Authors:** Restrict template editing permissions.

## Attack Surface: [Authentication and Authorization Bypass (Foreman-Specific Logic)](./attack_surfaces/authentication_and_authorization_bypass__foreman-specific_logic_.md)

*   **Description:** Circumventing Foreman's *internal* authentication or authorization logic to gain unauthorized access. This focuses on flaws *within Foreman's code*, not just misconfiguration of external systems.
    *   **How Foreman Contributes:** Foreman has its own RBAC system and authentication handling logic. Vulnerabilities *in this code* are the concern.
    *   **Example:** An attacker exploits a bug in Foreman's permission checking code to perform actions they shouldn't be allowed to, even with a correctly configured external authentication source.
    *   **Impact:** Unauthorized access to Foreman, potential privilege escalation, access to sensitive data, ability to manage hosts.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Regular Code Audits:** Thoroughly audit Foreman's authentication and authorization code for logic flaws.
        *   **Thorough Testing:** Implement comprehensive unit and integration tests to cover all authentication and authorization scenarios.
        *   **Follow Secure Coding Practices:** Adhere to secure coding principles to prevent common vulnerabilities.

## Attack Surface: [RCE via Plugin Vulnerabilities (Foreman-Loaded Plugins)](./attack_surfaces/rce_via_plugin_vulnerabilities__foreman-loaded_plugins_.md)

*   **Description:** Exploiting vulnerabilities in Foreman plugins *loaded and executed by Foreman* to execute arbitrary code.
    *   **How Foreman Contributes:** Foreman's plugin architecture allows for the loading and execution of third-party or custom code *within the Foreman process*.
    *   **Example:** An attacker exploits a vulnerability in a Foreman plugin that processes user input to inject and execute malicious code *on the Foreman server*.
    *   **Impact:** Compromise of the Foreman server.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Plugin Vetting:** Carefully vet plugins from trusted sources. Prioritize maintained plugins with good security records.
        *   **Regular Plugin Updates:** Keep all plugins up-to-date.
        *   **Code Review (Custom Plugins):** Thoroughly review custom plugin code for security vulnerabilities.
        *   **Least Privilege:** Run plugins with the least necessary privileges.
        *   **Input Validation (Plugins):** Plugins must validate and sanitize all input.
        *   **Dependency Management:** Regularly update plugin dependencies.

## Attack Surface: [Unsafe YAML Deserialization (within Foreman or Plugins)](./attack_surfaces/unsafe_yaml_deserialization__within_foreman_or_plugins_.md)

*   **Description:** Exploiting unsafe YAML deserialization *within Foreman or its loaded plugins* to achieve remote code execution.
    *   **How Foreman Contributes:** Foreman and its plugins may use YAML for configuration and data, and if they use unsafe deserialization methods, they are vulnerable.
    *   **Example:** An attacker submits a crafted YAML payload to a Foreman API endpoint or through a plugin that uses `YAML.load` (unsafely) within Foreman's process, leading to RCE.
    *   **Impact:** Remote code execution on the Foreman server.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Use Safe YAML Loading:** *Always* use `YAML.safe_load` (or equivalent) within Foreman and all plugins.
        *   **Input Validation:** Validate YAML input before parsing, even with `YAML.safe_load`.
        *   **Update Psych:** Ensure the Ruby YAML library (Psych) is up-to-date.

