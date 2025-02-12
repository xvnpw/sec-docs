# Threat Model Analysis for eslint/eslint

## Threat: [Threat 1: Malicious Plugin Execution](./threats/threat_1_malicious_plugin_execution.md)

*   **Description:** An attacker crafts a malicious ESLint plugin and publishes it to a public registry (e.g., npm). A developer unknowingly installs this plugin. When ESLint runs (during development or in the build pipeline), the plugin's code executes with the privileges of the user running ESLint. The attacker's code could steal credentials, modify source code, install backdoors, exfiltrate data, or perform other malicious actions, potentially leading to a full system compromise.
*   **Impact:** Complete system compromise, data exfiltration, source code modification, supply chain attack propagation.
*   **Affected ESLint Component:** Plugin loading mechanism (`eslint.config.js` or legacy configuration files, `require()` calls for plugins). The entire ESLint process is vulnerable once the malicious plugin is loaded.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strict Plugin Vetting:** Thoroughly research plugins before installation. Check author reputation, download counts, and source code (if available).  Prioritize well-known and actively maintained plugins.
    *   **Dependency Scanning:** Use tools like `npm audit`, `yarn audit`, Snyk, or Dependabot to identify known vulnerabilities in plugins *before* installation and regularly thereafter.
    *   **Version Pinning:** Pin plugin versions in `package.json` and use a lockfile (`package-lock.json` or `yarn.lock`) to prevent automatic updates to potentially malicious versions.
    *   **Private Registry:** For internal plugins, use a private npm registry to control access and reduce exposure to publicly available malicious packages.
    *   **Least Privilege:** Run ESLint with the minimum necessary privileges. Avoid running as root or administrator, especially in CI/CD environments. Use dedicated service accounts with limited permissions.

## Threat: [Threat 2: Malicious Shareable Config Injection](./threats/threat_2_malicious_shareable_config_injection.md)

*   **Description:** An attacker publishes a malicious shareable ESLint configuration to a public registry. This configuration might disable crucial security rules, enable insecure rules that permit dangerous practices, or even include malicious plugins as dependencies. A developer unknowingly extends this configuration in their project's ESLint setup.
*   **Impact:** Weakened security posture, introduction of vulnerabilities, potential for code execution (if the config includes malicious plugins as dependencies). This can lead to successful exploitation of the application.
*   **Affected ESLint Component:** Configuration loading and merging mechanism (`extends` property in `eslint.config.js` or legacy configuration files). The configuration resolution process is the attack vector.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Careful Config Selection:** Only extend configurations from *highly trusted* sources. Thoroughly review the configuration's source code *and* its dependencies before using it.
    *   **Configuration Auditing:** Regularly review the *entire* ESLint configuration (including all extended configs) to ensure security rules are not disabled or weakened. This should be part of the code review process.
    *   **Dependency Scanning:** Treat shareable configs as dependencies and scan them for vulnerabilities using tools like `npm audit`.
    *   **Version Pinning:** Pin the version of the shareable config in `package.json` and use a lockfile.

## Threat: [Threat 3: Configuration File Tampering](./threats/threat_3_configuration_file_tampering.md)

*   **Description:** An attacker gains unauthorized access to the developer's machine, the build server, or the source code repository and modifies the ESLint configuration file (`.eslintrc.js`, `.eslintrc.json`, or `eslint.config.js`). They could disable security rules, add malicious rules that allow insecure code, or point to a malicious plugin/config, effectively bypassing security checks.
*   **Impact:** Weakened security, introduction of vulnerabilities, potential for code execution (if a malicious plugin is referenced). This directly undermines the purpose of using ESLint for security.
*   **Affected ESLint Component:** The configuration file itself. The entire ESLint process is affected by changes to the configuration, as it dictates how ESLint operates.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **File System Permissions:** Restrict write access to the ESLint configuration file to authorized users and processes only. This is a fundamental security best practice.
    *   **Version Control:** Store the configuration file in version control (e.g., Git) and *require* code reviews for *any* changes to the configuration. This provides an audit trail and prevents unilateral changes.
    *   **Integrity Monitoring:** Use file integrity monitoring tools (e.g., OS-level tools or security software) to detect unauthorized modifications to the configuration file and trigger alerts.
    *   **CI/CD Security:** Secure the build pipeline to prevent unauthorized access and modification of build artifacts, including the configuration file. Implement strong access controls and follow the principle of least privilege.

## Threat: [Threat 4: Weakening Security Rules](./threats/threat_4_weakening_security_rules.md)

*   **Description:** Developers disable or weaken security-related ESLint rules (e.g., `no-eval`, `no-implied-eval`, `no-unsanitized/property`) using comments (`// eslint-disable-next-line`) or by modifying the configuration file. They do this to bypass warnings or make the code "easier" to write, but it introduces vulnerabilities.
*   **Impact:** Increased risk of XSS, code injection, and other security flaws.
*   **Affected ESLint Component:** The rule enforcement mechanism. Specific rules are disabled or their severity is reduced.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Strict Configuration Policy:** Establish a policy against disabling security-related rules without explicit justification and approval.
    *   **Code Review:** Enforce code reviews to catch instances where security rules are bypassed.
    *   **Configuration Auditing:** Regularly review the ESLint configuration to ensure security rules are enabled and configured correctly.
    *   **Education:** Train developers on the importance of secure coding practices and the purpose of security-related ESLint rules.
    * **Automated checks:** Use tools that can detect disabled eslint rules in pull requests.

