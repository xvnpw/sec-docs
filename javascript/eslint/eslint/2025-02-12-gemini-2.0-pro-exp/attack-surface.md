# Attack Surface Analysis for eslint/eslint

## Attack Surface: [Configuration File Manipulation](./attack_surfaces/configuration_file_manipulation.md)

*   **Description:** Attackers modify ESLint configuration files to weaken or disable security checks, or to introduce malicious configurations.
    *   **How ESLint Contributes:** ESLint's behavior is entirely driven by its configuration files.  These files are the primary control point.
    *   **Example:** An attacker changes `.eslintrc.js` to disable the `no-eval` rule, allowing the introduction of code that uses `eval()` with untrusted input.
    *   **Impact:**
        *   Introduction of security vulnerabilities into the codebase.
        *   Bypass of security best practices.
        *   Potential for code modification via malicious autofix rules.
    *   **Risk Severity:** **High**
    *   **Mitigation Strategies:**
        *   Treat configuration files as code: Use version control, require code reviews for changes, and include them in security scanning processes.
        *   Restrict write access to configuration files to authorized developers and build systems.
        *   Monitor configuration files for unauthorized changes.
        *   Use a secure method for managing shared configurations (e.g., signed packages, private repositories).

## Attack Surface: [Malicious Custom Rules](./attack_surfaces/malicious_custom_rules.md)

*   **Description:** Attackers introduce or exploit vulnerabilities in custom ESLint rules to execute arbitrary code during the linting process.
    *   **How ESLint Contributes:** ESLint allows the execution of arbitrary JavaScript code through custom rules.
    *   **Example:** A project uses a custom rule from a compromised npm package that contains a backdoor, allowing the attacker to execute commands on the developer's machine.
    *   **Impact:**
        *   Arbitrary code execution on the developer's machine.
        *   Data exfiltration (source code, credentials, etc.).
        *   Potential for full system compromise.
    *   **Risk Severity:** **Critical**
    *   **Mitigation Strategies:**
        *   Thoroughly vet any custom rules from external sources.  Review the code carefully for malicious behavior or vulnerabilities.
        *   Prefer well-established and widely used community rules over obscure or custom-built ones.
        *   If writing custom rules, follow secure coding practices and test them thoroughly for vulnerabilities.
        *   Consider running ESLint in a sandboxed environment (e.g., Docker) to limit the impact of a compromised rule.
        *   Regularly update custom rule dependencies.

## Attack Surface: [Malicious/Vulnerable Plugins](./attack_surfaces/maliciousvulnerable_plugins.md)

*   **Description:** Attackers exploit vulnerabilities in ESLint plugins or distribute malicious plugins to execute code or disable security checks.
    *   **How ESLint Contributes:** ESLint's plugin architecture allows for the loading of external code that extends its functionality.
    *   **Example:** A project uses a compromised `eslint-plugin-security` package that disables rules related to regular expression denial of service (ReDoS).
    *   **Impact:**
        *   Arbitrary code execution (if the plugin contains malicious code).
        *   Disabling of security rules provided by the plugin.
        *   Data exfiltration.
        *   System compromise.
    *   **Risk Severity:** **Critical**
    *   **Mitigation Strategies:**
        *   Only use plugins from trusted sources (e.g., well-known organizations, official repositories).
        *   Regularly update all ESLint plugins to the latest versions.
        *   Use a package manager with integrity checks (e.g., `package-lock.json`, `yarn.lock`).
        *   Review the source code of plugins if possible, especially for less-known plugins.
        *   Consider sandboxing ESLint execution.

## Attack Surface: [Malicious Shared Config Packages](./attack_surfaces/malicious_shared_config_packages.md)

*   **Description:** Attackers distribute malicious ESLint shared configuration packages that weaken security or introduce malicious rules.
    *   **How ESLint Contributes:** ESLint supports sharing configurations via packages, simplifying setup but introducing a supply chain risk.
    *   **Example:** A project uses a shared config from a compromised npm package that disables crucial security rules.
    *   **Impact:**
        *   Weakening of security posture by disabling important rules.
        *   Potential introduction of malicious rules (less common).
        *   Code modification via malicious autofix rules.
    *   **Risk Severity:** **High**
    *   **Mitigation Strategies:**
        *   Use shared configurations only from trusted sources (e.g., well-known organizations, official repositories).
        *   Carefully review the contents of any shared configuration before using it.  Understand the rules it enables and disables.
        *   Pin the version of the shared configuration package to prevent unexpected updates.
        *   Consider copying the relevant parts of a shared configuration into your project's own configuration file instead of relying on an external package.
        *   Regularly audit and review shared configurations.

