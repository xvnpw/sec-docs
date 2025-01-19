# Threat Model Analysis for kong/insomnia

## Threat: [Exposure of Sensitive Data in Insomnia Workspace Files](./threats/exposure_of_sensitive_data_in_insomnia_workspace_files.md)

* **Threat:** Exposure of Sensitive Data in Insomnia Workspace Files
    * **Description:** An attacker gains unauthorized access to a developer's local machine and directly reads Insomnia's workspace files. This could be achieved through malware, physical access, or exploiting operating system vulnerabilities. The attacker then extracts sensitive information like API keys, authentication tokens, request bodies containing secrets, and response data from these files.
    * **Impact:**  Unauthorized access to backend systems, data breaches, financial loss, reputational damage.
    * **Affected Component:** Insomnia's local data storage mechanism for workspaces (files on the filesystem).
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * Encourage the use of Insomnia's built-in encryption features for sensitive data within workspaces.
        * Implement full disk encryption on developer workstations.
        * Enforce strong password policies and multi-factor authentication for user accounts.
        * Utilize endpoint security solutions (antivirus, EDR) to detect and prevent malware.
        * Educate developers on the risks of storing sensitive data locally and best practices.

## Threat: [Malicious Insomnia Plugin Compromise](./threats/malicious_insomnia_plugin_compromise.md)

* **Threat:** Malicious Insomnia Plugin Compromise
    * **Description:** A developer installs a malicious Insomnia plugin from an untrusted source or a legitimate plugin is compromised by an attacker. The malicious plugin can then intercept API requests and responses, steal credentials, modify requests before they are sent, or even execute arbitrary code on the developer's machine.
    * **Impact:** Data exfiltration, manipulation of API calls leading to unintended consequences, compromise of the developer's workstation.
    * **Affected Component:** Insomnia's plugin system and the specific malicious plugin.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * Establish a strict policy for plugin usage, allowing only approved and vetted plugins.
        * Encourage developers to only install plugins from trusted sources and review their code if possible.
        * Implement a process for reviewing and auditing installed plugins.
        * Monitor for updates to installed plugins and promptly apply security patches.
        * Consider using Insomnia's plugin management features to control and audit installed plugins.

