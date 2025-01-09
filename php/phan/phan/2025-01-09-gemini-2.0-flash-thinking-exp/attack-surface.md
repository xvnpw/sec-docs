# Attack Surface Analysis for phan/phan

## Attack Surface: [Malicious Phan Configuration Injection](./attack_surfaces/malicious_phan_configuration_injection.md)

* **Description**:  An attacker injects malicious configuration options into Phan's configuration file.
* **How Phan Contributes**: Phan reads and applies the configuration options defined in its configuration file. If this file is modifiable by untrusted sources or generated based on untrusted input, malicious configurations can be introduced.
* **Example**: An attacker modifies the `.phan/config.php` file to set `directory_list` to include sensitive directories outside the project, allowing Phan to analyze and potentially expose information from those directories in its reports. Another example is setting a malicious `plugin_config` that could execute arbitrary code during Phan's analysis.
* **Impact**:  Information disclosure (sensitive files included in analysis), potential for indirect code execution (through malicious plugins or unintended Phan behavior), denial of service (resource-intensive analysis of unintended files).
* **Risk Severity**: High
* **Mitigation Strategies**:
    * Store the Phan configuration file under version control and review changes carefully.
    * Avoid generating the Phan configuration file based on untrusted input.
    * Restrict write access to the Phan configuration file to authorized personnel only.
    * Regularly audit the Phan configuration for unexpected or suspicious settings.

## Attack Surface: [Exploiting Vulnerabilities in Custom Phan Plugins or Extensions](./attack_surfaces/exploiting_vulnerabilities_in_custom_phan_plugins_or_extensions.md)

* **Description**: If the application uses custom Phan plugins or extensions, vulnerabilities in these extensions can introduce new attack vectors.
* **How Phan Contributes**: Phan's extensibility allows for custom plugins. If these plugins are poorly written or contain vulnerabilities, they can be exploited during Phan's execution.
* **Example**: A custom plugin designed to interact with external systems has an SQL injection vulnerability. When Phan executes this plugin, it could be exploited to access or modify data in the external system.
* **Impact**:  Depends on the functionality of the vulnerable plugin, but could range from information disclosure to remote code execution.
* **Risk Severity**: High
* **Mitigation Strategies**:
    * Thoroughly review and audit any custom Phan plugins for security vulnerabilities.
    * Follow secure coding practices when developing Phan plugins.
    * Limit the privileges and access of custom plugins.

