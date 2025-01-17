# Attack Surface Analysis for automapper/automapper

## Attack Surface: [Malicious Configuration Injection](./attack_surfaces/malicious_configuration_injection.md)

* **Description:** An attacker manipulates the AutoMapper configuration loaded by the application.
    * **How AutoMapper Contributes:** AutoMapper relies on configuration to define mapping rules. If this configuration source is compromised, the mapping behavior can be altered.
    * **Example:** An attacker modifies a configuration file used by AutoMapper to map a user-controlled input field directly to a sensitive internal property, bypassing intended security checks.
    * **Impact:** Data manipulation, information disclosure, privilege escalation if internal flags or roles are modified.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * Store configuration in secure locations with restricted access.
        * Validate configuration data loaded by AutoMapper.
        * Use immutable configuration if possible.
        * Avoid loading configuration from user-controlled sources.

## Attack Surface: [Malicious Custom Resolvers/Converters](./attack_surfaces/malicious_custom_resolversconverters.md)

* **Description:** An attacker exploits vulnerabilities in custom resolvers or type converters used by AutoMapper.
    * **How AutoMapper Contributes:** AutoMapper allows developers to define custom logic for resolving property values or converting types. If this custom logic is insecure, it becomes an attack vector.
    * **Example:** A custom resolver fetches data from an external API based on user input without proper sanitization, leading to a server-side request forgery (SSRF) vulnerability.
    * **Impact:** Code injection, denial of service, data breaches, SSRF, and other vulnerabilities depending on the custom logic.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * Thoroughly review and test all custom resolvers and converters for security vulnerabilities.
        * Sanitize and validate any user input used within custom logic.
        * Avoid performing sensitive operations or accessing external resources directly within custom resolvers/converters without proper security measures.
        * Apply the principle of least privilege to custom logic.

