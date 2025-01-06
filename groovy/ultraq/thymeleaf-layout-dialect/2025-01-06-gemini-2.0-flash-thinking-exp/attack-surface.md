# Attack Surface Analysis for ultraq/thymeleaf-layout-dialect

## Attack Surface: [Layout Name Injection](./attack_surfaces/layout_name_injection.md)

*   **Description:** An attacker can manipulate the layout name specified in the `@layout` attribute (or `layout:decorate`).
    *   **How thymeleaf-layout-dialect contributes to the attack surface:** The `@layout` (or `layout:decorate`) attribute directly uses the provided string to resolve and include a layout template. If this string is derived from untrusted input, it becomes an attack vector.
    *   **Example:** An attacker modifies a URL parameter like `?theme=untrusted/malicious_layout` which is then used in the template: `<div layout:decorate="${theme}">...</div>`. This could lead to including a malicious template.
    *   **Impact:** Arbitrary template inclusion, potentially leading to information disclosure (if the malicious template reveals sensitive data), denial of service (if the malicious template is resource-intensive), or even remote code execution if the included template has vulnerabilities.
    *   **Risk Severity:** High (Possibility of arbitrary code execution or sensitive data exposure depending on the included template).
    *   **Mitigation Strategies:**
        *   Sanitize and validate user-provided input used for layout names against a whitelist of allowed values.
        *   Avoid directly using user input to determine layout names. If necessary, map user-provided identifiers to predefined, safe layout names.
        *   Implement robust error handling to prevent information leakage if an invalid layout is requested.

## Attack Surface: [Security Misconfiguration of Layout Resolution](./attack_surfaces/security_misconfiguration_of_layout_resolution.md)

*   **Description:** If the mechanism for resolving layout template paths is not properly secured, an attacker might be able to influence the resolution process to point to malicious templates stored outside the intended template directory.
    *   **How thymeleaf-layout-dialect contributes to the attack surface:** The dialect relies on Thymeleaf's template resolution mechanism. If this mechanism is misconfigured, allowing for arbitrary file access or inclusion, the layout dialect can be a vehicle for exploiting this misconfiguration.
    *   **Example:** If the template resolver is configured to allow access to arbitrary files on the server, an attacker could potentially specify a layout path like `/etc/passwd` (depending on OS and permissions) in the `@layout` attribute, potentially exposing sensitive system files (though Thymeleaf typically has safeguards against this).
    *   **Impact:**  Potentially severe, ranging from information disclosure to remote code execution depending on the misconfiguration and the content of the maliciously included "template".
    *   **Risk Severity:** High (If the underlying template resolution mechanism is vulnerable).
    *   **Mitigation Strategies:**
        *   Ensure that Thymeleaf's template resolvers are configured to only access trusted template directories.
        *   Follow the principle of least privilege when configuring file system access for the application.
        *   Regularly review and audit template resolver configurations.

