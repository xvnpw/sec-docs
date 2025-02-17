# Attack Surface Analysis for krzysztofzablocki/sourcery

## Attack Surface: [Template Injection](./attack_surfaces/template_injection.md)

*   **Description:**  Unauthorized modification of Sourcery templates to inject malicious Swift code.
*   **How Sourcery Contributes:** Sourcery's core function is to generate code from templates; this is the mechanism of the attack.  The template engine and parsing process are directly involved.
*   **Example:** An attacker gains access to the template repository and modifies a template to include code that opens a reverse shell on the target system when the generated code is executed.  Another example: a template is modified to include a hardcoded API key in the generated code.
*   **Impact:**  Complete system compromise, data exfiltration, arbitrary code execution.  The attacker gains the same privileges as the application.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strict Access Control:** Implement rigorous access control to the template repository and build server, using the principle of least privilege.  Only authorized personnel should have write access.
    *   **Mandatory Code Reviews:**  Require thorough code reviews for *all* template changes, treating them as critical code modifications.  Multiple reviewers are recommended.
    *   **Version Control and Audit Trails:**  Use a version control system (e.g., Git) to track all template changes and maintain a complete audit trail.
    *   **Digital Signatures (Ideal):**  Ideally, templates would be digitally signed, and Sourcery would verify the signature before processing.  This is not a built-in feature of Sourcery, so it would require custom implementation.
    *   **Regular Security Audits:** Conduct periodic security audits of the build environment and template storage.
    *   **Input Validation (if applicable):** If templates are ever loaded from external sources (highly discouraged), rigorously validate and sanitize any input used to specify the template location.
    *   **Static Analysis of Generated Code:** Use static analysis tools to scan the *generated* code for potential vulnerabilities, as a second line of defense.

## Attack Surface: [Indirect Information Disclosure](./attack_surfaces/indirect_information_disclosure.md)

*   **Description:**  Compromised templates generating code that inadvertently reveals sensitive information.
*   **How Sourcery Contributes:** Sourcery generates the code that could potentially leak information, *based on the instructions in the template*. The template processing is the direct cause.
*   **Example:** A modified template generates code that logs database connection strings or API keys to a file or the console. Another example: generating code that exposes internal class structures or API endpoints that should be private.
*   **Impact:**  Exposure of sensitive data (credentials, internal architecture), potentially leading to further attacks.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Primary Mitigation: Template Security:** The most effective mitigation is to prevent template injection in the first place (see "Template Injection" mitigations). This is paramount.
    *   **Code Reviews (Generated Code):**  Thoroughly review the *generated* code, paying close attention to any potential information leaks.  Don't assume generated code is safe.
    *   **Secrets Management:**  Never hardcode secrets in templates (or anywhere else). Use a proper secrets management solution (e.g., environment variables, a secrets vault).
    *   **Static Analysis (Generated Code):** Use static analysis tools to scan the generated code for potential information disclosure vulnerabilities.

## Attack Surface: [Sourcery Configuration Manipulation](./attack_surfaces/sourcery_configuration_manipulation.md)

*   **Description:**  Unauthorized modification of Sourcery's configuration file (e.g., `.sourcery.yml`) to alter its behavior.
*   **How Sourcery Contributes:** Sourcery *directly* relies on its configuration file to determine input files, output paths, template locations, and other settings. This is a direct attack on Sourcery's operation.
*   **Example:** An attacker modifies the `.sourcery.yml` file to point the `templates` path to a directory containing malicious templates, or changes the `output` path to overwrite critical application files.
*   **Impact:**  Can lead to template injection (if template paths are changed), denial of service (if output paths are changed to overwrite critical files), or other unintended behavior.  Potentially allows for complete control over Sourcery's execution.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Strict Access Control:** Protect the Sourcery configuration file with the same level of access control as the templates and source code.
    *   **Version Control:** Store the configuration file in version control (e.g., Git) to track changes and facilitate rollbacks.
    *   **Regular Audits:** Periodically review the configuration file to ensure it hasn't been tampered with.
    *   **Configuration Validation (Ideal):** Ideally, Sourcery would have built-in validation of its configuration file to prevent obviously malicious settings (e.g., outputting to system directories). This is not a standard feature, so it would require custom implementation if deemed necessary.

