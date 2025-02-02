# Attack Surface Analysis for shopify/liquid

## Attack Surface: [Template Injection](./attack_surfaces/template_injection.md)

*   **Description:** Attackers inject malicious Liquid code into templates, gaining control over template rendering and potentially the application.
*   **Liquid Contribution:** Liquid's core functionality of parsing and executing template code is the direct enabler of this attack. Unsanitized user input incorporated into templates is interpreted as Liquid code.
*   **Example:**
    *   **Scenario:** A website uses user-provided input to dynamically generate parts of a Liquid template.
    *   **Exploit:** An attacker injects `{{ system.password }}` into the user input. If `system.password` is accessible in the Liquid context (bad practice), the password might be exposed. More complex injections can extract data, cause DoS, or potentially lead to RCE in specific environments.
*   **Impact:** Information Disclosure, Server-Side Request Forgery (SSRF) (context-dependent), Denial of Service (DoS), Potential Remote Code Execution (RCE) (in specific, misconfigured scenarios).
*   **Risk Severity:** **Critical** to **High**
*   **Mitigation Strategies:**
    *   **Strict Input Sanitization and Output Encoding:** Sanitize and validate all user inputs before incorporating them into Liquid templates. Encode output to prevent interpretation of malicious code.
    *   **Context Isolation:** Minimize data exposed in the Liquid context. Provide only necessary data and avoid sensitive or internal objects.
    *   **Template Security Review:** Regularly review templates for injection vulnerabilities, especially where user input is involved.
    *   **Content Security Policy (CSP):** Implement CSP to restrict rendered page capabilities and limit injection impact.

## Attack Surface: [Data Exposure through Context](./attack_surfaces/data_exposure_through_context.md)

*   **Description:** Sensitive data is inadvertently exposed within the Liquid rendering context, making it accessible through templates.
*   **Liquid Contribution:** Liquid's context mechanism provides access to data. Over-exposure of data in the context directly allows Liquid templates to access and reveal this information.
*   **Example:**
    *   **Scenario:** An application passes a user object with sensitive fields (e.g., internal IDs, private information) directly to the Liquid context.
    *   **Exploit:** An attacker, via template injection or by viewing accessible templates, uses Liquid syntax like `{{ user.internal_id }}` to reveal sensitive user data.
*   **Impact:** Information Disclosure of sensitive application data.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Context Data Minimization:** Carefully curate data passed to the Liquid context. Only include essential, non-sensitive data intended for template rendering.
    *   **Data Transformation and Filtering:** Transform and filter data before context injection to remove or mask sensitive information. Use view models or DTOs for templates.
    *   **Regular Context Review:** Periodically review context data to prevent unintended exposure of sensitive information.

## Attack Surface: [Server-Side Resource Consumption via Template Complexity](./attack_surfaces/server-side_resource_consumption_via_template_complexity.md)

*   **Description:** Maliciously crafted or excessively complex Liquid templates consume excessive server resources, leading to performance degradation or Denial of Service.
*   **Liquid Contribution:** Liquid's template engine processes template logic. Complex templates with nested structures directly increase processing time and resource usage during rendering.
*   **Example:**
    *   **Scenario:** An attacker can submit or inject templates.
    *   **Exploit:** Injecting a template with deeply nested loops (e.g., nested `{% for %}` loops iterating large ranges) will consume significant CPU and memory, potentially causing server slowdown or crash.
*   **Impact:** Denial of Service (DoS), Performance Degradation.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Template Complexity Limits:** Implement limits on template complexity, such as maximum loop iterations, nesting depth, or template size.
    *   **Request Timeouts:** Set timeouts for template rendering requests to prevent resource exhaustion from long-running templates.
    *   **Resource Monitoring:** Monitor server resources (CPU, memory) to detect and respond to resource exhaustion from complex templates.

## Attack Surface: [File System Access via `include` and `render` Tags (If Enabled and Misconfigured)](./attack_surfaces/file_system_access_via__include__and__render__tags__if_enabled_and_misconfigured_.md)

*   **Description:** Abuse of `include` and `render` tags to access or include arbitrary files from the server's file system, potentially leading to information disclosure or Local File Inclusion (LFI).
*   **Liquid Contribution:** Liquid's `include` and `render` tags are designed to load external templates. Misconfiguration in path handling for these tags directly enables file system access vulnerabilities.
*   **Example:**
    *   **Scenario:** An application uses `{% include template_name %}` where `template_name` is influenced by user input without proper validation.
    *   **Exploit:** An attacker provides input like `../../../../etc/passwd`. If path validation is insufficient, the `include` tag might attempt to load and render `/etc/passwd`, exposing system files.
*   **Impact:** Information Disclosure (file contents), Local File Inclusion (LFI).
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Strict Path Validation and Sanitization:** Thoroughly validate and sanitize any user input used to construct file paths for `include` and `render` tags.
    *   **Template Path Whitelisting:** Restrict allowed paths for `include` and `render` to a defined whitelist of template directories.
    *   **Avoid Dynamic Path Construction:** Minimize or eliminate dynamic template path construction based on user input. Prefer predefined template names.
    *   **Principle of Least Privilege for File System Access:** Ensure the application process running Liquid has minimal file system permissions.

