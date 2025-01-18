# Attack Surface Analysis for kataras/iris

## Attack Surface: [Route Parameter Injection](./attack_surfaces/route_parameter_injection.md)

*   **Attack Surface:** Route Parameter Injection
    *   **Description:** Attackers manipulate route parameters to inject malicious data, leading to unintended actions or information disclosure.
    *   **How Iris Contributes:** Iris's routing mechanism allows defining routes with parameters (e.g., `/users/{id:uint}`). If these parameters are not properly validated and sanitized before being used in database queries or system commands, it creates an entry point for injection attacks.
    *   **Example:** An attacker crafts a URL like `/users/1' OR '1'='1` if the application directly uses the `id` parameter in an SQL query without proper sanitization.
    *   **Impact:** Data breaches, unauthorized access, potential for remote code execution depending on the context.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Input Validation:**  Thoroughly validate all route parameters against expected types and formats using Iris's built-in validators or custom validation logic.
        *   **Parameterized Queries/ORMs:** Use parameterized queries or ORMs that automatically handle escaping and prevent SQL injection.
        *   **Output Encoding:** Encode data before displaying it to prevent cross-site scripting (XSS) if the parameter is reflected in the response.

## Attack Surface: [Wildcard Route Abuse](./attack_surfaces/wildcard_route_abuse.md)

*   **Attack Surface:** Wildcard Route Abuse
    *   **Description:** Attackers exploit wildcard routes to access unintended files or directories on the server.
    *   **How Iris Contributes:** Iris supports wildcard routes (e.g., `/static/*filepath`). If the application doesn't properly sanitize or restrict the `filepath` part, attackers can use path traversal techniques to access sensitive files outside the intended `static` directory.
    *   **Example:** An attacker requests `/static/../../../../etc/passwd` to attempt to access the system's password file.
    *   **Impact:** Information disclosure, potential for configuration or source code leakage.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Strict Path Validation:** Implement robust validation on the wildcard path to ensure it stays within the intended directory. Use functions that normalize and sanitize paths.
        *   **Restrict File Access:** Configure the web server or application to restrict access to sensitive files and directories.
        *   **Consider Alternatives:** If possible, avoid using wildcard routes for serving sensitive content.

## Attack Surface: [Custom Route Handler Vulnerabilities](./attack_surfaces/custom_route_handler_vulnerabilities.md)

*   **Attack Surface:** Custom Route Handler Vulnerabilities
    *   **Description:** Vulnerabilities introduced within the custom handler functions defined for specific routes.
    *   **How Iris Contributes:** Iris provides the framework for defining and executing these handlers. While Iris itself might be secure, vulnerabilities within the developer-written handler logic are part of the application's attack surface. This includes issues like insecure deserialization, command injection, or business logic flaws.
    *   **Example:** A handler that takes user input and directly executes a system command without sanitization, allowing command injection.
    *   **Impact:** Remote code execution, data manipulation, denial of service.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Secure Coding Practices:** Follow secure coding principles when writing route handlers, including input validation, output encoding, and avoiding insecure functions.
        *   **Principle of Least Privilege:** Ensure handlers only have the necessary permissions to perform their intended tasks.
        *   **Regular Security Audits:** Conduct regular code reviews and security audits of custom route handlers.

## Attack Surface: [Template Engine Vulnerabilities (Server-Side Template Injection - SSTI)](./attack_surfaces/template_engine_vulnerabilities__server-side_template_injection_-_ssti_.md)

*   **Attack Surface:** Template Engine Vulnerabilities (Server-Side Template Injection - SSTI)
    *   **Description:** Injecting malicious code into template expressions that are then executed by the template engine.
    *   **How Iris Contributes:** Iris integrates with various template engines. If user-controlled data is directly embedded into templates without proper sanitization or escaping, it can lead to SSTI vulnerabilities.
    *   **Example:** An attacker provides input like `{{ .Execute("os.exec", "rm -rf /") }}` if the template engine allows arbitrary code execution and user input is directly used in template rendering.
    *   **Impact:** Remote code execution, allowing attackers to take full control of the server.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Avoid Passing User-Controlled Data Directly to Templates:**  Sanitize and escape user input before using it in template rendering.
        *   **Use Safe Template Rendering Practices:**  Prefer template engines with auto-escaping features enabled by default.
        *   **Restrict Template Functionality:** Limit the available functions and features within the template engine to prevent dangerous operations.

## Attack Surface: [File Serving Vulnerabilities (Path Traversal)](./attack_surfaces/file_serving_vulnerabilities__path_traversal_.md)

*   **Attack Surface:** File Serving Vulnerabilities (Path Traversal)
    *   **Description:**  Exploiting Iris's file serving capabilities to access files outside the intended directory.
    *   **How Iris Contributes:** Iris provides methods for serving static files. If the application doesn't properly sanitize the requested file path, attackers can use path traversal techniques (e.g., `..`) to access arbitrary files on the server.
    *   **Example:** An attacker requests a file using a URL like `/static/../../../../sensitive.config` to try and access a configuration file.
    *   **Impact:** Information disclosure, potential for configuration or source code leakage.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Strict Path Validation:** Implement robust validation on file paths to ensure they stay within the intended directory. Use functions that normalize and sanitize paths.
        *   **Secure File Serving Configuration:** Configure the web server or application to restrict access to sensitive files and directories.

