# Attack Surface Analysis for handlebars-lang/handlebars.js

## Attack Surface: [Server-Side Template Injection (SSTI)](./attack_surfaces/server-side_template_injection__ssti_.md)

*   **Description:** Attackers inject malicious Handlebars expressions into templates processed on the server, leading to code execution or data breaches.
*   **Handlebars.js Contribution:** Handlebars.js renders templates based on provided data. If user-controlled data is directly embedded into templates without sanitization, Handlebars will execute injected expressions. The use of triple curly braces `{{{ }}}` for unescaped output significantly increases this risk.
*   **Example:**
    *   **Scenario:** A Node.js application uses Handlebars and dynamically constructs a template string using user input: `const templateString = '<h1>Welcome, ' + userInput + '!</h1>'; const template = Handlebars.compile(templateString);`.
    *   **Attack:** An attacker inputs `{{{process.mainModule.require('child_process').execSync('whoami')}}}` as `userInput`.
    *   **Handlebars Rendering:** Handlebars compiles and executes the injected code on the server when the template is rendered.
*   **Impact:** Remote Code Execution (RCE), Server-Side Request Forgery (SSRF), data exfiltration, denial of service.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Avoid Dynamic Template Construction with User Input:**  Do not construct template strings dynamically using user input. Pre-define templates and pass data as context.
    *   **Strict Input Sanitization:**  Sanitize and validate all user inputs before using them in template context data.
    *   **Output Encoding/Escaping:**  Use double curly braces `{{ }}` for output encoding by default. Avoid triple curly braces `{{{ }}}` unless absolutely necessary and with extreme caution.
    *   **Principle of Least Privilege:** Run the application with minimal necessary privileges to limit the impact of RCE.
    *   **Regular Security Audits:**  Periodically review templates and code for potential injection vulnerabilities.

## Attack Surface: [Client-Side Template Injection (CSTI)](./attack_surfaces/client-side_template_injection__csti_.md)

*   **Description:** Attackers inject malicious Handlebars expressions into templates rendered in the user's browser, leading to Cross-Site Scripting (XSS).
*   **Handlebars.js Contribution:** Handlebars.js can be used for client-side rendering. If templates are compiled client-side using user-controlled data, or if data used in client-side templates is not properly sanitized, XSS vulnerabilities can arise.
*   **Example:**
    *   **Scenario:** A JavaScript application compiles a Handlebars template directly from user input: `const template = Handlebars.compile(userInput);`.
    *   **Attack:** An attacker inputs `<img src=x onerror=alert('XSS')>` as `userInput`.
    *   **Handlebars Rendering:** Handlebars compiles and renders the malicious HTML, executing the JavaScript alert in the user's browser.
*   **Impact:** Cross-Site Scripting (XSS), session hijacking, website defacement, redirection to malicious sites, information theft.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Avoid Client-Side Compilation with User Input:**  Do not compile templates client-side using user-provided data. Pre-compile templates server-side or during a build process.
    *   **Strict Input Sanitization:** Sanitize and validate all user inputs used in client-side template context data.
    *   **Contextual Output Encoding:** Ensure data is properly encoded for the HTML context when rendered in templates. Handlebars' default escaping with `{{ }}` helps, but verify it's sufficient.
    *   **Content Security Policy (CSP):** Implement a strong CSP to mitigate the impact of XSS by controlling resource loading sources.
    *   **Regular Security Audits:** Review client-side template usage and JavaScript code for potential XSS vulnerabilities.

## Attack Surface: [Insecure Helper Functions](./attack_surfaces/insecure_helper_functions.md)

*   **Description:** Custom Handlebars helper functions, if not implemented securely, can introduce vulnerabilities like RCE, SSRF, or XSS.
*   **Handlebars.js Contribution:** Handlebars allows developers to extend template functionality with custom helper functions. The security of the application becomes dependent on the security of these custom helpers.
*   **Example:**
    *   **Scenario:** A helper function `executeCommand` is created to run shell commands based on template arguments: `{{executeCommand command}}`. The helper uses `child_process.execSync(command)` without proper input validation.
    *   **Attack:** An attacker crafts a template using `{{executeCommand 'ls -al /'}}` or `{{executeCommand 'rm -rf /'}}` (if permissions allow).
    *   **Helper Execution:** The `executeCommand` helper executes the attacker-controlled command on the server.
*   **Impact:** Remote Code Execution (RCE), Server-Side Request Forgery (SSRF), Cross-Site Scripting (XSS), information disclosure, denial of service, depending on the helper's functionality.
*   **Risk Severity:** **High** to **Critical** (depending on helper functionality)
*   **Mitigation Strategies:**
    *   **Secure Helper Implementation:**  Implement helper functions with robust security measures.
        *   **Input Validation:**  Thoroughly validate and sanitize all inputs to helper functions. Use allow-lists where possible.
        *   **Output Encoding:**  Properly encode outputs from helpers to prevent XSS.
        *   **Secure API Usage:**  If helpers interact with external APIs or system resources, ensure secure API usage and follow security best practices.
        *   **Principle of Least Privilege:**  Limit the privileges of helper functions to the minimum necessary. Avoid operations like shell command execution in helpers if possible.
    *   **Code Review for Helpers:**  Conduct thorough security code reviews of all custom helper functions.
    *   **Use Well-Vetted Libraries:**  Prefer using well-established and security-audited libraries for common helper functionalities instead of writing custom helpers from scratch.

## Attack Surface: [Denial of Service (DoS) via Complex Templates](./attack_surfaces/denial_of_service__dos__via_complex_templates.md)

*   **Description:** Overly complex or deeply nested Handlebars templates can consume excessive server resources during compilation or rendering, leading to DoS.
*   **Handlebars.js Contribution:** Handlebars' template parsing and rendering process can be resource-intensive for complex templates, especially when combined with large datasets or computationally expensive helpers.
*   **Example:**
    *   **Scenario:** An attacker submits a request with a very large and deeply nested Handlebars template or data that causes excessive CPU and memory usage during rendering.
    *   **Attack:**  Sending a request with a crafted template containing thousands of nested loops or conditional statements, or providing extremely large datasets to be processed by the template.
    *   **Handlebars Processing:** Handlebars attempts to compile and render the complex template, consuming excessive server resources and potentially crashing the application or server.
*   **Impact:** Denial of Service (DoS), application unavailability.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Template Complexity Limits:**  Establish and enforce limits on template complexity (e.g., nesting depth, template size) during development.
    *   **Resource Limits:**  Implement resource limits (CPU, memory, request timeouts) on the server to prevent a single request from consuming excessive resources.
    *   **Rate Limiting:**  Implement rate limiting to restrict the number of requests from a single source, mitigating DoS attempts.
    *   **Template Caching:** Cache compiled templates to reduce compilation overhead for frequently used templates.
    *   **Performance Testing:**  Conduct performance testing with realistic and potentially malicious template inputs to identify and address performance bottlenecks.

