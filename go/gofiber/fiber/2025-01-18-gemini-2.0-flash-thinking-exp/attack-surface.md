# Attack Surface Analysis for gofiber/fiber

## Attack Surface: [Route Parameter Injection](./attack_surfaces/route_parameter_injection.md)

*   **Description:** Attackers manipulate route parameters (e.g., `/users/:id`) to inject malicious data, leading to unintended actions or information disclosure.
    *   **How Fiber Contributes to the Attack Surface:** Fiber's routing mechanism allows defining dynamic parameters, and the `c.Params()` method provides direct access to these values. If not sanitized, these values can be directly used in database queries or other sensitive operations.
    *   **Example:** A route defined as `/users/:id` might be accessed with `/users/1; DELETE FROM users; --`. If the `id` parameter is directly used in a SQL query without sanitization, it could lead to SQL injection.
    *   **Impact:** Data breach, data manipulation, unauthorized access, potential for remote code execution depending on the context of the injection.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Input Validation:** Implement strict validation on route parameters to ensure they conform to the expected format and data type.
        *   **Parameterized Queries/ORMs:** Use parameterized queries or Object-Relational Mappers (ORMs) that automatically handle escaping and prevent SQL injection.
        *   **Avoid Direct Use in Sensitive Operations:**  Sanitize and validate parameters before using them in database queries, system commands, or other critical operations.

## Attack Surface: [Reflected Cross-Site Scripting (XSS) via Response Data](./attack_surfaces/reflected_cross-site_scripting__xss__via_response_data.md)

*   **Description:** User-provided data in requests is directly echoed back in the response without proper sanitization, allowing attackers to inject malicious scripts that execute in the victim's browser.
    *   **How Fiber Contributes to the Attack Surface:** Fiber's context object provides easy access to request data (e.g., `c.Query()`, `c.Params()`, `c.Body()`). If this data is directly included in the response without encoding, it creates an XSS vulnerability.
    *   **Example:** A search functionality might echo the search term back to the user. If the search term contains malicious JavaScript (e.g., `<script>alert('XSS')</script>`), it will be executed in the user's browser.
    *   **Impact:** Account takeover, session hijacking, defacement, redirection to malicious sites.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Output Encoding:** Always encode user-provided data before including it in HTML responses. Use context-aware encoding (e.g., HTML escaping for HTML content, JavaScript escaping for JavaScript content).
        *   **Content Security Policy (CSP):** Implement a strong CSP to restrict the sources from which the browser can load resources, mitigating the impact of XSS attacks.
        *   **Avoid Direct Reflection:** If possible, avoid directly reflecting user input in the response. If necessary, sanitize and encode it rigorously.

## Attack Surface: [Path Traversal in Static File Serving](./attack_surfaces/path_traversal_in_static_file_serving.md)

*   **Description:** Attackers manipulate file paths to access files outside the intended directory when using Fiber's static file serving capabilities.
    *   **How Fiber Contributes to the Attack Surface:** Fiber's `app.Static()` middleware serves static files from a specified directory. If not configured carefully, attackers can use relative paths (e.g., `../../sensitive.txt`) to access files outside the designated static directory.
    *   **Example:** If the static directory is set to `./public`, an attacker might request `/../../../../etc/passwd` to access the server's password file.
    *   **Impact:** Exposure of sensitive files, potential for configuration leaks, and in some cases, remote code execution if executable files are accessible.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Avoid Serving Sensitive Files:** Ensure that the static directory only contains publicly accessible files.
        *   **Restrict Access with Web Server Configuration:** If possible, configure the underlying web server (e.g., Nginx, Apache) to handle static file serving with stricter access controls.
        *   **Careful Configuration of `app.Static()`:** Ensure the root directory for static files is correctly configured and that there are no vulnerabilities in how Fiber handles file paths.

