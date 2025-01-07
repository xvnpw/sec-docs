# Attack Surface Analysis for fastify/fastify

## Attack Surface: [Unsanitized Route Parameters leading to Injection or Authorization Bypass](./attack_surfaces/unsanitized_route_parameters_leading_to_injection_or_authorization_bypass.md)

*   **Attack Surface:** Unsanitized Route Parameters leading to Injection or Authorization Bypass
    *   **Description:**  Attackers can manipulate route parameters to inject malicious data or bypass authorization checks if these parameters are not properly validated and sanitized before being used in application logic.
    *   **How Fastify Contributes:** Fastify's routing mechanism allows for defining routes with parameters. If developers directly use these parameters without sanitization, they create an entry point for attacks.
    *   **Example:** A route defined as `/users/:id` where the `id` parameter is used directly in a database query without validation. An attacker could send a request like `/users/admin'--` to potentially bypass authorization or execute malicious SQL (if database interaction is involved).
    *   **Impact:** Unauthorized access to resources, data manipulation, potential for further exploitation like SQL injection (if backend interaction is flawed).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Utilize Fastify's schema validation (`@fastify/swagger`, `@fastify/ajv`) to enforce expected data types and formats for route parameters.
        *   Sanitize route parameters before using them in any sensitive operations.
        *   Implement proper authorization checks within route handlers, independent of route parameters.
        *   Use parameterized queries or ORM features that automatically handle input sanitization when interacting with databases.

## Attack Surface: [Body Parsing Vulnerabilities (Prototype Pollution)](./attack_surfaces/body_parsing_vulnerabilities__prototype_pollution_.md)

*   **Attack Surface:** Body Parsing Vulnerabilities (Prototype Pollution)
    *   **Description:**  Maliciously crafted JSON or other data formats in the request body can inject properties into the `Object.prototype` or other shared prototypes, potentially leading to application-wide vulnerabilities.
    *   **How Fastify Contributes:** Fastify uses body-parser plugins to handle different content types. While it defaults to secure options (`secure-json-parse`), custom or misconfigured parsers can introduce vulnerabilities.
    *   **Example:** Sending a JSON payload like `{"__proto__": {"isAdmin": true}}` to an endpoint. If the body parser is vulnerable, this could add an `isAdmin` property to all objects, potentially granting unauthorized access.
    *   **Impact:**  Privilege escalation, denial of service, information disclosure, and other unpredictable behavior depending on how the polluted prototype is used.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Stick to Fastify's default body parsers (`secure-json-parse`).
        *   Carefully review and audit any custom body parsers used.
        *   Consider using libraries that offer protection against prototype pollution.
        *   Freeze or seal objects where possible to prevent modification of their prototypes.

## Attack Surface: [Unprotected Static File Serving (Directory Traversal)](./attack_surfaces/unprotected_static_file_serving__directory_traversal_.md)

*   **Attack Surface:** Unprotected Static File Serving (Directory Traversal)
    *   **Description:**  If the static file serving plugin (`@fastify/static`) is not configured correctly, attackers might be able to access files outside the intended public directory.
    *   **How Fastify Contributes:** Fastify provides the `@fastify/static` plugin for easily serving static files. Misconfiguration of the `root` option can lead to vulnerabilities.
    *   **Example:**  If the `root` is set to the application's root directory, an attacker could send a request like `/../../../../etc/passwd` to access sensitive system files.
    *   **Impact:**  Exposure of sensitive application code, configuration files, or even system files.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Ensure the `root` option in `@fastify/static` points to the specific directory containing only the intended public files.
        *   Avoid using overly permissive paths in the `prefix` option.
        *   Consider using a dedicated CDN for serving static assets instead of relying solely on the application server.

## Attack Surface: [Server-Side Request Forgery (SSRF) through User-Controlled URLs](./attack_surfaces/server-side_request_forgery__ssrf__through_user-controlled_urls.md)

*   **Attack Surface:** Server-Side Request Forgery (SSRF) through User-Controlled URLs
    *   **Description:** If the application makes requests to external URLs based on user input without proper validation, attackers can force the server to make requests to internal or arbitrary external resources.
    *   **How Fastify Contributes:** While Fastify itself doesn't directly *cause* SSRF, its role in handling requests and potentially forwarding or using user-provided URLs in backend logic creates the opportunity for this vulnerability.
    *   **Example:** An API endpoint that takes a URL as input to fetch remote content. An attacker could provide a URL to an internal service (e.g., `http://localhost:6379`) to interact with it, potentially exposing sensitive data or functionality.
    *   **Impact:** Access to internal services, data exfiltration, denial of service against internal or external systems.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Strictly validate and sanitize user-provided URLs.
        *   Use an allow-list of permitted domains or protocols.
        *   Avoid directly using user input in network requests.
        *   Implement proper network segmentation to limit the impact of SSRF.

