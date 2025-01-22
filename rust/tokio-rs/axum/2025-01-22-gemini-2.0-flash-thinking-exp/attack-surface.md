# Attack Surface Analysis for tokio-rs/axum

## Attack Surface: [Route Parameter Path Traversal](./attack_surfaces/route_parameter_path_traversal.md)

### 1. Route Parameter Path Traversal

*   **Description:** Attackers exploit vulnerabilities in how Axum applications handle route parameters to access files or directories outside the intended scope on the server's file system. Axum's routing system, if not used carefully, can directly contribute to this by allowing path parameters to be used in file path construction without sufficient validation.
*   **How Axum contributes to the attack surface:** Axum's routing mechanism allows capturing path parameters which handlers might directly use. Lack of built-in sanitization in Axum's routing for path parameters means developers must implement this manually, and omissions lead to this vulnerability.
*   **Example:** A route `/files/{filepath}` in an Axum application. A handler uses the `filepath` parameter to read a file. An attacker crafts a request like `/files/../../etc/passwd`. Without validation, Axum passes `../../etc/passwd` to the handler, potentially allowing access to `/etc/passwd`.
*   **Impact:** Unauthorized access to sensitive files, configuration files, source code, or potential Remote Code Execution if combined with file upload or other vulnerabilities.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Strict Input Validation:**  Validate route parameters within handlers to ensure they are safe and do not contain path traversal sequences like `..`.
    *   **Path Sanitization:** Use secure path manipulation functions to normalize and sanitize paths derived from route parameters before file system operations.
    *   **Avoid Direct File Path Construction:**  Prefer indirect file access methods, such as using an index or database lookup to map user-provided identifiers to safe file paths, instead of directly constructing paths from route parameters.

## Attack Surface: [Deserialization of Untrusted Data](./attack_surfaces/deserialization_of_untrusted_data.md)

### 2. Deserialization of Untrusted Data

*   **Description:** Attackers send malicious data in request bodies (JSON, Form, Query) that, when automatically deserialized by Axum's extractors, leads to code execution, denial of service, or other critical security breaches. Axum's extractors directly facilitate this by automatically deserializing data.
*   **How Axum contributes to the attack surface:** Axum's `Json`, `Form`, and `Query` extractors simplify data handling by automatically deserializing request payloads. This convenience becomes an attack surface if applications deserialize untrusted data without subsequent validation, as vulnerabilities in deserialization libraries or the target data structures can be exploited.
*   **Example:** An Axum handler uses `Json<User>` to extract JSON data into a `User` struct. An attacker sends a crafted JSON payload designed to exploit a deserialization vulnerability in `serde_json` (used by Axum) or the `User` struct's deserialization logic, potentially achieving Remote Code Execution.
*   **Impact:** Remote Code Execution (RCE), Denial of Service (DoS), data corruption, information disclosure, depending on the nature of the deserialization vulnerability.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Post-Deserialization Validation:**  Always validate deserialized data *after* extraction and *before* using it in application logic. Implement robust validation rules to enforce expected data formats and constraints.
    *   **Schema Validation:** Define and enforce strict schemas for expected data formats to limit the attack surface and ensure only valid data is processed.
    *   **Regular Dependency Updates:** Keep `serde`, `serde_json`, `serde_urlencoded`, and other deserialization-related dependencies updated to patch known vulnerabilities.
    *   **Consider Safer Data Handling:** For highly sensitive applications, consider alternative data handling approaches that minimize automatic deserialization of complex structures from untrusted sources, potentially using more manual parsing and validation.

## Attack Surface: [Middleware Ordering and Security Bypass](./attack_surfaces/middleware_ordering_and_security_bypass.md)

### 3. Middleware Ordering and Security Bypass

*   **Description:** Incorrect ordering of Axum middleware can lead to critical security middleware being bypassed, allowing unauthorized access to protected resources or bypassing essential security checks. Axum's middleware system's order-dependent execution is the core of this attack surface.
*   **How Axum contributes to the attack surface:** Axum's middleware pipeline executes middleware in the order they are added. Misconfiguration of this order, especially placing security middleware after content-serving or action-performing middleware, directly creates a bypass vulnerability.
*   **Example:** Authentication middleware is configured *after* middleware that serves static files in an Axum application. An attacker can directly request a protected static file. Because the static file middleware executes first, it serves the file before authentication is checked, bypassing the intended security control.
*   **Impact:** Authentication bypass, authorization bypass, access to sensitive data and functionality, potentially leading to full compromise of protected resources.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Careful Middleware Ordering Design:**  Thoroughly plan and document the intended middleware execution order. Ensure security-critical middleware (authentication, authorization, rate limiting, input sanitization) is always placed *before* middleware that handles requests or serves content that needs protection.
    *   **Explicit Middleware Configuration Review:** Regularly review Axum application's middleware configuration to verify the correct order and ensure no accidental bypasses are introduced during development or updates.
    *   **Automated Integration Tests:** Implement integration tests that specifically verify middleware behavior and confirm that security middleware is correctly applied to all intended routes and that bypasses are not possible.

## Attack Surface: [Information Disclosure in Error Responses (Potentially High Severity)](./attack_surfaces/information_disclosure_in_error_responses__potentially_high_severity_.md)

### 4. Information Disclosure in Error Responses (Potentially High Severity)

*   **Description:**  Axum applications, if not configured carefully, might expose detailed error messages in responses, especially in production. These messages can leak sensitive information about the application's internal workings, dependencies, or configuration, aiding attackers in reconnaissance and further attacks. While often Medium severity, if sensitive data is leaked, it can escalate to High.
*   **How Axum contributes to the attack surface:** Axum's default error handling or custom error handlers, if not designed with security in mind, can inadvertently return verbose error details.  The framework's flexibility in error handling means developers must explicitly implement secure error response strategies.
*   **Example:** A database connection error occurs in an Axum handler. The default or a poorly configured custom error handler returns a response to the client that includes the database connection string, internal server paths, or stack traces revealing application structure and dependencies.
*   **Impact:** Information leakage, aiding attacker reconnaissance, potentially revealing vulnerabilities, configuration details, or internal paths that can be exploited in further attacks. Can escalate to High severity if sensitive credentials or system information is leaked.
*   **Risk Severity:** High (in scenarios with sensitive information leakage)
*   **Mitigation Strategies:**
    *   **Production-Specific Error Handling:** Implement custom error handlers specifically for production environments. These handlers should log detailed errors securely server-side but return generic, user-friendly error messages to clients, avoiding sensitive details in responses.
    *   **Generic Error Responses for Clients:** In production, return generic error messages (e.g., "Internal Server Error") without specific details. Use appropriate HTTP status codes to indicate error categories.
    *   **Secure Error Logging:**  Log detailed error information securely on the server-side for debugging and monitoring. Ensure logs are protected from unauthorized access and are not exposed in client responses.
    *   **Configuration Security:** Avoid hardcoding sensitive information in code. Use environment variables or secure configuration management to prevent accidental leakage in error messages or code.

