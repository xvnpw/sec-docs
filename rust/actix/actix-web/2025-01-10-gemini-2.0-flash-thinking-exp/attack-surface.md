# Attack Surface Analysis for actix/actix-web

## Attack Surface: [Path Traversal via Route Parameters](./attack_surfaces/path_traversal_via_route_parameters.md)

*   **Description:** Attackers can manipulate route parameters to access files or resources outside the intended scope.
*   **How Actix Web Contributes:** Actix Web's flexible routing allows capturing path segments as parameters. If these parameters are directly used to construct file paths without proper sanitization, it creates a vulnerability.
*   **Example:** A route defined as `/files/{filename}` could be accessed with `/files/../../etc/passwd` if `filename` is used directly in `std::fs::read_to_string(filename)`.
*   **Impact:** Unauthorized access to sensitive files, potential code execution if accessed files are scripts.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Input Validation:** Sanitize and validate route parameters to ensure they conform to expected patterns and do not contain malicious sequences (e.g., `..`).
    *   **Canonicalization:** Resolve symbolic links and normalize paths to prevent traversal.
    *   **Restrict Access:** Avoid directly using route parameters to access file system resources. Use an intermediary layer with strict access controls.

## Attack Surface: [Injection Vulnerabilities via Extracted Data](./attack_surfaces/injection_vulnerabilities_via_extracted_data.md)

*   **Description:**  Untrusted data extracted from requests (path parameters, query parameters, body) is used in a context where it can be interpreted as code or commands.
*   **How Actix Web Contributes:** Actix Web provides mechanisms to easily extract data from various parts of the request. If this extracted data is not sanitized before being used in database queries or system commands, it creates an injection point.
*   **Example:**  A query parameter `search` used directly in a SQL query: `SELECT * FROM items WHERE name LIKE '%{search}%'`. An attacker could inject `%'; DROP TABLE items; --`.
*   **Impact:** Data breach, data manipulation, unauthorized access, remote code execution.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Input Sanitization and Validation:**  Thoroughly sanitize and validate all user-provided input before using it in any sensitive operations.
    *   **Parameterized Queries/Prepared Statements:** Use parameterized queries or prepared statements for database interactions to prevent SQL injection.
    *   **Context-Aware Output Encoding:** Encode output based on the context (HTML, JavaScript, etc.) to prevent cross-site scripting (XSS) attacks.
    *   **Avoid Dynamic Command Execution:**  Minimize the use of functions that execute arbitrary system commands based on user input.

## Attack Surface: [Deserialization Vulnerabilities (if using custom extractors with unsafe deserialization)](./attack_surfaces/deserialization_vulnerabilities__if_using_custom_extractors_with_unsafe_deserialization_.md)

*   **Description:**  Deserializing untrusted data can lead to arbitrary code execution if the deserialization process is vulnerable.
*   **How Actix Web Contributes:** If developers implement custom extractors that deserialize data (e.g., from request bodies) using libraries with known deserialization vulnerabilities, it introduces risk.
*   **Example:** Using a library like `serde_json` with custom deserialization logic that doesn't handle malicious input can lead to code execution.
*   **Impact:** Remote code execution, complete compromise of the application.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Avoid Deserializing Untrusted Data:** If possible, avoid deserializing data from untrusted sources.
    *   **Use Safe Deserialization Libraries:**  Choose deserialization libraries known for their security and follow best practices for their usage.
    *   **Input Validation Before Deserialization:**  Validate the structure and type of data before attempting deserialization.

## Attack Surface: [Bypassing Authentication/Authorization Middleware](./attack_surfaces/bypassing_authenticationauthorization_middleware.md)

*   **Description:**  Attackers can find ways to circumvent authentication or authorization checks, gaining unauthorized access to protected resources.
*   **How Actix Web Contributes:** Misconfiguration or incorrect ordering of Actix Web middleware can create vulnerabilities where authentication or authorization checks are not applied to certain routes or requests.
*   **Example:**  Authentication middleware is defined *after* a route handler that requires authentication, allowing unauthenticated access.
*   **Impact:** Unauthorized access to sensitive data or functionality.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Correct Middleware Ordering:** Ensure authentication and authorization middleware are registered and ordered correctly to apply to the intended routes.
    *   **Comprehensive Test Coverage:** Thoroughly test authentication and authorization logic to identify potential bypasses.
    *   **Principle of Least Privilege:** Implement authorization policies based on the principle of least privilege, granting only necessary permissions.

## Attack Surface: [File Upload Vulnerabilities (if handling file uploads directly)](./attack_surfaces/file_upload_vulnerabilities__if_handling_file_uploads_directly_.md)

*   **Description:**  Improper handling of file uploads can allow attackers to upload malicious files, leading to various attacks.
*   **How Actix Web Contributes:** Actix Web provides mechanisms to handle multipart form data, including file uploads. If developers don't implement proper validation and security measures, vulnerabilities arise.
*   **Example:**  Uploading a PHP script disguised as an image and then accessing it to execute arbitrary code on the server.
*   **Impact:** Remote code execution, defacement, data exfiltration, denial of service.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Input Validation:** Validate file types, sizes, and content based on expected values.
    *   **Sanitize Filenames:**  Sanitize uploaded filenames to prevent path traversal vulnerabilities.
    *   **Virus Scanning:** Integrate virus scanning tools to scan uploaded files for malware.
    *   **Store Files Securely:** Store uploaded files outside the web root or in a dedicated storage service with restricted access.
    *   **Content-Type Verification:** Verify the file's content type based on its magic number, not just the provided header.

