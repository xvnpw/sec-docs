# Attack Surface Analysis for onevcat/fengniao

## Attack Surface: [HTTP Header Injection](./attack_surfaces/http_header_injection.md)

**Description:** Attackers inject malicious data into HTTP headers, potentially leading to HTTP response splitting, session hijacking, or other header-based attacks.
*   **FengNiao Contribution:** FengNiao is responsible for parsing and processing HTTP headers. Vulnerabilities in its header parsing logic or lack of proper sanitization of header values before use can directly lead to header injection vulnerabilities.
*   **Example:** An attacker sends a request with a crafted `Location` header like: `Location: http://example.com%0d%0aSet-Cookie: malicious_cookie=evil`. If FengNiao's header handling is flawed, it might not sanitize the newline characters (`%0d%0a`), leading to HTTP response splitting and the server setting a malicious cookie.
*   **Impact:**  Session hijacking, cross-site scripting (XSS) via header injection, website defacement, redirection to malicious sites.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Input Validation and Sanitization within FengNiao:**  Review and harden FengNiao's header parsing code to ensure it strictly validates and sanitizes all header values before using them in responses or internal processing. This might require patching or contributing to the FengNiao project itself.
    *   **Use Secure Header Setting Functions (FengNiao Level):**  Ensure FengNiao utilizes secure, built-in functions of the underlying HTTP library (if any) for setting response headers, which are designed to prevent injection vulnerabilities.
    *   **Regular Security Audits of FengNiao Code:** Conduct security audits specifically focusing on FengNiao's header handling implementation to identify and fix potential injection vulnerabilities.

## Attack Surface: [Path Traversal in Route Matching](./attack_surfaces/path_traversal_in_route_matching.md)

**Description:** Attackers manipulate URL paths to access files or resources outside of the intended application directory, potentially gaining access to sensitive data or executing arbitrary code.
*   **FengNiao Contribution:** FengNiao's routing mechanism maps URL paths to specific handlers. If the route matching logic within FengNiao doesn't properly sanitize or validate URL paths provided in requests, it can be vulnerable to path traversal attacks.
*   **Example:** An application uses a route like `/files/{filename}`. If FengNiao's routing logic doesn't sanitize the `filename` parameter, an attacker could send a request like `/files/../../../../etc/passwd`.  FengNiao might incorrectly route this request and attempt to access the `/etc/passwd` file if path traversal is not prevented in its routing implementation.
*   **Impact:** Unauthorized access to sensitive files, information disclosure, potential for remote code execution if combined with other vulnerabilities.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Input Validation and Sanitization within FengNiao Routing:**  Review and strengthen FengNiao's route matching code to strictly validate and sanitize URL path parameters, specifically preventing path traversal sequences like `../` or `..%2f` during route resolution. This might require patching or contributing to the FengNiao project.
    *   **Secure Path Handling in FengNiao:** Ensure FengNiao's internal path handling functions (if any are used for file serving or resource access within the framework itself) are secure and prevent traversal outside of intended directories.
    *   **Whitelisting Allowed Paths (Application Level, but related to FengNiao routing):** While primarily application-level, ensure that when using FengNiao to serve files or resources, the application logic built on top of FengNiao enforces whitelisting of allowed paths and directories, preventing access to arbitrary files even if FengNiao's routing has a minor flaw.

