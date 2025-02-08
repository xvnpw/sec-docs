# Mitigation Strategies Analysis for cesanta/mongoose

## Mitigation Strategy: [Configuration Hardening](./mitigation_strategies/configuration_hardening.md)

**Description:**
1.  **Feature Audit:**  Review the Mongoose documentation and identify all available features.  Create a list of features that are *absolutely essential* for your application.
2.  **Disable Unused Features:**  In the Mongoose configuration (using functions like `mg_disable_http_endpoint`, `mg_set_option`, etc.), explicitly disable all features that are not on your essential list.  Examples:
    *   Disable CGI if not used: `mg_set_option(ctx, "cgi_interpreter", NULL);`
    *   Disable directory listing: `mg_set_option(ctx, "enable_directory_listing", "no");`
    *   Disable specific endpoints if not needed.
3.  **Access Control Lists (ACLs):**
    *   Define ACL rules using `mg_set_option(ctx, "access_control_list", ...)` to restrict access based on IP address or network.  Examples:
        *   `"+0.0.0.0/0,-192.168.1.0/24"` (allow all except a specific subnet)
        *   `"-0.0.0.0/0,+127.0.0.1"` (allow only localhost)
    *   Test ACL rules thoroughly.
4.  **Document Root:**
    *   Create a dedicated, isolated directory *only* for web files.
    *   Set the `document_root` option *precisely* to this directory.
    *   Ensure *no* sensitive files are within or below the document root.
5.  **Custom Error Pages:**
    *   Create custom HTML files for HTTP error codes (400, 401, 403, 404, 500, etc.).
    *   Configure Mongoose to use these via `mg_set_option(ctx, "error_pages", ...)` or by handling error events.
6.  **Limit Request Methods:** Use `mg_set_request_handler` to define handlers *only* for the HTTP methods your application uses (e.g., GET, POST). Return a 405 (Method Not Allowed) for others.
7.  **Request Size Limits:**
    *   Set `request_timeout_ms` appropriately (e.g., `mg_set_option(ctx, "request_timeout_ms", "30000");`).
    *   For file uploads, handle `MG_EV_HTTP_PART_DATA` to enforce size limits.
8. **Connection Limits:** Use Mongoose options (check documentation for your version) to limit concurrent connections based on server resources.

**Threats Mitigated:**
*   **Directory Traversal (Severity: Critical):**  Improper `document_root` or directory listing allows access outside the web directory.
*   **Denial of Service (DoS) (Severity: High):**  Large requests or connections overwhelm the server. Limits mitigate this.
*   **Information Disclosure (Severity: Medium to High):**  Default error pages or directory listing reveal information.
*   **Unauthorized Access (Severity: High):**  Lack of ACLs allows unauthorized access.
*   **HTTP Method Tampering (Severity: Medium):**  Unexpected methods might exploit vulnerabilities.

**Impact:**
*   **Directory Traversal:** Risk reduction: Very High.
*   **DoS:** Risk reduction: High.
*   **Information Disclosure:** Risk reduction: High.
*   **Unauthorized Access:** Risk reduction: High.
*   **HTTP Method Tampering:** Risk reduction: Medium.

**Currently Implemented:** [Example: "`document_root` is set correctly. Directory listing is disabled. Basic ACLs for admin interface. Custom 404 page."]

**Missing Implementation:** [Example: "Need custom error pages for all codes. Request size limits are missing. Review and refine ACLs for all resources."]

## Mitigation Strategy: [WebSockets Security (If Used)](./mitigation_strategies/websockets_security__if_used_.md)

**Description:**
1.  **Origin Validation:**
    *   In the `MG_EV_WEBSOCKET_OPEN` handler, *strictly* check the `Origin` header in the `mg_http_message` structure.
    *   Compare the `Origin` against a list of *explicitly allowed* origins.  Avoid wildcards.
    *   Reject the connection (return non-zero) if the `Origin` is not allowed.
2.  **Subprotocol Negotiation:**
    *   If using WebSocket subprotocols, define supported subprotocols.
    *   In `MG_EV_WEBSOCKET_OPEN`, check the `Sec-WebSocket-Protocol` header.
    *   Reject the connection if the requested subprotocol is not supported.
3.  **Message Size Limits:**
    *   In the `MG_EV_WEBSOCKET_MSG` handler, check the message size (`hm->data.len`).
    *   If the size exceeds a limit, close the connection or take action.
4.  **Rate Limiting:**
    *   Track messages received per client within a time window.
    *   If a client exceeds a rate, close the connection or take action.  This is implemented *using* Mongoose's event handling, but the logic is application-specific.

**Threats Mitigated:**
*   **Cross-Origin WebSocket Hijacking (Severity: High):**  Origin validation prevents this.
*   **Denial of Service (DoS) (Severity: High):**  Message size limits and rate limiting mitigate this.
*   **Protocol Mismatch (Severity: Medium):**  Subprotocol validation helps.

**Impact:**
*   **Cross-Origin WebSocket Hijacking:** Risk reduction: Very High.
*   **DoS:** Risk reduction: High.
*   **Protocol Mismatch:** Risk reduction: Medium.

**Currently Implemented:** [Example: "Origin validation is implemented, but uses a wildcard. Message size limits are in place."]

**Missing Implementation:** [Example: "Replace wildcard in origin validation with explicit origins. Rate limiting is not implemented."]

## Mitigation Strategy: [SSL/TLS Configuration (If Used)](./mitigation_strategies/ssltls_configuration__if_used_.md)

**Description:**
1.  **Obtain a Valid Certificate:** Get a TLS/SSL certificate from a trusted CA (e.g., Let's Encrypt).
2.  **Configure Mongoose for HTTPS:**
    *   Set `ssl_certificate` to the certificate file path.
    *   Set `ssl_key` to the private key file path.
    *   Protect the private key file with appropriate permissions.
3.  **Cipher Suite Selection:**
    *   Use `ssl_cipher_suite` to specify *strong, modern* cipher suites. Consult resources like the Mozilla SSL Configuration Generator. Example (update regularly):
        ```
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:..."
        ```
    *   *Disable* weak or outdated ciphers (DES, RC4, MD5, weak DH).
4.  **HSTS (HTTP Strict Transport Security):**
    *   Add the `Strict-Transport-Security` header using `extra_headers` or in request handlers. Example:
        ```
        "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
        ```
    *   Set an appropriate `max-age`.
    *   Consider `includeSubDomains` and `preload`.
5.  **Certificate Validation (Client Mode):** If Mongoose acts as a client (outbound HTTPS), configure it to validate server certificates, usually with a trusted CA bundle. This is done through Mongoose's API for making client connections.
6. **Certificate Pinning (Optional, Advanced):** If used, configure Mongoose with the expected public key pins. Requires careful management.

**Threats Mitigated:**
*   **Man-in-the-Middle (MITM) Attacks (Severity: Critical):** Proper TLS prevents interception.
*   **Data Eavesdropping (Severity: Critical):** Encryption prevents eavesdropping.
*   **Data Tampering (Severity: Critical):** Encryption and integrity checks prevent tampering.
*   **Weak Cipher Attacks (Severity: High):** Strong ciphers prevent decryption.

**Impact:**
*   **MITM Attacks:** Risk reduction: Very High.
*   **Data Eavesdropping:** Risk reduction: Very High.
*   **Data Tampering:** Risk reduction: Very High.
*   **Weak Cipher Attacks:** Risk reduction: Very High.

**Currently Implemented:** [Example: "HTTPS enabled with Let's Encrypt. HSTS enabled."]

**Missing Implementation:** [Example: "Review and update cipher suite list. Certificate validation for outbound requests not implemented."]

## Mitigation Strategy: [Event Handling and Callbacks (Within Mongoose's Context)](./mitigation_strategies/event_handling_and_callbacks__within_mongoose's_context_.md)

**Description:**
1.  **Identify All Callbacks:** Review code and find all Mongoose event handlers/callbacks.
2.  **Robust Error Handling:**
    *   Within *each* callback, use `try...catch` (or equivalent) to handle errors.
    *   Log errors with context (request details, timestamp).
    *   Return appropriate error responses (HTTP status codes). Avoid exposing internal details.
3.  **Input Validation (Within Callbacks):**
    *   *Validate all data* received from Mongoose within callbacks (headers, parameters, POST data, WebSocket messages).
    *   Use appropriate validation (regex, type checks, range checks).
    *   Reject invalid data and return errors.
4.  **Avoid Blocking Operations:**
    *   Identify potentially blocking operations within callbacks (database queries, network requests, file I/O).
    *   Use asynchronous operations or worker threads to avoid blocking the Mongoose event loop. This is crucial for Mongoose's responsiveness.
5. **Code Review:** Have another developer review callback code, focusing on error handling, input validation, and blocking operations. This is a general practice, but it's *critical* within the context of Mongoose event handlers.

**Threats Mitigated:**
*   **Denial of Service (DoS) (Severity: High):** Unhandled errors or blocking operations cause unresponsiveness.
*   **Information Disclosure (Severity: Medium):** Unhandled errors can leak details.
*   **Code Injection (Severity: Critical):** Missing input validation allows injection.
*   **Various Application-Specific Vulnerabilities (Severity: Variable):** Callback errors lead to diverse issues.

**Impact:**
*   **DoS:** Risk reduction: High.
*   **Information Disclosure:** Risk reduction: Medium.
*   **Code Injection:** Risk reduction: Very High.
*   **Application-Specific Vulnerabilities:** Risk reduction: Variable.

**Currently Implemented:** [Example: "Basic error handling in most callbacks. Input validation for some data."]

**Missing Implementation:** [Example: "Add comprehensive error handling to *all* callbacks. Thorough and consistent input validation. Review for blocking operations."]

