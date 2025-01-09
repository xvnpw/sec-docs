# Attack Surface Analysis for tornadoweb/tornado

## Attack Surface: [Parameter Injection via `get_argument`](./attack_surfaces/parameter_injection_via__get_argument_.md)

*   **Description:** Attackers can inject malicious data into request parameters (GET or POST) that are not properly validated or sanitized when retrieved using Tornado's `get_argument`, `get_arguments`, or similar methods.
*   **How Tornado Contributes:** Tornado provides convenient methods for accessing request parameters, but it doesn't automatically sanitize or validate them. The responsibility lies with the developer.
*   **Example:** A URL like `/search?query=<script>alert("XSS")</script>` where the `query` parameter is directly used in a template without escaping.
*   **Impact:** Cross-site scripting (XSS), SQL injection (if the parameter is used in a database query), command injection (if the parameter is used in a system call), or other unintended behavior.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Input Validation:** Implement strict validation of all user-provided input based on expected data types, formats, and allowed values.
    *   **Output Encoding/Escaping:** Properly escape or encode output when rendering data in HTML templates, JSON responses, or other contexts to prevent interpretation as code. Tornado's template engine provides auto-escaping, ensure it's enabled and used correctly.
    *   **Use Prepared Statements/Parameterized Queries:** When interacting with databases, use parameterized queries or prepared statements to prevent SQL injection.

## Attack Surface: [Path Traversal in Static File Handling](./attack_surfaces/path_traversal_in_static_file_handling.md)

*   **Description:** If static file handling is enabled, attackers might manipulate the requested file path to access files outside the designated static directory.
*   **How Tornado Contributes:** Tornado provides a `StaticFileHandler` for serving static files. If not configured correctly or if user input is used to construct the file path without proper validation, it can become vulnerable.
*   **Example:** A request like `/static/../../../../etc/passwd` attempting to access a sensitive system file.
*   **Impact:** Exposure of sensitive files, configuration details, or even application source code.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Restrict Static File Directory:** Carefully define the root directory for static files and ensure it doesn't contain sensitive information.
    *   **Avoid User Input in File Paths:** Never directly use user-provided input to construct file paths for static file serving.
    *   **Canonicalization:** Canonicalize file paths to remove relative path components (like `..`) before attempting to access the file. Tornado's `StaticFileHandler` performs some basic checks, but additional validation might be necessary.

## Attack Surface: [Cross-Site WebSocket Hijacking (CSWSH)](./attack_surfaces/cross-site_websocket_hijacking__cswsh_.md)

*   **Description:** Attackers can trick a user's browser into initiating a WebSocket connection to a malicious server, potentially allowing the attacker to impersonate the user or intercept sensitive data exchanged over the WebSocket.
*   **How Tornado Contributes:** Tornado provides robust WebSocket support, but it's the developer's responsibility to implement proper origin checks and authentication for WebSocket connections.
*   **Example:** A malicious website embedding JavaScript that attempts to establish a WebSocket connection to the legitimate Tornado application's WebSocket endpoint.
*   **Impact:** Unauthorized actions performed on behalf of the user, leakage of sensitive data transmitted over the WebSocket.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Origin Checks:** Implement server-side validation of the `Origin` header during the WebSocket handshake to only allow connections from trusted domains. Tornado provides mechanisms to access the `Origin` header.
    *   **CSRF Prevention for WebSocket Handshake:** Employ CSRF tokens or other mechanisms to protect the initial HTTP handshake that upgrades to a WebSocket connection.
    *   **Authentication and Authorization:** Implement proper authentication and authorization mechanisms for WebSocket connections to ensure only authorized users can interact with the endpoint.

## Attack Surface: [Server-Side Template Injection (SSTI)](./attack_surfaces/server-side_template_injection__ssti_.md)

*   **Description:** If user-controlled input is directly embedded into Tornado templates without proper sanitization or if unsafe template constructs are used, attackers can inject malicious code that is executed on the server.
*   **How Tornado Contributes:** Tornado's template engine, while generally safe with auto-escaping enabled, can become vulnerable if developers bypass escaping or use advanced features without understanding the security implications.
*   **Example:** Using `{{ handler.settings["secret_key"] }}` in a template if `handler.settings` is influenced by user input, potentially revealing sensitive server-side configuration.
*   **Impact:** Remote code execution, allowing attackers to gain full control of the server.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strict Template Escaping:** Ensure auto-escaping is enabled and active for all template rendering. Be extremely cautious when using `{% raw %}` or other mechanisms that disable escaping.
    *   **Avoid User Input in Template Logic:** Minimize the use of user-provided input directly within template logic.
    *   **Secure Template Context:** Carefully control the variables and objects passed to the template context to prevent access to sensitive or dangerous attributes and methods.
    *   **Template Sandboxing (Advanced):** In highly sensitive applications, consider using a more restrictive template engine or implementing custom sandboxing measures.

