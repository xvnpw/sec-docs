# Attack Surface Analysis for tornadoweb/tornado

## Attack Surface: [Server-Side Template Injection (SSTI)](./attack_surfaces/server-side_template_injection__ssti_.md)

*   **Description:**  An attacker injects malicious code into template syntax, which is then executed on the server when the template is rendered.
    *   **How Tornado Contributes:** Tornado's template engine, if used to render user-supplied data directly without proper escaping, becomes vulnerable. The `{{ ... }}` syntax for expressions can be exploited.
    *   **Example:**  A user provides input like `{{ 7*7 }}` or more malicious code within a form field that is then rendered in a template without sanitization.
    *   **Impact:**  Remote code execution (RCE), allowing the attacker to gain full control of the server.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Developers:**
            *   **Always escape user-provided data before rendering it in templates.** Use Tornado's built-in escaping mechanisms or a dedicated templating language that enforces security by default.
            *   **Avoid allowing users to control template content or paths.**
            *   **Use a sandboxed template engine if dynamic templating with user input is absolutely necessary.**
            *   **Implement Content Security Policy (CSP) to restrict the sources from which the browser can load resources.**

## Attack Surface: [Cross-Site WebSocket Hijacking (CSWSH)](./attack_surfaces/cross-site_websocket_hijacking__cswsh_.md)

*   **Description:** An attacker on a malicious website tricks a user's browser into making a WebSocket connection to a legitimate application, allowing the attacker to send and receive messages as the user.
    *   **How Tornado Contributes:** Tornado's WebSocket handler, if not properly secured against cross-origin requests, can be targeted. The lack of built-in protection against CSRF for WebSockets makes it vulnerable.
    *   **Example:** A user is logged into a Tornado application with a WebSocket connection. They visit a malicious website that contains JavaScript to initiate a WebSocket connection to the legitimate application's endpoint.
    *   **Impact:**  Unauthorized actions performed on behalf of the user, data exfiltration, session hijacking.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developers:**
            *   **Implement origin checking in the WebSocket `open` method.** Verify the `Origin` header of the incoming connection request and reject connections from unauthorized origins.
            *   **Use a strong authentication mechanism for WebSocket connections.**
            *   **Consider using a challenge-response mechanism during the WebSocket handshake.**
            *   **Implement proper session management and tie WebSocket connections to authenticated sessions.**

## Attack Surface: [Path Traversal via Static File Handling](./attack_surfaces/path_traversal_via_static_file_handling.md)

*   **Description:** An attacker manipulates the URL to access files outside the intended static file directory.
    *   **How Tornado Contributes:**  If the `StaticFileHandler` is configured without proper safeguards, attackers can use ".." sequences in the URL to navigate the file system.
    *   **Example:**  A request like `/static/../../../../etc/passwd` could potentially expose sensitive system files if not handled correctly.
    *   **Impact:**  Exposure of sensitive files, potential for configuration disclosure, and in some cases, even code execution if executable files are accessible.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developers:**
            *   **Ensure the `path` argument to `StaticFileHandler` points to the specific directory intended for serving static files.**
            *   **Avoid constructing file paths based on user input without thorough validation and sanitization.**
            *   **Consider using a dedicated web server (like Nginx or Apache) in front of Tornado to handle static file serving, as they often have more robust security features for this purpose.**

## Attack Surface: [Parameter Injection](./attack_surfaces/parameter_injection.md)

*   **Description:**  An attacker injects malicious code or commands into application parameters, which are then processed by the backend.
    *   **How Tornado Contributes:** Tornado's request handling methods (`self.get_argument`, `self.get_arguments`) retrieve parameters. If these parameters are used directly in database queries, system commands, or other sensitive operations without sanitization, it creates an attack vector.
    *   **Example:**  A URL like `/search?query='; DROP TABLE users; --` could be used for SQL injection if the `query` parameter is directly used in a database query.
    *   **Impact:**  Data breach, data manipulation, unauthorized access, remote code execution (depending on the context of the injection).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Developers:**
            *   **Always sanitize and validate user input before using it in any backend operations.**
            *   **Use parameterized queries or prepared statements to prevent SQL injection.**
            *   **Avoid constructing system commands directly from user input. If necessary, use safe libraries and escape user-provided data.**
            *   **Implement input validation on the server-side to ensure data conforms to expected formats and constraints.**

