### High and Critical Tornado-Specific Threats

This list contains high and critical security threats that directly involve the Tornado web framework.

*   **Threat:** Asynchronous Race Condition leading to Data Corruption
    *   **Description:** An attacker might send concurrent requests designed to exploit race conditions in asynchronous code within Tornado. If developers haven't properly synchronized access to shared resources managed by Tornado's I/O loop, the order of operations might lead to data being written or read incorrectly, resulting in corrupted data.
    *   **Impact:** Data corruption, inconsistent application state, potential for unauthorized data modification.
    *   **Affected Component:** `tornado.ioloop`, `tornado.web.RequestHandler` (specifically within asynchronous methods and callbacks).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Use appropriate synchronization primitives like `asyncio.Lock`, `threading.Lock`, or `tornado.locks.Lock` to protect access to shared resources.
        *   Carefully review asynchronous code for potential race conditions, especially when dealing with shared state managed by Tornado's event loop.
        *   Employ atomic operations where possible.

*   **Threat:** WebSocket Resource Exhaustion
    *   **Description:** An attacker might open a large number of WebSocket connections to the server, leveraging Tornado's WebSocket handling to consume excessive resources (memory, CPU, file descriptors). This can lead to the server becoming unresponsive or crashing, effectively causing a denial of service.
    *   **Impact:** Denial of service, application unavailability.
    *   **Affected Component:** `tornado.websocket.WebSocketHandler`, `tornado.ioloop`.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Implement connection limits per client IP address within the Tornado application or using a reverse proxy.
        *   Set timeouts for inactive WebSocket connections handled by Tornado.
        *   Monitor server resource usage and implement alerts for unusual WebSocket connection activity.

*   **Threat:** Blocking the Tornado I/O Loop
    *   **Description:** An attacker might trigger a request that causes a synchronous, long-running operation within a Tornado request handler. This directly blocks the Tornado I/O loop, preventing the server from processing other requests efficiently and potentially leading to denial of service for other users.
    *   **Impact:** Denial of service, performance degradation for other users.
    *   **Affected Component:** `tornado.ioloop`, `tornado.web.RequestHandler`.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Avoid performing blocking operations directly within Tornado request handlers.
        *   Offload long-running tasks to background processes, threads, or asynchronous tasks using libraries like `asyncio`, ensuring they don't block the main Tornado event loop.
        *   Use non-blocking I/O operations for network requests and file access within Tornado handlers.

*   **Threat:** Server-Side Template Injection (SSTI) via Tornado Templates
    *   **Description:** If user-controlled data is directly embedded into Tornado templates without proper escaping, an attacker might inject malicious template code. When the template is rendered by Tornado's template engine, this code executes on the server, potentially allowing for remote code execution or access to sensitive information.
    *   **Impact:** Remote code execution, information disclosure, server compromise.
    *   **Affected Component:** `tornado.template.Template`.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Always escape user-provided data before rendering it in templates using appropriate escaping functions provided by `tornado.escape` (e.g., `escape()`).
        *   Avoid allowing users to directly control template code or syntax within Tornado templates.
        *   Consider using a template engine with automatic escaping enabled by default, although care must still be taken with raw output.

*   **Threat:** Insecure `cookie_secret` leading to Cookie Forgery
    *   **Description:** If the `cookie_secret` used by Tornado for signing cookies (e.g., for `xsrf_cookies` or secure cookies) is weak or predictable, an attacker might be able to forge valid cookies. This could allow them to bypass authentication managed by Tornado, perform actions as another user, or circumvent Tornado's XSRF protection.
    *   **Impact:** Authentication bypass, session hijacking, cross-site request forgery.
    *   **Affected Component:** `tornado.web.Application` (configuration), `tornado.web.RequestHandler` (cookie handling).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Generate a strong, unpredictable, and sufficiently long `cookie_secret` for the Tornado application.
        *   Store the `cookie_secret` securely and avoid hardcoding it in the application code.
        *   Rotate the `cookie_secret` periodically.

*   **Threat:** Debug Mode Enabled in Production
    *   **Description:** If Tornado's debug mode is enabled in a production environment, it can expose sensitive information like stack traces, source code snippets, and allow for interactive debugging through Tornado's built-in mechanisms. An attacker could leverage this information to understand the application's internals and identify further vulnerabilities.
    *   **Impact:** Information disclosure, aiding in further attacks, potential for remote code execution through the debugger exposed by Tornado.
    *   **Affected Component:** `tornado.web.Application` (configuration).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Ensure the `debug=False` setting is used when creating the `tornado.web.Application` instance in production environments.
        *   Avoid relying on the presence of the `X-Tornado-Version` header for security checks.