# Threat Model Analysis for tornadoweb/tornado

## Threat: [I/O Loop Blocking Denial of Service](./threats/io_loop_blocking_denial_of_service.md)

*   **Threat:** I/O Loop Blocking Denial of Service

    *   **Description:** An attacker sends a request that triggers a long-running, synchronous operation within a Tornado request handler (e.g., a large file read, a complex calculation, a blocking external API call without using Tornado's asynchronous tools). This blocks the single-threaded event loop, preventing Tornado from processing any other requests until the blocking operation completes. The attacker can repeat this to cause a sustained denial of service.
    *   **Impact:** Complete service unavailability for all users. Legitimate requests are not processed.
    *   **Affected Tornado Component:** `RequestHandler` (any handler method), `IOLoop`.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Use asynchronous operations (`await`, `gen.coroutine`, `AsyncHTTPClient`, asynchronous database drivers).
        *   Offload blocking tasks to a thread pool using `tornado.concurrent.run_on_executor` (with careful thread pool sizing and monitoring).
        *   Implement strict timeouts for all operations, especially network and database interactions.
        *   Rate-limit potentially expensive operations.
        *   Avoid synchronous file I/O in handlers; use `run_on_executor` if necessary.

## Threat: [WebSocket Connection Exhaustion DoS](./threats/websocket_connection_exhaustion_dos.md)

*   **Threat:** WebSocket Connection Exhaustion DoS

    *   **Description:** An attacker opens a large number of WebSocket connections to the Tornado server and keeps them alive (potentially sending minimal data to avoid idle timeouts). This consumes server resources (memory, file descriptors, potentially CPU), preventing legitimate users from establishing WebSocket connections or even impacting other parts of the application.
    *   **Impact:** Denial of service specifically for WebSocket functionality; potential impact on other application components due to resource exhaustion.
    *   **Affected Tornado Component:** `WebSocketHandler`.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Implement connection limits per IP address or user.
        *   Set reasonable timeouts for idle WebSocket connections using `WebSocketHandler.set_idle_connection_timeout` and `WebSocketHandler.ping_interval`.
        *   Monitor the number of active WebSocket connections.
        *   Implement authentication and authorization for WebSocket connections.
        *   Use a reverse proxy (Nginx, HAProxy) for connection management and offloading.

## Threat: [Unvalidated WebSocket Message Data Manipulation](./threats/unvalidated_websocket_message_data_manipulation.md)

*   **Threat:** Unvalidated WebSocket Message Data Manipulation

    *   **Description:** An attacker sends crafted, malicious data over an established WebSocket connection. The application does not properly validate or sanitize this data before using it, leading to potential server-side vulnerabilities.  For example, if the data is used to update database records without proper escaping, it could lead to data corruption or unauthorized data modification. If the data is used in an `eval()` call (which should *never* be done), it could lead to remote code execution.
    *   **Impact:** Data corruption, unauthorized data modification, potential remote code execution (if `eval()` or similar is used unsafely), application-specific vulnerabilities.
    *   **Affected Tornado Component:** `WebSocketHandler.on_message`.
    *   **Risk Severity:** High (potentially Critical if RCE is possible)
    *   **Mitigation Strategies:**
        *   Strictly validate the format and content of all incoming WebSocket messages (schema validation).
        *   Sanitize all data received from WebSockets before using it in any server-side operations.
        *   Implement authorization checks to ensure users can only send permitted messages.
        *   *Never* use `eval()` or similar functions on data received from WebSockets.

## Threat: [Template Injection (Tornado's Templating Engine)](./threats/template_injection__tornado's_templating_engine_.md)

*   **Threat:** Template Injection (Tornado's Templating Engine)

    *   **Description:** An attacker provides input that is used to construct a template name or is directly injected into a template without proper escaping.  If auto-escaping is disabled or bypassed, the attacker can inject arbitrary template code, which can lead to server-side code execution.
    *   **Impact:** Server-side code execution, complete server compromise.
    *   **Affected Tornado Component:** `tornado.template.Template`, `RequestHandler.render`, `RequestHandler.render_string`.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Avoid using user-supplied data to construct template names.
        *   Ensure auto-escaping is enabled (it is by default).
        *   If disabling auto-escaping, use `{% raw ... %}` and manually escape user data.
        *   Use a strict Content Security Policy (CSP).

## Threat: [Directory Traversal via `StaticFileHandler`](./threats/directory_traversal_via__staticfilehandler_.md)

*   **Threat:** Directory Traversal via `StaticFileHandler`

    *   **Description:** An attacker crafts a URL containing ".." sequences or other path manipulation characters to attempt to access files outside the intended static file directory. This is possible if `StaticFileHandler` is misconfigured or if user input is used to construct file paths without proper sanitization.
    *   **Impact:** Unauthorized access to sensitive files on the server, potential information disclosure.
    *   **Affected Tornado Component:** `tornado.web.StaticFileHandler`.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Ensure `static_path` points to a dedicated, isolated directory.
        *   Avoid using user input to construct file paths for `StaticFileHandler`.
        *   If user input is unavoidable, thoroughly sanitize it to remove ".." and other malicious characters.
        *   Use a web server (Nginx, Apache) to serve static files.

## Threat: [Weak or Predictable `cookie_secret`](./threats/weak_or_predictable__cookie_secret_.md)

*   **Threat:** Weak or Predictable `cookie_secret`

    *   **Description:** An attacker gains access to or guesses the `cookie_secret` used by the Tornado application to sign cookies.  With the secret, the attacker can forge arbitrary cookies, potentially impersonating other users or gaining elevated privileges.
    *   **Impact:** User impersonation, privilege escalation, session hijacking.
    *   **Affected Tornado Component:** `RequestHandler.set_secure_cookie`, `RequestHandler.get_secure_cookie`, Application settings (`cookie_secret`).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Use a strong, randomly generated `cookie_secret` (at least 32 bytes, preferably 64).
        *   Store the `cookie_secret` securely, *outside* of the codebase (environment variables, secrets management system).
        *   Rotate the `cookie_secret` periodically.

## Threat: [Vulnerabilities in Tornado or Dependencies](./threats/vulnerabilities_in_tornado_or_dependencies.md)

*   **Threat:** Vulnerabilities in Tornado or Dependencies

    *   **Description:** Tornado itself, or one of its dependencies, contains a security vulnerability that is publicly disclosed or discovered by an attacker.
    *   **Impact:** Varies depending on the vulnerability; could range from denial of service to remote code execution.
    *   **Affected Tornado Component:** Any.
    *   **Risk Severity:** Varies (potentially Critical)
    *   **Mitigation Strategies:**
        *   Keep Tornado and all dependencies up to date.
        *   Use a dependency vulnerability scanner.
        *   Monitor security advisories for Tornado and its dependencies.

## Threat: [Asynchronous Task Resource Exhaustion](./threats/asynchronous_task_resource_exhaustion.md)

* **Threat:** Asynchronous Task Resource Exhaustion

    * **Description:** The application launches too many concurrent asynchronous tasks (e.g., using `tornado.gen.Task` or `asyncio.ensure_future` without limits) or fails to properly close resources (database connections, file handles) within asynchronous callbacks. This leads to resource exhaustion (memory leaks, file descriptor exhaustion, connection pool exhaustion).
    * **Impact:** Denial of service, application instability.
    * **Affected Tornado Component:** `tornado.gen`, `asyncio` integration, any asynchronous handler.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * Use connection pooling with appropriate limits.
        * Implement backpressure or rate limiting for asynchronous tasks.
        * Ensure proper resource cleanup in `finally` blocks or using context managers (`async with`).
        * Monitor resource usage.
        * Use a task queue (Celery) for long-running or resource-intensive background tasks.

