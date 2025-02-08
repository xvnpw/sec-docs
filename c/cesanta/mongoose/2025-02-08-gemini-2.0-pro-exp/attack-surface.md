# Attack Surface Analysis for cesanta/mongoose

## Attack Surface: [Unintended Network Exposure](./attack_surfaces/unintended_network_exposure.md)

*   **Description:** The application listens on unintended network interfaces or ports due to Mongoose's default binding behavior or misconfiguration.
*   **Mongoose Contribution:** Mongoose, by default, may bind to all interfaces (0.0.0.0) if not explicitly configured using `mg_bind_opt()` or `mg_bind()`. It also supports multiple protocols, any of which could be unintentionally enabled.
*   **Example:** A developer uses `mg_bind(&mgr, "8080", ev_handler);` without specifying an IP address. The application becomes accessible on all network interfaces, including public ones.
*   **Impact:** Unauthorized access to the application, data breaches, remote code execution.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Explicit Binding:** *Always* use `mg_bind_opt()` or `mg_bind()` with a specific, trusted IP address (e.g., `127.0.0.1` for localhost) and port: `mg_bind_opt(&mgr, "127.0.0.1:8080", ev_handler, opts);`.  Never rely on the default binding behavior.
    *   **Protocol Disablement:** Explicitly disable any protocols (HTTP, HTTPS, WebSocket, MQTT) not required by the application.  Carefully review event handlers to ensure only necessary protocols are active.
    *   **Firewall:** Use a firewall to restrict access to the Mongoose port.

## Attack Surface: [Buffer Overflow in Request Handling](./attack_surfaces/buffer_overflow_in_request_handling.md)

*   **Description:** An attacker sends a crafted HTTP request with excessively long headers, URL, or body data, causing a buffer overflow in Mongoose's internal parsing routines.
*   **Mongoose Contribution:** Mongoose is directly responsible for parsing all incoming HTTP requests. Vulnerabilities in its C code can lead to buffer overflows.
*   **Example:** An attacker sends an HTTP request with a URL containing thousands of characters, exceeding Mongoose's internal buffer for URL processing, leading to memory corruption.
*   **Impact:** Remote code execution, denial of service, application crash.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Update Mongoose:** *Always* use the latest stable version of Mongoose to benefit from security patches. This is the most crucial mitigation.
    *   **Input Validation (within Mongoose context):** While general input validation is important, focus on limits *within* Mongoose's control:
        *   **`request_size_limit`:** Use `mg_set_option(nc->mgr, "request_size_limit", "10240");` (example: 10KB limit) to limit the overall request size.
        *   **Header Checks (in event handler):** Within your event handler (e.g., `MG_EV_HTTP_REQUEST`), check the lengths of individual headers using `mg_get_http_header()` and reject requests with excessively long headers *before* further processing.
    *   **Fuzzing:** Use fuzzing tools specifically targeting Mongoose's HTTP parsing capabilities.
    *   **Memory Safety Tools:** Use AddressSanitizer (ASan) or Valgrind during development and testing.

## Attack Surface: [Denial of Service (DoS) via Resource Exhaustion](./attack_surfaces/denial_of_service__dos__via_resource_exhaustion.md)

*   **Description:** An attacker overwhelms Mongoose with requests, exhausting its resources (connections, threads, memory).
*   **Mongoose Contribution:** Mongoose has finite resources, and its connection handling and request processing are directly susceptible to DoS attacks.
*   **Example:** An attacker uses a tool to send a flood of SYN requests or slowly sends HTTP headers (Slowloris), tying up Mongoose's connection pool.
*   **Impact:** Application unavailability.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Connection Limits:** Use `mg_set_option` to configure:
        *   `"num_threads"`:  Indirectly limits the number of concurrent connections Mongoose can handle.  Choose a reasonable value based on expected load and available resources.
        *   `"max_connections"`: If available in your Mongoose version, directly limit the maximum number of connections.
    *   **Request Timeouts:**  *Crucially*, use `mg_set_option` with `"request_timeout_ms"` to set a reasonable timeout for requests.  This prevents slow clients (like in a Slowloris attack) from holding connections open indefinitely.  Example: `mg_set_option(nc->mgr, "request_timeout_ms", "5000");` (5-second timeout).
    *   **Rate Limiting (within event handler):** Implement basic rate limiting *within* your Mongoose event handler.  For example, track the number of requests from each IP address within a time window and reject excessive requests.  This is *Mongoose-specific* mitigation.
    * **Resource Monitoring:** Monitor Mongoose's resource usage.

## Attack Surface: [Directory Traversal (when using Mongoose's file serving)](./attack_surfaces/directory_traversal__when_using_mongoose's_file_serving_.md)

*   **Description:** An attacker uses `../` in a URL to access files outside the configured document root.
*   **Mongoose Contribution:** This vulnerability is *directly* related to Mongoose's built-in file serving functionality (`mg_serve_http` and related functions).
*   **Example:** If the document root is `/var/www/html`, an attacker requests `/../../etc/passwd`.
*   **Impact:** Unauthorized access to sensitive files.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Secure Document Root:** Use `mg_set_option(nc->mgr, "document_root", "/path/to/safe/webroot");` to set a *dedicated* and restricted document root that *does not* contain any sensitive files or system directories.
    *   **Avoid Custom File Handling:** *Rely* on Mongoose's built-in `mg_serve_http` function for serving static files.  Do *not* implement custom file handling logic that might introduce vulnerabilities.  `mg_serve_http` is designed to handle directory traversal safely *if* the document root is configured correctly.
    * **Input validation (if absolutely necessary):** If, for a very specific and well-justified reason, you *must* handle file paths based on user input (strongly discouraged), use `mg_vcmp` to compare paths and ensure they are within the document root. Reject any path containing `../` or absolute paths.

## Attack Surface: [Cross-Site WebSocket Hijacking (CSWSH) (if using Mongoose's WebSockets)](./attack_surfaces/cross-site_websocket_hijacking__cswsh___if_using_mongoose's_websockets_.md)

*   **Description:** An attacker establishes a WebSocket connection from a malicious origin, bypassing the same-origin policy.
*   **Mongoose Contribution:** Mongoose's WebSocket implementation must include proper origin validation to prevent this.
*   **Example:** A malicious website establishes a WebSocket connection to a Mongoose server running on a user's local network without proper origin checks.
*   **Impact:** Unauthorized access to WebSocket functionality, data manipulation.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Origin Validation (in event handler):** *Crucially*, within the `MG_EV_WEBSOCKET_HANDSHAKE_REQUEST` event handler, check the `Origin` header and compare it to a *whitelist* of allowed origins.  Reject connections from any other origin.  This is a *Mongoose-specific* mitigation, as it's implemented within the Mongoose event loop.
    *   **Secure WebSockets (wss://):** Use `wss://` (with properly configured SSL/TLS certificates in Mongoose) to encrypt the WebSocket connection.

