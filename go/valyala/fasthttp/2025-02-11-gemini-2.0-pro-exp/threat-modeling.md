# Threat Model Analysis for valyala/fasthttp

## Threat: [Denial of Service via Large Request Body](./threats/denial_of_service_via_large_request_body.md)

*   **Threat:**  Denial of Service via Large Request Body

    *   **Description:**  An attacker sends a request with an extremely large request body.  The server attempts to allocate memory to store the entire body, potentially leading to memory exhaustion and a crash (OOM - Out of Memory).
    *   **Impact:**  Server crash or unresponsiveness due to memory exhaustion.  Denial of service for all users.
    *   **Affected Component:**  `fasthttp.Server` (request body parsing and handling).  `RequestCtx.Request.Body()` and related methods.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Set `fasthttp.Server.MaxRequestBodySize` to a reasonable limit based on the application's requirements.  This prevents `fasthttp` from allocating excessive memory for request bodies.
        *   Validate the `Content-Length` header (if present) against `MaxRequestBodySize` *before* reading the body.  Reject requests that exceed the limit.
        *   Consider using streaming techniques to process large request bodies in chunks, rather than loading the entire body into memory at once.  This is more complex but can handle very large uploads.

## Threat: [Denial of Service via Large Request Headers](./threats/denial_of_service_via_large_request_headers.md)

*   **Threat:**  Denial of Service via Large Request Headers

    *   **Description:** Similar to the large request body attack, but the attacker sends a request with excessively large headers (e.g., many custom headers, or a single header with a very long value).
    *   **Impact:**  Server crash or unresponsiveness due to memory exhaustion.  Denial of service.
    *   **Affected Component:**  `fasthttp.Server` (header parsing and handling). `RequestCtx.Request.Header` and related methods.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Set `fasthttp.Server.MaxRequestHeaderSize` to a reasonable limit. This prevents excessive memory allocation for headers.
        *   Validate the size of individual headers if custom headers are used.

## Threat: [Denial of Service via Slow Connections (Slowloris-like)](./threats/denial_of_service_via_slow_connections__slowloris-like_.md)

*   **Threat:**  Denial of Service via Slow Connections (Slowloris-like)

    *   **Description:**  An attacker opens numerous connections to the server but sends data very slowly (or not at all after the initial handshake).  This ties up server resources (connections, potentially worker threads) waiting for data that never arrives, preventing legitimate users from accessing the service.  While `fasthttp` is designed to be resistant, variations of this attack are possible.
    *   **Impact:**  Service unavailability for legitimate users.  Potential server crash if resources are completely exhausted.
    *   **Affected Component:**  `fasthttp.Server` (specifically, connection handling and timeout mechanisms).  `TCPListener` if used directly.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Configure appropriate timeouts: `fasthttp.Server.ReadTimeout`, `fasthttp.Server.WriteTimeout`, and especially `fasthttp.Server.IdleTimeout`.  These should be set to reasonable values based on expected client behavior.
        *   Monitor connection counts and durations.  Alert on unusually high numbers of long-lived connections.
        *   Use a reverse proxy (Nginx, HAProxy) in front of `fasthttp`.  The proxy can handle slow connections more efficiently and provide additional protection.
        *   Implement rate limiting (either in the application or at the proxy level) to limit the number of connections from a single IP address.

## Threat: [Denial of Service via Connection Flooding](./threats/denial_of_service_via_connection_flooding.md)

*   **Threat:**  Denial of Service via Connection Flooding

    *   **Description:**  An attacker rapidly opens and closes connections to the server, even if the requests themselves are small and valid.  This can exhaust system resources like file descriptors, preventing the server from accepting new connections.
    *   **Impact:**  Denial of service for legitimate users.  The server becomes unable to accept new connections.
    *   **Affected Component:**  `fasthttp.Server` (connection handling).  The underlying operating system's network stack.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Use operating system-level limits (e.g., `ulimit -n` on Linux) to restrict the maximum number of open file descriptors per process.
        *   Implement rate limiting (at the application or reverse proxy level) to limit the rate of new connections from a single IP address.
        *   Monitor connection rates and alert on unusually high rates.
        *   Consider using a reverse proxy that can handle connection pooling and reuse.

## Threat: [HTTP Request Smuggling (via ambiguous headers)](./threats/http_request_smuggling__via_ambiguous_headers_.md)

*   **Threat:**  HTTP Request Smuggling (via ambiguous headers)

    *   **Description:**  An attacker crafts a request with ambiguous or conflicting `Transfer-Encoding` and `Content-Length` headers.  If `fasthttp` and a frontend proxy (e.g., Nginx) interpret these headers differently, the attacker might be able to "smuggle" a second request hidden within the first, bypassing security controls.
    *   **Impact:**  Bypass of security controls (e.g., WAF, authentication).  Potential for unauthorized access to data or functionality.  Cache poisoning.
    *   **Affected Component:**  `fasthttp.Server` (header parsing, specifically handling of `Transfer-Encoding` and `Content-Length`).  Interaction with the frontend proxy.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Crucially:** Configure the reverse proxy to *reject* ambiguous requests (requests with both `Transfer-Encoding: chunked` and a `Content-Length` header).  This is the primary defense.
        *   Ensure that `fasthttp` and the reverse proxy are configured to handle these headers in a consistent manner.  Prefer using only `Transfer-Encoding: chunked` for dynamically sized responses.
        *   Thoroughly test the interaction between `fasthttp` and the proxy with a variety of malformed and ambiguous requests.  Use a fuzzer.

