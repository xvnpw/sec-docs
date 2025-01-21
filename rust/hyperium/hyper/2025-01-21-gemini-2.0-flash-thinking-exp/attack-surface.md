# Attack Surface Analysis for hyperium/hyper

## Attack Surface: [Oversized HTTP Headers](./attack_surfaces/oversized_http_headers.md)

*   **Description:** An attacker sends HTTP requests with excessively large headers.
    *   **How Hyper Contributes:** Hyper is responsible for parsing and processing these headers. If not configured with appropriate limits, it can consume excessive memory or processing time.
    *   **Example:** Sending a request with a header like `X-Very-Long-Header: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`.
    *   **Impact:** Denial of Service (DoS) due to resource exhaustion (memory or CPU).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developers:** Configure `hyper`'s `Http` builder with appropriate limits for maximum header size using methods like `max_header_size`.

## Attack Surface: [Oversized Request Body](./attack_surfaces/oversized_request_body.md)

*   **Description:** An attacker sends HTTP requests with excessively large bodies.
    *   **How Hyper Contributes:** Hyper is responsible for reading and buffering the request body. Without proper limits, this can lead to memory exhaustion.
    *   **Example:** Sending a `POST` request with a multi-gigabyte payload.
    *   **Impact:** Denial of Service (DoS) due to memory exhaustion.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developers:** Configure `hyper`'s server builder with a limit on the maximum request body size using methods like `max_body_size`.

## Attack Surface: [Connection Limit Exhaustion](./attack_surfaces/connection_limit_exhaustion.md)

*   **Description:** An attacker opens a large number of connections to the server, exhausting available resources.
    *   **How Hyper Contributes:** Hyper manages the underlying TCP connections. If not configured with appropriate limits, it can be overwhelmed by excessive connection attempts.
    *   **Example:** A botnet sending a flood of connection requests to the server.
    *   **Impact:** Denial of Service (DoS) as the server becomes unable to accept new connections.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developers:** Configure `hyper`'s server builder with limits on the maximum number of concurrent connections.

## Attack Surface: [Slowloris Attacks (Connection Holding)](./attack_surfaces/slowloris_attacks__connection_holding_.md)

*   **Description:** An attacker slowly sends partial HTTP requests, keeping many connections open and exhausting server resources.
    *   **How Hyper Contributes:** Hyper maintains these connections while waiting for the complete request. If timeouts are not configured properly, these connections can be held open indefinitely.
    *   **Example:** Sending a `GET` request but sending headers and the final newline character very slowly.
    *   **Impact:** Denial of Service (DoS) due to the server being unable to handle legitimate requests.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developers:** Configure aggressive timeouts for connection inactivity and request completion in `hyper`s server builder.

