# Mitigation Strategies Analysis for unetworking/uwebsockets

## Mitigation Strategy: [Connection Limits (uWS Configuration)](./mitigation_strategies/connection_limits__uws_configuration_.md)

*   **Description:**
    1.  **Identify Resource Limits:** Determine the maximum concurrent connections your server can handle (RAM, CPU, network, OS limits).
    2.  **Configure `maxConnections`:** In your `uWS::App` or `uWS::SSLApp` configuration, set the `maxConnections` option to a value *below* your identified limits. This is a direct uWebSockets setting.
    3.  **Test:** Load test to ensure the limit is effective and doesn't negatively impact legitimate users.

*   **Threats Mitigated:**
    *   **Denial of Service (DoS):** (Severity: High) - Limits connections, preventing resource exhaustion.
    *   **Distributed Denial of Service (DDoS):** (Severity: High) - Makes DDoS more difficult by limiting the impact of each attacking node.
    *   **Resource Exhaustion:** (Severity: High) - Protects server resources.

*   **Impact:**
    *   **DoS:** Significantly reduces risk.
    *   **DDoS:** Reduces impact; server remains operational up to the limit.
    *   **Resource Exhaustion:** High impact; prevents crashes.

*   **Currently Implemented:**
    *   Example: `src/server.cpp`, `uWS::App` configuration: `maxConnections = 1000`.

*   **Missing Implementation:**
    *   Example:  The limit of 1000 might be too high; re-evaluate based on load testing.

## Mitigation Strategy: [Backpressure Handling (uWS API)](./mitigation_strategies/backpressure_handling__uws_api_.md)

*   **Description:**
    1.  **Monitor `getBufferedAmount()`:** In your WebSocket message handling, regularly call `getBufferedAmount()` on the `uWS::WebSocket` object to check the send buffer size.
    2.  **Set Thresholds:** Define "warning" and "critical" thresholds for the buffered amount.
    3.  **`pause()` and `resume()`:**
        *   If the "critical" threshold is exceeded, call `uWS::WebSocket::pause()` to stop reading from the socket.
        *   When the buffer drains below the threshold, call `uWS::WebSocket::resume()` to resume reading.  This directly uses uWebSockets' API for flow control.

*   **Threats Mitigated:**
    *   **Denial of Service (DoS):** (Severity: High) - Prevents fast clients/data floods from overwhelming buffers.
    *   **Memory Exhaustion:** (Severity: High) - Protects against excessive memory usage.
    *   **Application Instability:** (Severity: Medium) - Prevents buffer-related crashes.

*   **Impact:**
    *   **DoS:** High impact; prevents a specific DoS type.
    *   **Memory Exhaustion:** High impact; reduces risk.
    *   **Application Instability:** Medium impact; improves stability.

*   **Currently Implemented:**
    *   Example: `src/websocket_handler.cpp` checks `getBufferedAmount()` and logs warnings.

*   **Missing Implementation:**
    *   Example: `pause()` and `resume()` are *not* used.  The application doesn't actively stop reading. Thresholds need review.

## Mitigation Strategy: [Timeouts (uWS Configuration)](./mitigation_strategies/timeouts__uws_configuration_.md)

*   **Description:**
    1.  **Set `idleTimeout`:** In your `uWS::App` or `uWS::SSLApp` configuration, set the `idleTimeout` option (in seconds). This is a direct uWebSockets setting that controls how long a connection remains open without activity.
    2.  **Test and Tune:** Adjust the timeout based on your application's needs and network conditions.

*   **Threats Mitigated:**
    *   **Slowloris Attacks:** (Severity: High) - Closes connections held open by slow data sending.
    *   **Resource Exhaustion:** (Severity: Medium) - Frees resources from idle connections.
    *   **Denial of Service (DoS):** (Severity: Medium) - Mitigates Slowloris.

*   **Impact:**
    *   **Slowloris Attacks:** High impact; prevents the attack.
    *   **Resource Exhaustion:** Medium impact; reduces usage.
    *   **DoS:** Medium impact; protects against a specific type.

*   **Currently Implemented:**
    *   Example: `src/server.cpp`, `uWS::App` configuration: `idleTimeout = 60`.

*   **Missing Implementation:**
    *   Example: 60 seconds might be too long; re-evaluate.

## Mitigation Strategy: [Origin Checking (uWS API)](./mitigation_strategies/origin_checking__uws_api_.md)

*   **Description:**
    1.  **Access `Origin` Header:** In your connection handler, access the `Origin` header from the incoming request using uWebSockets' header access methods.
    2.  **Whitelist:** Compare the `Origin` value *exactly* against a hardcoded whitelist of allowed origins.
    3.  **Reject Invalid:** If the `Origin` is missing, empty, or not in the whitelist, *reject* the connection using uWebSockets' connection rejection mechanism (typically returning `false` from the connection handler).

*   **Threats Mitigated:**
    *   **Cross-Site WebSocket Hijacking (CSWSH):** (Severity: High) - Prevents control from malicious websites.

*   **Impact:**
    *   **CSWSH:** High impact; prevents the attack.

*   **Currently Implemented:**
    *   Example: `src/websocket_handler.cpp` checks the `Origin` header.

*   **Missing Implementation:**
    *   Example: The check is not strict (case-insensitive, allows subdomains).  `null` origin handling is undefined.

## Mitigation Strategy: [Message Size Limits (uWS Configuration)](./mitigation_strategies/message_size_limits__uws_configuration_.md)

*   **Description:**
    1.  **Determine Max Size:** Decide on the maximum acceptable WebSocket message size for your application.
    2.  **Configure `maxPayloadLength`:** In your `uWS::App` or `uWS::SSLApp` configuration, set the `maxPayloadLength` option (in bytes) to this limit. This is a direct uWebSockets setting.

*   **Threats Mitigated:**
    *   **Denial of Service (DoS):** (Severity: High) - Prevents large messages from exhausting memory.
    *   **Resource Exhaustion:** (Severity: High) - Protects memory.
    *   **Buffer Overflow (Potential):** (Severity: Medium) - Reduces risk.

*   **Impact:**
    *   **DoS:** High impact; prevents a specific DoS type.
    *   **Resource Exhaustion:** High impact; reduces risk.
    *   **Buffer Overflow:** Medium impact; reduces attack surface.

*   **Currently Implemented:**
    *   Example: `src/server.cpp`, `uWS::App` configuration: `maxPayloadLength = 1048576`.

*   **Missing Implementation:**
    *   Example: No limit on reassembled fragmented message size.

