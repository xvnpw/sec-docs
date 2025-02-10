# Mitigation Strategies Analysis for gorilla/websocket

## Mitigation Strategy: [Strict Origin Checking](./mitigation_strategies/strict_origin_checking.md)

**Description:**
1.  **Identify Allowed Origins:** Determine the exact, fully qualified domains (including protocol and port, if necessary) that are permitted to establish WebSocket connections.  Avoid wildcards.  Examples: `https://yourdomain.com`, `https://api.yourdomain.com:8443`.
2.  **Implement `CheckOrigin`:** Use the `websocket.Upgrader`'s `CheckOrigin` field. Set it to a function.
3.  **Whitelist Logic:** Inside the `CheckOrigin` function:
    *   Get the `Origin` header from the `http.Request`.
    *   Compare the `Origin` against your allowed origins.
    *   Return `true` if allowed, `false` otherwise. Return `false` if the `Origin` header is *missing*.
4.  **Configuration:** Store allowed origins in a configuration file or environment variables. The `CheckOrigin` function should read this.
5.  **Testing:** Test with valid, invalid, and missing `Origin` headers.

*   **Threats Mitigated:**
    *   **Cross-Site WebSocket Hijacking (CSWSH):** (Severity: High) - Prevents WebSocket connections from malicious sites.
    *   **Unauthorized Access:** (Severity: High) - Limits connections to authorized origins.

*   **Impact:**
    *   **CSWSH:** Risk reduced to near zero with correct implementation.
    *   **Unauthorized Access:** Significantly reduces unauthorized connections.

*   **Currently Implemented:**  [ *Example: Yes, in `websocket/handler.go`, function `handleConnection`* ]

*   **Missing Implementation:** [ *Example: Origins are hardcoded; move to config file.* ]

## Mitigation Strategy: [Connection Limits (Global and Per-IP)](./mitigation_strategies/connection_limits__global_and_per-ip_.md)

**Description:**
1.  **Global Limit:**
    *   Determine a maximum number of *concurrent* WebSocket connections.
    *   Use an atomic counter to track active connections.
    *   Before accepting, check the global limit. Reject if exceeded (e.g., HTTP 503).
2.  **Per-IP Limit:**
    *   Determine a maximum number of connections *per IP address*.
    *   Use a data structure (e.g., a map) to track connections per IP.
    *   Before accepting, check the per-IP limit. Reject if exceeded.
    *   Consider `golang.org/x/time/rate` for advanced rate limiting.
3.  **Reverse Proxy (Recommended):** Configure connection limits in your reverse proxy (Nginx, HAProxy) to offload management.

*   **Threats Mitigated:**
    *   **Denial of Service (DoS):** (Severity: High) - Limits connections, preventing resource exhaustion.
    *   **Resource Exhaustion:** (Severity: High) - Protects server resources.

*   **Impact:**
    *   **DoS:** Significantly reduces the impact of connection-based DoS.
    *   **Resource Exhaustion:** Prevents crashes due to excessive connections.

*   **Currently Implemented:** [ *Example: Per-IP limits in `websocket/limiter.go`. No global limits.* ]

*   **Missing Implementation:** [ *Example: Implement global limits. Consider a better rate-limiting library.* ]

## Mitigation Strategy: [Read/Write Deadlines](./mitigation_strategies/readwrite_deadlines.md)

**Description:**
1.  **Set Read Deadline:** After establishing a connection (`conn`), use `conn.SetReadDeadline(time.Now().Add(timeout))`. Choose an appropriate `timeout`.
2.  **Set Write Deadline:** Use `conn.SetWriteDeadline(time.Now().Add(timeout))`. 
3.  **Handle Deadline Errors:** In read/write loops, check for deadline errors (`net.Error` with `Timeout() == true`). Close the connection on error.
4.  **Dynamic Adjustment (Optional):** Adjust deadlines based on activity or network conditions.

*   **Threats Mitigated:**
    *   **Slowloris Attacks:** (Severity: Medium) - Prevents slow data sending.
    *   **Idle Connection Resource Consumption:** (Severity: Medium) - Frees resources from inactive connections.
    *   **Dead Connections:** (Severity: Low) - Detects and closes broken connections.

*   **Impact:**
    *   **Slowloris:** Mitigates Slowloris attacks.
    *   **Idle Connections:** Reduces resource consumption.
    *   **Dead Connections:** Improves stability.

*   **Currently Implemented:** [ *Example: Read deadlines in `websocket/handler.go`, `readLoop`. No write deadlines.* ]

*   **Missing Implementation:** [ *Example: Implement write deadlines. Make deadlines configurable.* ]

## Mitigation Strategy: [Message Size Limits](./mitigation_strategies/message_size_limits.md)

**Description:**
1.  **Determine Maximum Size:** Decide on a maximum message size (in bytes).
2.  **Set Read Limit:** Before the read loop, use `conn.SetReadLimit(maxSize)`.
3.  **Handle Limit Exceeded:** If a message is too large, `ReadMessage` returns `websocket.ErrReadLimit`. Close the connection.

*   **Threats Mitigated:**
    *   **Memory Exhaustion (DoS):** (Severity: High) - Prevents large messages from consuming memory.
    *   **Buffer Overflow (Potentially):** (Severity: High, but less likely in Go)

*   **Impact:**
    *   **Memory Exhaustion:** Prevents memory exhaustion attacks.
    *   **Buffer Overflow:** Reduces the (low) risk.

*   **Currently Implemented:** [ *Example: `SetReadLimit` in `websocket/handler.go`, `handleConnection`.* ]

*   **Missing Implementation:** [ *Example: Max size is hardcoded; make it configurable.* ]

## Mitigation Strategy: [Ping/Pong Heartbeats](./mitigation_strategies/pingpong_heartbeats.md)

**Description:**
1.  **Server-Side Ping:**
    *   Use a `time.Ticker` (e.g., every 30 seconds - the "ping period").
    *   In the loop, send a ping: `conn.WriteControl(websocket.PingMessage, data, time.Now().Add(writeWait))`. `data` can be empty. `writeWait` is a short write timeout.
2.  **Client-Side Pong Handler:**
    *   Client: Set a pong handler: `conn.SetPongHandler(handler)`.
    *   The `handler` is called on pong messages.
    *   In the handler, *reset the read deadline*: `conn.SetReadDeadline(time.Now().Add(pongWait))`. `pongWait` is slightly longer than the ping period.
3.  **Server-Side Read Deadline:** Ensure a read deadline is set (see strategy #3). If it expires *without* a pong, close the connection.
4. **Close Handler:** Set close handler using `conn.SetCloseHandler` to handle close messages.

*   **Threats Mitigated:**
    *   **Idle Connection Resource Consumption:** (Severity: Medium) - Closes idle connections.
    *   **Dead Connections:** (Severity: Low) - Detects broken connections.
    *   **Half-Open Connections:** (Severity: Medium)

*   **Impact:**
    *   **Idle Connections:** Reduces resource consumption.
    *   **Dead Connections:** Improves stability.
    *   **Half-Open Connections:** Improves resource management.

*   **Currently Implemented:** [ *Example: No ping/pong implemented.* ]

*   **Missing Implementation:** [ *Example: Implement the entire ping/pong mechanism.* ]

## Mitigation Strategy: [Subprotocol Negotiation Validation](./mitigation_strategies/subprotocol_negotiation_validation.md)

**Description:**
1. **Define Allowed Subprotocols:** List supported subprotocols.
2. **Validate Negotiated Subprotocol:** During the handshake, the client may request subprotocols. The server selects one or none.
3. **Check Against Whitelist:** After the handshake, verify the negotiated subprotocol (if any) is in your allowed list.
4. **Reject Invalid Subprotocols:** If not in the whitelist, close the connection (`websocket.CloseProtocolError`).

* **Threats Mitigated:**
    * **Exploitation of Unsupported Subprotocols:** (Severity: Medium)
    * **Application Logic Errors:** (Severity: Variable)

* **Impact:**
    * **Exploitation of Unsupported Subprotocols:** Reduces attack risk.
    * **Application Logic Errors:** Improves robustness.

* **Currently Implemented:** [ *Example: No subprotocol negotiation used.* ]

* **Missing Implementation:** [ *Example: Implement if subprotocols are used.* ]

## Mitigation Strategy: [Strict Message *Type* Validation (Binary vs. Text)](./mitigation_strategies/strict_message_type_validation__binary_vs__text_.md)

**Description:**
1.  **Determine Expected Message Types:** Decide whether your application expects *only* text messages (`websocket.TextMessage`), *only* binary messages (`websocket.BinaryMessage`), or both.
2.  **Validate in Read Loop:**  Within your `ReadMessage` loop, check the `messageType` returned by `conn.ReadMessage()`.
3.  **Reject Unexpected Types:** If the `messageType` is not one of the expected types, close the connection with `websocket.CloseUnsupportedData`.  For example, if you *only* expect text messages, and you receive a binary message, close the connection.

* **Threats Mitigated:**
    * **Unexpected Application Behavior:** (Severity: Medium) - Prevents your application from processing data in an unexpected format, which could lead to vulnerabilities or crashes.
    * **Potential Exploits:** (Severity: Low to Medium) - Reduces the attack surface by limiting the types of messages your application will handle.  Some exploits might rely on sending unexpected message types.

* **Impact:**
    * **Unexpected Behavior:** Improves application robustness and predictability.
    * **Potential Exploits:** Provides a small but useful layer of defense.

* **Currently Implemented:** [ *Example:  No explicit message type checking is performed.* ]

* **Missing Implementation:** [ *Example: Add a check for `messageType` in the `readLoop` function in `websocket/handler.go` and close the connection with `websocket.CloseUnsupportedData` if the type is unexpected.* ]

