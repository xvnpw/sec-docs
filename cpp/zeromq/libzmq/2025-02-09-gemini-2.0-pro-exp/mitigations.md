# Mitigation Strategies Analysis for zeromq/libzmq

## Mitigation Strategy: [Implement Strong Authentication using CurveZMQ](./mitigation_strategies/implement_strong_authentication_using_curvezmq.md)

*   **Description:**
    1.  **Generate Key Pairs:** Use the `zmq_curve_keypair()` function (or equivalent in your language binding) to generate a public/private key pair for *each* server and client.
    2.  **Secure Key Distribution:** (This part is *not* directly `libzmq`, but is *essential* for CurveZMQ to work securely)
        *   **Server:** Store the server's *private* key securely.  *Never* hardcode it. Use environment variables (loaded securely), a configuration service, or a KMS. Distribute the server's *public* key to clients.
        *   **Client:** Obtain the server's *public* key through a secure channel.
    3.  **Configure Sockets:** (This is the core `libzmq` part)
        *   **Server:**
            *   Set `ZMQ_CURVE_SERVER` to 1 on the server socket using `zmq_setsockopt()`.
            *   Set `ZMQ_CURVE_SECRETKEY` to the server's *private* key using `zmq_setsockopt()`.
            *   Set `ZMQ_CURVE_PUBLICKEY` to the server's *public* key using `zmq_setsockopt()`.
        *   **Client:**
            *   Set `ZMQ_CURVE_SERVERKEY` to the server's *public* key using `zmq_setsockopt()`.
            *   Set `ZMQ_CURVE_PUBLICKEY` to the client's *public* key using `zmq_setsockopt()`.
            *   Set `ZMQ_CURVE_SECRETKEY` to the client's *private* key using `zmq_setsockopt()`.
    4.  **Connection Establishment:** ZeroMQ handles the cryptographic handshake.
    5. **Verification (Optional):** After connection, verify the peer's public key. (This is *not* a direct `libzmq` feature, but a recommended practice).

*   **Threats Mitigated:**
    *   **Unauthenticated Connections:** (Severity: Critical)
    *   **Data Exposure:** (Severity: Critical)
    *   **Message Injection/Tampering (Partial):** (Severity: High) - Requires additional digital signatures for full mitigation.

*   **Impact:**
    *   **Unauthenticated Connections:** Risk reduced to near zero (with proper key management).
    *   **Data Exposure:** Risk reduced to near zero (with proper key management).
    *   **Message Injection/Tampering:** Risk significantly reduced.

*   **Currently Implemented:**
    *   Implemented in `message_broker` (`broker.cpp`, lines 50-75) and `data_processor` (`processor.py`, lines 30-45). Key exchange via environment variables.

*   **Missing Implementation:**
    *   `monitoring_agent` does *not* use CurveZMQ. Key verification is not implemented.

## Mitigation Strategy: [Set `ZMQ_MAXMSGSIZE`](./mitigation_strategies/set__zmq_maxmsgsize_.md)

*   **Description:**
    *   On each socket, set the `ZMQ_MAXMSGSIZE` option to a reasonable value using `zmq_setsockopt()`.  This limits the maximum size of a message that can be sent or received on that socket.

*   **Threats Mitigated:**
    *   **DoS via Large Messages:** (Severity: High)

*   **Impact:**
    *   **DoS via Large Messages:** Risk significantly reduced.

*   **Currently Implemented:**
    *   Set to 10MB on all sockets in `message_broker` (`broker.cpp`, line 40).

*   **Missing Implementation:**
    *   Should be consistently applied to *all* sockets in *all* components, including `data_processor` and `monitoring_agent`.

## Mitigation Strategy: [Use High Water Marks (`ZMQ_RCVHWM` and `ZMQ_SNDHWM`)](./mitigation_strategies/use_high_water_marks___zmq_rcvhwm__and__zmq_sndhwm__.md)

*   **Description:**
    *   On each socket, set `ZMQ_RCVHWM` (receive high water mark) and `ZMQ_SNDHWM` (send high water mark) to reasonable values using `zmq_setsockopt()`.  These control the maximum number of messages queued for sending and receiving.

*   **Threats Mitigated:**
    *   **DoS via Message Flooding:** (Severity: High)
    *   **Resource Exhaustion:** (Severity: High)

*   **Impact:**
    *   **DoS via Message Flooding:** Risk significantly reduced.
    *   **Resource Exhaustion:** Risk significantly reduced.

*   **Currently Implemented:**
    *   Set to 1000 on all sockets in `message_broker` (`broker.cpp`, line 45).

*   **Missing Implementation:**
    *   Should be consistently applied to *all* sockets in *all* components.  The values should be tuned based on expected traffic and resource constraints.

## Mitigation Strategy: [Use Correct Socket Types](./mitigation_strategies/use_correct_socket_types.md)

*   **Description:**
    1.  **Review Design:** Review the application's architecture and messaging patterns.
    2.  **Choose Appropriate Sockets:** Select the correct ZeroMQ socket types (e.g., `ZMQ_PUB`, `ZMQ_SUB`, `ZMQ_REQ`, `ZMQ_REP`, `ZMQ_DEALER`, `ZMQ_ROUTER`, `ZMQ_PUSH`, `ZMQ_PULL`) for each component using `zmq_socket()`.  The choice depends on the communication pattern.
    3.  **Validate Connections:** Ensure sockets are connected in a compatible way (e.g., `ZMQ_REQ` to `ZMQ_REP`, `ZMQ_PUB` to `ZMQ_SUB`).

*   **Threats Mitigated:**
    *   **Improper Socket Usage:** (Severity: Variable, potentially High)

*   **Impact:**
    *   **Improper Socket Usage:** Risk significantly reduced.

*   **Currently Implemented:**
    *   `message_broker` uses `ZMQ_ROUTER` and `ZMQ_DEALER`. `data_processor` uses `ZMQ_REQ` and `ZMQ_REP`. `monitoring_agent` uses `ZMQ_REQ`.  Basic patterns seem correct.

*   **Missing Implementation:**
    *   A thorough review of all socket connections and messaging patterns is needed.

## Mitigation Strategy: [Use Heartbeats (`ZMQ_HEARTBEAT_IVL`, `ZMQ_HEARTBEAT_TIMEOUT`, `ZMQ_HEARTBEAT_TTL`)](./mitigation_strategies/use_heartbeats___zmq_heartbeat_ivl____zmq_heartbeat_timeout____zmq_heartbeat_ttl__.md)

*   **Description:**
    *   On relevant sockets (particularly those using connection-oriented transports like TCP), set the following options using `zmq_setsockopt()`:
        *   `ZMQ_HEARTBEAT_IVL`:  The interval (in milliseconds) between heartbeat messages.
        *   `ZMQ_HEARTBEAT_TIMEOUT`: The timeout (in milliseconds) before a peer is considered disconnected if no heartbeat is received.
        *   `ZMQ_HEARTBEAT_TTL`: Time-to-live for heartbeats (in milliseconds).  Recommended to be slightly larger than the timeout.
    * This feature is available on connection oriented socket types.

*   **Threats Mitigated:**
    *   **DoS via Slow/Dead Clients:** (Severity: Medium) - Helps detect and disconnect unresponsive clients.

*   **Impact:**
    *   **DoS via Slow/Dead Clients:** Risk reduced.

*   **Currently Implemented:**
    *   Not implemented anywhere.

*   **Missing Implementation:**
    *   Should be implemented on sockets in the `message_broker` that handle client connections, and potentially on other long-lived connections.

## Mitigation Strategy: [Set `ZMQ_LINGER` appropriately.](./mitigation_strategies/set__zmq_linger__appropriately.md)

* **Description:**
    * Set the `ZMQ_LINGER` option on each socket using `zmq_setsockopt()`. This option controls the behavior of `zmq_close()`:
        * `ZMQ_LINGER = -1`: Wait indefinitely for pending messages to be sent.
        * `ZMQ_LINGER = 0`: Discard pending messages immediately.
        * `ZMQ_LINGER = positive value`: Wait up to the specified number of milliseconds for pending messages to be sent.
    * Choose a value that balances the need to deliver messages reliably with the need to avoid blocking the application indefinitely.

* **Threats Mitigated:**
    * **Data Loss (if linger is too short):** (Severity: Medium)
    * **Application Hang (if linger is too long):** (Severity: Medium)

* **Impact:**
    * **Data Loss:** Risk reduced by choosing a non-zero linger value.
    * **Application Hang:** Risk reduced by choosing a finite linger value.

* **Currently Implemented:**
    * Not explicitly set in most components, relying on the default value (which might vary).

* **Missing Implementation:**
    * Should be explicitly set on *all* sockets in *all* components to a well-defined value based on the application's requirements.

