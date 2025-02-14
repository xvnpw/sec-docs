# Threat Model Analysis for walkor/workerman

## Threat: [Slowloris Attack](./threats/slowloris_attack.md)

*   **Description:** An attacker opens numerous connections to the Workerman server but sends data very slowly or sends incomplete HTTP requests. This keeps connections open and consumes worker processes, preventing legitimate users from connecting. The attacker maintains these connections for as long as possible.
*   **Impact:** Denial of Service (DoS). Legitimate users are unable to access the application. The server may become unresponsive.
*   **Workerman Component Affected:** `Worker` class (connection handling), `TcpConnection` class.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Implement connection timeouts using `$connection->maxSendBufferSize` and `$connection->close()` after a defined inactivity period.
    *   Use a reverse proxy (Nginx, Apache) in front of Workerman. Configure the proxy to handle connection management, enforce stricter timeouts, and provide slowloris protection.
    *   Monitor connection counts and resource usage (CPU, memory, file descriptors). Alert on anomalies.
    *   Consider using Workerman's `maxPackageSize` to limit the size of individual requests.

## Threat: [Connection Flooding](./threats/connection_flooding.md)

*   **Description:** An attacker rapidly opens and closes a large number of connections to the Workerman server. This overwhelms the server's ability to handle new connection requests, even if individual connections are short-lived.
*   **Impact:** Denial of Service (DoS). Legitimate users are unable to connect to the application.
*   **Workerman Component Affected:** `Worker` class (connection handling), `TcpConnection` class.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Use a reverse proxy (Nginx, Apache) to handle connection limits and rate limiting. This is the most effective defense.
    *   Implement connection rate limiting within the Workerman application (less efficient than a reverse proxy). Track connection attempts per IP address within a time window.
    *   Configure operating system-level connection limits (e.g., `iptables`, `firewalld`).

## Threat: [Large Request Body DoS](./threats/large_request_body_dos.md)

*   **Description:** An attacker sends a request with an extremely large body. This consumes server memory and potentially crashes worker processes, even with Workerman's asynchronous handling.
*   **Impact:** Denial of Service (DoS), potential application crashes.
*   **Workerman Component Affected:** `TcpConnection` class (receiving data), `Worker` class (process management).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Strictly enforce `maxPackageSize` in Workerman's configuration (`Worker::$maxPackageSize`).
    *   Use a reverse proxy to enforce request body size limits *before* the request reaches Workerman.
    *   Implement input validation and sanitization to reject excessively large data early.

## Threat: [State Manipulation via Persistent Connections](./threats/state_manipulation_via_persistent_connections.md)

*   **Description:** An attacker exploits the persistent nature of Workerman connections to manipulate shared state or access data from other connections. This occurs if the application incorrectly assumes each connection is a new, isolated session.  This is a *direct* consequence of Workerman's persistent connection model.
*   **Impact:** Data breaches, unauthorized access, application misbehavior. The attacker might be able to impersonate other users or access their data.
*   **Workerman Component Affected:** Application logic within event handlers (`onMessage`, `onConnect`, etc.) that uses global or static variables, or incorrectly manages session state. *However*, the vulnerability is *enabled* by Workerman's persistent connection model.  This is the key distinction.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   Treat each connection as potentially long-lived. Avoid relying on connection closure to reset state.
    *   Implement robust session management using a dedicated library or database. Tie session data to a unique identifier (e.g., a cookie), *not* the connection itself.
    *   Carefully consider the use of global or static variables. Use connection-specific data storage (`$connection->data`) where appropriate.

## Threat: [Protocol Hijacking/Downgrade (If Multiple Protocols are Enabled)](./threats/protocol_hijackingdowngrade__if_multiple_protocols_are_enabled_.md)

*   **Description:** If Workerman is configured to support multiple protocols (e.g., HTTP and WebSocket), an attacker attempts to force a downgrade to a less secure protocol or exploits vulnerabilities in one protocol to affect another. This is a direct threat if Workerman is configured to handle multiple protocols.
*   **Impact:** Potential bypass of security mechanisms, unauthorized access, data breaches.
*   **Workerman Component Affected:** `Worker` class (protocol handling), application logic handling different protocols.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   If only one protocol is needed, disable support for others.
    *   Validate protocol-specific headers and data to prevent cross-protocol attacks.
    *   Apply security mechanisms (authentication, authorization) consistently across all protocols.
    *   Use separate worker processes or ports for different protocols.

## Threat: [Insecure Default Configurations](./threats/insecure_default_configurations.md)

*   **Description:** An attacker exploits default Workerman settings that are insecure for production. This is a direct threat related to how Workerman is configured.
*   **Impact:** Varies depending on the specific setting, but can range from DoS to complete system compromise.
*   **Workerman Component Affected:** `Worker` class configuration (all settings).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Thoroughly review *all* Workerman configuration options and adjust them for security. Pay attention to `count`, `user`, `group`, `transport`, `maxPackageSize`, `stdoutFile`, and `logFile`.
    *   Disable unnecessary features.

## Threat: [Running Workerman as Root](./threats/running_workerman_as_root.md)

*   **Description:** An attacker compromises a Workerman worker process running as root, gaining full system control. This is a direct threat related to how Workerman is run.
*   **Impact:** Complete system compromise.
*   **Workerman Component Affected:** The entire Workerman process.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   Always run Workerman as a dedicated, non-privileged user.
    *   Use a process manager (systemd, supervisord).

