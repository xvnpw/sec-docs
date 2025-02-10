# Threat Model Analysis for gorilla/websocket

## Threat: [Cross-Site WebSocket Hijacking (CSWSH)](./threats/cross-site_websocket_hijacking__cswsh_.md)

*   **Description:** An attacker tricks a user's browser into making a WebSocket connection to the attacker's server, or to the legitimate server but with malicious intent.  The attacker crafts a malicious webpage that initiates a WebSocket connection, leveraging the browser's automatic cookie handling (if applicable) to make the connection appear legitimate.
*   **Impact:** The attacker can send and receive messages on behalf of the victim, accessing sensitive data, performing unauthorized actions, or disrupting service.
*   **Affected Component:** `gorilla/websocket.Upgrader` (handshake process, origin validation).
*   **Risk Severity:** High (if authentication relies on cookies and origin checks are weak) or Critical (if no origin checks are performed).
*   **Mitigation Strategies:**
    *   **Strict `CheckOrigin` Implementation:** Use `Upgrader.CheckOrigin` to *explicitly* verify the `Origin` header against a whitelist.  Do *not* accept all origins.
    *   **CSRF Tokens (for Handshake):** Use a CSRF token in the initial HTTP request (if applicable) and verify it during the WebSocket handshake.
    *   **Authentication Tokens (Not Just Cookies):** Use authentication tokens (e.g., JWTs) passed in the handshake and validated server-side, rather than relying solely on cookies.

## Threat: [Denial of Service (DoS) via Connection Exhaustion](./threats/denial_of_service__dos__via_connection_exhaustion.md)

*   **Description:** An attacker opens many WebSocket connections, consuming server resources (memory, file descriptors, CPU) and preventing legitimate connections.
*   **Impact:** Application unavailability.
*   **Affected Component:** `gorilla/websocket.Conn` (multiple instances), server resources.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Connection Limits:** Implement limits on concurrent connections per user, IP, and globally (custom logic required).
    *   **Reverse Proxy/Load Balancer:** Use a reverse proxy (Nginx, HAProxy) for connection limits and rate limiting.

## Threat: [Denial of Service (DoS) via Slowloris](./threats/denial_of_service__dos__via_slowloris.md)

*   **Description:** An attacker opens connections but sends data very slowly, keeping connections open and consuming resources.
*   **Impact:** Application unavailability.
*   **Affected Component:** `gorilla/websocket.Conn` (read/write operations).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Read and Write Deadlines:** Use `Conn.SetReadDeadline` and `Conn.SetWriteDeadline` for timeouts.
    *   **Reverse Proxy Configuration:** Utilize reverse proxy features for Slowloris protection.

## Threat: [Denial of Service (DoS) via Message Flooding](./threats/denial_of_service__dos__via_message_flooding.md)

*   **Description:** An attacker sends many or very large WebSocket messages, overwhelming server processing.
*   **Impact:** Application slowdown or unresponsiveness.
*   **Affected Component:** `gorilla/websocket.Conn` (`ReadMessage`, application message handling).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Message Rate Limiting:** Implement rate limiting (custom logic).
    *   **Message Size Limits:** Use `Conn.SetReadLimit`.
    *   **Input Validation:** Validate message content to prevent excessive resource consumption.

## Threat: [Data Tampering (Man-in-the-Middle)](./threats/data_tampering__man-in-the-middle_.md)

*   **Description:** An attacker intercepts and modifies WebSocket messages in transit.
*   **Impact:** Compromised data integrity; altered commands, data, or messages.
*   **Affected Component:** The entire WebSocket communication channel.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Use WSS (WebSocket Secure):** *Always* use `wss://` for encrypted connections (TLS).

## Threat: [Information Disclosure (Eavesdropping)](./threats/information_disclosure__eavesdropping_.md)

*   **Description:** An attacker intercepts and reads WebSocket messages.
*   **Impact:** Exposure of sensitive data.
*   **Affected Component:** The entire WebSocket communication channel.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Use WSS (WebSocket Secure):** *Always* use `wss://` for encrypted connections (TLS).

## Threat: [Information Disclosure (Server-Side Leaks)](./threats/information_disclosure__server-side_leaks_.md)

*   **Description:** The server inadvertently sends sensitive information to the client via WebSocket messages.
*   **Impact:** Exposure of sensitive information, leading to privacy violations or further attacks.
*   **Affected Component:** Application logic handling WebSocket messages and sending data.
*   **Risk Severity:** High to Critical (depending on the leaked information).
*   **Mitigation Strategies:**
    *   **Data Minimization:** Send only the *minimum* necessary data.
    *   **Careful Error Handling:** Avoid detailed error messages to the client.
    *   **Code Reviews:** Review code for potential leaks.
    *   **Input Validation and Output Encoding:** Sanitize and encode data appropriately.

## Threat: [Client Impersonation](./threats/client_impersonation.md)

*   **Description:** A malicious client impersonates another user, gaining unauthorized access.
*   **Impact:** Access to data or actions on behalf of the impersonated user.
*   **Affected Component:** Authentication/authorization logic (often during handshake).
*   **Risk Severity:** High to Critical (depending on the application).
*   **Mitigation Strategies:**
    *   **Secure Authentication Propagation:** Securely associate user identity with the WebSocket connection (e.g., validate JWTs during handshake).
    *   **Do Not Trust Client-Provided User IDs:** Validate user IDs server-side against the authenticated user.

## Threat: [Unauthorized Actions (Elevation of Privilege)](./threats/unauthorized_actions__elevation_of_privilege_.md)

*   **Description:** A client sends messages to trigger unauthorized actions due to missing or flawed authorization checks.
*   **Impact:** Attacker performs actions they shouldn't, leading to breaches or compromise.
*   **Affected Component:** Server-side message handling and authorization checks.
*   **Risk Severity:** High to Critical (depending on the actions).
*   **Mitigation Strategies:**
    *   **Strict Authorization Checks:** Verify permissions for *every* action triggered by a WebSocket message.
    *   **Principle of Least Privilege:** Users have only minimum necessary permissions.

