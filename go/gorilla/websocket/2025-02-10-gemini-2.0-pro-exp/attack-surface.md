# Attack Surface Analysis for gorilla/websocket

## Attack Surface: [Cross-Site WebSocket Hijacking (CSWSH)](./attack_surfaces/cross-site_websocket_hijacking__cswsh_.md)

*   **Description:** An attacker tricks a user's browser into establishing a WebSocket connection to a vulnerable server from a malicious origin, allowing the attacker to interact with the server as the legitimate user.
*   **WebSocket Contribution:** WebSockets don't inherently enforce the same-origin policy in the same way as standard HTTP requests. The `Origin` header is present, but validation is the server's responsibility.
*   **Example:** A malicious website (attacker.com) includes JavaScript that opens a WebSocket connection to `wss://your-app.com/ws`. If `your-app.com` doesn't validate the `Origin`, the connection succeeds, and the attacker's script can send/receive messages.
*   **Impact:** Data theft, unauthorized actions on behalf of the user, session hijacking (if WebSockets are used for session management).
*   **Risk Severity:** **High** to **Critical** (depending on the sensitivity of exposed data/actions).
*   **Mitigation Strategies:**
    *   **Strict Origin Validation:** Implement a custom `CheckOrigin` function in your `websocket.Upgrader`. This function should compare the `Origin` header against a *whitelist* of allowed origins. *Do not* use wildcards (`*`) without fully understanding the risks.
    *   **Same-Site Cookies:** If cookies are used with WebSockets, set the `SameSite` attribute on cookies to `Strict` or `Lax` to prevent cross-origin cookie transmission.
    *   **CSRF Tokens (if applicable):** If the WebSocket connection is established after an initial HTTP request, consider using CSRF tokens to verify the handshake's legitimacy.

## Attack Surface: [Denial of Service (DoS) - Large Messages](./attack_surfaces/denial_of_service__dos__-_large_messages.md)

*   **Description:** An attacker sends excessively large WebSocket messages to overwhelm the server's resources (memory, CPU).
*   **WebSocket Contribution:** WebSockets are designed for persistent connections and *can* handle large messages. Without limits, this capability is easily abused.
*   **Example:** An attacker sends a WebSocket message containing gigabytes of random data.
*   **Impact:** Server becomes unresponsive, preventing legitimate users from accessing the service.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Message Size Limits:** Use `Conn.SetReadLimit()` to set a maximum size for incoming messages. Reject messages exceeding this limit. Choose a limit appropriate for your application.

## Attack Surface: [Denial of Service (DoS) - Connection Flooding](./attack_surfaces/denial_of_service__dos__-_connection_flooding.md)

*   **Description:** An attacker opens a large number of WebSocket connections, exhausting server resources (file descriptors, memory, CPU).
*   **WebSocket Contribution:** The persistent nature of WebSocket connections makes them a prime target for connection exhaustion attacks.
*   **Example:** An attacker uses a script to rapidly open thousands of WebSocket connections to the server.
*   **Impact:** Server becomes unresponsive, preventing legitimate users from accessing the service.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Connection Limits (per IP):** Limit the number of concurrent WebSocket connections allowed from a single IP address.
    *   **Global Connection Limits:** Limit the total number of concurrent WebSocket connections the server will accept.
    *   **Reverse Proxy:** Use a reverse proxy (e.g., Nginx, HAProxy) to handle connection limiting. Reverse proxies are often better equipped for this.
    *   **Rate Limiting:** Implement rate limiting on connection attempts to prevent rapid connection establishment.

## Attack Surface: [Input Validation Vulnerabilities (leading to Injection Attacks)](./attack_surfaces/input_validation_vulnerabilities__leading_to_injection_attacks_.md)

*   **Description:** Data received over WebSocket connections is not properly validated/sanitized, leading to vulnerabilities like injection attacks (if the data is used in database queries or other sensitive operations).  This is *critical* when WebSocket data directly influences server-side actions.
*   **WebSocket Contribution:** WebSockets provide a channel for *arbitrary* data. It's the application's responsibility to treat this data as *untrusted*.
*   **Example:** An attacker sends a WebSocket message containing a malicious SQL query string, used directly in a database query without parameterization.
*   **Impact:** Varies widely. Could include SQL injection, cross-site scripting (XSS) if data is displayed in a web UI, command injection, etc.  The impact is directly tied to *how* the WebSocket data is used.
*   **Risk Severity:** **High** to **Critical** (depending on the specific vulnerability and data usage).
*   **Mitigation Strategies:**
    *   **Strict Input Validation:** Validate *all* data received over WebSockets. Check data types, lengths, formats, and allowed characters.
    *   **Parameterized Queries:** Use parameterized queries or prepared statements for *all* database interactions.
    *   **Output Encoding:** If WebSocket data is used to generate output (e.g., HTML), use appropriate output encoding to prevent XSS.
    *   **Context-Specific Sanitization:** Sanitize data based on the context in which it will be used.

## Attack Surface: [Insufficient TLS Configuration (wss://)](./attack_surfaces/insufficient_tls_configuration__wss_.md)

*   **Description:** Weak TLS settings expose the WebSocket connection (using `wss://`) to eavesdropping or man-in-the-middle attacks.
*   **WebSocket Contribution:** While `gorilla/websocket` supports TLS, the configuration is the developer's responsibility.  The *use* of WebSockets necessitates secure transport.
*   **Example:** Using an outdated TLS version (e.g., TLS 1.0 or 1.1) or weak cipher suites.
*   **Impact:** Compromise of data confidentiality and integrity.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Strong TLS Configuration:** Use TLS 1.2 or 1.3 with strong cipher suites. Use the `tls.Config` structure to customize TLS settings.
    *   **Certificate Validation:** Ensure proper validation of the server's certificate.
    *   **Regular Updates:** Keep your TLS libraries and configurations up-to-date.

