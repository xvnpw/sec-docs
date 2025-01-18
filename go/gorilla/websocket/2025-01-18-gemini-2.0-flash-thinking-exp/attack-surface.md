# Attack Surface Analysis for gorilla/websocket

## Attack Surface: [WebSocket Handshake Manipulation (Origin Header Spoofing)](./attack_surfaces/websocket_handshake_manipulation__origin_header_spoofing_.md)

**Description:** An attacker attempts to bypass server-side origin checks by forging the `Origin` header during the initial WebSocket handshake.

**How WebSocket Contributes:** The WebSocket handshake relies on the `Origin` header for basic cross-origin protection. If not properly validated, this mechanism can be circumvented.

**Example:** A malicious website embeds JavaScript that attempts to establish a WebSocket connection to the target application, setting an `Origin` header that matches an allowed domain.

**Impact:** Allows unauthorized cross-origin connections, potentially leading to data breaches, unauthorized actions, or cross-site WebSocket hijacking.

**Risk Severity:** High

**Mitigation Strategies:**
*   **Server-Side Origin Validation:** Implement strict server-side validation of the `Origin` header against a whitelist of allowed origins. Do not rely solely on the browser's enforcement.
*   **Consider Additional Authentication:** Implement stronger authentication mechanisms beyond just the `Origin` header, especially for sensitive operations.

## Attack Surface: [Malicious Payloads (Client to Server)](./attack_surfaces/malicious_payloads__client_to_server_.md)

**Description:** An attacker sends crafted WebSocket messages to the server designed to exploit vulnerabilities in the application's logic or data processing.

**How WebSocket Contributes:** WebSockets provide a persistent, bidirectional communication channel, allowing attackers to send a continuous stream of potentially malicious data.

**Example:** An attacker sends a WebSocket message containing a specially crafted string that, when processed by the server, causes a buffer overflow or triggers an unexpected code path.

**Impact:** Can lead to application crashes, data corruption, unauthorized access, or remote code execution depending on the vulnerability.

**Risk Severity:** Critical to High (depending on the specific vulnerability)

**Mitigation Strategies:**
*   **Robust Input Validation and Sanitization:** Implement strict input validation and sanitization on the server-side for all data received via WebSocket messages. Define expected message formats and reject unexpected or malformed data.
*   **Rate Limiting and Throttling:** Implement rate limiting on incoming WebSocket messages to prevent denial-of-service attacks or rapid exploitation attempts.
*   **Secure Message Parsing:** Use secure and well-tested libraries for parsing WebSocket message formats (e.g., JSON, Protocol Buffers). Be wary of custom parsing logic.

## Attack Surface: [Malicious Payloads (Server to Client - XSS via WebSocket)](./attack_surfaces/malicious_payloads__server_to_client_-_xss_via_websocket_.md)

**Description:** A compromised server (or an attacker manipulating server responses) sends malicious data via WebSocket that, when rendered by the client-side application, executes arbitrary JavaScript code in the user's browser.

**How WebSocket Contributes:** WebSockets enable real-time data pushing from the server to the client. If the client doesn't properly sanitize this data, it can be exploited for XSS.

**Example:** The server sends a WebSocket message containing `<script>alert('You are hacked!');</script>` which the client-side JavaScript directly inserts into the DOM without escaping.

**Impact:** Allows attackers to execute arbitrary JavaScript in the user's browser, potentially stealing cookies, session tokens, or performing actions on behalf of the user.

**Risk Severity:** High

**Mitigation Strategies:**
*   **Client-Side Output Encoding/Escaping:**  Always encode or escape data received via WebSocket before rendering it in the browser's DOM. Use appropriate escaping functions based on the context (HTML, JavaScript, URL).
*   **Content Security Policy (CSP):** Implement a strong Content Security Policy to restrict the sources from which the browser can load resources, mitigating the impact of injected scripts.

