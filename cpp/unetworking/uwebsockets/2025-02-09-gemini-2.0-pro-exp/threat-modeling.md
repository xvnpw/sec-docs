# Threat Model Analysis for unetworking/uwebsockets

## Threat: [Slowloris Attack](./threats/slowloris_attack.md)

*   **Threat:** Slowloris Attack
    *   **Description:** An attacker opens numerous connections to the uWebSockets.js server but sends data very slowly or incompletely. They might send partial HTTP requests or WebSocket frames, keeping connections open for extended periods without completing them.  uWebSockets.js's performance focus might make it *more* susceptible if not properly configured to handle this.
    *   **Impact:** Denial of Service (DoS). Legitimate users are unable to connect or experience significant performance degradation. The server may become unresponsive or crash.
    *   **Affected Component:** `uWS::App`, `uWS::SSLApp`, connection handling logic, socket management (internal to uWebSockets.js).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Implement strict connection timeouts (idle, handshake, and data transfer timeouts) using `setTimeout` and related options within the `uWS::App` or `uWS::SSLApp` configuration.  This is *crucial* for uWebSockets.js.
        *   Limit the maximum number of concurrent connections, both globally and per IP address.
        *   Monitor connection states and actively close connections that are not progressing.
        *   Use a reverse proxy (Nginx, HAProxy) for an additional layer of defense, but configure uWebSockets.js timeouts *regardless*.

## Threat: [Large Message/Frame DoS](./threats/large_messageframe_dos.md)

*   **Threat:** Large Message/Frame DoS
    *   **Description:** An attacker sends excessively large HTTP requests (if using HTTP) or WebSocket messages/frames. This forces the server to allocate large amounts of memory, potentially leading to resource exhaustion, even with uWebSockets.js's optimizations.
    *   **Impact:** Denial of Service (DoS). Memory exhaustion can lead to server crashes, unresponsiveness, or significant performance degradation.
    *   **Affected Component:** `uWS::App`, `uWS::SSLApp`, `uWS::WebSocket<...>::onMessage`, HTTP request parsing, WebSocket frame parsing (internal to uWebSockets.js).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Set strict limits on the maximum allowed size for HTTP requests and WebSocket messages using the `maxPayloadLength` option in the `uWS::WebSocketBehavior` and similar options for HTTP requests. This is *essential* for uWebSockets.js.
        *   Monitor memory usage and trigger alerts.

## Threat: [Outdated uWebSockets.js Version](./threats/outdated_uwebsockets_js_version.md)

*   **Threat:** Outdated uWebSockets.js Version
    *   **Description:** The application uses an outdated version of uWebSockets.js that contains *known* security vulnerabilities (e.g., a publicly disclosed CVE).
    *   **Impact:** Varies depending on the specific vulnerability, but could range from DoS to RCE. This is a direct threat because it's a vulnerability *within* uWebSockets.js.
    *   **Affected Component:** Potentially any part of uWebSockets.js, depending on the vulnerability.
    *   **Risk Severity:** Critical (if known, exploitable vulnerabilities exist in the used version)
    *   **Mitigation Strategies:**
        *   Regularly update to the latest stable release of uWebSockets.js.  This is the *single most important* mitigation.
        *   Monitor security advisories and mailing lists.
        *   Use dependency management tools.

## Threat: [Incorrect Configuration Leading to DoS](./threats/incorrect_configuration_leading_to_dos.md)

* **Threat:** Incorrect Configuration Leading to DoS
    * **Description:** Misconfiguration of uWebSockets.js options, specifically those related to resource limits (e.g., excessively large `maxPayloadLength`, extremely long or disabled timeouts). This directly impacts uWebSockets.js's ability to protect itself.
    * **Impact:** Denial of Service (DoS). The misconfiguration allows an attacker to exploit resource exhaustion vulnerabilities more easily.
    * **Affected Component:** `uWS::App`, `uWS::SSLApp`, `uWS::WebSocketBehavior`, and any component related to the misconfigured option.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        *   Thoroughly understand the documentation for each configuration option, *especially* those related to timeouts and message sizes.
        *   Use secure defaults whenever possible.  Do *not* disable timeouts.
        *   Regularly review and audit the configuration.

