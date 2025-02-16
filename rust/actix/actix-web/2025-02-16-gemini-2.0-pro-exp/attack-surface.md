# Attack Surface Analysis for actix/actix-web

## Attack Surface: [HTTP Request Smuggling](./attack_surfaces/http_request_smuggling.md)

*   **Description:** Exploits discrepancies in how HTTP requests are parsed, allowing attackers to "smuggle" a hidden request.
*   **Actix-Web Contribution:** Actix-Web's HTTP request parsing logic (handling of `Content-Length`, `Transfer-Encoding`, chunked encoding) is the *direct* point of vulnerability.
*   **Example:** Conflicting `Content-Length` and `Transfer-Encoding` headers allow bypassing security controls via a hidden, smuggled request.
*   **Impact:** Authentication bypass, data modification, session hijacking, potentially leading to complete server compromise.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Keep Actix-Web Updated:**  Prioritize updating Actix-Web and its dependencies.
    *   **Web Application Firewall (WAF):** Use a WAF configured to detect and block request smuggling.
    *   **Proxy Configuration:** Ensure any front-end proxies are securely configured and updated.
    *   **Avoid Chained Proxies:** Minimize the number of proxies in front of Actix-Web.
    *   **Testing:** Specifically test for request smuggling vulnerabilities.

## Attack Surface: [Request Parsing Vulnerabilities (General - High Risk Subset)](./attack_surfaces/request_parsing_vulnerabilities__general_-_high_risk_subset_.md)

*   **Description:** Flaws in Actix-Web's parsing of HTTP requests leading to DoS or *potential* RCE.  This is a narrowed-down version of the previous entry, focusing on the highest-risk aspects.
*   **Actix-Web Contribution:** Actix-Web's core request parsing is the *direct* attack surface.
*   **Example:**
    *   **Header Injection (DoS):**  Extremely large or malformed headers causing resource exhaustion or crashes.
    *   **Malformed Body (Potential RCE):**  Exploiting a vulnerability in a body parsing library (e.g., `serde_json`) used by Actix-Web, *if* such a vulnerability exists and is exploitable.  This is less likely but still a high-impact scenario.
*   **Impact:** Denial of Service (DoS), *Potentially* Remote Code Execution (RCE) in rare cases.
*   **Risk Severity:** High (DoS), Potentially Critical (RCE - but less probable)
*   **Mitigation Strategies:**
    *   **Limit Input Sizes:** Configure Actix-Web to limit header, body, and query parameter sizes. Use Actix-Web's built-in configuration.
    *   **Dependency Management:** Keep Actix-Web and all dependencies (especially parsing libraries) up-to-date. Use `cargo audit`.
    *   **WAF:** A WAF can filter malicious requests.
    *   **Input Validation:** *Always* validate and sanitize all input *after* Actix-Web parses it, but this is *secondary* to preventing the parsing vulnerability itself.

## Attack Surface: [WebSocket Vulnerabilities (CSWSH & DoS)](./attack_surfaces/websocket_vulnerabilities__cswsh_&_dos_.md)

*   **Description:** Exploits targeting Actix-Web's WebSocket implementation, specifically Cross-Site WebSocket Hijacking (CSWSH) and Denial of Service.
*   **Actix-Web Contribution:** Actix-Web's WebSocket handling (connection establishment, message processing) is the *direct* point of vulnerability.
*   **Example:**
    *   **CSWSH:** A malicious website establishes a WebSocket connection to the Actix-Web application without the user's knowledge.
    *   **WebSocket DoS:** An attacker opens numerous WebSocket connections, exhausting resources.
*   **Impact:** Data theft, unauthorized actions, denial of service.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Strict Origin Checks:** Implement *strict* origin checks in the Actix-Web WebSocket handler.
    *   **Authentication & Authorization:** Require authentication and authorization for WebSocket connections.
    *   **TLS (wss://):** Always use TLS (wss://) for WebSocket connections.
    *   **Rate Limiting & Connection Limits:** Implement rate limiting and connection limits within Actix-Web.
    *   **Input Validation:** Validate *all* data received over the WebSocket, but this is *secondary* to preventing unauthorized connections.

## Attack Surface: [Insecure Configuration](./attack_surfaces/insecure_configuration.md)

* **Description:** Misconfiguration of Actix-Web, leading to security weaknesses.
* **Actix-Web Contribution:** Actix-Web provides various configuration options. Incorrect settings can *directly* introduce vulnerabilities.
* **Example:**
    *   Leaving Actix-Web's debug mode enabled in production.
    *   Not configuring TLS/SSL.
* **Impact:** Information disclosure, unauthorized access, data breaches.
* **Risk Severity:** High to Critical
* **Mitigation Strategies:**
    *   **Review Configuration:** Thoroughly review all Actix-Web configuration options.
    *   **Disable Debug Mode:** Disable debug mode in production.
    *   **Enable TLS/SSL:** Always use TLS/SSL (HTTPS).
    *   **Regular Audits:** Regularly audit the configuration.

