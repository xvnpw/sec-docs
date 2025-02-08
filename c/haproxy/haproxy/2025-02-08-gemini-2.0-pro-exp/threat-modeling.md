# Threat Model Analysis for haproxy/haproxy

## Threat: [HTTP Request Smuggling (via inconsistent parsing)](./threats/http_request_smuggling__via_inconsistent_parsing_.md)

*   **Description:** An attacker crafts a malicious HTTP request that is interpreted differently by HAProxy and the backend server.  This exploits ambiguities in how `Content-Length` and `Transfer-Encoding` headers are handled, or other HTTP/1.1 pipelining inconsistencies. The attacker bypasses security checks, accesses unauthorized resources, or poisons the web cache.
    *   **Impact:**  Unauthorized access to backend resources, data breaches, cache poisoning, potential for remote code execution on the backend (depending on the backend's vulnerability).
    *   **Affected Component:**  HAProxy's HTTP parsing engine (frontend and backend request processing), specifically how it handles `Content-Length`, `Transfer-Encoding`, and connection reuse.
    *   **Risk Severity:**  Critical
    *   **Mitigation Strategies:**
        *   Ensure HAProxy and backend servers are configured to use consistent HTTP parsing rules.  Prefer HTTP/2, which is less susceptible to smuggling.
        *   If using HTTP/1.1, disable connection reuse (`option http-server-close`) on the backend if possible, or use `option forceclose`.
        *   Use `http-request deny if { req.hdr_cnt(content-length) gt 1 }` and similar rules.
        *   Use `http-request deny if { req.hdr_cnt(transfer-encoding) gt 1 }`.
        *   Carefully validate and sanitize all incoming HTTP headers.
        *   Keep HAProxy updated to the latest version.

## Threat: [Slowloris (Slow HTTP Request) DoS](./threats/slowloris__slow_http_request__dos.md)

*   **Description:** An attacker opens numerous connections to HAProxy and sends HTTP requests very slowly, keeping connections open. This exhausts HAProxy's connection pool, preventing legitimate clients from connecting.
    *   **Impact:**  Denial of service; legitimate users cannot access the application.
    *   **Affected Component:**  HAProxy's connection handling (frontend), specifically the number of concurrent connections it can handle.
    *   **Risk Severity:**  High
    *   **Mitigation Strategies:**
        *   Configure `timeout client` and `timeout server` to reasonable values (e.g., 30 seconds).
        *   Use `req.hdr_timeout` in an ACL.
        *   Configure `maxconn` (global and frontend).
        *   Use HAProxy's stick tables to track and limit connections from individual clients (`stick-table type ip size 1m expire 30s store conn_rate(30s)` and `tcp-request connection track-sc1 src`).
        *   Use `req.conntimeout`.

## Threat: [HTTP Header Overflow](./threats/http_header_overflow.md)

*   **Description:** An attacker sends an HTTP request with excessively large headers (or many headers). This consumes excessive memory in HAProxy, potentially leading to a crash or denial of service.
    *   **Impact:**  Denial of service; HAProxy becomes unresponsive.  Potentially exploitable for remote code execution (though less likely).
    *   **Affected Component:**  HAProxy's HTTP header parsing and buffering mechanisms.
    *   **Risk Severity:**  High
    *   **Mitigation Strategies:**
        *   Configure `tune.bufsize` and `tune.maxrewrite` appropriately.
        *   Use `http-request deny if { req.hdrs_len gt 8192 }` (adjust as needed).
        *   Use `http-request deny if { req.hdr_cnt() gt 100 }` (adjust as needed).

## Threat: [SSL/TLS Misconfiguration (Weak Ciphers/Protocols)](./threats/ssltls_misconfiguration__weak_ciphersprotocols_.md)

*   **Description:** HAProxy is configured to use weak or outdated SSL/TLS ciphers and protocols (e.g., SSLv3, RC4).  Allows an attacker to perform a MitM attack and decrypt traffic.
    *   **Impact:**  Loss of confidentiality and integrity of communication between clients and HAProxy. Data breaches, session hijacking.
    *   **Affected Component:**  HAProxy's SSL/TLS library and configuration (frontend `bind` options).
    *   **Risk Severity:**  High
    *   **Mitigation Strategies:**
        *   Use only strong, modern ciphers and protocols (TLS 1.3, TLS 1.2 with strong cipher suites). Use `ssl-default-bind-ciphers` and `ssl-default-bind-options`.
        *   Disable SSLv3 and older protocols.
        *   Use a strong, well-known CA.
        *   Regularly test your SSL/TLS configuration (e.g., SSL Labs).
        *   Enable HSTS.
        *   Configure OCSP stapling.

## Threat: [Configuration Injection (via Management Interface)](./threats/configuration_injection__via_management_interface_.md)

*   **Description:** An attacker gains access to HAProxy's management interface (socket or HTTP) and injects malicious configuration directives.  Could redirect traffic, disable security, or expose information.
    *   **Impact:**  Complete compromise of HAProxy, potential redirection to malicious backends, data breaches, denial of service.
    *   **Affected Component:**  HAProxy's management interface (stats socket, HTTP stats page).
    *   **Risk Severity:**  Critical
    *   **Mitigation Strategies:**
        *   Restrict access to the management interface to trusted IPs using ACLs (`bind :8080; stats uri /; stats auth admin:password; stats admin if { src 192.168.1.1 }`).
        *   Use strong authentication.
        *   Disable the management interface if not needed.
        *   Monitor access logs.
        *   Consider a separate, secured network for management.

