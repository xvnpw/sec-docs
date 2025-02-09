# Threat Model Analysis for nginx/nginx

## Threat: [Directory Listing Exposure](./threats/directory_listing_exposure.md)

*   **Description:** An attacker navigates to a directory on the web server lacking an index file (e.g., `index.html`). If `autoindex` is enabled, Nginx generates and displays a listing of all files and subdirectories, potentially exposing source code, configuration files, or other sensitive data.
*   **Impact:** Leakage of sensitive information, potentially leading to further compromise.
*   **Nginx Component Affected:** `autoindex` directive (`ngx_http_autoindex_module`).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Disable `autoindex`: Use `autoindex off;` in the appropriate context (http, server, or location). Ensure all served directories have index files.

## Threat: [Slowloris DoS Attack](./threats/slowloris_dos_attack.md)

*   **Description:** An attacker opens many connections to Nginx and sends HTTP requests very slowly, keeping connections open and consuming server resources, preventing legitimate access.
*   **Impact:** Denial of service; application unavailability.
*   **Nginx Component Affected:** Core Nginx connection handling, worker processes.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Configure Timeouts:** Set appropriate values for `client_header_timeout`, `client_body_timeout`, `send_timeout`, and `keepalive_timeout` to quickly close slow connections.
    *   **Limit Connections (with caution):** `limit_conn` can help, but be mindful of legitimate users behind shared proxies.
    *   **Consider a WAF:** A WAF can often detect and mitigate Slowloris.

## Threat: [HTTP Flood DDoS Attack](./threats/http_flood_ddos_attack.md)

*   **Description:** An attacker sends a massive volume of HTTP requests, overwhelming Nginx's capacity to process them, often from a botnet.
*   **Impact:** Denial of service; application unavailability.
*   **Nginx Component Affected:** Core Nginx connection handling, worker processes, potentially upstream servers.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Rate Limiting:** Use `limit_req` to restrict requests from a single IP address. This is a *crucial* defense.
    *   **Connection Limiting (with caution):** `limit_conn` can help, but consider legitimate users behind shared proxies.
    *   **Web Application Firewall (WAF):** A WAF is *highly recommended*.
    *   **CDN:** A CDN can absorb much of the attack traffic.
    *   **Upstream Capacity:** Ensure upstream servers can handle legitimate traffic.

## Threat: [HTTP Request Smuggling](./threats/http_request_smuggling.md)

*   **Description:** An attacker crafts an ambiguous HTTP request interpreted differently by Nginx and a backend server, often using conflicting `Content-Length` and `Transfer-Encoding` headers, "smuggling" a malicious request.
*   **Impact:** Bypass of security controls, potential unauthorized access, data modification, or even RCE (depending on the backend).
*   **Nginx Component Affected:** HTTP request parsing, interaction with upstream servers via `proxy_pass`.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Consistent Configuration:** Ensure Nginx and backend servers use the *same* HTTP parsing rules.
    *   **Reject Ambiguous Requests (if possible):** Some servers/WAFs can reject requests with conflicting headers.
    *   **Web Application Firewall (WAF):** A WAF with HTTP protocol validation is *essential*.
    *   **Keep Software Updated:** Vulnerabilities are often patched in newer versions.

## Threat: [Weak SSL/TLS Configuration](./threats/weak_ssltls_configuration.md)

*   **Description:** An attacker intercepts encrypted communication. If Nginx uses weak ciphers, outdated protocols (SSLv3, TLS 1.0, TLS 1.1), or has an improperly configured certificate, the attacker can decrypt traffic, stealing sensitive data.
*   **Impact:** Loss of confidentiality; sensitive data exposed; MITM attacks possible.
*   **Nginx Component Affected:** `ssl_protocols`, `ssl_ciphers`, `ssl_certificate`, `ssl_certificate_key` directives (`ngx_http_ssl_module`).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Use Strong Ciphers and Protocols:** Only TLS 1.2 and TLS 1.3, with strong cipher suites.
    *   **Use a Valid Certificate:** Obtain a certificate from a trusted CA.
    *   **Enable HSTS:** Use `add_header` to add the `Strict-Transport-Security` header.
    *   **Regularly Test Configuration:** Use tools like SSL Labs' SSL Server Test.

## Threat: [Misconfigured `proxy_pass`](./threats/misconfigured__proxy_pass_.md)

*   **Description:** An attacker exploits an incorrectly configured `proxy_pass` directive to access unintended backend resources or bypass security restrictions (e.g., missing trailing slash, overly permissive regex).
*   **Impact:** Unauthorized access to backend systems, potential data breaches or server compromise.
*   **Nginx Component Affected:** `proxy_pass` directive (`ngx_http_proxy_module`), `location` block configuration.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Careful Configuration:** Thoroughly review and test `proxy_pass` configurations. Be precise with location matching.
    *   **Principle of Least Privilege:** Only expose necessary backend resources.
    *   **Input Validation (at the application level):** Backend application should still validate input and enforce authorization.

## Threat: [Vulnerability in Nginx Core or Modules](./threats/vulnerability_in_nginx_core_or_modules.md)

*   **Description:** An attacker exploits a newly discovered or unpatched vulnerability in Nginx core or a loaded module, potentially leading to DoS, information disclosure, or RCE.
*   **Impact:** Varies, but can range from DoS to complete server compromise.
*   **Nginx Component Affected:** Potentially any part of Nginx core or any loaded module.
*   **Risk Severity:** Varies (High to Critical), depending on the vulnerability.
*   **Mitigation Strategies:**
    *   **Keep Nginx Updated:** This is the *most important* mitigation. Regularly update to the latest stable release.
    *   **Use Only Necessary Modules:** Minimize the attack surface.
    *   **Use Trusted Modules:** Only install from reputable sources; review code/security history.
    *   **Monitor Security Advisories:** Subscribe to Nginx security announcements.

## Threat: [HPACK Bomb (HTTP/2)](./threats/hpack_bomb__http2_.md)

*   **Description:** An attacker sends a crafted HTTP/2 request with a compressed header block (HPACK) that consumes excessive CPU when decompressed, causing DoS.
*   **Impact:** Denial of service due to CPU exhaustion.
*   **Nginx Component Affected:** `ngx_http_v2_module` (HTTP/2 module).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Keep Nginx Updated:** Nginx has implemented mitigations.
    *   **Limit HTTP/2 Header Size:** Use `http2_max_header_size`.
    *   **Web Application Firewall (WAF):** A WAF with HTTP/2 support can help.
    *   **Rate Limiting (limit_req):** Can help mitigate the impact.

