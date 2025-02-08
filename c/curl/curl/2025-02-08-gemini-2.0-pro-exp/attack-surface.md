# Attack Surface Analysis for curl/curl

## Attack Surface: [Man-in-the-Middle (MitM) via TLS Misconfiguration](./attack_surfaces/man-in-the-middle__mitm__via_tls_misconfiguration.md)

*   **Description:** An attacker intercepts the communication between the application and the server, potentially reading or modifying data in transit.
*   **How curl contributes:** `libcurl` handles TLS/SSL connections. If TLS verification is disabled or improperly configured, `libcurl` will not detect a fraudulent certificate presented by an attacker.
*   **Example:** An application uses `libcurl` to connect to `https://api.example.com`, but `CURLOPT_SSL_VERIFYPEER` is set to 0. An attacker on the same network presents a self-signed certificate for `api.example.com`, and the application accepts it, allowing the attacker to see all API requests and responses.
*   **Impact:** Complete compromise of data confidentiality and integrity. The attacker can steal credentials, inject malicious data, or impersonate the server.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Developers:**
        *   Ensure `CURLOPT_SSL_VERIFYPEER` is set to 1 (enabled).
        *   Ensure `CURLOPT_SSL_VERIFYHOST` is set to 2 (verify hostname).
        *   Provide a valid CA bundle using `CURLOPT_CAINFO` or `CURLOPT_CAPATH`.
        *   Consider certificate pinning (`CURLOPT_PINNEDPUBLICKEY`) for high-security scenarios, but carefully manage the operational complexities.
        *   Avoid custom verification callbacks unless absolutely necessary and thoroughly audited by security experts.

## Attack Surface: [HTTP Request Smuggling](./attack_surfaces/http_request_smuggling.md)

*   **Description:** An attacker exploits ambiguities in how `libcurl` and the server handle malformed HTTP requests to inject additional requests, bypassing security controls.
*   **How curl contributes:** `libcurl` constructs and sends HTTP requests. Vulnerabilities in how it handles headers like `Transfer-Encoding` and `Content-Length` can be exploited.
*   **Example:** An attacker sends a specially crafted request with conflicting `Transfer-Encoding` and `Content-Length` headers. `libcurl` and the server interpret the request differently, allowing the attacker to "smuggle" a second request that bypasses authentication.
*   **Impact:** Bypass of security controls, unauthorized access to resources, potential for data modification or exfiltration.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developers:**
        *   Keep `libcurl` updated to the latest version.
        *   Avoid manually setting `Transfer-Encoding` or `Content-Length` headers using `CURLOPT_HTTPHEADER` unless absolutely necessary and with extreme caution. Validate any user-supplied input used in these headers.
        *   Ensure the backend server is configured to reject ambiguous requests and is also patched against request smuggling vulnerabilities.
        *   Use a Web Application Firewall (WAF) that can detect and block request smuggling attempts.

## Attack Surface: [Plaintext Protocol Usage (FTP)](./attack_surfaces/plaintext_protocol_usage__ftp_.md)

*   **Description:** Using unencrypted protocols like plain FTP transmits data, including credentials, in cleartext, making it vulnerable to eavesdropping.
*   **How curl contributes:** `libcurl` supports various protocols, including insecure ones like plain FTP. If the application uses plain FTP, `libcurl` will transmit data without encryption.
*   **Example:** An application uses `libcurl` to connect to `ftp://example.com` to download files. An attacker on the same network can sniff the network traffic and capture the FTP username and password.
*   **Impact:** Exposure of sensitive data, including credentials, leading to unauthorized access.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developers:**
        *   *Always* prefer secure alternatives: FTPS (`ftps://`) or SFTP (`sftp://`) over plain FTP.
        *   If plain FTP is unavoidable (e.g., legacy systems), strongly warn users about the risks.
        *   Consider tunneling the connection through a VPN or other secure channel if plain FTP must be used.

## Attack Surface: [libcurl Vulnerabilities (Buffer Overflows, Integer Overflows, etc.)](./attack_surfaces/libcurl_vulnerabilities__buffer_overflows__integer_overflows__etc__.md)

*   **Description:** `libcurl` itself can have vulnerabilities (e.g., buffer overflows, integer overflows) that can be exploited by malicious servers or crafted URLs.
*   **How curl contributes:** These are vulnerabilities *within* the `libcurl` library code itself.
*   **Example:** A malicious server sends a specially crafted response that triggers a buffer overflow in `libcurl`, leading to arbitrary code execution within the application.
*   **Impact:** Potentially complete system compromise, depending on the nature of the vulnerability and the application's privileges.
*   **Risk Severity:** High to Critical (depending on the specific vulnerability)
*   **Mitigation Strategies:**
    *   **Developers:**
        *   *Keep `libcurl` updated to the latest version.* This is the most crucial mitigation.
        *   Use a memory-safe language (if possible) to interact with `libcurl`'s C API, reducing the risk of introducing *new* vulnerabilities in the application's wrapper code.
        *   Consider using fuzzing techniques to test the application's interaction with `libcurl`.
        *   If using a language with a `libcurl` binding, ensure the binding is also kept up-to-date.

## Attack Surface: [Sensitive Data in URLs](./attack_surfaces/sensitive_data_in_urls.md)

*   **Description:** Including sensitive information, like API keys or passwords, directly in the URL.
*   **How curl contributes:** `libcurl` processes the provided URL. If the URL contains sensitive data, `libcurl` will transmit it as part of the request.
*   **Example:** An application uses `libcurl` to make a request to `https://api.example.com/data?apikey=SECRET_KEY`. The `SECRET_KEY` is exposed in logs, browser history, and potentially to intermediate proxies.
*   **Impact:** Exposure of sensitive credentials, leading to unauthorized access.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Developers:**
        *   Use HTTP headers (e.g., `Authorization`, a custom header) to transmit API keys, tokens, or other credentials.
        *   Use the request body (e.g., for POST requests) to send sensitive data, rather than the URL.
        *   Never include secrets directly in the URL.

