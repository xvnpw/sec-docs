# Threat Model Analysis for apache/httpcomponents-core

## Threat: [Inadequate Hostname Verification](./threats/inadequate_hostname_verification.md)

*   **Threat:** Inadequate Hostname Verification

    *   **Description:** An attacker performs a Man-in-the-Middle (MITM) attack, intercepting the TLS connection. They present a forged certificate for the target domain. Because the application's hostname verification is misconfigured or disabled (using `NoopHostnameVerifier` or `AllowAllHostnameVerifier`), it accepts the invalid certificate.
    *   **Impact:** The attacker can decrypt, modify, and re-encrypt traffic. This leads to complete compromise of confidentiality and integrity, allowing credential theft, data manipulation, and injection of malicious content.
    *   **Affected Component:** `org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory`, specifically the `HostnameVerifier` used during the TLS handshake. Incorrect use of `NoopHostnameVerifier` or `AllowAllHostnameVerifier`.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Use the `DefaultHostnameVerifier` (or a custom verifier with equally strict rules).
        *   Explicitly configure the `SSLConnectionSocketFactory` with the chosen `HostnameVerifier`.
        *   Thoroughly test certificate validation with valid and *invalid* certificates.
        *   Avoid using `NoopHostnameVerifier` or `AllowAllHostnameVerifier` in production.

## Threat: [HTTP Request Smuggling (Client-Side)](./threats/http_request_smuggling__client-side_.md)

*   **Threat:** HTTP Request Smuggling (Client-Side)

    *   **Description:** The application sends an HTTP request with ambiguous headers (e.g., conflicting `Content-Length` and `Transfer-Encoding`). The frontend server (using HttpComponents Core) and the backend server interpret the request differently, allowing a "smuggled" second request. While HttpComponents Core *aims* to prevent this, incorrect usage or interaction with vulnerable backends can still lead to issues. This is considered "direct" because the library's handling of headers is involved, even if a vulnerable backend is also required.
    *   **Impact:** The attacker can bypass security controls, access unauthorized resources, poison the web cache, or hijack user sessions.
    *   **Affected Component:** `org.apache.hc.core5.http.message.BasicHttpRequest` (and related classes for constructing requests), specifically how headers are handled and validated. Interaction with a vulnerable backend is a key factor, but the library's role in constructing the request makes it a direct concern.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Use the latest version of HttpComponents Core.
        *   Ensure strict adherence to HTTP/1.1 and HTTP/2 specifications when constructing requests.
        *   Validate and sanitize all outgoing HTTP headers.
        *   Avoid forwarding user-supplied data directly into headers without validation.
        *   Test interaction with the backend server using tools that detect request smuggling.
        *   Consider a Web Application Firewall (WAF).

