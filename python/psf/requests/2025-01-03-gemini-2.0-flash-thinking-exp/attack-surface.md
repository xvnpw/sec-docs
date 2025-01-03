# Attack Surface Analysis for psf/requests

## Attack Surface: [Server-Side Request Forgery (SSRF)](./attack_surfaces/server-side_request_forgery_(ssrf).md)

- **Description:** An attacker can induce the application to make HTTP requests to arbitrary destinations, potentially internal resources or external systems.
    - **How Requests Contributes:** The `requests` library is the mechanism used to make these HTTP requests. If the target URL is not properly validated and is influenced by user input, it becomes vulnerable.
    - **Example:** An application takes a URL as input to fetch content. An attacker provides `http://internal-server/admin` as the URL, and the application, using `requests`, fetches this internal page.
    - **Impact:** Access to internal resources, potential data breaches, port scanning of internal networks, denial of service against internal services.
    - **Risk Severity:** Critical
    - **Mitigation Strategies:**
        - **Strict Input Validation:** Sanitize and validate all user-provided URLs against a whitelist of allowed hosts or patterns.
        - **URL Parsing and Verification:**  Parse URLs to extract the hostname and verify it against allowed lists.
        - **Disable or Restrict Redirections:** Carefully manage or disable automatic redirections to prevent attackers from redirecting requests to internal hosts.
        - **Network Segmentation:** Isolate the application server from internal resources if possible.
        - **Use a Proxy or Firewall:** Route `requests` traffic through a proxy that can enforce restrictions on outbound requests.

## Attack Surface: [Header Injection](./attack_surfaces/header_injection.md)

- **Description:** Attackers can inject arbitrary HTTP headers into requests made by the application.
    - **How Requests Contributes:** The `requests` library allows setting custom headers. If header values are directly taken from user input without sanitization, injection is possible.
    - **Example:** An application allows users to set a custom `User-Agent` header. An attacker injects `X-Forwarded-For: malicious.host` which might be trusted by backend systems.
    - **Impact:** Bypassing security controls, cache poisoning, cross-site scripting (if response headers are reflected), information disclosure.
    - **Risk Severity:** High
    - **Mitigation Strategies:**
        - **Strict Input Validation:** Sanitize and validate all user-provided header values.
        - **Use Safe Header Setting Methods:** If possible, use specific `requests` parameters for standard headers instead of directly manipulating the `headers` dictionary.
        - **Avoid Reflecting Response Headers:** Be cautious when reflecting response headers back to the user.

## Attack Surface: [Insecure TLS/SSL Configuration](./attack_surfaces/insecure_tlsssl_configuration.md)

- **Description:** The application might be configured to make requests over insecure connections or with weak TLS/SSL settings.
    - **How Requests Contributes:** `requests` provides options to disable SSL verification (`verify=False`) or use specific TLS versions. Misconfiguration can expose traffic.
    - **Example:** An application sets `verify=False` to bypass certificate errors, making it vulnerable to Man-in-the-Middle (MitM) attacks.
    - **Impact:** Man-in-the-Middle (MitM) attacks, eavesdropping on sensitive data, data tampering.
    - **Risk Severity:** High
    - **Mitigation Strategies:**
        - **Enable SSL Verification:** Always set `verify=True` and ensure the system has up-to-date CA certificates.
        - **Specify Minimum TLS Version:** Configure `requests` to use a secure minimum TLS version (e.g., TLS 1.2 or higher).
        - **Review Cipher Suites:** Ensure that strong and secure cipher suites are used.
        - **Handle Certificate Errors Properly:** Instead of disabling verification, investigate and fix the underlying certificate issues.

