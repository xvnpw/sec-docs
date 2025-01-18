# Attack Surface Analysis for dart-lang/http

## Attack Surface: [Man-in-the-Middle (MITM) due to Insufficient TLS Configuration](./attack_surfaces/man-in-the-middle__mitm__due_to_insufficient_tls_configuration.md)

* **Description:** Attackers intercept communication between the application and a remote server, potentially reading or modifying sensitive data.
    * **How http contributes to the attack surface:** The `http` package handles the underlying network communication, including TLS/SSL. If the application doesn't explicitly configure secure connections (HTTPS) or disables certificate validation, it becomes vulnerable.
    * **Example:** An application makes an HTTP request (instead of HTTPS) to a server containing user credentials. An attacker on the network intercepts the request and steals the credentials.
    * **Impact:** Confidentiality breach, data manipulation, account compromise.
    * **Risk Severity:** Critical
    * **Mitigation Strategies:**
        * Always use HTTPS: Ensure all requests are made over secure connections.
        * Enforce certificate validation: Do not disable or bypass certificate validation. The `http` package allows customization of `badCertificateCallback`, ensure it's not used to allow invalid certificates.
        * Enforce strong TLS versions and cipher suites: Configure the `HttpClient` to use secure protocols and ciphers.
        * Consider Certificate Pinning: For critical connections, pin the expected server certificate to prevent MITM attacks even with compromised CAs.

## Attack Surface: [Server-Side Request Forgery (SSRF)](./attack_surfaces/server-side_request_forgery__ssrf_.md)

* **Description:** An attacker can induce the application to make requests to unintended locations, potentially internal resources or external services.
    * **How http contributes to the attack surface:** The `http` package provides the functionality to make arbitrary HTTP requests. If the target URL is constructed based on user input without proper sanitization, attackers can control the destination.
    * **Example:** A user provides a URL as input, and the application uses the `http` package to fetch content from that URL. An attacker provides an internal IP address (e.g., `http://192.168.1.10/admin`) forcing the application to make a request to an internal service.
    * **Impact:** Access to internal resources, information disclosure, potential for further attacks on internal systems.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * Validate and sanitize user-provided URLs: Implement strict validation to ensure URLs are within expected domains and protocols.
        * Use allow-lists for target domains: Restrict the application's ability to make requests to a predefined set of trusted domains.
        * Avoid directly using user input in URL construction: If possible, use identifiers that map to internal resources instead of directly using user-provided URLs.
        * Implement network segmentation: Isolate internal networks from the internet-facing application.

## Attack Surface: [Exposure of Sensitive Information in Request/Response Data](./attack_surfaces/exposure_of_sensitive_information_in_requestresponse_data.md)

* **Description:** Sensitive information is unintentionally included in HTTP requests or responses, making it vulnerable to interception or logging.
    * **How http contributes to the attack surface:** The `http` package handles the transmission of request and response data. If the application includes sensitive data in URLs, headers, or bodies without proper consideration for security, it can be exposed.
    * **Example:** An application includes an API key directly in the URL query parameters when making a request using the `http` package. This key could be logged on intermediate servers or visible in browser history.
    * **Impact:** Confidentiality breach, unauthorized access, account compromise.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * Avoid including sensitive information in URLs: Use request bodies or secure headers for sensitive data.
        * Use appropriate HTTP methods: Use POST requests for sending sensitive data in the body.
        * Encrypt sensitive data: Encrypt sensitive data before sending it in requests or storing it in responses.
        * Implement secure logging practices: Avoid logging sensitive information or sanitize logs before storage.

