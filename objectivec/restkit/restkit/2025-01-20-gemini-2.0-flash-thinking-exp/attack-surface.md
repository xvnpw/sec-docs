# Attack Surface Analysis for restkit/restkit

## Attack Surface: [Server-Side Request Forgery (SSRF) via Unvalidated Base URLs](./attack_surfaces/server-side_request_forgery__ssrf__via_unvalidated_base_urls.md)

*   **Description:** An attacker can manipulate the application to make unintended HTTP requests to arbitrary internal or external servers.
    *   **How RestKit Contributes:** `RKObjectManager` uses a base URL for API requests. If this base URL is derived from user input or a weakly controlled configuration without proper validation, an attacker can modify it.
    *   **Example:** An attacker modifies a configuration file or API endpoint that sets the `baseURL` of `RKObjectManager` to an internal server address, allowing them to scan internal ports or access internal resources.
    *   **Impact:** Access to internal resources, potential data breaches, launching attacks from the application's infrastructure.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Developer:**  Strictly validate and sanitize any input used to construct the base URL for `RKObjectManager`. Use a whitelist of allowed base URLs if possible. Avoid dynamic base URL construction based on user input.

## Attack Surface: [Header Injection via Custom Headers](./attack_surfaces/header_injection_via_custom_headers.md)

*   **Description:** An attacker can inject malicious HTTP headers into requests made by the application.
    *   **How RestKit Contributes:** RestKit allows setting custom headers using methods like `setValue:forHeaderField:`. If the values for these headers are taken directly from user input without sanitization, injection is possible.
    *   **Example:** An attacker provides a malicious value for a custom header like `X-Forwarded-For`, potentially bypassing IP-based access controls on the server.
    *   **Impact:** Bypassing security controls, cache poisoning, session hijacking (depending on the injected header).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developer:** Sanitize and validate all user-provided input before setting it as a header value. Use predefined header values where possible. Be cautious with headers that influence server-side logic.

## Attack Surface: [Insecure Communication via HTTP](./attack_surfaces/insecure_communication_via_http.md)

*   **Description:** Sensitive data is transmitted over an unencrypted HTTP connection, making it vulnerable to interception.
    *   **How RestKit Contributes:** While RestKit supports HTTPS, developers might incorrectly configure it to use HTTP or allow the protocol to be determined by user-provided URLs without enforcement.
    *   **Example:** An application connects to an API using a URL starting with `http://`, exposing authentication tokens or personal data during transmission.
    *   **Impact:** Data breaches, credential theft, man-in-the-middle attacks.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Developer:**  Enforce HTTPS for all API communication. Configure `RKObjectManager` to only accept HTTPS URLs. Implement certificate pinning for added security.

## Attack Surface: [Exposure of Sensitive Data in Mapped Objects](./attack_surfaces/exposure_of_sensitive_data_in_mapped_objects.md)

*   **Description:** Sensitive information received from the API is inadvertently stored or logged in application objects without proper protection.
    *   **How RestKit Contributes:** RestKit automatically maps data from API responses to application objects. If developers don't explicitly handle sensitive data, it might be stored in memory or logs in plain text.
    *   **Example:** API responses contain sensitive user details or authentication tokens, which are mapped to application objects and then logged or persisted without encryption.
    *   **Impact:** Data breaches, privacy violations.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developer:**  Carefully review the data being mapped. Mark sensitive properties as transient or exclude them from mapping if they don't need to be persisted. Implement secure storage mechanisms for sensitive data. Avoid logging sensitive information.

