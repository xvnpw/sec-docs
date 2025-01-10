# Attack Surface Analysis for onevcat/fengniao

## Attack Surface: [URL Manipulation through `baseURL` and Path Components](./attack_surfaces/url_manipulation_through__baseurl__and_path_components.md)

*   **Description:** Attackers can manipulate the final URL constructed by the application if path components are not properly validated or sanitized before being combined with the `baseURL`.
    *   **How FengNiao Contributes:** FengNiao provides the `baseURL` and methods to append path components. If the application logic concatenates untrusted input as path components, FengNiao facilitates the construction of malicious URLs.
    *   **Example:** An application takes user input for a document name and appends it to the base URL. A malicious user inputs `../../sensitive_data`. FengNiao, without application-level validation, would make a request to a potentially sensitive resource.
    *   **Impact:** Access to unauthorized resources, bypassing access controls, information disclosure.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Implement strict input validation and sanitization on all data used to construct URLs *before* passing it to FengNiao.
        *   Use parameterized requests or URL builders provided by FengNiao (if available and suitable) to avoid direct string concatenation.
        *   Avoid directly incorporating user-provided data into URL paths when using FengNiao. If necessary, use a whitelist of allowed values or encode the data appropriately.

## Attack Surface: [Parameter Injection through `parameters`](./attack_surfaces/parameter_injection_through__parameters_.md)

*   **Description:** Attackers can inject malicious data into request parameters if the application doesn't sanitize or validate the values passed to FengNiao's `parameters` dictionary.
    *   **How FengNiao Contributes:** FengNiao directly transmits the content of the `parameters` dictionary in the request. It does not inherently sanitize or validate this data.
    *   **Example:** An application uses user input to search for items. A malicious user inputs a SQL injection payload (e.g., `' OR '1'='1`). FengNiao will send this unsanitized data to the backend.
    *   **Impact:** SQL injection, command injection, server-side request forgery (SSRF) depending on how the backend processes the parameters.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Always validate and sanitize all input data *before* adding it to the `parameters` dictionary used with FengNiao.
        *   The backend API should also implement parameterized queries or prepared statements to prevent SQL injection regardless of client-side sanitization.

## Attack Surface: [Header Injection through `headers`](./attack_surfaces/header_injection_through__headers_.md)

*   **Description:** Attackers can inject malicious headers if the application allows user-controlled data to be used as header values in FengNiao's `headers` dictionary.
    *   **How FengNiao Contributes:** FengNiao allows setting arbitrary headers through the `headers` dictionary. It does not prevent the inclusion of potentially harmful headers or values.
    *   **Example:** An application allows users to set a custom user-agent. A malicious user injects a header like `X-Forwarded-For: malicious_ip\r\nEvil-Header: attack` using FengNiao's `headers` functionality. This could lead to HTTP response splitting or other header-based attacks.
    *   **Impact:** HTTP response splitting, session fixation, bypassing security mechanisms (e.g., manipulating CSP headers if the backend blindly trusts them).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Avoid allowing user-controlled data to directly set HTTP headers when using FengNiao.
        *   If custom headers are necessary, use a predefined set of allowed headers and validate the values against a strict whitelist *before* setting them in FengNiao's `headers`.

## Attack Surface: [Insecure Handling of Redirects](./attack_surfaces/insecure_handling_of_redirects.md)

*   **Description:** If the application automatically follows redirects returned by the server through FengNiao without proper validation of the redirect URL, attackers could redirect users to malicious websites.
    *   **How FengNiao Contributes:** FengNiao, by default, will follow HTTP redirects. This behavior, if not controlled by the application, can lead to users being redirected to untrusted locations.
    *   **Example:** An attacker compromises a legitimate endpoint and configures it to redirect to a phishing site. The application using FengNiao automatically follows this redirect, potentially exposing users to the malicious site.
    *   **Impact:** Phishing attacks, malware distribution.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Configure FengNiao to *not* automatically follow redirects and handle redirects manually, allowing for validation of the redirect URL before proceeding.
        *   If automatic redirects are necessary, strictly validate the redirect URL against a whitelist of allowed domains *after* FengNiao receives the redirect response but before acting upon it (if such an interception point is available).

