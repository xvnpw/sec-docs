# Attack Surface Analysis for dart-lang/http

## Attack Surface: [URL Injection](./attack_surfaces/url_injection.md)

*   **Description:** Attackers can manipulate the URL used in HTTP requests by injecting malicious code or parameters. This leads to the `http` package making requests to unintended or malicious locations.
*   **How http contributes:** The `http` package's functions like `http.get(Uri.parse(userInput))` directly process URLs provided as strings or `Uri` objects. If these URLs are constructed from unsanitized user input, the `http` package will execute requests to attacker-controlled URLs.
*   **Example:** An application uses `http.get(Uri.parse(userInput))` where `userInput` is taken directly from a user. An attacker provides `https://example.com/api?param=value&redirect=//malicious.site`. The `http` package will attempt to fetch content from `https://example.com/api?param=value&redirect=//malicious.site`, potentially leading to redirection to `malicious.site` depending on server-side behavior.
*   **Impact:** Redirection to phishing sites, exfiltration of sensitive data to attacker-controlled servers, bypassing intended access controls, potential server-side vulnerability exploitation if the manipulated URL is processed by the backend.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Strict Input Validation:**  Thoroughly validate and sanitize all user-provided input *before* constructing URLs that are passed to `http` methods.
    *   **Secure URL Construction:** Use secure URL parsing and construction methods. Avoid string concatenation of user input directly into URLs. Utilize `Uri` class methods for safe URL manipulation and parameter encoding.
    *   **Parameterization:** Favor parameterized queries over embedding user input directly into URL paths.
    *   **Content Security Policy (CSP) for Web Contexts:** Implement CSP headers in web applications to limit the impact of potential redirection vulnerabilities initiated via `http` requests.

## Attack Surface: [Header Injection](./attack_surfaces/header_injection.md)

*   **Description:** Attackers can inject malicious headers into HTTP requests by manipulating header values provided to the `http` package. This can lead to server-side misbehavior or exploitation of intermediary systems.
*   **How http contributes:** The `http` package allows setting custom headers via the `headers` parameter in request methods (e.g., `http.get(url, headers: {'X-Custom-Header': userInput})`). If `userInput` is not sanitized, attackers can inject arbitrary headers.
*   **Example:** An application uses `http.post(url, headers: {'User-Agent': userInput})` where `userInput` is directly from user input. An attacker provides `Evil-Header: Malicious-Value\r\nUser-Agent: My-Legit-Agent`. The `http` package will send these headers. The server or intermediary systems might interpret `Evil-Header: Malicious-Value` as a separate header due to the newline injection (`\r\n`), leading to unintended behavior.
*   **Impact:** Server-side misbehavior, bypassing security controls, potential exploitation of vulnerabilities in proxies or servers that process headers, information disclosure through manipulated headers.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Header Value Sanitization:** Sanitize and validate user input intended for HTTP header values *before* passing them to the `headers` parameter in `http` methods. Remove or encode characters that could be interpreted as header separators or control characters (e.g., newline characters, colon).
    *   **Avoid User-Controlled Headers (Where Possible):** Minimize the use of user-controlled headers. If custom headers are necessary, use a whitelist approach for allowed header names and strictly validate values.
    *   **Secure Server-Side Header Handling:** Ensure backend systems are robust against header injection attacks and properly handle potentially unexpected or malicious headers sent by the `http` client.

## Attack Surface: [Unvalidated Redirects](./attack_surfaces/unvalidated_redirects.md)

*   **Description:** If an application relies on the `http` package's default redirect following behavior without validating the redirect target, attackers can force the application to follow redirects to malicious sites.
*   **How http contributes:** The `http` package, by default, automatically follows HTTP redirects. If an application uses `http` to fetch resources and doesn't explicitly control or validate redirects, it can be vulnerable.
*   **Example:** An application uses `http.get(userInputUrl)` to fetch content. An attacker provides a `userInputUrl` that initially points to a legitimate site but redirects (via HTTP 301/302) to a phishing site. The `http` package, by default, will follow this redirect and the application might unknowingly process content from or redirect the user to the malicious site.
*   **Impact:** Phishing attacks, malware distribution, exposure to malicious content, potential for further attacks if the application processes content from the malicious redirect target without validation.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Redirect Validation:** When using `http` to fetch resources, especially from user-provided or untrusted sources, validate the target URL of redirects *before* allowing the `http` package to follow them. Check against a whitelist of allowed domains or implement other validation logic.
    *   **Disable Automatic Redirects and Handle Manually:** Configure the `http` client to *not* automatically follow redirects (using `Client` options if available, or by inspecting response codes). Implement manual redirect handling with explicit validation of the `Location` header before making a new request.
    *   **Inform Users (If Necessary):** If redirection is required and validation is complex, consider informing users about potential redirects and the target domain before proceeding, especially in user-facing applications.

