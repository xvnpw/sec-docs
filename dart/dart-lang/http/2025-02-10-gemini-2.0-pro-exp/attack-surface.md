# Attack Surface Analysis for dart-lang/http

## Attack Surface: [Server-Side Request Forgery (SSRF)](./attack_surfaces/server-side_request_forgery__ssrf_.md)

*   **Description:**  The application allows an attacker to control the URL used by the `http` package to make requests, enabling them to access internal resources or external systems.
*   **How `http` Contributes:**  `http` is the *essential* tool used to make the network request to the attacker-controlled URL.  Without the `http` package's request functionality, the SSRF attack is not possible in this context.
*   **Example:**  An application uses `http.get(userProvidedUrl)` to fetch data. The attacker provides `http://169.254.169.254/latest/meta-data/` to retrieve cloud instance metadata.
*   **Impact:**  Access to internal services, data exfiltration, network scanning, potential remote code execution.
*   **Risk Severity:**  Critical (if sensitive internal resources are accessible) or High (depending on accessible resources).
*   **Mitigation Strategies:**
    *   **Strict URL Whitelist:**  Allow only specific, pre-approved URLs or domains.  Reject all others.
    *   **Network Segmentation:**  Isolate the application from sensitive internal networks.
    *   **Disable Unnecessary Protocols:** Restrict allowed URL schemes (e.g., only `https://`).
    *   **Do Not Return Raw Responses:** Process and sanitize data from the `http` response before returning it to the user.

## Attack Surface: [Unvalidated Redirects (when automatic redirects are enabled)](./attack_surfaces/unvalidated_redirects__when_automatic_redirects_are_enabled_.md)

*   **Description:** The application, using `http`'s default or explicitly enabled automatic redirect handling, follows HTTP redirects (3xx status codes) without validating the target URL.
*   **How `http` Contributes:** `http`'s *automatic redirect following* is the core mechanism that enables this attack.  If redirects were handled manually, this specific vulnerability wouldn't exist.
*   **Example:**  An application uses `http.get(url)` and the server responds with a 302 redirect to `https://malicious.com`.  `http` automatically follows the redirect, sending the user's request (potentially including cookies or headers) to the malicious site.
*   **Impact:**  Phishing attacks, open redirect vulnerabilities, potential SSRF (if the redirect points internally).
*   **Risk Severity:** High (due to phishing potential).
*   **Mitigation Strategies:**
    *   **Disable Automatic Redirects:**  Configure the `http` client to *not* automatically follow redirects (this is the *most secure* option).  Handle redirects manually.  This is done by creating a custom `Client` and overriding the `send` method.
    *   **Whitelist Redirect Targets:** If automatic redirects are *absolutely required*, implement a strict whitelist of allowed redirect target domains.
    *   **Check `response.isRedirect` and `response.headers['location']`:** Before following redirect, check these properties.

