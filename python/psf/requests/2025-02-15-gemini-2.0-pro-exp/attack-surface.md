# Attack Surface Analysis for psf/requests

## Attack Surface: [Unvalidated Redirects](./attack_surfaces/unvalidated_redirects.md)

*   **Description:**  The application blindly follows HTTP redirects (3xx status codes) without verifying the destination, potentially leading to malicious sites.
*   **How `requests` Contributes:** `requests` follows redirects by default (`allow_redirects=True`). This is a *direct* feature of `requests`.
*   **Example:**
    1.  Application requests `https://example.com/login`.
    2.  Attacker compromises `example.com` or intercepts the request.
    3.  Server responds with a 302 redirect to `https://evil.com/fake-login`.
    4.  `requests` automatically follows the redirect.
    5.  User unknowingly enters credentials on `evil.com`.
*   **Impact:** Credential theft, phishing, malware download, session hijacking.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Disable Redirects:** Use `allow_redirects=False` if redirects are not essential. This is the most direct and effective mitigation.
    *   **Whitelist Redirect Domains:** If redirects are necessary, maintain a strict whitelist of allowed domains.  Validate the `Location` header against this whitelist *before* allowing `requests` to follow the redirect.  Do *not* rely solely on the initial URL.
    *   **Custom Redirect Validation:** Implement a function to check for common redirect attack patterns (open redirects, relative path redirects).

## Attack Surface: [Man-in-the-Middle (MitM) Attacks (TLS/SSL Issues)](./attack_surfaces/man-in-the-middle__mitm__attacks__tlsssl_issues_.md)

*   **Description:**  An attacker intercepts communication between the application and the server due to disabled or improperly configured TLS/SSL certificate verification.
*   **How `requests` Contributes:** `requests` provides the `verify` parameter for certificate validation.  Incorrect configuration (e.g., `verify=False`) directly exposes the application. This is a core feature of how `requests` handles secure connections.
*   **Example:**
    1.  Application makes a request to `https://api.example.com`.
    2.  Attacker intercepts the connection and presents a fake certificate.
    3.  If `verify=False` or the CA bundle is misconfigured, `requests` will not detect the invalid certificate.
    4.  Attacker can read and modify all data exchanged.
*   **Impact:**  Complete compromise of communication, data theft, data manipulation, credential theft.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Enable Certificate Verification:**  Always use `verify=True` (the default) in production. This is the primary and most direct mitigation.
    *   **Use a Valid CA Bundle:** Ensure the `verify` parameter points to a valid and up-to-date CA bundle (or relies on the system's default bundle).
    *   **Avoid `verify=False`:** Never disable certificate verification in production.
    *   **Certificate Pinning (Advanced):** Consider using certificate pinning (with libraries like `requests-toolbelt`) for enhanced security, but be aware of the operational complexities.

## Attack Surface: [Server-Side Request Forgery (SSRF)](./attack_surfaces/server-side_request_forgery__ssrf_.md)

*   **Description:**  The application allows user-controlled input to specify the URL that `requests` will fetch, enabling requests to internal or sensitive resources.
*   **How `requests` Contributes:** `requests` fetches data from the URL provided to it.  If this URL is controlled by an attacker, SSRF is possible. This is a direct consequence of how `requests` operates.
*   **Example:**
    1.  Application has a feature to fetch data from a URL provided by the user: `/fetch?url=http://example.com`.
    2.  Attacker provides a malicious URL: `/fetch?url=http://169.254.169.254/latest/meta-data/` (AWS metadata service).
    3.  `requests` fetches data from the internal AWS metadata service, potentially exposing sensitive information.
*   **Impact:** Access to internal systems, cloud metadata, sensitive data exposure, potential for remote code execution.
*   **Risk Severity:** High to Critical (depending on the accessible resources)
*   **Mitigation Strategies:**
    *   **Avoid User-Controlled URLs:**  Do not allow users to directly specify the URL used by `requests`. This is the most effective mitigation.
    *   **Strict Whitelist:** If user-provided URLs are unavoidable, implement a very strict whitelist of allowed domains and protocols.  *Never* use a blacklist.
    *   **URL Validation:**  Thoroughly validate and sanitize any user-provided URL *before* passing it to `requests`.
    *   **Network Isolation:** Run the application in an isolated environment (e.g., a container) with limited network access.  (While this is a general security practice, it *directly* mitigates the impact of SSRF via `requests`.)
    *   **"Deny by Default" Network Policy:** Configure the application's environment to deny all outbound network connections except those explicitly required. (Similar to network isolation, this directly limits the damage from SSRF.)

## Attack Surface: [Content-Type Spoofing](./attack_surfaces/content-type_spoofing.md)

*   **Description:** The application does not properly validate the `Content-Type` header of the response, potentially leading to misinterpretation of the data.
*   **How `requests` Contributes:** `requests` provides the `Content-Type` header in the `response.headers` dictionary, but it's the application's responsibility to validate it. The library is directly involved in providing access to this potentially malicious header.
*   **Example:**
    1.  Application requests a resource expecting a JSON response.
    2.  Attacker sends a response with `Content-Type: application/json` but the body contains HTML with malicious JavaScript.
    3.  If the application doesn't validate the content, it might execute the JavaScript.
*   **Impact:** Cross-site scripting (XSS), execution of malicious code.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Validate Content-Type:** Always validate the `Content-Type` header against an expected whitelist. This is the primary mitigation.
    *   **Don't Rely on Extensions:** Do not rely on file extensions to determine the content type.
    *   **Use `response.json()` Safely:** Only use `response.json()` when you are *certain* the response is valid JSON. This is a direct `requests` method that can be misused.

