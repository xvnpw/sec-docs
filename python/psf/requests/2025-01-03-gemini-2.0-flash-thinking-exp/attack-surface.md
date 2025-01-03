# Attack Surface Analysis for psf/requests

## Attack Surface: [URL Injection](./attack_surfaces/url_injection.md)

*   **Attack Surface:** URL Injection
    *   **Description:**  Applications construct URLs dynamically using user-provided input without proper sanitization.
    *   **How `requests` Contributes:** The `requests.get()`, `requests.post()`, and similar functions accept a URL as a primary argument. If this URL is built using unsanitized user input, it becomes vulnerable.
    *   **Example:**
        ```python
        import requests
        user_input = input("Enter a website: ")
        url = f"https://{user_input}"
        response = requests.get(url)
        ```
        An attacker could input `evil.com/sensitive_data` leading to the application making a request to an unintended location.
    *   **Impact:** Server-Side Request Forgery (SSRF), allowing attackers to access internal resources, interact with other services, or potentially perform actions on behalf of the server. Can also lead to phishing by redirecting users to malicious sites.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Input Validation:**  Strictly validate and sanitize user-provided input before incorporating it into URLs. Use allowlists of allowed domains or URL patterns.
        *   **URL Parsing:**  Use libraries to parse and reconstruct URLs safely, ensuring no malicious components are introduced.
        *   **Avoid Dynamic URL Construction:**  Where possible, avoid constructing URLs dynamically based on user input. Use predefined URLs or limited, well-defined parameters.

## Attack Surface: [Header Injection](./attack_surfaces/header_injection.md)

*   **Attack Surface:** Header Injection
    *   **Description:**  Applications allow users to influence HTTP headers sent by `requests` without proper validation.
    *   **How `requests` Contributes:** The `headers` parameter in `requests` functions allows setting custom HTTP headers. If user input is directly used as header values, it can lead to injection.
    *   **Example:**
        ```python
        import requests
        user_agent = input("Enter your User-Agent: ")
        headers = {'User-Agent': user_agent}
        response = requests.get("https://example.com", headers=headers)
        ```
        An attacker could inject newline characters (`\r\n`) to create additional headers, potentially leading to HTTP Response Splitting.
    *   **Impact:** HTTP Response Splitting, allowing attackers to inject arbitrary content into the HTTP response, potentially leading to Cross-Site Scripting (XSS) or cache poisoning. Session fixation by setting a specific `Set-Cookie` header.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Header Value Sanitization:**  Sanitize header values to remove or escape control characters like newline characters.
        *   **Avoid Dynamic Header Construction:**  Minimize the use of user input directly in header values. Use predefined header values or a limited set of allowed options.
        *   **Framework-Level Protection:** Utilize web frameworks that provide built-in protection against header injection vulnerabilities.

## Attack Surface: [Disabling SSL/TLS Verification](./attack_surfaces/disabling_ssltls_verification.md)

*   **Attack Surface:** Disabling SSL/TLS Verification
    *   **Description:**  Applications disable SSL/TLS certificate verification for `requests` calls.
    *   **How `requests` Contributes:** The `verify=False` parameter in `requests` functions disables SSL/TLS certificate verification.
    *   **Example:**
        ```python
        import requests
        response = requests.get("https://insecure-website.com", verify=False)
        ```
    *   **Impact:** Man-in-the-Middle (MITM) attacks. Attackers can intercept and modify communication between the application and the server, potentially stealing sensitive data or injecting malicious content.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Always Verify Certificates:**  Never set `verify=False` in production environments.
        *   **Use a Certificate Bundle:** Ensure the system has an up-to-date certificate authority (CA) bundle.
        *   **Pin Certificates (Advanced):** For critical connections, consider certificate pinning to ensure you are connecting to the expected server.

## Attack Surface: [Uncontrolled Redirects](./attack_surfaces/uncontrolled_redirects.md)

*   **Attack Surface:** Uncontrolled Redirects
    *   **Description:**  Applications blindly follow redirects returned by the server without proper validation.
    *   **How `requests` Contributes:** By default, `requests` follows redirects (`allow_redirects=True`). If the initial request is to an attacker-controlled server, they can redirect the application to a malicious site.
    *   **Example:**
        ```python
        import requests
        response = requests.get("https://attacker.com/redirect_to_evil")
        # requests will automatically follow the redirect
        ```
    *   **Impact:** Open Redirect vulnerabilities, allowing attackers to craft URLs that redirect users to malicious sites after passing through the legitimate application's domain, potentially for phishing or malware distribution. Can also be used in SSRF attacks.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Carefully Evaluate Redirect Destinations:** If redirects are necessary, validate the destination URL against a whitelist of allowed domains or patterns before following the redirect.
        *   **Limit Redirect Hops:**  Restrict the number of redirects `requests` will follow using the `max_redirects` parameter.
        *   **Inspect Redirect History:** Examine the `response.history` to understand the redirection path.

