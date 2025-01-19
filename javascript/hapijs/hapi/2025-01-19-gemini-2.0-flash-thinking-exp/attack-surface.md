# Attack Surface Analysis for hapijs/hapi

## Attack Surface: [Parameter Injection](./attack_surfaces/parameter_injection.md)

**Description:** Attackers can manipulate route parameters to inject unexpected values, potentially leading to unauthorized access, data breaches, or code execution.
*   **How Hapi Contributes to the Attack Surface:** Hapi's route definition syntax (`/users/{id}`) makes it easy to define dynamic routes. If these parameters are directly used in database queries or file system operations without proper sanitization, it creates an injection risk.
*   **Example:** A route `/items/{itemId}` might be accessed with `/items/1' OR '1'='1`. If the `itemId` is directly used in an SQL query, it could bypass intended logic.
*   **Impact:** Data breaches, unauthorized access to resources, potential for remote code execution depending on the context of the injection.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Input Validation:** Utilize Hapi's Joi validation to enforce expected data types and formats for route parameters.
    *   **Parameterized Queries:** Employ parameterized queries or ORM features that handle escaping automatically when interacting with databases.

## Attack Surface: [Vulnerable Plugins](./attack_surfaces/vulnerable_plugins.md)

**Description:** Third-party Hapi plugins might contain security vulnerabilities that can be exploited in the application.
*   **How Hapi Contributes to the Attack Surface:** Hapi's plugin architecture encourages the use of community-developed extensions. If these plugins are not well-maintained or contain security flaws, they introduce vulnerabilities into the application.
*   **Example:** A plugin used for authentication might have a flaw allowing for authentication bypass, or a plugin handling file uploads might be vulnerable to path traversal.
*   **Impact:** Wide range of impacts depending on the vulnerability in the plugin, including data breaches, remote code execution, and denial of service.
*   **Risk Severity:** Medium to Critical (depending on the plugin's function and the severity of the vulnerability)
*   **Mitigation Strategies:**
    *   **Careful Plugin Selection:** Choose plugins from reputable sources with active maintenance and a good security track record.
    *   **Vulnerability Scanning:** Regularly scan dependencies, including Hapi plugins, for known vulnerabilities using tools like `npm audit` or dedicated security scanners.
    *   **Stay Updated:** Keep Hapi and all its plugins updated to the latest versions to patch known security flaws.

## Attack Surface: [CORS Misconfiguration](./attack_surfaces/cors_misconfiguration.md)

**Description:** Incorrectly configured Cross-Origin Resource Sharing (CORS) can allow unauthorized websites to access the application's resources, potentially leading to data theft or CSRF attacks.
*   **How Hapi Contributes to the Attack Surface:** Hapi provides mechanisms to configure CORS through plugins like `hapi-cors`. Misconfiguration of these settings can expose the application to cross-origin attacks.
*   **Example:** Setting `Access-Control-Allow-Origin` to `*` allows any website to make requests to the API, potentially exposing sensitive data or actions.
*   **Impact:** Data breaches, Cross-Site Request Forgery (CSRF) attacks, exposure of sensitive API endpoints.
*   **Risk Severity:** Medium to High
*   **Mitigation Strategies:**
    *   **Restrict Allowed Origins:** Configure CORS to only allow requests from trusted and explicitly defined origins. Avoid using wildcard (`*`) in production.
    *   **Proper Credential Handling:** Carefully configure `Access-Control-Allow-Credentials` and ensure it aligns with the allowed origins.

## Attack Surface: [Missing or Misconfigured Security Headers](./attack_surfaces/missing_or_misconfigured_security_headers.md)

**Description:** Lack of proper security headers can leave the application vulnerable to various client-side attacks.
*   **How Hapi Contributes to the Attack Surface:** While Hapi doesn't automatically set all security headers, it provides mechanisms (e.g., through response extensions or plugins like `inert`) to configure them. Failure to implement these headers correctly increases the attack surface.
*   **Example:** Missing `Content-Security-Policy` (CSP) can make the application vulnerable to Cross-Site Scripting (XSS) attacks. Missing `Strict-Transport-Security` (HSTS) can leave users vulnerable to man-in-the-middle attacks.
*   **Impact:** Cross-Site Scripting (XSS), Clickjacking, MIME sniffing attacks, man-in-the-middle attacks.
*   **Risk Severity:** Medium to High
*   **Mitigation Strategies:**
    *   **Implement Security Headers:** Configure essential security headers like `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`.
    *   **Use a Security Header Plugin:** Consider using a Hapi plugin that simplifies the management and configuration of security headers.

