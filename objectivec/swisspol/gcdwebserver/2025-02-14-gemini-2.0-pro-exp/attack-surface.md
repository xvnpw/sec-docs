# Attack Surface Analysis for swisspol/gcdwebserver

## Attack Surface: [Path Traversal via Handlers](./attack_surfaces/path_traversal_via_handlers.md)

*Description:* Attackers manipulate file paths within requests to access files outside the intended directory.  This exploits vulnerabilities in *how* a developer's handler code uses `GCDWebServer`'s request processing.
*GCDWebServer Contribution:* `GCDWebServer` provides the *mechanism* for handlers to access the request path and associated data (query parameters, etc.).  It does *not* inherently validate or sanitize this data; that is the responsibility of the handler code written by the developer using the library. The library facilitates the *possibility* of the vulnerability, but the vulnerability itself exists in the *application's* handler.
*Example:* A handler uses `request.query["filename"]` directly to open a file, without any checks. An attacker provides `filename=../../etc/passwd`.
*Impact:* Unauthorized access to sensitive files, potentially leading to system compromise.
*Risk Severity:* Critical
*Mitigation Strategies:*
    *   **Strict Input Validation:** Validate and sanitize *all* parts of the request used to construct file paths within the handler. Reject any input containing suspicious characters (e.g., "../", "/", control characters).
    *   **Whitelist Allowed Paths/Filenames:** Maintain a whitelist of allowed file names or paths, and reject any request that doesn't match the whitelist. This is *far* more secure than trying to blacklist dangerous characters.
    *   **Safe Base Directory:** Construct file paths by combining a known, safe base directory with the *sanitized* user input.  *Never* use user-provided input directly as the full file path.
    *   **Canonicalization:** Before accessing a file, canonicalize the path to resolve any symbolic links or relative path components.

## Attack Surface: [Handler Logic Errors (Authentication/Authorization Bypass)](./attack_surfaces/handler_logic_errors__authenticationauthorization_bypass_.md)

*Description:* Flaws in the authentication, authorization, or session management logic *within* a `GCDWebServer` handler allow attackers to bypass security controls.
*GCDWebServer Contribution:* `GCDWebServer` provides the *framework* for developers to implement these security mechanisms *within* their handlers.  The library itself does not provide built-in authentication or authorization; it's the developer's responsibility to implement these correctly *using* the handler's request and response objects. The vulnerability lies in the *application's* handler code, not the library itself, but the library provides the context in which the handler operates.
*Example:* A handler checks for a cookie named "admin" but doesn't verify its signature or origin, allowing an attacker to set a fake "admin" cookie.
*Impact:* Unauthorized access to sensitive functionality or data, potentially leading to complete application compromise.
*Risk Severity:* High to Critical (depending on the protected resource)
*Mitigation Strategies:*
    *   **Use Established Security Libraries:** Leverage well-vetted authentication and authorization libraries instead of implementing these mechanisms from scratch within the handler.
    *   **Centralized Security Logic:** Implement security checks in a centralized and consistent manner, rather than scattering them throughout individual handlers.
    *   **Secure Session Management:** Use secure, randomly generated session identifiers, and handle session data securely (e.g., server-side storage, proper expiration).
    *   **Input Validation (Always):** Validate *all* input within the handler, even for authenticated users, to prevent other vulnerabilities.
    *   **Thorough Testing:** Rigorously test authentication and authorization logic, including edge cases and negative scenarios.

## Attack Surface: [Resource Exhaustion (DoS) via Handler Abuse](./attack_surfaces/resource_exhaustion__dos__via_handler_abuse.md)

*Description:* Attackers exploit handlers designed for resource-intensive operations to cause denial of service by consuming excessive server resources.
*GCDWebServer Contribution:* `GCDWebServer` provides the *environment* in which handlers execute.  It does *not* automatically limit the resources a handler can consume.  The developer must implement resource limits and safeguards *within* the handler code. The library provides the *concurrency model* (GCD), which, if misused, can exacerbate resource exhaustion issues.
*Example:* A handler allows file uploads but doesn't limit the file size. An attacker uploads a massive file, consuming all available disk space or memory.
*Impact:* Denial of service, preventing legitimate users from accessing the application.
*Risk Severity:* High
*Mitigation Strategies:*
    *   **Request Body Size Limits:** Enforce strict limits on the size of request bodies *within the handler*, especially for file uploads.
    *   **Timeouts:** Set timeouts for handler operations to prevent long-running requests from blocking resources indefinitely.
    *   **Rate Limiting:** Limit the rate at which clients can call specific handlers, particularly those known to be resource-intensive.
    *   **Resource Monitoring:** Monitor server resource usage and implement alerts for unusual activity.
    *   **Careful Asynchronous Task Management:** Use GCD responsibly within handlers. Avoid creating an unbounded number of asynchronous tasks, which could lead to resource exhaustion.
    *   **Input Validation:** Validate input to prevent excessively large or complex data from being processed.

## Attack Surface: [Unintended Handler Exposure](./attack_surfaces/unintended_handler_exposure.md)

*Description:* Handlers intended for internal use are accidentally exposed publicly due to misconfiguration of routes *within* the `GCDWebServer` setup.
*GCDWebServer Contribution:* `GCDWebServer` allows developers to *define* the routes and associate them with handlers.  The vulnerability arises from *incorrectly* defining these routes, exposing handlers that should be protected. The library provides the *routing mechanism*, but the developer is responsible for using it securely.
*Example:* A handler for administrative functions is registered at `/admin` without any authentication checks, making it accessible to anyone.
*Impact:* Unauthorized access to sensitive functionality or data.
*Risk Severity:* High to Critical (depending on the exposed functionality)
*Mitigation Strategies:*
    *   **Careful Route Configuration:** Meticulously review and double-check the paths for which handlers are registered. Use a clear and consistent naming convention to differentiate between public and internal routes.
    *   **Code Review:** Conduct thorough code reviews, specifically focusing on the code that registers handlers with `GCDWebServer`.
    *   **Automated Testing:** Implement automated tests to verify that sensitive routes are *not* accessible without proper authentication.
    *   **Centralized Route Management:** If feasible, manage all route registrations in a single, centralized location to simplify review and auditing.

