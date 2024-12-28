### High and Critical Threats Directly Involving Hapi.js

This list details high and critical security threats that directly involve the Hapi.js framework.

*   **Threat:** Route Parameter Injection
    *   **Description:** An attacker manipulates route parameters in a URL to access unintended resources or trigger unexpected application behavior by exploiting Hapi's flexible routing and parameter extraction. This occurs when route parameter values are not properly validated within Hapi route handlers, allowing attackers to bypass intended access controls or access data associated with other entities.
    *   **Impact:** Unauthorized access to data, potential data breaches, modification of data belonging to other users, or execution of unintended code paths due to insufficient validation of `request.params` within Hapi.
    *   **Affected Hapi Component:** `server.route()` configuration, specifically the `path` definition and how `request.params` are handled in route handlers.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Implement robust input validation for all route parameters using Hapi's Joi validation library within route handlers.
        *   Define strict schemas for route parameters within the `config.validate.params` option of `server.route()`, specifying expected data types and formats.
        *   Avoid directly using `request.params` in database queries or sensitive operations without thorough validation and sanitization.

*   **Threat:** Payload Parsing Denial of Service (DoS)
    *   **Description:** An attacker sends excessively large or malformed payloads to the server, exploiting vulnerabilities in Hapi's built-in payload parsing mechanisms. This can consume excessive server resources (CPU, memory) managed by the Hapi server, leading to a denial of service for legitimate users.
    *   **Impact:** Application unavailability, server crashes, and disruption of service for legitimate users due to resource exhaustion within the Hapi process.
    *   **Affected Hapi Component:** `request.payload` handling, specifically the default payload parsing mechanisms configured within Hapi for different content types (e.g., JSON, multipart) and the `payload` configuration options in `server.options`.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Set appropriate `payload.maxBytes` limits in the `server.options` configuration to restrict the maximum size of incoming payloads processed by Hapi.
        *   Configure `payload.parse` options within `server.options` to limit the depth and complexity of parsed payloads (e.g., `json.limit`, `json.parse`).
        *   Consider using a dedicated rate limiting or request size limiting middleware or plugin *before* the request reaches Hapi's core handling.

*   **Threat:** Missing or Misconfigured Route Authentication/Authorization
    *   **Description:** Routes are not properly protected with authentication or authorization checks using Hapi's built-in authentication framework, allowing unauthorized users to access sensitive resources or perform privileged actions. This occurs when the `auth` option in `server.route()` is not correctly configured or is omitted entirely.
    *   **Impact:** Unauthorized access to data and functionality managed by Hapi routes, potential data breaches, and the ability for attackers to perform actions they shouldn't be able to through unprotected Hapi endpoints.
    *   **Affected Hapi Component:** `server.route()` configuration, specifically the `auth` option.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Explicitly define authentication strategies for all routes that require protection using the `auth` option in `server.route()`.
        *   Implement granular authorization checks within route handlers, leveraging Hapi's authentication context (`request.auth`), to ensure users have the necessary permissions to access specific resources or perform actions.
        *   Regularly review route configurations to ensure that authentication and authorization are correctly applied using Hapi's mechanisms.

*   **Threat:** Insecure Cookie Configuration
    *   **Description:** Hapi's cookie management, when used directly or through plugins, is not configured securely, leading to vulnerabilities like session hijacking or cross-site scripting (XSS) through cookie manipulation. This involves improper setting of cookie attributes like `HttpOnly`, `Secure`, and `SameSite` within Hapi's response handling.
    *   **Impact:** Session hijacking, where an attacker steals a user's session cookie managed by Hapi and impersonates them. Potential for XSS attacks if cookies are accessible to client-side scripts due to missing `HttpOnly`.
    *   **Affected Hapi Component:** Hapi's cookie setting mechanisms, often used within authentication plugins or custom handlers via `h.state()` or `h.unstate()`.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Set the `HttpOnly` flag for session cookies using `h.state()` options to prevent client-side JavaScript from accessing them, mitigating XSS risks.
        *   Set the `Secure` flag for session cookies using `h.state()` options to ensure they are only transmitted over HTTPS, preventing interception over insecure connections.
        *   Consider using the `SameSite` attribute with `h.state()` options to protect against cross-site request forgery (CSRF) attacks.

*   **Threat:** Information Disclosure through Error Responses
    *   **Description:** Default or poorly customized error responses generated by Hapi expose sensitive information about the application's internal workings, such as file paths, database details, or stack traces. This information, directly returned by Hapi's error handling, can be valuable to attackers for reconnaissance.
    *   **Impact:** Provides attackers with valuable information about the application's structure and potential vulnerabilities, aiding in planning and executing more targeted attacks based on Hapi's error output.
    *   **Affected Hapi Component:** Hapi's default error handling mechanism and any custom error handling logic implemented using Hapi's extension points (e.g., `onPreResponse`).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Customize error responses using Hapi's extension points (like `onPreResponse`) to avoid exposing sensitive details in production environments.
        *   Log detailed error information server-side for debugging purposes but do not send it directly to the client through Hapi's response.
        *   Disable debug mode and detailed error reporting in Hapi's configuration for production environments.