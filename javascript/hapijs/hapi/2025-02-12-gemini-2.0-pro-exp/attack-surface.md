# Attack Surface Analysis for hapijs/hapi

## Attack Surface: [Route Configuration Vulnerabilities](./attack_surfaces/route_configuration_vulnerabilities.md)

*   *Description:*  Improperly configured routes expose endpoints or data unintentionally, due to Hapi's routing mechanisms.
    *   *Hapi Contribution:* Hapi's flexible routing system requires careful configuration of authentication (`auth` strategies), authorization, and input validation within route definitions.  This is a *direct* Hapi concern.
    *   *Example:* A route defined as `/admin/users` without a properly configured Hapi `auth` strategy allows unauthenticated access.  Or, a route `/files/{path}` where the `path` parameter is handled by a Hapi route handler, and the handler doesn't properly sanitize the input using Hapi's validation mechanisms (Joi).
    *   *Impact:* Unauthorized access to sensitive data, functionality, or system resources. Potential for complete system compromise.
    *   *Risk Severity:* **Critical** to **High**.
    *   *Mitigation Strategies:*
        *   **Hapi `auth` Strategies:** Implement and *correctly configure* Hapi's built-in authentication strategies (e.g., `hapi-auth-jwt2`, `bell`) on all routes requiring protection.  Thoroughly test these integrations.
        *   **Hapi Route Options:** Use Hapi's route configuration options (e.g., `validate.params`, `validate.payload`, `validate.query`) to enforce strict input validation using Joi schemas *within the route definition itself*.
        *   **Hapi Route-Specific Authorization:** Implement authorization logic *within* Hapi route handlers or pre-handler extensions (`onPreAuth`, `onPreHandler`) to enforce fine-grained access control.
        *   **Method Restriction (Hapi):**  Explicitly define allowed HTTP methods within the Hapi route configuration.

## Attack Surface: [Request Validation Bypass (Joi - within Hapi context)](./attack_surfaces/request_validation_bypass__joi_-_within_hapi_context_.md)

*   *Description:*  Circumventing or misconfiguring Joi validation *within Hapi's request handling pipeline* allows malicious input.
    *   *Hapi Contribution:* Hapi *integrates* Joi directly into its request lifecycle via the `validate` option in route configurations.  This is the key Hapi-specific aspect.  Weak or missing Joi schemas *within this Hapi context* are the vulnerability.
    *   *Example:* A Hapi route with a `validate.payload` option that uses a Joi schema, but the schema is too permissive (e.g., doesn't validate string lengths or formats).  Or, a developer accidentally disables Hapi's validation for a specific route.
    *   *Impact:*  Injection attacks (XSS, SQLi, command injection – though these are mitigated *by* Hapi if Joi is used correctly), data corruption, denial-of-service.
    *   *Risk Severity:* **Critical** to **High**.
    *   *Mitigation Strategies:*
        *   **Hapi `validate` Option:**  Use the `validate` option in *every* Hapi route configuration to enforce Joi validation on `params`, `payload`, `query`, and `headers`.
        *   **Comprehensive Joi Schemas (within Hapi):**  Create detailed and strict Joi schemas *specifically for use within Hapi's `validate` option*.  Validate all relevant input aspects.
        *   **Hapi Validation Configuration:** Ensure that Hapi's validation settings (e.g., `failAction`) are configured to appropriately handle validation errors (e.g., reject the request).
        *   **Testing Hapi-Joi Integration:** Write unit tests that specifically target the interaction between Hapi routes and Joi validation.

## Attack Surface: [Plugin-Related Vulnerabilities (Hapi Plugins)](./attack_surfaces/plugin-related_vulnerabilities__hapi_plugins_.md)

*   *Description:*  Using vulnerable or misconfigured *Hapi plugins* introduces security risks.
    *   *Hapi Contribution:* This is *entirely* about Hapi's plugin ecosystem.  The vulnerability stems from the use of third-party code *within the Hapi framework*.
    *   *Example:*  Using an outdated Hapi plugin for authentication that has a known vulnerability allowing authentication bypass. Or, a Hapi plugin that handles file uploads but doesn't properly sanitize filenames, leading to a path traversal vulnerability *within the context of the Hapi application*.
    *   *Impact:*  Varies widely, but can be **Critical** (e.g., authentication bypass, RCE) or **High** (e.g., information disclosure).
    *   *Mitigation Strategies:*
        *   **Hapi Plugin Selection:**  Choose *only* well-maintained, reputable Hapi plugins from trusted sources.  Prioritize official Hapi plugins when available.
        *   **Hapi Plugin Updates:**  Keep *all* Hapi plugins updated to their latest versions to patch security vulnerabilities.  This is crucial for the Hapi ecosystem.
        *   **Hapi Plugin Configuration:**  Thoroughly review and securely configure *all* options provided by Hapi plugins.  Misconfiguration of a Hapi plugin is a direct Hapi-related risk.
        *   **Hapi Plugin Auditing:** If possible, review the source code of Hapi plugins, especially those handling sensitive operations.

## Attack Surface: [State Management (Hapi's `yar` or similar)](./attack_surfaces/state_management__hapi's__yar__or_similar_.md)

* *Description:* Improper configuration of Hapi's state management, leading to session-related vulnerabilities.
    * *Hapi Contribution:* Hapi often uses `yar` (or similar plugins) for session management. Misconfiguration *of these Hapi-specific tools* is the direct risk.
    * *Example:* Configuring `yar` with weak cookie security settings (missing `HttpOnly`, `Secure`, or `SameSite` attributes) *within the Hapi server configuration*.
    * *Impact:* Session hijacking, unauthorized access.
    * *Risk Severity:* **High**
    * *Mitigation Strategies:*
        * **Secure `yar` Configuration:** When using `yar` (or any Hapi state management plugin), *meticulously* configure all cookie security attributes (`HttpOnly`, `Secure`, `SameSite`, `ttl`, etc.) within the Hapi server setup.
        * **Hapi-Specific Session Handling:** Follow best practices for session management *specifically within the context of Hapi and its chosen state management plugin*.
        * **Review Hapi Documentation:** Consult the official Hapi documentation for `yar` (or the chosen plugin) for the most up-to-date security recommendations.

