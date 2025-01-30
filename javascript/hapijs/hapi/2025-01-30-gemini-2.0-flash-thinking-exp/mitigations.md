# Mitigation Strategies Analysis for hapijs/hapi

## Mitigation Strategy: [Input Validation and Sanitization using Joi](./mitigation_strategies/input_validation_and_sanitization_using_joi.md)

*   **Description:**
    1.  **Identify all route handlers:** Review your Hapi.js application and list all route handlers that accept user input (payload, query parameters, path parameters, headers).
    2.  **Define Joi schemas:** For each route handler, create a Joi schema that precisely defines the expected structure, data types, formats, and constraints for all input parameters. Utilize Joi's extensive validation rules and features.
    3.  **Implement validation in route handlers:** In each route handler, use `request.payload`, `request.query`, `request.params`, and `request.headers` to access user input. Use `Joi.validate(input, schema)` within the Hapi route handler's `handler` function to validate the input against the defined schema. Hapi automatically handles validation failures and returns appropriate error responses.
    4.  **Handle validation errors (Hapi's built-in):** Hapi's validation automatically returns a 400 Bad Request response when validation fails, including details about the validation errors. Customize error responses using Hapi's error handling if needed, but leverage the framework's default behavior.
    5.  **Sanitize input where necessary using Joi:** Use Joi's sanitization features (e.g., `trim()`, `escapeHtml()`) within the schema definition to normalize and sanitize input data before processing, especially for string inputs.
    6.  **Regularly review and update schemas:** As your application evolves, regularly review and update Joi schemas to ensure they remain comprehensive and aligned with your application's requirements and new routes.

    *   **Threats Mitigated:**
        *   SQL Injection (High Severity)
        *   NoSQL Injection (High Severity)
        *   Cross-Site Scripting (XSS) (High Severity)
        *   Command Injection (High Severity)
        *   Data Integrity Issues (Medium Severity)
        *   Parameter Tampering (Medium Severity)

    *   **Impact:**
        *   SQL Injection: High Risk Reduction
        *   NoSQL Injection: High Risk Reduction
        *   Cross-Site Scripting (XSS): Medium Risk Reduction
        *   Command Injection: High Risk Reduction
        *   Data Integrity Issues: High Risk Reduction
        *   Parameter Tampering: Medium Risk Reduction

    *   **Currently Implemented:**
        *   Implemented in API routes (`/api/users`, `/api/products`) for payload and query parameter validation using Joi schemas defined in route configuration files.

    *   **Missing Implementation:**
        *   Missing in some older admin panel routes that were developed before Joi validation was fully adopted.
        *   Header validation is not consistently implemented across all routes.

## Mitigation Strategy: [Secure Authentication and Authorization with Hapi Plugins](./mitigation_strategies/secure_authentication_and_authorization_with_hapi_plugins.md)

*   **Description:**
    1.  **Choose appropriate Hapi authentication plugin:** Select a Hapi authentication plugin from the `@hapi` scope or reputable community plugins that matches your application's authentication mechanism (e.g., `@hapi/jwt` for token-based API authentication, `@hapi/hauth-cookie` for session-based web application authentication, `@hapi/basic` for basic auth).
    2.  **Install and register the plugin:** Install the chosen plugin using npm and register it with your Hapi server using `server.register()` during server startup.
    3.  **Configure authentication strategy using `server.auth.strategy()`:** Define an authentication strategy using `server.auth.strategy()`, configuring the plugin with necessary options like secret keys, token verification functions, cookie settings, and strategy-specific configurations as provided by the plugin documentation.
    4.  **Apply authentication strategy to routes using `config.auth`:** Use `config.auth` in route definitions to enforce authentication for specific routes or groups of routes. Specify the name of the strategy defined in step 3. Use different strategies for different route sets if needed (e.g., API vs. admin panel) by defining and applying multiple strategies.
    5.  **Implement authorization logic within route handlers or using Hapi extensions:** Within route handlers or using Hapi's `server.ext('onPreHandler')` extension point, implement logic to check user roles, permissions, or scopes to control access to resources based on the authenticated user's identity. Leverage Hapi's request object (`request.auth.credentials`) to access authentication information.
    6.  **Securely manage secrets and keys:** Store authentication secrets and keys securely (e.g., using environment variables, secrets management systems) and avoid hardcoding them in the application code. Configure plugins to retrieve secrets from secure sources.
    7.  **Regularly update plugins:** Keep authentication and authorization plugins updated to the latest versions using npm to patch security vulnerabilities and benefit from improvements.

    *   **Threats Mitigated:**
        *   Unauthorized Access (High Severity)
        *   Session Hijacking (High Severity)
        *   Brute-Force Attacks (Medium Severity)
        *   Privilege Escalation (High Severity)

    *   **Impact:**
        *   Unauthorized Access: High Risk Reduction
        *   Session Hijacking: High Risk Reduction
        *   Brute-Force Attacks: Medium Risk Reduction
        *   Privilege Escalation: High Risk Reduction

    *   **Currently Implemented:**
        *   `@hapi/jwt` is implemented for API authentication in `/api/*` routes. JWT strategy is configured and applied to all API endpoints.
        *   Basic role-based authorization is implemented in route handlers to check user roles before granting access to specific resources.

    *   **Missing Implementation:**
        *   Authorization logic is not consistently applied across all API endpoints. Some routes rely on implicit authorization rather than explicit role checks.
        *   Admin panel (`/admin/*`) still uses basic authentication which is less secure than cookie-based session management. Consider migrating to `@hapi/hauth-cookie` or a more robust session management plugin.

## Mitigation Strategy: [Plugin Security Management](./mitigation_strategies/plugin_security_management.md)

*   **Description:**
    1.  **Establish a Hapi plugin vetting process:** Before using any new Hapi plugin, especially those outside the `@hapi` scope, implement a process to evaluate its security and suitability within the Hapi ecosystem.
    2.  **Check plugin maintainership and community on npm and GitHub:** Assess the plugin's npm page and GitHub repository for maintainer activity, community support, issue tracking, and recent updates. Prioritize plugins actively maintained and with a healthy Hapi community presence.
    3.  **Review plugin code (if necessary) on GitHub:** For critical plugins or those with limited community vetting, review the plugin's source code on GitHub for potential security vulnerabilities, coding flaws, and adherence to Hapi best practices.
    4.  **Check for known vulnerabilities using npm audit and vulnerability databases:** Search for known vulnerabilities associated with the plugin using `npm audit` and online vulnerability databases like the National Vulnerability Database (NVD) or Snyk vulnerability database.
    5.  **Minimize plugin usage in Hapi application:** Only use plugins that are strictly necessary for your Hapi application's functionality. Avoid adding plugins for features that can be implemented with core Hapi features or custom code using Hapi's extension points and request lifecycle.
    6.  **Keep plugins updated using npm:** Regularly update all Hapi plugins to the latest versions using `npm update` to benefit from security patches, bug fixes, and improvements within the Hapi ecosystem. Use `npm audit fix` to automatically update vulnerable dependencies.
    7.  **Implement dependency management using `package-lock.json` or `yarn.lock`:** Use `package-lock.json` (npm) or `yarn.lock` (Yarn) to ensure consistent plugin versions across environments and track plugin dependencies within your Hapi project.

    *   **Threats Mitigated:**
        *   Vulnerabilities in Plugins (High Severity)
        *   Supply Chain Attacks (Medium to High Severity)
        *   Malicious Plugins (High Severity)

    *   **Impact:**
        *   Vulnerabilities in Plugins: High Risk Reduction
        *   Supply Chain Attacks: Medium to High Risk Reduction
        *   Malicious Plugins: High Risk Reduction

    *   **Currently Implemented:**
        *   Basic plugin vetting is performed by senior developers before introducing new plugins.
        *   `npm audit` is run regularly to check for known vulnerabilities in dependencies.

    *   **Missing Implementation:**
        *   No formal documented Hapi plugin vetting process exists.
        *   Code review of plugin source code on GitHub is not consistently performed, especially for less common plugins.
        *   Plugin update process is not automated and relies on manual checks. Consider using automated dependency update tools.

## Mitigation Strategy: [Server Configuration Hardening within Hapi](./mitigation_strategies/server_configuration_hardening_within_hapi.md)

*   **Description:**
    1.  **Disable unnecessary Hapi features and plugins:** Review your Hapi server configuration and disable any features or plugins that are not essential for your application's functionality using `server.options` and plugin registration options.
    2.  **Set timeouts using `server.options.timeout`:** Configure `server.options.timeout` to set appropriate timeouts for requests and connections within Hapi to prevent resource exhaustion and DoS attacks.
    3.  **Limit request payload size using `server.options.payload.maxBytes`:** Use `server.options.payload.maxBytes` to restrict the maximum allowed request payload size within Hapi to prevent large payload attacks.
    4.  **Configure TLS/SSL using `server.connection({ tls: { ... } })`:** Ensure TLS/SSL is properly configured for HTTPS using `server.connection({ tls: { ... } })` when creating your Hapi server connection. Use strong ciphers and protocols, and disable insecure protocols like SSLv3 within the TLS configuration.
    5.  **Enable HSTS using Hapi's header setting capabilities:** Implement HSTS by setting the `Strict-Transport-Security` header using Hapi's header setting capabilities, specifically using `server.ext('onPreResponse')` to add the header to all responses.
    6.  **Set security headers using `server.ext('onPreResponse')`:** Configure Hapi to send security headers like `X-Frame-Options`, `X-Content-Type-Options`, `Content-Security-Policy`, `Referrer-Policy`, and `Permissions-Policy` in responses using `server.ext('onPreResponse')`. Define header values according to security best practices.

    *   **Threats Mitigated:**
        *   Denial of Service (DoS) Attacks (High Severity)
        *   Man-in-the-Middle (MitM) Attacks (High Severity)
        *   Clickjacking (Medium Severity)
        *   MIME-Sniffing Vulnerabilities (Low Severity)
        *   Cross-Site Scripting (XSS) (Medium to High Severity)
        *   Information Leakage (Low Severity)

    *   **Impact:**
        *   Denial of Service (DoS) Attacks: Medium Risk Reduction
        *   Man-in-the-Middle (MitM) Attacks: High Risk Reduction
        *   Clickjacking: Medium Risk Reduction
        *   MIME-Sniffing Vulnerabilities: Low Risk Reduction
        *   Cross-Site Scripting (XSS): Medium to High Risk Reduction
        *   Information Leakage: Low Risk Reduction

    *   **Currently Implemented:**
        *   TLS/SSL is configured for HTTPS.
        *   `X-Frame-Options` and `X-Content-Type-Options` headers are set globally using `server.ext('onPreResponse')`.
        *   Request payload size limit is configured in `server.options.payload.maxBytes`.

    *   **Missing Implementation:**
        *   HSTS is not enabled. Implement `Strict-Transport-Security` header using `server.ext('onPreResponse')`.
        *   `Content-Security-Policy`, `Referrer-Policy`, and `Permissions-Policy` headers are not implemented. Add these headers using `server.ext('onPreResponse')` with appropriate configurations.
        *   Timeouts are not explicitly configured and rely on default Hapi settings. Explicitly set timeouts in `server.options.timeout`.

## Mitigation Strategy: [Error Handling and Logging Security using Hapi Extensions](./mitigation_strategies/error_handling_and_logging_security_using_hapi_extensions.md)

*   **Description:**
    1.  **Implement generic error responses using `server.ext('onPreResponse')`:** In `server.ext('onPreResponse')`, customize error responses to return generic error messages to clients in production environments. Use Hapi's response toolkit (`h`) to modify the response payload and status code. Avoid exposing detailed error messages or stack traces in production responses.
    2.  **Centralized logging using Hapi's logging features or plugins:** Configure a centralized logging system (e.g., using Winston, Bunyan, or external logging services) to collect logs from your Hapi application. Integrate your chosen logging system with Hapi using Hapi's built-in logging features (`server.log()`) or dedicated logging plugins.
    3.  **Log security-relevant events using `server.log()`:** Log important security events such as authentication failures, authorization violations, input validation errors, and suspicious activity using `server.log()` within relevant parts of your Hapi application code (e.g., authentication strategies, route handlers, extension points).
    4.  **Sanitize log data before using `server.log()`:** Before logging sensitive data, sanitize or redact it (e.g., passwords, API keys, personal information) to prevent logging sensitive information in plain text. Implement sanitization logic before calling `server.log()`.
    5.  **Secure log storage and access (external to Hapi):** Ensure that log files or logging services are stored securely and access to logs is restricted to authorized personnel. This is generally handled outside of Hapi itself, in your logging infrastructure.
    6.  **Monitor logs for security incidents (external to Hapi):** Regularly monitor logs for suspicious patterns, anomalies, and security incidents. Set up alerts for critical security events within your logging system. Log monitoring is typically handled by external monitoring tools or services.

    *   **Threats Mitigated:**
        *   Information Leakage (Medium Severity)
        *   Security Monitoring Gaps (Medium Severity)
        *   Data Breaches through Logs (High Severity)

    *   **Impact:**
        *   Information Leakage: Medium Risk Reduction
        *   Security Monitoring Gaps: Medium Risk Reduction
        *   Data Breaches through Logs: High Risk Reduction

    *   **Currently Implemented:**
        *   Generic error responses are implemented using `server.ext('onPreResponse')`.
        *   Winston is used for logging application events to files, integrated using `server.log()`.

    *   **Missing Implementation:**
        *   Centralized logging to a dedicated logging service is not implemented. Logs are only stored locally. Consider using a plugin or custom integration for centralized logging.
        *   Security event logging is not comprehensive. Ensure all security-relevant events are logged using `server.log()`.
        *   Log data sanitization is not implemented. Implement sanitization logic before calling `server.log()` to prevent logging sensitive data.
        *   Log monitoring and alerting are not set up. Implement monitoring and alerting within your logging infrastructure.

## Mitigation Strategy: [Rate Limiting and Denial of Service (DoS) Prevention using Hapi Plugins or Extensions](./mitigation_strategies/rate_limiting_and_denial_of_service__dos__prevention_using_hapi_plugins_or_extensions.md)

*   **Description:**
    1.  **Choose a Hapi rate limiting plugin or implement custom middleware using Hapi extensions:** Select a Hapi rate limiting plugin (e.g., `@hapi/ratelimit`) or implement custom rate limiting middleware using Hapi's extension points (`server.ext('onRequest')` or route-specific `ext` configuration).
    2.  **Install and register the plugin/middleware:** Install the plugin using npm and register it with your Hapi server using `server.register()`, or implement your custom middleware and register it as a global or route-specific extension.
    3.  **Configure rate limits within the plugin or middleware:** Define rate limits based on your application's usage patterns and security requirements within the plugin's configuration or your custom middleware logic. Configure limits for different routes or functionalities if needed. Consider factors like requests per minute/hour, burst limits, and keying strategies (e.g., IP address, user ID, using Hapi's `request` object).
    4.  **Apply rate limiting to routes using plugin options or Hapi route configuration:** Apply rate limiting to relevant routes using the plugin's options or by configuring route-specific extensions in Hapi. Target publicly accessible or resource-intensive routes.
    5.  **Handle rate limit exceeded responses using plugin options or custom middleware:** Customize the response when rate limits are exceeded (e.g., HTTP 429 Too Many Requests) using the plugin's options or by handling rate limit exceeded conditions in your custom middleware and using Hapi's response toolkit (`h`). Provide informative messages to clients.
    6.  **Monitor rate limiting metrics (plugin-specific or custom implementation):** Monitor rate limiting metrics to detect potential attacks or abuse and adjust rate limits as needed. Plugins may provide built-in metrics, or you may need to implement custom metrics collection in your middleware.

    *   **Threats Mitigated:**
        *   Brute-Force Attacks (Medium to High Severity)
        *   Denial of Service (DoS) Attacks (Medium Severity)
        *   Resource Exhaustion (Medium Severity)
        *   API Abuse (Medium Severity)

    *   **Impact:**
        *   Brute-Force Attacks: Medium to High Risk Reduction
        *   Denial of Service (DoS) Attacks: Medium Risk Reduction
        *   Resource Exhaustion: Medium Risk Reduction
        *   API Abuse: Medium Risk Reduction

    *   **Currently Implemented:**
        *   Basic rate limiting is implemented using a custom middleware based on IP address for login routes (`/login`).

    *   **Missing Implementation:**
        *   Rate limiting is not implemented for other API routes or resource-intensive endpoints. Consider using `@hapi/ratelimit` or extending the custom middleware.
        *   More sophisticated rate limiting strategies (e.g., token-based, user-based) are not implemented. Explore plugin options or enhance custom middleware for more advanced strategies using Hapi's authentication and request context.
        *   Rate limiting configuration is not centralized and is hardcoded in middleware. Centralize configuration for easier management and updates.
        *   Rate limiting metrics are not monitored. Implement monitoring to track rate limiting effectiveness and identify potential issues.

## Mitigation Strategy: [CORS (Cross-Origin Resource Sharing) Configuration using `@hapi/cors` plugin](./mitigation_strategies/cors__cross-origin_resource_sharing__configuration_using__@hapicors__plugin.md)

*   **Description:**
    1.  **Install and register `@hapi/cors` plugin:** Install the `@hapi/cors` plugin using npm and register it with your Hapi server using `server.register(require('@hapi/cors'))`.
    2.  **Configure CORS options using `server.connection({ routes: { cors: { ... } } })` or route-specific options:** Configure CORS options using `server.connection({ routes: { cors: { ... } } })` to set global CORS defaults for all routes, or configure route-specific CORS settings using the `config.cors` option in individual route definitions.
    3.  **Define allowed origins using `origin` option:** Specify the `origin` option within the CORS configuration to define the allowed origins that can access your application's resources. Use specific origins (arrays of domains or functions for dynamic origin checking) instead of wildcards (`*`) in production for enhanced security.
    4.  **Configure allowed methods and headers using `methods` and `headers` options:** Define `methods` and `headers` options to specify the allowed HTTP methods and headers for cross-origin requests. Restrict these to only the necessary methods and headers for your application's functionality to minimize attack surface.
    5.  **Handle credentials using `credentials: true` option:** If your application uses credentials (cookies, authorization headers) in cross-origin requests, configure `credentials: true` in the CORS options and ensure `Access-Control-Allow-Origin` is not set to `*`. When using credentials, `Access-Control-Allow-Origin` must be a specific origin, not a wildcard.
    6.  **Review CORS configuration regularly:** Regularly review your CORS configuration to ensure it is still appropriate and secure as your application evolves and frontend domains change. Update CORS settings as needed to maintain security and functionality.

    *   **Threats Mitigated:**
        *   Cross-Site Request Forgery (CSRF) (Medium Severity - indirect mitigation)
        *   Unauthorized Access from Untrusted Origins (Medium Severity)
        *   Data Exfiltration (Medium Severity)

    *   **Impact:**
        *   Cross-Site Request Forgery (CSRF): Medium Risk Reduction
        *   Unauthorized Access from Untrusted Origins: Medium Risk Reduction
        *   Data Exfiltration: Medium Risk Reduction

    *   **Currently Implemented:**
        *   `@hapi/cors` plugin is registered.
        *   Basic CORS configuration is set globally allowing requests from a specific frontend domain.

    *   **Missing Implementation:**
        *   CORS configuration is not route-specific. Consider using route-specific CORS configurations for finer-grained control.
        *   Allowed methods and headers are not explicitly restricted and might be overly permissive. Restrict `methods` and `headers` to only necessary values.
        *   CORS configuration is not regularly reviewed and updated. Implement a process for periodic review of CORS settings.

