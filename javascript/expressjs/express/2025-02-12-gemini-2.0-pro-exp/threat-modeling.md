# Threat Model Analysis for expressjs/express

## Threat: [Middleware Ordering Vulnerabilities](./threats/middleware_ordering_vulnerabilities.md)

*   **Description:** An attacker exploits the incorrect order of middleware in the Express application.  The core issue is that Express.js *allows* middleware to be ordered in a way that creates vulnerabilities.  For example, placing authentication middleware *after* a route handler that accesses sensitive data allows an attacker to bypass authentication.  Similarly, incorrect error handling middleware placement can lead to information disclosure or prevent proper handling of security-related errors. This is a *direct* threat because the vulnerability stems from how Express handles middleware execution.
    *   **Impact:** Authentication bypass, authorization bypass, information disclosure, denial of service.
    *   **Affected Express Component:** `app.use()`, the order in which middleware functions are registered. This is a fundamental aspect of how Express applications are structured.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Carefully plan and document the middleware order.  Follow a standard pattern (security headers, CORS, body parsing, HPP, CSRF, authentication, authorization, route handlers, error handling).
        *   Use route-specific middleware (`app.get('/protected', authMiddleware, handler)`) to limit the scope of middleware execution and enforce correct ordering for specific routes.
        *   Thoroughly test the application with various request patterns to ensure middleware behaves as expected, especially under attack scenarios.

## Threat: [Route Parameter Pollution (RPP) / HTTP Parameter Pollution (HPP)](./threats/route_parameter_pollution__rpp___http_parameter_pollution__hpp_.md)

*   **Description:** An attacker sends multiple HTTP parameters with the *same name*.  Express.js, without specific handling, might process these inconsistently. The vulnerability lies in how Express *parses* and makes these parameters available to the application. The attacker might aim to bypass input validation, cause unexpected application behavior, or trigger errors.  For example, sending `?id=1&id=2` might cause the application to use `id=1`, `id=2`, or an array `[1, 2]`, depending on the middleware and route configuration. This is a *direct* threat because it relates to how Express handles incoming request data.
    *   **Impact:** Bypass of input validation, unexpected application state changes, potential denial of service, information disclosure.
    *   **Affected Express Component:** Routing (`app.get`, `app.post`, etc.), request object (`req.query`, `req.params`, `req.body`), middleware that processes parameters. These are core components of Express's request handling.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Use dedicated HPP middleware like `hpp`. This consolidates multiple parameters into a single, predictable value (e.g., an array or the last occurrence).
        *   Implement strict input validation using libraries like `express-validator` or Joi.  Validate the *type* and *structure* of parameters, explicitly handling arrays if multiple values are expected. This is crucial because Express itself doesn't enforce strict parameter types.
        *   Sanitize all input parameters, even after validation, to remove any unexpected characters or data.

## Threat: [Regular Expression Denial of Service (ReDoS) in Routes](./threats/regular_expression_denial_of_service__redos__in_routes.md)

*   **Description:** An attacker crafts a malicious input string that exploits a poorly designed regular expression used *within* an Express route definition.  This causes the regular expression engine (which Express uses for route matching) to consume excessive CPU resources, leading to a denial of service.  The vulnerability is *direct* because it's tied to how Express uses regular expressions for its routing mechanism.
    *   **Impact:** Denial of service (application becomes unresponsive).
    *   **Affected Express Component:** Routing (`app.get`, `app.post`, etc.) where regular expressions are used for route matching (e.g., `/user/:id([0-9]+)`). This is a core feature of Express routing.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Avoid complex regular expressions in routes.  Prefer simpler, more specific matching patterns.
        *   Use parameterized routes (e.g., `/user/:id`) and validate the parameter type (e.g., ensure `:id` is an integer) *instead* of relying on complex regexes within the route definition. This leverages Express's built-in parameter handling.
        *   Test regular expressions with tools that detect catastrophic backtracking (e.g., online ReDoS checkers).
        *   Implement timeouts for route matching (defense-in-depth). This is a general mitigation, but it helps limit the impact of ReDoS within Express.
        *   Consider using a safer regular expression engine if complex regexes are unavoidable and performance is critical.

## Threat: [Incorrect Trust Proxy Configuration](./threats/incorrect_trust_proxy_configuration.md)

*   **Description:** If the Express application is behind a reverse proxy (e.g., Nginx, a load balancer), an attacker can spoof their IP address if the `trust proxy` setting is misconfigured.  This is a *direct* threat because it involves a specific configuration option *within* Express (`app.set('trust proxy')`) that, if misused, creates a vulnerability. The attacker can bypass IP-based restrictions or manipulate logging.
    *   **Impact:** IP spoofing, bypassing IP-based restrictions, inaccurate logging, potential for other attacks that rely on accurate IP information.
    *   **Affected Express Component:** `app.set('trust proxy', value)` configuration. This is a specific Express setting.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   If behind a trusted proxy, set `app.set('trust proxy', true)`. 
        *   If you know the specific IP addresses or subnets of your proxy servers, configure `trust proxy` with those values: `app.set('trust proxy', ['192.168.1.0/24', '10.0.0.0/8'])`. 
        *   Thoroughly understand the implications of different `trust proxy` settings as documented in the Express.js documentation.

