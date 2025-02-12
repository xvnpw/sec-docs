# Mitigation Strategies Analysis for hapijs/hapi

## Mitigation Strategy: [Comprehensive `joi` Input Validation (Hapi-Specific)](./mitigation_strategies/comprehensive__joi__input_validation__hapi-specific_.md)

**Mitigation Strategy:** Comprehensive `joi` Input Validation (Hapi-Specific)

**Description:**
1.  **Identify All Input Points:** List all Hapi routes and identify every point where the application receives data: path parameters, query parameters, request body (payload), and headers.
2.  **Create `joi` Schemas:** For *each* input point, create a corresponding `joi` schema, leveraging Hapi's built-in `joi` integration. Use `Joi.object()` for payloads and query parameters.
3.  **Define Specific Types:** Use specific `joi` types and constraints:
    *   `Joi.string().email()`, `Joi.string().alphanum()`, `Joi.string().uri()`, `Joi.number().integer().min(1)`, `Joi.boolean()`, `Joi.date().iso()`, `Joi.string().regex(/.../)`.
4.  **Mandatory vs. Optional:** Use `.required()` for mandatory fields and `.optional()` for optional fields.
5.  **Forbidden Fields:** Use `.forbidden()` to explicitly disallow unexpected fields.
6.  **Strip Unnecessary Fields:** Use `.strip()` to remove validated but unnecessary fields.
7.  **`failAction` Configuration:** Set the `failAction` option in your Hapi route configuration (`options.validate.failAction`).  Options include `'error'`, `'log'`, a custom function, or the default (400 Bad Request).
8.  **Asynchronous Validation:** Use `Joi.validateAsync()` for asynchronous validation rules (e.g., database lookups).
9.  **Regular Review:** Regularly review and update `joi` schemas.

**Threats Mitigated:**
*   **Cross-Site Scripting (XSS) (High Severity):** `joi` helps prevent XSS by validating input types and structure, making it harder to inject malicious scripts (though sanitization is still recommended *after* validation).
*   **NoSQL Injection (High Severity):** `joi`'s type validation and restrictions prevent manipulation of queries.
*   **Command Injection (High Severity):** Strict input validation with `joi` reduces the risk.
*   **Data Type Mismatches (Medium Severity):** `joi` enforces expected types.
*   **Business Logic Errors (Variable Severity):** Custom `joi` extensions can enforce business rules.

**Impact:**
*   **XSS, NoSQL Injection, Command Injection:** Risk significantly reduced (from High to Low/Negligible).
*   **Data Type Mismatches:** Risk eliminated (from Medium to None).
*   **Business Logic Errors:** Risk reduced.

**Currently Implemented:**
*   Examples:
    *   "Implemented for user registration (`/register`) and product creation (`/products`). Schemas in `src/validation/`. `failAction` is default."
    *   "Partially implemented. Basic validation exists, but not all fields are validated, and `forbidden()` is not consistent."

**Missing Implementation:**
*   Examples:
    *   "Missing for `/comments` (high XSS risk)."
    *   "Missing for query parameters on `/search` (NoSQL injection risk)."
    *   "`forbidden()` is not used in any schemas."
    *   "No regular review process for `joi` schemas."

## Mitigation Strategy: [Secure Route Configuration (Hapi-Specific)](./mitigation_strategies/secure_route_configuration__hapi-specific_.md)

**Mitigation Strategy:** Secure Route Configuration (Hapi-Specific)

**Description:**
1.  **Explicit Route Definitions:** Define each Hapi route explicitly with its HTTP method (GET, POST, PUT, DELETE, etc.) and path. Avoid wildcard routes (`/{param*}`) unless absolutely necessary and with strong `joi` validation.
2.  **Specific HTTP Methods:** Use the correct HTTP method for each route. Avoid `method: '*'`.  
3.  **Route Ordering:** Define more specific routes *before* less specific routes in your Hapi server configuration.
4.  **`vhost` Configuration (if applicable):** If using Hapi's virtual hosts (`vhost` option), ensure each virtual host has its own isolated set of routes.
5.  **Avoid Route-Based Logic:** Keep Hapi route handlers concise. Move complex logic to services.

**Threats Mitigated:**
*   **Unintended Route Access (Medium to High Severity):** Explicit definitions and correct methods prevent unauthorized access.
*   **Information Disclosure (Medium Severity):** Proper ordering and `vhost` configuration prevent exposure.
*   **Denial of Service (DoS) (Medium Severity):** Avoiding broad wildcards reduces DoS risk.
*   **Method Tampering (Medium Severity):** Specific methods prevent bypassing security controls.

**Impact:**
*   **Unintended Route Access, Information Disclosure, DoS, Method Tampering:** Risk significantly reduced.

**Currently Implemented:**
*   Examples:
    *   "All routes are explicit with specific methods. No wildcards. Ordering needs review."
    *   "Virtual hosts are not used."
    *   "Most logic is in services, but some handlers are complex."

**Missing Implementation:**
*   Examples:
    *   "Wildcard route (`/admin/{path*}`) needs stricter validation."
    *   "Route ordering needs a comprehensive review."
    *   "`/legacy` uses `method: '*'`. Needs specific methods."
    *   "Complex logic in `/process-payment` should be moved."

## Mitigation Strategy: [Secure Authentication and Authorization (Hapi-Specific)](./mitigation_strategies/secure_authentication_and_authorization__hapi-specific_.md)

**Mitigation Strategy:** Secure Authentication and Authorization (Hapi-Specific)

**Description:**
1.  **Use Established Strategies:** Use Hapi authentication strategies like `hapi-auth-jwt2` (JWT) or `bell` (OAuth). Avoid custom logic.
2.  **Secure Strategy Configuration:** Configure the chosen Hapi authentication strategy securely:
    *   **`hapi-auth-jwt2`:** Strong keys, appropriate expiration (`exp`), validate issuer (`iss`) and audience (`aud`), secure algorithms (`algorithms` option).
    *   **`bell`:** Securely store client IDs/secrets, use appropriate scopes, validate redirect URIs.
3.  **`auth` Route Option:** Use the `auth` option in your Hapi route configurations to protect routes. Specify the strategy.
4.  **Authentication Modes:** Use the `mode` option (`'required'`, `'optional'`, `'try'`) appropriately.
5.  **Authorization Checks (Post-Authentication):** After authentication, implement authorization checks. Use `request.auth.credentials` to access user information (roles, permissions) for authorization.

**Threats Mitigated:**
*   **Authentication Bypass (High Severity):** Strong strategies and configurations prevent bypass.
*   **Unauthorized Access (High Severity):** Authorization checks ensure only authorized users access resources.
*   **Privilege Escalation (High Severity):** Proper authorization prevents gaining unintended privileges.

**Impact:**
*   **Authentication Bypass, Unauthorized Access, Privilege Escalation:** Risk significantly reduced.

**Currently Implemented:**
*   Examples:
    *   "Uses `hapi-auth-jwt2`. JWTs signed with strong key, expiration set. `auth` option used on protected routes."
    *   "Basic authorization checks based on roles in `request.auth.credentials.roles`."

**Missing Implementation:**
*   Examples:
    *   "Not validating `iss` and `aud` claims in JWTs."
    *   "Authorization checks are not comprehensive."
    *   "Need more granular authorization based on permissions, not just roles."

## Mitigation Strategy: [Secure Error Handling (Hapi-Specific)](./mitigation_strategies/secure_error_handling__hapi-specific_.md)

**Mitigation Strategy:** Secure Error Handling (Hapi-Specific)

**Description:**
1.  **Avoid Default Error Responses:** Do *not* rely on Hapi's default error responses in production.
2.  **Use Boom Errors:** Use Boom errors (`@hapi/boom`) for consistent, user-friendly responses.
3.  **Custom Error Handling:** Implement custom logic to catch errors and use `h.response()` to create responses.
4.  **`onPreResponse` Extension:** Use Hapi's `onPreResponse` extension point to intercept errors globally:
    *   Log detailed error information (including stack traces) securely.
    *   Transform Boom errors into user-friendly responses.
    *   Hide internal details from the client.
5.  **Never Expose Stack Traces:** Never return stack traces to the client in production.

**Threats Mitigated:**
*   **Information Disclosure (Medium to High Severity):** Prevents revealing internal details through errors.
*   **Error-Based Attacks (Variable Severity):** Consistent, controlled error responses make exploitation harder.

**Impact:**
*   **Information Disclosure, Error-Based Attacks:** Risk significantly reduced.

**Currently Implemented:**
*   Examples:
    *   "Uses Boom errors. `onPreResponse` logs errors. Stack traces not exposed."

**Missing Implementation:**
*   Examples:
    *   "Some routes return default Hapi errors."
    *   "Not consistently using Boom errors."
    *   "`onPreResponse` not fully utilized."
    *   "Need to review to ensure no sensitive information is leaked."

## Mitigation Strategy: [Secure State Management (Cookies - Hapi-Specific)](./mitigation_strategies/secure_state_management__cookies_-_hapi-specific_.md)

**Mitigation Strategy:** Secure State Management (Cookies - Hapi-Specific)

**Description:**
1.  **Use `server.state`:** Use Hapi's `server.state` API to define and manage cookies.
2.  **`isSecure`:** Always set `isSecure: true`.
3.  **`isHttpOnly`:** Always set `isHttpOnly: true`.
4.  **`isSameSite`:** Set `isSameSite` to `'Strict'` or `'Lax'`.
5.  **`domain`:** Set the `domain` attribute appropriately.
6.  **`path`:** Set the `path` attribute appropriately.
7.  **`ttl` (Time-to-Live):** Set a reasonable `ttl` value (milliseconds).
8.  **`encodingKey`:** If using cookie encryption, use a strong, randomly generated, and securely stored `encodingKey`. Rotate this key.
9. **Avoid Storing Sensitive Data in Cookies:** Minimize the amount of sensitive data stored in cookies.

**Threats Mitigated:**
*   **Session Hijacking (High Severity):** `isSecure`, `isHttpOnly`, strong `encodingKey` reduce risk.
*   **Cross-Site Request Forgery (CSRF) (High Severity):** `isSameSite` mitigates CSRF.
*   **Cross-Site Scripting (XSS) (High Severity):** `isHttpOnly` prevents XSS from accessing cookies.
*   **Information Disclosure (Medium Severity):** Proper `domain` and `path` prevent leaks.

**Impact:**
*   **Session Hijacking, CSRF, XSS (cookie access), Information Disclosure:** Risk significantly reduced.

**Currently Implemented:**
*   Examples:
     *   "Uses `server.state`. `isSecure`, `isHttpOnly`, `isSameSite: 'Lax'` set. Strong `encodingKey` used and stored securely."

**Missing Implementation:**
*   Examples:
    *   "Not consistently using `server.state`. Some cookies set manually."
    *   "`isSameSite` not set for all cookies."
    *   "Review `ttl` values."
    *   "Sensitive data in cookies without encryption."
    *   "Consider switching to `isSameSite: 'Strict'`."

## Mitigation Strategy: [Secure Caching Configuration (Hapi-Specific)](./mitigation_strategies/secure_caching_configuration__hapi-specific_.md)

**Mitigation Strategy:** Secure Caching Configuration (Hapi-Specific)

**Description:**
1.  **Cache Key Design:**  Design cache keys using Hapi's `server.cache` to be specific to the user and request. Include relevant parameters (user ID, query parameters, etc.) in the key.
2.  **Cache Invalidation:** Implement cache invalidation within your Hapi application logic. When data changes, invalidate corresponding cache entries.
3.  **Cache Size Limits:** Set size limits using the `max` option in Hapi's `server.cache` configuration.
4.  **Avoid Caching Sensitive Data:** Avoid caching sensitive data unless absolutely necessary. If required, encrypt and restrict access.
5. **Use `segments`:** Use different cache segments for different types of data using Hapi's `segments` option in `server.cache`.

**Threats Mitigated:**
*   **Stale Data (Medium Severity):** Proper invalidation ensures up-to-date information.
*   **Denial of Service (DoS) (Medium Severity):** Size limits prevent cache exhaustion.
*   **Information Disclosure (Medium to High Severity):** Careful key design and avoiding sensitive data prevent exposure.

**Impact:**
    *   **Stale Data, DoS, Information Disclosure:** Risk significantly reduced.

**Currently Implemented:**
*   Examples:
    *   "Uses `server.cache`. Keys include query parameters. Time-based invalidation (`ttl`). Size limits set."

**Missing Implementation:**
*   Examples:
    *   "Not all relevant parameters in keys."
    *   "Need a more robust invalidation strategy."
    *   "Caching user-specific data without encryption."
    *   "Should use different cache segments."

