# Attack Surface Analysis for expressjs/express

## Attack Surface: [Route Parameter Pollution (RPP) / HTTP Parameter Pollution (HPP)](./attack_surfaces/route_parameter_pollution__rpp___http_parameter_pollution__hpp_.md)

**Description:** Attackers send multiple HTTP parameters (query string or body) with the same name, aiming to confuse application logic and bypass security checks or access unintended data.

**How Express Contributes:** Express's routing and middleware (especially body-parsing middleware like `body-parser` and `express.json()`) are directly responsible for parsing and making these parameters available to the application via `req.params`, `req.query`, and `req.body`.  The framework's handling of duplicate parameters is a key factor.

**Example:**
    *   URL: `/user?id=1&id=2` (RPP)
    *   POST Body: `id=1&id=2` (HPP)
    *   Express might populate `req.query.id` or `req.body.id` with either "1", "2", or an array `["1", "2"]`, depending on configuration.  Inconsistent handling across the application can lead to vulnerabilities.

**Impact:** Bypass of security checks, unauthorized data access/modification, potential denial of service.

**Risk Severity:** High to Critical.

**Mitigation Strategies:**
    *   **Strict Input Validation:** Use schema validation (Joi, Zod, express-validator) to *enforce* expected types, formats, and allowed values for *all* parameters. Reject requests that don't conform.
    *   **Middleware Configuration:** Carefully configure body-parsing middleware to handle duplicate parameters in a *defined and secure* way (reject, use first, use last, or provide a clear API). Document this behavior.
    *   **Defensive Programming:**  Code defensively, assuming parameters *might* be arrays or unexpected values.  Explicitly handle all possible cases.
    *   **Input Sanitization:** Sanitize all input *after* validation.

## Attack Surface: [Middleware Ordering Issues](./attack_surfaces/middleware_ordering_issues.md)

**Description:** Incorrect ordering of Express middleware creates vulnerabilities by allowing requests to bypass security checks.

**How Express Contributes:** Express's middleware execution is *strictly sequential*, based on the order of `app.use()` calls. This is a core feature of Express and a direct contributor to this vulnerability.

**Example:** Placing authentication middleware *after* a route that accesses sensitive data allows unauthenticated access.

**Impact:** Authentication/authorization bypass, information leakage, data corruption.

**Risk Severity:** High to Critical.

**Mitigation Strategies:**
    *   **Documented Middleware Order:**  Establish and strictly adhere to a documented middleware order (logging, body parsing, security, auth, application logic, error handling).
    *   **Automated Tests:** Write tests that *specifically verify* the correct middleware order and that security checks are applied before sensitive operations.
    *   **Code Reviews:**  Focus on middleware order during code reviews.
    *   **Centralized Middleware:** Manage middleware registration in a centralized module to enforce consistency.

## Attack Surface: [Regular Expression Denial of Service (ReDoS) in Routing](./attack_surfaces/regular_expression_denial_of_service__redos__in_routing.md)

**Description:** Attackers exploit poorly written regular expressions used in Express *routes* to cause excessive CPU consumption and denial of service.

**How Express Contributes:** Express *directly uses* regular expressions for route matching (e.g., `app.get('/user/:id([0-9]+)', ...)`).  Vulnerable regexes in these routes are directly exposed to attacker input. This is a *direct* consequence of Express's routing mechanism.

**Example:** A route with a vulnerable regex like `app.get('/search/:query(.*)', ...)` can be exploited with a crafted input string.

**Impact:** Denial of Service (DoS).

**Risk Severity:** High.

**Mitigation Strategies:**
    *   **Regular Expression Analysis:** Use tools to analyze route regexes for ReDoS vulnerabilities.
    *   **Simple Regular Expressions:**  Use simple, well-defined regexes for routing. Avoid complexity.
    *   **Input Validation (Pre-Regex):** Validate and limit the length/characters of route parameters *before* the regex is applied.
    *   **Timeout Mechanisms:** Consider libraries or techniques to limit regex execution time.
    *   **Avoid User-Controlled Regex:** Never allow users to supply regexes used in routing.

## Attack Surface: [Server-Side Template Injection (SSTI) (When Using Template Engines with Express)](./attack_surfaces/server-side_template_injection__ssti___when_using_template_engines_with_express_.md)

**Description:**  Attackers inject malicious code into server-side templates, leading to code execution.

**How Express Contributes:** While not a direct feature of Express *itself*, Express is *very commonly* used with template engines (Pug, EJS, Handlebars).  Express's `res.render()` function is the direct mechanism by which templates are rendered, and thus, where the vulnerability manifests if user input is unsafely handled. The *combination* of Express and a template engine creates this attack surface.

**Example:** Unsafely rendering user input in an EJS template: `res.render('index', { username: req.query.username });`

**Impact:** Remote Code Execution (RCE), complete server compromise.

**Risk Severity:** Critical.

**Mitigation Strategies:**
    *   **Auto-Escaping:** Use template engines with automatic escaping by default (e.g., Pug).
    *   **Template Parameters:** Pass data to templates as parameters, *never* by concatenating user input.
    *   **Input Sanitization:** Sanitize user input before passing it to the template engine.
    *   **Content Security Policy (CSP):** Use CSP to mitigate the impact of SSTI.
    *   **Context-Aware Escaping:** If manual escaping is needed, use the template engine's context-aware escaping functions.

