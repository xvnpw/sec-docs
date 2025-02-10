# Attack Surface Analysis for dart-lang/shelf

## Attack Surface: [Path Traversal (via `shelf_static` or custom handlers)](./attack_surfaces/path_traversal__via__shelf_static__or_custom_handlers_.md)

*   **Description:** Attackers use `../` sequences in URLs to attempt to access files outside the intended directory.
    *   **How Shelf Contributes:** `shelf_static` and custom file-serving logic within `shelf` handlers require careful path sanitization, which is the developer's responsibility.  `shelf` *does not* automatically prevent this, making it a direct concern.
    *   **Example:** `GET /static/../../etc/passwd`
    *   **Impact:** Unauthorized access to sensitive files on the server, potentially leading to complete system compromise.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Developers: *Never* directly use user-provided input to construct file paths.
        *   Developers: Sanitize and validate all URL path components influencing file access.
        *   Developers: Use `path.normalize` from the `path` package to resolve relative paths *safely*.
        *   Developers: *After* normalization, verify that the resulting path is within the intended directory (using string comparison or a dedicated library).
        *   Developers/Users: Consider using a dedicated, well-vetted static file server (like nginx) in production instead of relying solely on `shelf_static`.

## Attack Surface: [Routing Ambiguities and Overlapping Routes](./attack_surfaces/routing_ambiguities_and_overlapping_routes.md)

*   **Description:** Poorly defined routes with overlaps can lead to unexpected handler invocation.
    *   **How Shelf Contributes:** `shelf`'s routing logic depends on the order and specificity of route definitions. Ambiguities are possible if not carefully managed, and this is a direct function of how `shelf` handles routing.
    *   **Example:** `/users/<id>` and `/users/admin` could be ambiguous if not handled correctly.
    *   **Impact:** Attackers might reach unintended handlers, potentially bypassing security checks or accessing unauthorized resources.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Developers: Design routes to be clear and unambiguous, avoiding overlaps.
        *   Developers: Use `shelf_router` for explicit and well-defined route definitions.
        *   Developers: Thoroughly test routing logic with various inputs, including edge cases.
        *   Developers: Log routing decisions to aid in debugging and auditing.

## Attack Surface: [Regular Expression Denial of Service (ReDoS) in Routing](./attack_surfaces/regular_expression_denial_of_service__redos__in_routing.md)

*   **Description:** Attackers exploit poorly crafted regular expressions in route definitions to cause excessive CPU consumption.
    *   **How Shelf Contributes:** If `shelf_router` is used with regular expressions in route patterns, those expressions are directly used for matching by `shelf`. This is a direct vulnerability introduced by `shelf`'s routing mechanism.
    *   **Example:** A route defined with the regex `^/(a+)+$` could be vulnerable.
    *   **Impact:** Denial of service due to server resource exhaustion.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Developers: Avoid complex or nested regular expressions in routing.
        *   Developers: If regular expressions are necessary, use a library that provides protection against ReDoS (e.g., by limiting backtracking).
        *   Developers: Thoroughly test regular expressions with various inputs, including potentially malicious ones.
        *   Developers: Prefer simpler string matching or parameter extraction where possible.

## Attack Surface: [Middleware Ordering Issues](./attack_surfaces/middleware_ordering_issues.md)

*   **Description:** Incorrect order of middleware execution can bypass security checks.
    *   **How Shelf Contributes:** `shelf` allows chaining middleware, and the order is *critical* for security.  The framework itself provides the mechanism for middleware chaining, making ordering a direct `shelf` concern.
    *   **Example:** Authentication middleware placed *after* authorization middleware.
    *   **Impact:** Security checks might be bypassed, leading to unauthorized access.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Developers: Carefully consider the order of middleware components.
        *   Developers: Place security-related middleware (authentication, authorization, input validation) *before* middleware that handles business logic or accesses sensitive data.
        *   Developers: Document the intended order and purpose of each middleware component.

## Attack Surface: [Exception Handling Failures in Middleware/Handlers](./attack_surfaces/exception_handling_failures_in_middlewarehandlers.md)

*   **Description:** Unhandled exceptions can leak sensitive information or cause denial of service.
    *   **How Shelf Contributes:** While application logic is responsible for *handling* exceptions, `shelf`'s request/response pipeline and the way it handles uncaught exceptions within middleware and handlers are directly relevant. `shelf` provides a default error handler, but it might reveal too much information in production.
    *   **Example:** An unhandled database exception revealing database connection details.
    *   **Impact:** Information disclosure (stack traces, internal implementation details), potential denial of service.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Developers: Implement robust error handling in *all* middleware and handlers.
        *   Developers: Catch all expected exceptions and return appropriate HTTP error responses (e.g., 500 Internal Server Error) *without* revealing sensitive information.
        *   Developers: Use a centralized error handling mechanism for consistency.
        *   Developers: Log all unhandled exceptions for debugging and auditing.

## Attack Surface: [Improper Handling of `Future`s](./attack_surfaces/improper_handling_of__future_s.md)

*   **Description:** Incorrect use of `Future`s can lead to race conditions, data inconsistencies, or unhandled exceptions.
    *   **How Shelf Contributes:** `shelf` *heavily* relies on asynchronous programming with `Future`s for its core request handling.  The framework's design necessitates the correct use of `Future`s.
    *   **Example:** Accessing `request.read()` without `await`ing it.
    *   **Impact:** Race conditions, data corruption, unhandled exceptions, denial of service.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Developers: Always `await` `Future`s when their results are needed.
        *   Developers: Use `try-catch` blocks within `async` functions to handle potential errors.
        *   Developers: Use `.catchError` or `.whenComplete` to handle errors and cleanup resources associated with `Future`s.

