# Attack Surface Analysis for gorilla/mux

## Attack Surface: [Overly Permissive Routes](./attack_surfaces/overly_permissive_routes.md)

*   **Description:** Routes defined with broad patterns that unintentionally expose handlers to unexpected inputs or HTTP methods.
    *   **How `mux` Contributes:** `mux`'s flexible routing capabilities make it easy to create overly general routes if not used carefully.  This is the *core* function of `mux`.
    *   **Example:** A route `/api/{resource}/{id}` without restrictions on `{resource}` could expose internal APIs. `/admin/{anything...}` without authentication.
    *   **Impact:** Unauthorized access to sensitive data or functionality, potential for remote code execution (RCE) if the handler is vulnerable.
    *   **Risk Severity:** High to Critical.
    *   **Mitigation Strategies:**
        *   **Specificity:** Define routes as specifically as possible.
        *   **Method Restriction:** Use `mux.Methods()` to restrict HTTP methods.
        *   **Input Validation:** Rigorous input validation *within each handler*.
        *   **Regular Audits:** Regularly review route configurations.
        *   **Least Privilege:** Handlers should operate with least privilege.

## Attack Surface: [Incorrect Path Variable Handling](./attack_surfaces/incorrect_path_variable_handling.md)

*   **Description:** Failure to sanitize or validate path variables extracted by `mux.Vars(r)`. 
    *   **How `mux` Contributes:** `mux` provides the `Vars()` function to extract path variables *without* sanitization or validation. This is a direct feature of `mux`.
    *   **Example:** `/users/{id}` used directly in a SQL query (SQLi) or file access (path traversal).
    *   **Impact:** SQL injection, path traversal, potentially RCE or data breaches.
    *   **Risk Severity:** High to Critical.
    *   **Mitigation Strategies:**
        *   **Sanitization:** Always sanitize path variables.
        *   **Validation:** Validate path variable format and range.
        *   **Parameterized Queries:** Use parameterized queries or ORMs (SQLi prevention).
        *   **Safe File Access:** Prevent path traversal.
        *   **Type Conversion:** Convert to the appropriate data type.

## Attack Surface: [Regular Expression Denial of Service (ReDoS)](./attack_surfaces/regular_expression_denial_of_service__redos_.md)

*   **Description:** Using vulnerable regular expressions in route definitions (within `mux`) for matching.
    *   **How `mux` Contributes:** `mux` *directly* uses regular expressions for route matching, making this a `mux`-specific attack vector.
    *   **Example:** `/products/{name:.*[a-z]+.*}` with malicious input causing backtracking.
    *   **Impact:** Denial of service (DoS).
    *   **Risk Severity:** High.
    *   **Mitigation Strategies:**
        *   **Regex Review:** Carefully review and test all regexes.
        *   **Avoid Complexity:** Avoid overly complex regex patterns.
        *   **Regex Analysis Tools:** Use tools to detect ReDoS vulnerabilities.
        *   **Input Length Limits:** Limit input length.
        *   **Timeouts:** Implement request timeouts.
        * **Alternative Matching:** Consider simpler matching if possible.

## Attack Surface: [Unintended Route Overlap](./attack_surfaces/unintended_route_overlap.md)

*   **Description:** Multiple routes unintentionally matching the same request.
    *   **How `mux` Contributes:** `mux`'s routing logic and precedence rules, if misconfigured, can lead to this overlap. This is inherent to how `mux` handles route matching.
    *   **Example:** `/users/{id}` and `/users/profile` both potentially matching `/users/profile`.
    *   **Impact:** Execution of the wrong handler, leading to incorrect data, unauthorized access, or unexpected behavior.
    *   **Risk Severity:** High (depending on the consequences).
    *   **Mitigation Strategies:**
        *   **Careful Design:** Plan routes to avoid overlaps.
        *   **`mux.Walk`:** Use `mux.Walk` to inspect routes.
        *   **Testing:** Thoroughly test with various request patterns.
        *   **Route Ordering:** Register specific routes first.
        *   **Explicit Matching:** Use more explicit criteria.

