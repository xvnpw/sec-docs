# Attack Surface Analysis for nikic/fastroute

## Attack Surface: [Overlapping Route Definitions](./attack_surfaces/overlapping_route_definitions.md)

*   **Description:** Defining multiple routes that match the same URI pattern, leading to ambiguity in which handler will be executed.
    *   **How FastRoute Contributes:** FastRoute relies on the order of route definition. If routes are not defined carefully, a more general route might be matched before a more specific one, leading to unintended behavior.
    *   **Example:**
        *   Route 1: `/users/{id}` - Handles requests for specific user IDs.
        *   Route 2: `/users/create` - Handles requests to create a new user.
        If Route 1 is defined before Route 2, a request to `/users/create` might be incorrectly matched by the `{id}` parameter, potentially leading to an error or unexpected action.
    *   **Impact:**  Logic errors, access control bypasses (if different handlers have different authorization checks), denial of service (if the wrong handler is resource-intensive).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Define routes from most specific to least specific.
        *   Use more restrictive route patterns where possible.
        *   Implement thorough testing to ensure routes behave as expected.
        *   Utilize route grouping or namespacing features (if available in the application framework) to organize routes logically.

## Attack Surface: [Insecure Regular Expressions in Route Parameters](./attack_surfaces/insecure_regular_expressions_in_route_parameters.md)

*   **Description:** Using overly complex or poorly written regular expressions within route parameters (e.g., `{param:regex}`) that can lead to Regular Expression Denial of Service (ReDoS) or bypass intended input validation.
    *   **How FastRoute Contributes:** FastRoute allows the use of regular expressions for parameter matching. If these regexes are not carefully crafted, they can become a vulnerability.
    *   **Example:**
        *   Route: `/search/{query:.+?(.+)+}`
        An attacker could send a long string like `/search/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!` which could cause the regex engine to consume excessive CPU time due to backtracking.
    *   **Impact:** Denial of Service (ReDoS), potential for bypassing intended input validation leading to further vulnerabilities in the handler.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Avoid complex regular expressions in route parameters if possible.
        *   Thoroughly test regular expressions with various inputs, including potentially malicious ones.
        *   Use simpler, more specific regex patterns.
        *   Consider alternative input validation methods within the handler if complex validation is required.
        *   Implement timeouts for regex matching if the framework allows.

## Attack Surface: [Unintended Route Matching due to Broad Wildcards](./attack_surfaces/unintended_route_matching_due_to_broad_wildcards.md)

*   **Description:** Using overly broad wildcard patterns (e.g., `/api/{path+}`) without sufficient validation in the corresponding handler, potentially exposing more of the application's functionality than intended.
    *   **How FastRoute Contributes:** FastRoute's wildcard functionality allows capturing multiple path segments. If not used cautiously, it can lead to unintended route matches.
    *   **Example:**
        *   Route: `/admin/{path+}`
        If the handler for this route doesn't properly validate the `path` parameter, an attacker might be able to access unintended administrative functions by crafting URIs like `/admin/users/delete/123`.
    *   **Impact:** Access control bypass, unauthorized access to resources or functionalities.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Avoid using overly broad wildcards unless absolutely necessary.
        *   Implement strict input validation and sanitization within the handler for wildcard parameters.
        *   Use more specific route patterns whenever possible.
        *   Consider breaking down broad functionalities into more specific routes.

