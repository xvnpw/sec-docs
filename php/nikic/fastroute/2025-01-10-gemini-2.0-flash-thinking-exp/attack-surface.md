# Attack Surface Analysis for nikic/fastroute

## Attack Surface: [Conflicting Route Definitions](./attack_surfaces/conflicting_route_definitions.md)

*   **Description:** The application has route definitions that overlap or have ambiguous matching rules.
    *   **How fastroute contributes to the attack surface:** `fastroute`'s route matching algorithm will follow a specific order or priority when multiple routes could potentially match a given URI. Attackers can exploit this to target unintended handlers.
    *   **Example:** Defining both `/users/{id}` and `/users/admin` where `/users/admin` might be incorrectly matched by the more general `/users/{id}` route.
    *   **Impact:** Access to unintended resources or functionality, bypassing authorization checks, or triggering incorrect application logic.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Carefully review and plan route definitions to avoid overlaps and ambiguities.
        *   Utilize more specific route patterns where possible.
        *   Leverage `fastroute`'s features for defining route priorities or constraints if available.
        *   Thoroughly test routing logic with various URI inputs to ensure intended behavior.

## Attack Surface: [Regular Expression Denial of Service (ReDoS) in Route Definitions](./attack_surfaces/regular_expression_denial_of_service__redos__in_route_definitions.md)

*   **Description:** If regular expressions are used in route definitions, poorly written or complex regexes can be vulnerable to ReDoS attacks.
    *   **How fastroute contributes to the attack surface:** `fastroute` uses these regular expressions to match incoming URIs. A vulnerable regex can cause the matching process to take an excessively long time for specific crafted URIs.
    *   **Example:** Defining a route like `/path/{param:[a-zA-Z]+([a-zA-Z]+)*}` and sending a long string of 'a' characters as the parameter value.
    *   **Impact:** Denial of Service (DoS) due to excessive CPU consumption during route matching.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Avoid overly complex regular expressions in route definitions.
        *   Thoroughly test regular expressions for performance with various inputs, including potentially malicious ones.
        *   Consider alternative, simpler route definition methods if possible.
        *   Implement timeouts or resource limits for route matching operations.

