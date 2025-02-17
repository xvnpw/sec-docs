# Attack Tree Analysis for graphql/graphql-js

Objective: Unauthorized Data Access, Modification, or Denial of Service via `graphql-js`

## Attack Tree Visualization

                                      [Attacker's Goal: Unauthorized Data Access, Modification, or Denial of Service via graphql-js]
                                                                    |
                                        ========================================================================================
                                        |||                                                                               |||
                    [*** 1. Information Disclosure ***]                                                                [*** 3. Denial of Service (DoS) ***]
                                        |||
                    ====================================                                                                =================================================
                    |||                  |||                |||                                                                 |||                                 |||
        [*** 1.1 Introspection Abuse ***] [1.2 Field Suggestion] [*** 1.3 Error Leaks ***]                          [*** 3.1 Query Complexity ***] [*** 3.2 Field Duplication ***]
                    |||                  |||                |||                                                                 |||                                 |||
    ========================   -----------------   ==========                                                      =========================   =========================
    |||                      |||   |               |   |||          |||                                                      |||                       |||   |||                       |||
[*** 1.1.1 Query Schema ***] [*** 1.1.2 List Types ***] [1.2.1 Typos] [1.2.2 Partial] [*** 1.3.1 Stack Traces ***] [1.3.2 Field Errors]   [*** 3.1.1 Deep Nesting ***] [*** 3.1.2 Many Fields ***] [*** 3.2.1 Aliases ***] [*** 3.2.2 Fragments ***]

## Attack Tree Path: [1. Information Disclosure](./attack_tree_paths/1__information_disclosure.md)

*   **Critical Node: 1.1 Introspection Abuse**
    *   **Description:** Exploiting GraphQL's introspection system to reveal schema details.
    *   **High-Risk Path:** Direct access to introspection features if enabled.
    *   **Critical Node: 1.1.1 Query Schema**
        *   **Description:** Using introspection queries (e.g., `__schema`, `__type`) to obtain a complete map of the GraphQL schema, including types, fields, arguments, and relationships.
        *   **Likelihood:** High (if introspection is enabled)
        *   **Impact:** High (full schema exposure)
        *   **Effort:** Very Low (simple query)
        *   **Skill Level:** Beginner
        *   **Detection Difficulty:** Medium (detectable through query logging)
    *   **Critical Node: 1.1.2 List Types**
        *   **Description:** Specifically querying for all available types using introspection, potentially revealing internal or administrative types.
        *   **Likelihood:** High (if introspection is enabled)
        *   **Impact:** Medium (exposure of type names)
        *   **Effort:** Very Low (simple query)
        *   **Skill Level:** Beginner
        *   **Detection Difficulty:** Medium (detectable through query logging)

*  **1.2 Field Suggestion**
    *   **Description:**  Leveraging field suggestions to discover valid field names.
    *   **High-Risk Path:**  Exploiting enabled field suggestions through typos or partial inputs.
    *   **1.2.1 Typos**
        *   **Description:** Intentionally making typos in field names to trigger suggestions.
        *   **Likelihood:** Medium (if suggestions are enabled)
        *   **Impact:** Low (exposure of individual field names)
        *   **Effort:** Very Low (trial and error)
        *   **Skill Level:** Beginner
        *   **Detection Difficulty:** Hard (requires analyzing error responses)
    *   **1.2.2 Partial**
        *   **Description:** Providing partial field names to get auto-completion suggestions.
        *   **Likelihood:** Medium (if suggestions are enabled)
        *   **Impact:** Low (exposure of individual field names)
        *   **Effort:** Very Low (trial and error)
        *   **Skill Level:** Beginner
        *   **Detection Difficulty:** Hard (requires analyzing error responses)

*   **Critical Node: 1.3 Error Leaks**
    *   **Description:** Obtaining sensitive information from error messages.
    *   **High-Risk Path:** Triggering errors and examining the responses.
    *   **Critical Node: 1.3.1 Stack Traces**
        *   **Description:**  Exploiting error responses that include stack traces, revealing internal implementation details, file paths, and potentially data.
        *   **Likelihood:** Low (should be disabled in production)
        *   **Impact:** Very High (code and data exposure)
        *   **Effort:** Very Low (trigger an error)
        *   **Skill Level:** Beginner
        *   **Detection Difficulty:** Very Easy (visible in error responses)
    * **1.3.2 Field Errors**
        *   **Description:** Error messages related to specific fields (e.g., "Field 'secretField' does not exist") can confirm the existence or non-existence of fields.
        *   **Likelihood:** Medium (depends on error handling)
        *   **Impact:** Low (confirmation of field existence)
        *   **Effort:** Very Low (trigger an error)
        *   **Skill Level:** Beginner
        *   **Detection Difficulty:** Medium (requires analyzing error responses)

## Attack Tree Path: [3. Denial of Service (DoS)](./attack_tree_paths/3__denial_of_service__dos_.md)

*   **Critical Node: 3.1 Query Complexity**
    *   **Description:** Crafting overly complex queries to consume excessive server resources.
    *   **High-Risk Path:**  Submitting queries with deep nesting or a large number of fields.
    *   **Critical Node: 3.1.1 Deep Nesting**
        *   **Description:** Creating deeply nested queries to force the server to traverse many levels of relationships.
        *   **Likelihood:** Medium (if no complexity limits)
        *   **Impact:** High (service unavailability)
        *   **Effort:** Low (craft a nested query)
        *   **Skill Level:** Intermediate
        *   **Detection Difficulty:** Medium (performance monitoring)
    *   **Critical Node: 3.1.2 Many Fields**
        *   **Description:** Requesting a large number of fields in a single query.
        *   **Likelihood:** Medium (if no complexity limits)
        *   **Impact:** High (service unavailability)
        *   **Effort:** Low (craft a wide query)
        *   **Skill Level:** Intermediate
        *   **Detection Difficulty:** Medium (performance monitoring)

*   **Critical Node: 3.2 Field Duplication**
    *   **Description:**  Duplicating fields within a query to increase processing load.
    *   **High-Risk Path:** Using aliases or fragments to request the same data multiple times.
    *   **Critical Node: 3.2.1 Aliases**
        *   **Description:** Using aliases to request the same field multiple times under different names.
        *   **Likelihood:** Medium (if no complexity limits)
        *   **Impact:** High (service unavailability)
        *   **Effort:** Low (use aliases)
        *   **Skill Level:** Intermediate
        *   **Detection Difficulty:** Medium (performance monitoring)
    *   **Critical Node: 3.2.2 Fragments**
        *   **Description:** Defining fragments that include the same fields multiple times and then including those fragments in the query.
        *   **Likelihood:** Medium (if no complexity limits)
        *   **Impact:** High (service unavailability)
        *   **Effort:** Low (use fragments)
        *   **Skill Level:** Intermediate
        *   **Detection Difficulty:** Medium (performance monitoring)

