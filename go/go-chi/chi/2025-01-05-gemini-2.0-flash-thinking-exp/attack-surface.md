# Attack Surface Analysis for go-chi/chi

## Attack Surface: [Path Traversal via Route Parameters](./attack_surfaces/path_traversal_via_route_parameters.md)

*   **Description:** Attackers exploit insufficient validation of path parameters in routes to access files or resources outside the intended directory.
*   **How Chi Contributes:** Chi's flexible route definition allows capturing path segments as parameters (e.g., `/files/{filepath}`). If the application doesn't sanitize these parameters, attackers can inject path traversal sequences.
*   **Example:**
    *   Route definition: `r.Get("/files/{filepath}", fileHandler)`
    *   Malicious request: `/files/../../etc/passwd`
    *   If `fileHandler` directly uses the `filepath` parameter to access the file system without validation, it could expose sensitive files.
*   **Impact:** Unauthorized access to sensitive files, potential for information disclosure, and in some cases, remote code execution if accessed files can be interpreted as code.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   Implement robust input validation on route parameters.
    *   Use allow-lists for expected characters and patterns in path parameters.
    *   Sanitize or reject any input containing path traversal sequences (e.g., `..`, `./`).
    *   Avoid directly using user-provided input to construct file paths.
    *   Utilize secure file access methods that restrict access based on defined permissions.

## Attack Surface: [Ambiguous Route Definitions](./attack_surfaces/ambiguous_route_definitions.md)

*   **Description:** Defining overlapping or ambiguous routes can lead to the execution of unintended handlers.
*   **How Chi Contributes:** Chi's routing mechanism relies on matching the most specific route first. However, poorly defined routes can create ambiguity, allowing attackers to target unintended endpoints.
*   **Example:**
    *   Route 1: `r.Get("/users/{id}", userHandler)`
    *   Route 2: `r.Get("/users/admin", adminHandler)`
    *   A request to `/users/admin` might be incorrectly routed to `userHandler` if the order or specificity is not carefully considered.
*   **Impact:** Access to unauthorized functionality, bypassing security controls, potential for privilege escalation.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Carefully design route patterns to avoid overlaps.
    *   Prioritize more specific routes over generic ones.
    *   Thoroughly test routing logic to ensure requests are handled as intended.
    *   Consider using Chi's route grouping features to organize routes logically.

## Attack Surface: [Method Spoofing via Middleware](./attack_surfaces/method_spoofing_via_middleware.md)

*   **Description:** Attackers bypass method-based access controls by using middleware that allows overriding the HTTP method.
*   **How Chi Contributes:** Chi allows using middleware to modify the request, including the HTTP method (e.g., using `X-HTTP-Method-Override`). If not carefully controlled, this can be exploited.
*   **Example:**
    *   Middleware: Checks for `X-HTTP-Method-Override` header.
    *   Application restricts `DELETE` requests to authorized users.
    *   An unauthorized user sends a `POST` request with `X-HTTP-Method-Override: DELETE` to bypass the restriction.
*   **Impact:** Bypassing authorization checks, performing actions that should be restricted based on the HTTP method.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Avoid using method-override middleware in production environments unless absolutely necessary and with strict controls.
    *   If method overriding is required, implement robust authentication and authorization checks that are not solely reliant on the initial HTTP method.
    *   Carefully review and understand the behavior of any method-override middleware used.

