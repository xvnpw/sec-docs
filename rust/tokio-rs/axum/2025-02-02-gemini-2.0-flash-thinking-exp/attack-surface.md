# Attack Surface Analysis for tokio-rs/axum

## Attack Surface: [Path Parameter Injection](./attack_surfaces/path_parameter_injection.md)

*   **Description:** Exploiting path parameters in routes to manipulate application behavior, access unauthorized resources, or inject malicious payloads.
*   **Axum Contribution:** Axum's routing system and `Path` extractor directly enable the use of path parameters. If these are not validated within Axum handlers, it creates a direct attack surface.
*   **Example:** A route `/users/{id}` where `id` is used in a database query without validation. An attacker uses `id=1; DELETE FROM users; --` to attempt SQL injection.
*   **Impact:** Data breach, data manipulation, unauthorized access, denial of service.
*   **Risk Severity:** High to Critical
*   **Mitigation Strategies:**
    *   **Input Validation:**  Strictly validate all path parameters within handler functions using libraries like `validator` or manual checks. Ensure parameters conform to expected formats, types, and ranges *before* using them in application logic.
    *   **Parameterized Queries:**  Always use parameterized queries or ORM features when path parameters are used in database interactions to prevent SQL injection.
    *   **Principle of Least Privilege:** Limit application access to only necessary resources, reducing the impact of potential path traversal vulnerabilities.

## Attack Surface: [Query Parameter Injection](./attack_surfaces/query_parameter_injection.md)

*   **Description:** Injecting malicious code or manipulating application logic through query parameters in the URL.
*   **Axum Contribution:** Axum's automatic query parameter parsing and `Query` extractor make query parameters easily accessible. Lack of validation in Axum handlers directly leads to this attack surface.
*   **Example:** An application uses a `search` query parameter in a database query without sanitization. An attacker injects SQL code in the `search` parameter.
*   **Impact:** Data breach, data manipulation, unauthorized access, denial of service.
*   **Risk Severity:** High to Critical
*   **Mitigation Strategies:**
    *   **Input Validation:** Validate and sanitize all query parameters within Axum handlers against expected formats and values. Use libraries like `validator` or manual checks.
    *   **Parameterized Queries:**  Utilize parameterized queries or ORM features to prevent SQL injection when query parameters are used in database interactions.
    *   **Content Security Policy (CSP):** Implement CSP to reduce the impact of potential client-side injection vulnerabilities that might be triggered by query parameter manipulation.

## Attack Surface: [Request Body Deserialization Vulnerabilities](./attack_surfaces/request_body_deserialization_vulnerabilities.md)

*   **Description:** Exploiting vulnerabilities arising from deserializing request bodies (e.g., JSON, XML, forms) into application data structures. This includes deserialization of untrusted data leading to code execution or resource exhaustion.
*   **Axum Contribution:** Axum's seamless integration with `serde` via extractors like `Json` and `Form` simplifies deserialization. However, insecure deserialization practices within Axum handlers directly expose the application.
*   **Example:**
    *   **Deserialization of Untrusted Data:** An Axum application deserializing JSON without schema validation is vulnerable if `serde` or application logic has flaws when processing unexpected JSON structures, potentially leading to Remote Code Execution if specific deserialization gadgets are present in dependencies.
    *   **Resource Exhaustion:** Sending a very large or deeply nested JSON payload to an Axum endpoint, causing excessive resource consumption during deserialization and leading to Denial of Service.
*   **Impact:** Remote code execution, denial of service, data corruption.
*   **Risk Severity:** Medium to Critical (Critical in RCE scenarios)
*   **Mitigation Strategies:**
    *   **Schema Validation:** Implement strict schema validation for request bodies using libraries like `serde_json_schema` or `schemars` to ensure incoming data conforms to expected structures *before* deserialization within Axum handlers.
    *   **Request Body Size Limits:** Enforce limits on the size of request bodies within Axum configuration or middleware to prevent resource exhaustion attacks.
    *   **Secure Deserialization Practices:**  Keep `serde` and related dependencies updated to patch known deserialization vulnerabilities. Be mindful of potential deserialization gadgets in project dependencies.

## Attack Surface: [Misconfigured HTTP Method Handling](./attack_surfaces/misconfigured_http_method_handling.md)

*   **Description:** Incorrectly configuring or handling HTTP methods (GET, POST, PUT, DELETE, etc.) for routes, leading to unintended access or actions, potentially allowing unauthorized modification of resources.
*   **Axum Contribution:** Axum's method-aware routing directly relies on developers correctly configuring method handlers (e.g., `.get()`, `.post()`). Misconfigurations in Axum route definitions directly create this vulnerability.
*   **Example:** A resource intended for read-only access via `GET` is inadvertently also accessible via `POST` due to a routing misconfiguration in Axum, allowing unauthorized data modification through `POST` requests.
*   **Impact:** Unauthorized data modification, data corruption, privilege escalation.
*   **Risk Severity:** Medium to High (Can be Critical if sensitive data modification is possible)
*   **Mitigation Strategies:**
    *   **Explicit and Correct Route Definitions:** Carefully define allowed HTTP methods for each route in Axum, ensuring they strictly align with the intended functionality and resource access control. Double-check route definitions for any unintended method handlers.
    *   **Testing:** Thoroughly test route configurations, specifically method handling, to verify that only intended methods are allowed for each resource and that unauthorized methods are correctly rejected by Axum.
    *   **Principle of Least Privilege for Methods:** Restrict HTTP methods to the absolute minimum required for each route and resource. Avoid allowing methods that are not explicitly needed.

