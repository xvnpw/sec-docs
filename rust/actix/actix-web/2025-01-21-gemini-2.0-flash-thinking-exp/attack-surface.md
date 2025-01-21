# Attack Surface Analysis for actix/actix-web

## Attack Surface: [Path Traversal via Route Parameters](./attack_surfaces/path_traversal_via_route_parameters.md)

**Description:** An attacker can manipulate URL route parameters to access files or directories outside the intended scope on the server's file system.

**How Actix Web Contributes:** Actix Web's route parameter extraction (`web::Path`) provides the raw parameter value. If this value is directly used to construct file paths without proper sanitization, it becomes vulnerable.

**Example:** A route defined as `/files/{filename}` and the application uses `std::fs::read_to_string(format!("uploads/{}", filename))`. An attacker could request `/files/../../etc/passwd`.

**Impact:**  Access to sensitive files, potential for arbitrary code execution if combined with other vulnerabilities.

**Risk Severity:** Critical

**Mitigation Strategies:**

*   **Input Sanitization:**  Thoroughly validate and sanitize route parameters before using them in file system operations. Use allow-lists of permitted characters or patterns.
*   **Absolute Paths:**  Construct absolute paths to the intended resources instead of relying on user-provided input for path construction.
*   **Chroot Environments:**  Confine the application's access to a specific directory.

## Attack Surface: [Deserialization of Untrusted Data (via `Json` or `Form` extractors)](./attack_surfaces/deserialization_of_untrusted_data__via__json__or__form__extractors_.md)

**Description:**  The application deserializes data from request bodies (JSON or form data) without proper validation, potentially leading to arbitrary code execution or denial of service.

**How Actix Web Contributes:** Actix Web's `web::Json` and `web::Form` extractors automatically deserialize request bodies using libraries like `serde`. If the data is not validated after deserialization, vulnerabilities in the deserialization process can be exploited.

**Example:**  An application uses `web::Json<User>` where `User` has a `command` field. A malicious user sends a JSON payload like `{"command": "system('rm -rf /')"}`, and if not handled carefully, this could be executed.

**Impact:**  Arbitrary code execution, denial of service, information disclosure.

**Risk Severity:** Critical

**Mitigation Strategies:**

*   **Schema Validation:** Use libraries like `serde_valid` or implement custom validation to ensure the deserialized data conforms to the expected schema and constraints.
*   **Principle of Least Privilege:** Avoid deserializing complex data structures directly into sensitive operations.
*   **Input Sanitization:** Sanitize data after deserialization before using it in critical operations.

## Attack Surface: [Security Bypass in Custom Middleware](./attack_surfaces/security_bypass_in_custom_middleware.md)

**Description:**  Incorrectly implemented custom middleware can introduce vulnerabilities that bypass intended security measures like authentication or authorization.

**How Actix Web Contributes:** Actix Web allows developers to create custom middleware to intercept and process requests. Flaws in the logic of this middleware can create security gaps.

**Example:** A custom authentication middleware checks for a specific header but doesn't handle missing or malformed headers correctly, allowing unauthenticated access.

**Impact:** Unauthorized access to resources, data breaches, privilege escalation.

**Risk Severity:** High

**Mitigation Strategies:**

*   **Thorough Testing:**  Rigorous testing of custom middleware, including negative test cases and edge cases.
*   **Code Reviews:**  Peer review of custom middleware code to identify potential flaws.
*   **Use Established Patterns:**  Follow established security patterns and best practices when implementing authentication and authorization logic in middleware.

## Attack Surface: [Denial of Service via Resource Exhaustion in Middleware](./attack_surfaces/denial_of_service_via_resource_exhaustion_in_middleware.md)

**Description:**  Middleware performs computationally expensive operations or consumes excessive resources on every request, allowing attackers to overload the server with requests.

**How Actix Web Contributes:** Actix Web's middleware pipeline executes sequentially for each request. If a middleware component is inefficient or performs unbounded operations, it can become a bottleneck.

**Example:**  A logging middleware that writes extensive information to a slow disk on every request, or a middleware that performs complex cryptographic operations without proper limits.

**Impact:**  Service unavailability, performance degradation.

**Risk Severity:** High

**Mitigation Strategies:**

*   **Performance Optimization:**  Optimize the performance of middleware components.
*   **Rate Limiting:** Implement rate limiting middleware to restrict the number of requests from a single source.
*   **Resource Limits:**  Set appropriate resource limits (e.g., memory, CPU) for the application.
*   **Asynchronous Operations:**  Use asynchronous operations within middleware to avoid blocking the request processing pipeline.

## Attack Surface: [Server-Side Request Forgery (SSRF) via Actix Web Client](./attack_surfaces/server-side_request_forgery__ssrf__via_actix_web_client.md)

**Description:**  The application makes outbound HTTP requests based on user-controlled input without proper validation, allowing attackers to make requests to internal resources or external services.

**How Actix Web Contributes:**  If the application uses `actix_web::client` to make outbound requests and the target URL or parameters are derived from user input without sanitization, it's vulnerable to SSRF.

**Example:** An application allows users to provide a URL to fetch content from. If the application directly uses this URL in an `actix_web::client::Client::get(user_provided_url).send()`, an attacker could provide an internal URL like `http://localhost:8080/admin`.

**Impact:** Access to internal resources, data breaches, potential for further attacks on internal systems.

**Risk Severity:** High

**Mitigation Strategies:**

*   **Input Validation:**  Strictly validate and sanitize user-provided URLs. Use allow-lists of permitted domains or protocols.
*   **Avoid User Input in URLs:**  Whenever possible, avoid directly using user input to construct URLs for outbound requests.
*   **Network Segmentation:**  Isolate the application server from internal resources.
*   **Disable Unnecessary Protocols:**  Disable protocols that are not required for outbound requests.

