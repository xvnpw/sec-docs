# Attack Surface Analysis for hapijs/hapi

## Attack Surface: [Overly Permissive Route Definitions](./attack_surfaces/overly_permissive_route_definitions.md)

*   **Attack Surface:** Overly Permissive Route Definitions
    *   **Description:** Defining routes that are too broad (e.g., using wildcards excessively) can expose unintended parts of the application or internal logic.
    *   **How Hapi Contributes to the Attack Surface:** Hapi's flexible routing system allows for defining routes with parameters and wildcards. If not carefully designed, these features can lead to overly permissive patterns.
    *   **Example:** A route defined as `/api/{entity}/{id*}` might unintentionally allow access to various sub-paths under an entity, even if not explicitly intended. An attacker could try URLs like `/api/user/../../admin` if the `id` parameter isn't properly validated.
    *   **Impact:** Unauthorized access to resources, potential information disclosure, or unintended execution of application logic.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Define specific and restrictive route patterns.
        *   Avoid excessive use of wildcards.
        *   Thoroughly validate and sanitize parameters extracted from route paths.
        *   Use Hapi's routing constraints to limit the scope of parameters.

## Attack Surface: [Payload Parsing Vulnerabilities](./attack_surfaces/payload_parsing_vulnerabilities.md)

*   **Attack Surface:** Payload Parsing Vulnerabilities
    *   **Description:** Exploiting vulnerabilities in the libraries Hapi uses to parse request payloads (e.g., JSON, URL-encoded, multipart).
    *   **How Hapi Contributes to the Attack Surface:** Hapi automatically parses request payloads based on the `Content-Type` header. This relies on underlying libraries which might have vulnerabilities.
    *   **Example:** Sending a deeply nested JSON payload could potentially cause a denial-of-service (DoS) attack by exhausting server resources during parsing. Older versions of JSON parsing libraries might have vulnerabilities to specific malformed JSON structures.
    *   **Impact:** Denial of Service, potential Remote Code Execution (depending on the underlying vulnerability).
    *   **Risk Severity:** High to Critical (depending on the specific vulnerability).
    *   **Mitigation Strategies:**
        *   Keep Hapi and its dependencies (especially parsing libraries) updated to the latest versions.
        *   Implement payload size limits to prevent resource exhaustion.
        *   Consider using schema validation (like `joi`) to enforce the structure and types of incoming payloads, which can mitigate some parsing vulnerabilities.

## Attack Surface: [Insecure Session Management](./attack_surfaces/insecure_session_management.md)

*   **Attack Surface:** Insecure Session Management
    *   **Description:** Vulnerabilities related to how user sessions are created, maintained, and invalidated.
    *   **How Hapi Contributes to the Attack Surface:** Hapi provides mechanisms for state management, often using cookies. Improper configuration of these mechanisms can lead to vulnerabilities.
    *   **Example:** If session cookies are not marked as `HttpOnly`, client-side scripts could potentially access them, leading to session hijacking via Cross-Site Scripting (XSS). Lack of the `Secure` flag on cookies means they might be transmitted over insecure HTTP connections.
    *   **Impact:** Session hijacking, account takeover, unauthorized access to user data.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Configure session cookies with the `HttpOnly`, `Secure`, and `SameSite` attributes.
        *   Use a strong and cryptographically secure session ID generation mechanism (often handled by underlying libraries).
        *   Implement session timeout and idle timeout mechanisms.
        *   Consider using a dedicated session management plugin for enhanced security features.

## Attack Surface: [Vulnerabilities in Hapi Plugins](./attack_surfaces/vulnerabilities_in_hapi_plugins.md)

*   **Attack Surface:** Vulnerabilities in Hapi Plugins
    *   **Description:** Security flaws present in third-party or custom Hapi plugins used by the application.
    *   **How Hapi Contributes to the Attack Surface:** Hapi's plugin architecture allows extending its functionality. However, vulnerabilities in these plugins directly impact the application's security.
    *   **Example:** A poorly written authentication plugin might have vulnerabilities allowing bypass, or a plugin handling file uploads might be susceptible to path traversal attacks.
    *   **Impact:**  Wide range of impacts depending on the plugin's functionality, including unauthorized access, data breaches, and remote code execution.
    *   **Risk Severity:** Medium to Critical (depending on the plugin's vulnerability and privileges).
    *   **Mitigation Strategies:**
        *   Carefully vet and review the code of third-party plugins before using them.
        *   Keep plugins updated to their latest versions to patch known vulnerabilities.
        *   Follow secure coding practices when developing custom Hapi plugins.
        *   Implement security boundaries and least privilege principles for plugins.

## Attack Surface: [Improper Input Validation and Sanitization](./attack_surfaces/improper_input_validation_and_sanitization.md)

*   **Attack Surface:** Improper Input Validation and Sanitization
    *   **Description:** Failing to properly validate and sanitize user-supplied input can lead to various vulnerabilities.
    *   **How Hapi Contributes to the Attack Surface:** While Hapi provides tools for validation (like `joi`), developers must actively implement and configure these. Neglecting this step introduces risk.
    *   **Example:** If user input for a search query is not sanitized, it could be used to inject malicious scripts (Cross-Site Scripting) if the output is rendered in HTML without proper encoding.
    *   **Impact:** Cross-Site Scripting (XSS), Command Injection, other injection attacks, data corruption.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Utilize Hapi's validation features (e.g., `joi`) to define schemas and validate all incoming data.
        *   Sanitize user input before processing or storing it, especially when dealing with HTML or other potentially dangerous formats.
        *   Implement output encoding to prevent XSS when displaying user-generated content.

