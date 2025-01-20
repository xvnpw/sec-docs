# Attack Surface Analysis for doctrine/orm

## Attack Surface: [SQL Injection through DQL or Native Queries](./attack_surfaces/sql_injection_through_dql_or_native_queries.md)

*   **Description:** Attackers inject malicious SQL code into queries executed by the application, potentially leading to unauthorized data access, modification, or deletion.
    *   **How ORM Contributes:** Doctrine's DQL and ability to execute native SQL queries can become vulnerable if user-supplied data is directly incorporated into these queries without proper sanitization or parameterization. Dynamic DQL construction and direct string concatenation in native queries are primary contributors.
    *   **Example:**  A vulnerable DQL query might look like: `$entityManager->createQuery("SELECT u FROM App\\Entity\\User u WHERE u.username = '" . $_GET['username'] . "'");`  An attacker could provide `' OR '1'='1` as the username to bypass authentication.
    *   **Impact:** Full database compromise, data breaches, data manipulation, denial of service.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Always use parameterized queries: Doctrine supports parameter binding for both DQL and native SQL, which prevents SQL injection by treating user input as data, not executable code.
        *   Avoid dynamic DQL construction with direct user input: If dynamic queries are necessary, use Doctrine's query builder and parameter binding.
        *   Sanitize user input (as a secondary measure): While parameterization is the primary defense, input validation and sanitization can provide an additional layer of security.

## Attack Surface: [Mass Assignment Vulnerabilities](./attack_surfaces/mass_assignment_vulnerabilities.md)

*   **Description:** Attackers can modify unintended entity properties by manipulating input data during entity creation or updates.
    *   **How ORM Contributes:** Doctrine's ability to hydrate entities directly from request data can be exploited if not handled carefully. If an application blindly sets entity properties based on user input without validation or whitelisting, attackers can modify sensitive fields.
    *   **Example:** An HTTP POST request with unexpected fields like `isAdmin=1` could potentially set the `isAdmin` property of a `User` entity if the application directly hydrates the entity from the request data without proper checks.
    *   **Impact:** Privilege escalation, data manipulation, bypassing business logic.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Use Form Handling Libraries: Utilize form handling components (like Symfony Forms) that provide mechanisms for data validation, filtering, and mapping to entities, allowing you to define allowed fields.
        *   Data Transfer Objects (DTOs):  Map request data to DTOs first, validate the DTO, and then selectively transfer validated data to entities.
        *   Explicitly Define Allowed Fields: When updating entities, only set the properties that are explicitly intended to be modified based on the user's action. Avoid directly setting all properties from the request.
        *   Consider using the `#[Ignore]` attribute (if available in your Doctrine version) to explicitly exclude properties from mass assignment.

