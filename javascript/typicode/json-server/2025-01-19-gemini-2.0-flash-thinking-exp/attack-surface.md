# Attack Surface Analysis for typicode/json-server

## Attack Surface: [Unauthenticated Data Modification via REST API](./attack_surfaces/unauthenticated_data_modification_via_rest_api.md)

*   **Description:**  Attackers can directly modify, create, or delete data through the exposed RESTful API endpoints without providing any credentials.
    *   **How json-server Contributes:** `json-server` by default does not implement any authentication or authorization mechanisms. It directly maps HTTP methods (GET, POST, PUT, PATCH, DELETE) to CRUD operations on the underlying JSON data.
    *   **Example:** An attacker could send a `DELETE` request to `/posts/1` to delete a blog post without any authentication check.
    *   **Impact:** Complete compromise of data integrity, potential data loss, and unauthorized manipulation of application state.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Implement Authentication Middleware:**  Use middleware (e.g., Express middleware) to verify user identity before allowing access to API endpoints. This could involve JWT, OAuth 2.0, or other authentication schemes.
        *   **Implement Authorization Middleware:**  After authentication, implement authorization checks to ensure the authenticated user has the necessary permissions to perform the requested action on the specific resource.
        *   **Do not expose `json-server` directly to the public internet without authentication.

## Attack Surface: [Unauthenticated Data Access (Information Disclosure)](./attack_surfaces/unauthenticated_data_access__information_disclosure_.md)

*   **Description:** Attackers can read any data served by `json-server` without providing any credentials.
    *   **How json-server Contributes:**  `json-server` serves the entire JSON database through simple GET requests to the defined resources.
    *   **Example:** An attacker could send a `GET` request to `/users` to retrieve a list of all users and their associated data.
    *   **Impact:** Exposure of sensitive information, privacy violations, and potential misuse of leaked data.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Implement Authentication Middleware:** As above, require authentication for accessing any data served by `json-server`.
        *   **Implement Authorization Middleware:** Control which authenticated users can access specific resources or fields within resources.
        *   **Consider using `json-server` for non-sensitive data only or in controlled environments.

## Attack Surface: [Mass Assignment Vulnerabilities](./attack_surfaces/mass_assignment_vulnerabilities.md)

*   **Description:** Attackers can modify unintended fields in a resource by including them in `PUT` or `PATCH` requests.
    *   **How json-server Contributes:** `json-server` by default attempts to update all fields provided in the request body. It doesn't inherently filter or validate which fields are allowed to be updated.
    *   **Example:**  A user might send a `PATCH` request to `/users/1` with a body like `{"isAdmin": true, "name": "Legitimate User"}` intending to update their name, but inadvertently granting themselves administrator privileges if the `isAdmin` field exists in the data structure.
    *   **Impact:** Privilege escalation, unauthorized modification of sensitive attributes, and potential compromise of application logic.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Implement Input Validation and Sanitization:**  In middleware or application logic, explicitly define and validate which fields are allowed to be updated for each resource. Sanitize input to prevent unexpected data types or formats.
        *   **Use DTOs (Data Transfer Objects) or whitelisting:**  Define specific data structures for updates and only process fields present in these structures.
        *   **Avoid directly mapping request bodies to database entities without validation.

## Attack Surface: [Exposure of Entire Database (Configuration Risk)](./attack_surfaces/exposure_of_entire_database__configuration_risk_.md)

*   **Description:** The entire JSON database is served by default, potentially exposing sensitive information if not intended.
    *   **How json-server Contributes:** `json-server`'s core functionality is to serve the provided JSON file as a REST API.
    *   **Example:** If the `db.json` file contains user credentials or other confidential data, a simple GET request to the root endpoint or a specific resource could expose this information.
    *   **Impact:**  Significant data breach, privacy violations, and potential legal repercussions.
    *   **Risk Severity:** Critical (if sensitive data is present)
    *   **Mitigation Strategies:**
        *   **Do not store sensitive data directly in the `db.json` file if `json-server` is publicly accessible.**
        *   **Use `json-server` for prototyping or development with non-sensitive data.**
        *   **Implement authentication and authorization to control access to the data.**
        *   **Consider using a real database for production environments.

