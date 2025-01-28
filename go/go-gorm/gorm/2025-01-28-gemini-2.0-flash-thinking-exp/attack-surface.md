# Attack Surface Analysis for go-gorm/gorm

## Attack Surface: [Raw SQL Injection](./attack_surfaces/raw_sql_injection.md)

*   **Description:** Vulnerability arising from directly embedding user-controlled input into raw SQL queries without proper sanitization or parameterization.
*   **GORM Contribution:** GORM's `db.Raw()`, `db.Exec()`, and `db.Query()` methods enable the execution of raw SQL, creating direct pathways for SQL injection if input is mishandled.
*   **Example:**
    *   **Scenario:** An application uses `db.Raw("SELECT * FROM items WHERE name LIKE '" + userInput + "%'").Scan(&items)` to search for items, directly concatenating user input for a `LIKE` clause.
    *   **Malicious Input:** A user provides input like `"' UNION SELECT password FROM users WHERE username = 'admin' --"`.
    *   **Impact:**  Critical - Unauthorized data access, potential data modification or deletion, and in some cases, command execution on the database server.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Prioritize Parameterized Queries:**  Always use parameterized queries with placeholders (e.g., `db.Raw("SELECT * FROM items WHERE name LIKE ?", userInput+"%").Scan(&items)`) when using `db.Raw()`, `db.Exec()`, or `db.Query()`.
    *   **Minimize Raw SQL Usage:**  Favor GORM's query builder methods (`db.Where()`, `db.Find()`, etc.) which inherently handle parameterization, reducing the need for raw SQL.
    *   **Strict Input Sanitization:**  Sanitize and validate user input even when using parameterized queries to prevent unexpected data types or malicious patterns that might bypass intended logic.

## Attack Surface: [Dynamic Query Construction with Unsafe Input](./attack_surfaces/dynamic_query_construction_with_unsafe_input.md)

*   **Description:** Vulnerability stemming from constructing dynamic queries (using `db.Where()`, `db.Order()`, etc.) with unsanitized user input, leading to unintended query modifications or SQL injection.
*   **GORM Contribution:** GORM's flexible query builder methods become vulnerable if developers directly incorporate unsanitized user input into conditions, column names, or order clauses, opening doors for manipulation.
*   **Example:**
    *   **Scenario:** An application allows users to filter products based on a column name provided in the request: `db.Where(userInputColumn + " = ?", inputValue).Find(&products)`.
    *   **Malicious Input:** A user provides `userInputColumn` as `"price OR 1=1"` and `inputValue` as `"1"`.
    *   **Impact:** High - SQL injection, potentially leading to unauthorized data access, data manipulation, or denial of service due to malformed queries.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Input Validation and Allow-listing:**  Rigorous validation of user input intended for dynamic query parts. Implement strict allow-lists for column names, order directions, and other dynamic elements.
    *   **Parameterized `Where` Conditions:**  When using `db.Where()` with dynamic conditions, utilize parameterized queries or GORM's condition syntax that supports placeholders to prevent injection within conditions.
    *   **Abstraction for Query Building:**  Create secure abstraction layers or helper functions to construct queries based on user input, ensuring validation and sanitization within these layers before interacting with GORM's query builder.

## Attack Surface: [Mass Assignment Vulnerabilities](./attack_surfaces/mass_assignment_vulnerabilities.md)

*   **Description:** Uncontrolled modification of model fields through user-provided data during create or update operations, potentially allowing attackers to modify protected attributes and escalate privileges.
*   **GORM Contribution:** GORM's default mass assignment behavior, where all struct fields can be populated from input during `Create()` or `Updates()`, can be exploited if field access is not explicitly controlled.
*   **Example:**
    *   **Scenario:** An application uses `db.Create(&userInputData)` to create a new user, directly using user-provided data to populate the `User` struct, which includes an `IsAdmin` field.
    *   **Malicious Input:** A user sends a request with JSON data including `{"username": "attacker", "password": "password123", "is_admin": true}`.
    *   **Impact:** High - Privilege escalation, allowing unauthorized users to modify sensitive attributes like `is_admin`, leading to significant security breaches.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Explicitly Select Fields for Updates:**  Use `db.Model(&User{}).Select("username", "password").Updates(&userInputData)` to precisely define which fields are permitted for updates, preventing unintended modifications.
    *   **Data Transfer Objects (DTOs):**  Employ DTO structs that exclusively contain fields intended for user modification. Map data from validated DTOs to GORM models, ensuring only authorized fields are updated.
    *   **Field Whitelisting:**  Implement whitelisting mechanisms to explicitly define allowed fields for mass assignment, rejecting any attempts to modify unlisted fields.
    *   **Authorization Checks Before Modification:**  Enforce robust authorization checks prior to executing create or update operations to verify user permissions to modify the targeted data and fields.

