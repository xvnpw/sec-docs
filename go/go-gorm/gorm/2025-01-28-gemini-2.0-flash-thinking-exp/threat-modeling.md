# Threat Model Analysis for go-gorm/gorm

## Threat: [Raw SQL Injection](./threats/raw_sql_injection.md)

*   **Description:** An attacker could inject malicious SQL code by manipulating user input that is directly used in raw SQL queries executed via GORM's `Exec`, `Raw`, or `Statement` methods. This allows bypassing application logic, reading sensitive data, modifying data, or executing arbitrary commands on the database server.
*   **Impact:** Critical
    *   Data Breach (Confidentiality)
    *   Data Manipulation (Integrity)
    *   Account Takeover (Availability, Confidentiality, Integrity)
    *   Denial of Service (Availability)
*   **GORM Component Affected:** `Exec`, `Raw`, `Statement` methods, SQL query execution.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   Prioritize using GORM's query builder and parameterized queries for all database interactions.
    *   If raw SQL is absolutely necessary, strictly use parameterized queries with placeholders (`?`) and pass arguments separately to GORM methods.
    *   Implement robust input validation and sanitization on all user-provided data before incorporating it into any SQL query, even parameterized ones.
    *   Conduct thorough and regular code reviews, specifically focusing on any usage of `Exec`, `Raw`, and `Statement` to identify and eliminate potential injection points.

## Threat: [Incorrect `Where` Clause Injection](./threats/incorrect__where__clause_injection.md)

*   **Description:** An attacker could manipulate user input to inject malicious SQL into `Where` clauses if conditions are constructed using string concatenation or formatting instead of GORM's secure parameterized methods or map-based conditions. This can lead to unauthorized data access or modification by altering the intended query logic and bypassing access controls.
*   **Impact:** High
    *   Data Breach (Confidentiality)
    *   Data Manipulation (Integrity)
    *   Authorization Bypass (Confidentiality, Integrity)
*   **GORM Component Affected:** `Where` clause construction, query building.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Always utilize GORM's query builder methods (e.g., `Where("field = ?", userInput)`) or map structures for defining `Where` conditions when dealing with user-supplied input.
    *   Strictly avoid string concatenation or formatting to build `Where` conditions that include user-provided data.
    *   Establish and enforce a consistent practice of using parameterized queries within `Where` clauses throughout the application codebase.

## Threat: [Unprotected Mass Assignment](./threats/unprotected_mass_assignment.md)

*   **Description:** An attacker could send malicious requests with crafted payloads containing unexpected or unauthorized field values during record creation or update operations. If mass assignment is not properly restricted, the attacker could successfully modify fields they should not have direct access to, potentially leading to privilege escalation (e.g., setting an `is_admin` flag) or alteration of critical data.
*   **Impact:** High
    *   Privilege Escalation (Confidentiality, Integrity)
    *   Data Manipulation (Integrity)
    *   Authorization Bypass (Confidentiality, Integrity)
*   **GORM Component Affected:** Model creation and update operations, mass assignment feature.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Consistently use GORM's `Select` or `Omit` methods to explicitly define a whitelist of fields that are permitted for mass assignment during create and update operations.
    *   Implement Data Transfer Objects (DTOs) to act as an intermediary layer for data input, allowing for strict control over which data is mapped to GORM models before database interaction.
    *   Enforce robust authorization checks and validation logic before performing any create or update operations to ensure that the user has the necessary permissions to modify the intended fields and data.

