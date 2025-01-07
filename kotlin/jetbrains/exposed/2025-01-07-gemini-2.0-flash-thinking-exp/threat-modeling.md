# Threat Model Analysis for jetbrains/exposed

## Threat: [SQL Injection via String Interpolation](./threats/sql_injection_via_string_interpolation.md)

*   **Threat:** SQL Injection via String Interpolation
    *   **Description:** An attacker can inject malicious SQL code into user-supplied input that is directly embedded into SQL queries using string interpolation within Exposed. This allows the attacker to execute arbitrary SQL commands against the database. For example, if user input for a `username` is directly interpolated into a query like `User.find { Users.name eq "$username" }`, an attacker could input `' OR '1'='1` to bypass authentication.
    *   **Impact:** Complete compromise of the database, including data breach, data modification, data deletion, and potentially gaining access to the underlying operating system if database permissions are misconfigured.
    *   **Affected Component:** `org.jetbrains.exposed.sql.SqlExpressionBuilder` (when using string interpolation directly within query builders).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Never use string interpolation directly for user-provided data in SQL queries.**
        *   **Always use parameterized queries or Exposed's type-safe query builder with proper escaping.** Utilize functions like `eq`, `like`, `Op.build { ... }` with placeholders for user input.

## Threat: [SQL Injection via Improperly Parameterized Queries](./threats/sql_injection_via_improperly_parameterized_queries.md)

*   **Threat:** SQL Injection via Improperly Parameterized Queries
    *   **Description:** Even when using parameterization, if not implemented correctly, vulnerabilities can arise. For instance, if an attacker can control the parameter names or if the underlying JDBC driver has vulnerabilities in how it handles parameters, injection might be possible. While less common with modern JDBC drivers, improper usage can still introduce risks.
    *   **Impact:** Similar to string interpolation SQL injection, leading to database compromise.
    *   **Affected Component:** `org.jetbrains.exposed.sql.SqlExpressionBuilder` (if parameterization is misused or the underlying driver has issues).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Ensure correct usage of Exposed's parameterization features.**
        *   **Keep the JDBC driver updated to the latest version to patch potential vulnerabilities.**
        *   **Avoid dynamic construction of parameter names based on user input.**
        *   **Review the generated SQL queries during development to verify proper parameterization.**

## Threat: [Data Tampering via Insecure Updates/Deletes](./threats/data_tampering_via_insecure_updatesdeletes.md)

*   **Threat:** Data Tampering via Insecure Updates/Deletes
    *   **Description:** If application logic directly uses user-controlled input to determine which records to update or delete using Exposed's update or delete functions without proper validation, an attacker could potentially modify or delete data they shouldn't have access to. For example, if a user ID is directly taken from the request without validation and used in a `User.deleteWhere { Users.id eq userId }` call.
    *   **Impact:** Data corruption, data loss, violation of data integrity.
    *   **Affected Component:** `org.jetbrains.exposed.sql.statements.UpdateStatement`, `org.jetbrains.exposed.sql.statements.DeleteStatement`.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Implement robust authorization checks at the application layer before performing any data modification operations using Exposed.**
        *   **Validate all input parameters used in update and delete queries.**
        *   **Utilize Exposed's transaction management features to ensure atomicity and consistency.**

