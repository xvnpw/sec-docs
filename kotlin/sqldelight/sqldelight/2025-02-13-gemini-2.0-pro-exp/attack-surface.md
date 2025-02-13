# Attack Surface Analysis for sqldelight/sqldelight

## Attack Surface: [SQL Injection (through misuse)](./attack_surfaces/sql_injection__through_misuse_.md)

*   **Description:**  Bypassing SQLDelight's built-in parameterized query protections by manually constructing SQL queries with user-supplied data, *specifically within the context of how SQLDelight is used or misused*.
*   **How SQLDelight Contributes:** SQLDelight provides the *capability* to execute raw SQL (e.g., through `execute` methods or similar low-level APIs).  The vulnerability arises when developers *choose* to use these features with unsanitized, dynamically generated SQL strings *instead* of using SQLDelight's type-safe query generation. This is a direct misuse of the library's features.
*   **Example:**
    ```kotlin
    // VULNERABLE CODE (Direct misuse of SQLDelight):
    val userInput = request.getParameter("username")
    // Even if using a SQLDelight Database instance, constructing the SQL string manually is the problem.
    myDatabase.sqlDriver.execute(null, "SELECT * FROM users WHERE username = '$userInput'", 0, null)

    // CORRECT (SQLDelight way):
    // In users.sq:
    // selectUserByUsername:
    // SELECT * FROM users WHERE username = ?;

    // In Kotlin code:
    val user = queries.selectUserByUsername(userInput).executeAsOneOrNull()
    ```
*   **Impact:**  Complete database compromise, including data theft, modification, and deletion.  Potential for remote code execution (RCE) depending on the database and its configuration.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strictly enforce the use of SQLDelight's `.sq` files and generated code for *all* database interactions.** This is the primary mitigation.  All SQL should be defined within `.sq` files.
    *   **Prohibit manual SQL string construction *anywhere* in the codebase that interacts with the database.** Use code reviews and static analysis tools.
    *   **Implement a linter rule to forbid direct use of underlying database connection APIs and SQLDelight's raw `execute` methods with string concatenation.**
    *   **Comprehensive developer training on the correct and *exclusive* use of SQLDelight's type-safe API.**

## Attack Surface: [Data Exposure (Overly Permissive Queries)](./attack_surfaces/data_exposure__overly_permissive_queries_.md)

*   **Description:**  Writing queries *within SQLDelight's `.sq` files* that retrieve more data than necessary, leading to potential data leakage.
*   **How SQLDelight Contributes:** SQLDelight's `.sq` file format allows developers to define *any* SQL query.  The vulnerability lies in the *design* of these queries, specifically choosing to retrieve excessive data. This is a direct consequence of how the developer uses SQLDelight's query definition mechanism.
*   **Example:**
    ```sql
    -- In users.sq (VULNERABLE, within SQLDelight's control):
    selectAllUsers:
    SELECT * FROM users; -- Retrieves all columns, including sensitive data.

    -- In users.sq (BETTER, within SQLDelight's control):
    selectUsernames:
    SELECT username FROM users; -- Only retrieves usernames.
    ```
*   **Impact:**  Leakage of sensitive data, potentially violating privacy regulations.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Mandate the principle of least privilege *within* `.sq` file query definitions: Select only the specific columns required.**
    *   **Conduct code reviews specifically focused on the `.sq` files, ensuring that queries are not overly broad and only retrieve necessary data.**
    *   **Although access control is primarily an application-level concern, ensure that even if a query retrieves more data than intended, the application layer prevents unauthorized access to that data.** This is a defense-in-depth measure.

## Attack Surface: [Denial of Service (Unbounded/Complex Queries)](./attack_surfaces/denial_of_service__unboundedcomplex_queries_.md)

*   **Description:**  Writing queries *within SQLDelight's `.sq` files* that are unbounded (no `LIMIT`) or computationally expensive, leading to database resource exhaustion.
*   **How SQLDelight Contributes:** The vulnerability stems from the SQL queries *defined within the `.sq` files* themselves. SQLDelight executes the queries as defined; it doesn't inherently prevent poorly designed queries.
*   **Example:**
    ```sql
    -- In products.sq (VULNERABLE, within SQLDelight):
    searchProducts:
    SELECT * FROM products WHERE description LIKE ?; -- No LIMIT, potentially slow.

    -- In products.sq (BETTER, within SQLDelight):
    searchProductsLimited:
    SELECT * FROM products WHERE description LIKE ? LIMIT 100; -- Added a LIMIT.
    ```
*   **Impact:**  Application unavailability.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Enforce the use of `LIMIT` clauses in all `.sq` file queries that could potentially return a large result set.**
    *   **Review and optimize complex queries *defined in `.sq` files* to reduce their resource consumption.  This includes considering appropriate indexing.**
    *   **While input validation is important, the primary mitigation here is to control the *queries themselves* within the `.sq` files.**

## Attack Surface: [Migration Script Issues](./attack_surfaces/migration_script_issues.md)

*   **Description:** Errors or unintended data modifications *within SQLDelight's `.sqm` migration files*, leading to database problems.
*   **How SQLDelight Contributes:** SQLDelight *uses* `.sqm` files for schema management.  The vulnerability lies entirely within the *content and correctness* of these files, which are directly managed by the developer using SQLDelight.
*   **Example:**
    ```sql
    -- In 001_create_users.sqm (VULNERABLE, within SQLDelight):
    CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL,
        passwrd TEXT NOT NULL -- Typo!
    );

    -- In 002_add_email.sqm (POTENTIALLY VULNERABLE, within SQLDelight):
    ALTER TABLE users ADD COLUMN email TEXT;
    UPDATE users SET email = 'unknown@example.com'; -- Modifies ALL emails!
    ```
*   **Impact:**  Database corruption, data loss, inconsistent schema, application downtime.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Mandatory, thorough testing of *all* `.sqm` migration scripts in a non-production environment before deployment.**
    *   **Implement a rollback mechanism for failed migrations.**
    *   **Use version control (e.g., Git) for `.sqm` files.**
    *   **Database backups *before* applying migrations.**
    *   **Ensure transactions are used within `.sqm` scripts for atomicity.**
    * **Review all SQL code inside `.sqm` files**

