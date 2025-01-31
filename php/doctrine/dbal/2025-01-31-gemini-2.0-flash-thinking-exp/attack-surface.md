# Attack Surface Analysis for doctrine/dbal

## Attack Surface: [SQL Injection via Raw Queries](./attack_surfaces/sql_injection_via_raw_queries.md)

**Description:**  Executing raw SQL queries using `query()` or `exec()` with unsanitized user input directly embedded in the SQL string.
*   **DBAL Contribution:** DBAL provides the `query()` and `exec()` methods which, while powerful, allow developers to bypass parameter binding and execute arbitrary SQL. If used carelessly, they directly expose the application to SQL injection.
*   **Example:**
    ```php
    $userInput = $_GET['username'];
    $sql = "SELECT * FROM users WHERE username = '" . $userInput . "'"; // Vulnerable!
    $statement = $conn->query($sql);
    ```
    An attacker could inject `'; DROP TABLE users; --` as `username` to execute malicious SQL.
*   **Impact:**  Critical. Full database compromise, data breach, data manipulation, denial of service.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Never use `query()` or `exec()` with unsanitized user input directly in the SQL string.**
    *   **Always use prepared statements and parameter binding** with `executeQuery()` or `executeStatement()` and placeholders (`?` or named parameters).

## Attack Surface: [SQL Injection via Incorrect Parameter Binding](./attack_surfaces/sql_injection_via_incorrect_parameter_binding.md)

**Description:**  Incorrectly using parameter binding, such as concatenating user input even when intending to use placeholders, or misunderstanding how parameter binding works, leading to potential SQL injection.
*   **DBAL Contribution:** While DBAL provides secure parameter binding mechanisms, developers might misuse them or make implementation errors, negating the intended security benefits.
*   **Example:**
    ```php
    $userInput = $_GET['id'];
    $sql = "SELECT * FROM products WHERE id = ?"; // Intention to use binding
    $statement = $conn->executeQuery($sql, [$userInput]); // Still vulnerable if $userInput is not properly validated as integer and contains malicious SQL
    ```
    If the application expects an integer for `id` but doesn't enforce it, an attacker could inject non-integer values or even SQL fragments.
*   **Impact:** High to Critical. Data breach, data manipulation, depending on the vulnerability and database system.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Strictly adhere to parameter binding for all user-provided data.**
    *   **Validate and sanitize user input** to match the expected data type and format *before* passing it to `executeQuery()` or `executeStatement()`.
    *   **Use type hinting and casting** in your application code to ensure data types are as expected before database interaction.

## Attack Surface: [Connection String Injection](./attack_surfaces/connection_string_injection.md)

**Description:**  Dynamically constructing the database connection string using user-controlled input, allowing attackers to inject malicious connection parameters.
*   **DBAL Contribution:** DBAL uses connection parameters provided to `DriverManager::getConnection()` to establish database connections. If these parameters are built from untrusted sources, DBAL becomes the mechanism to exploit connection string injection.
*   **Example:**
    ```php
    $dbHost = $_GET['db_host'];
    $connectionParams = [
        'dbname' => 'mydb',
        'user' => 'user',
        'password' => 'password',
        'host' => $dbHost, // User-controlled host!
        'driver' => 'pdo_mysql',
    ];
    $conn = DriverManager::getConnection($connectionParams);
    ```
    An attacker could set `db_host` to a malicious server or inject options like `allowMultiQueries=true` (for MySQL) to enable further SQL injection possibilities.
*   **Impact:** High to Critical. Connecting to rogue database, enabling dangerous database features, denial of service, potential for further exploitation.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Never construct connection strings dynamically from user input.**
    *   **Hardcode connection parameters in configuration files** that are securely managed and not accessible to users.
    *   **If dynamic configuration is absolutely necessary, strictly validate and sanitize** all input used in connection parameters against a whitelist of allowed values.

## Attack Surface: [Schema Manipulation Exposure](./attack_surfaces/schema_manipulation_exposure.md)

**Description:**  Unintentionally exposing DBAL's schema management functionalities (like `SchemaManager`) to unauthorized users, allowing them to modify the database schema.
*   **DBAL Contribution:** DBAL provides powerful schema management tools through `SchemaManager`. If access to these tools is not properly controlled within the application, it creates an attack surface for unauthorized schema modifications.
*   **Example:**
    ```php
    // In a poorly designed admin panel:
    $tableName = $_POST['table_name'];
    $sm = $conn->createSchemaManager();
    $sm->dropTable($tableName); // User-controlled table name!
    ```
    An attacker could manipulate `table_name` to drop critical tables, causing data loss and application malfunction.
*   **Impact:** Medium to High. Data loss, denial of service, application disruption, potential privilege escalation depending on database permissions.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Restrict access to DBAL's schema management functionalities to only authorized administrators.**
    *   **Implement robust access control mechanisms** within the application to prevent unauthorized users from accessing schema management features.

## Attack Surface: [Resource Exhaustion via Malicious Queries](./attack_surfaces/resource_exhaustion_via_malicious_queries.md)

**Description:**  Attackers crafting complex or resource-intensive queries that overwhelm the database server, leading to denial of service.
*   **DBAL Contribution:** DBAL is the component responsible for executing queries against the database. If the application allows users to influence query complexity without proper safeguards, DBAL becomes the execution engine for DoS attacks.
*   **Example:**
    An attacker might manipulate application parameters to generate extremely complex JOIN queries or queries without proper filtering, causing the database to consume excessive resources and become unresponsive.
*   **Impact:** Medium to High. Denial of service, application unavailability, performance degradation for legitimate users.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Implement query complexity limits and timeouts** at the database level and/or application level.
    *   **Optimize database queries** for performance and efficiency.
    *   **Use database connection pooling and resource management** to limit the impact of resource-intensive queries.

