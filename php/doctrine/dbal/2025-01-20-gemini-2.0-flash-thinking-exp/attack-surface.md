# Attack Surface Analysis for doctrine/dbal

## Attack Surface: [SQL Injection via Raw SQL Queries](./attack_surfaces/sql_injection_via_raw_sql_queries.md)

*   **Description:**  Executing raw SQL queries with unsanitized user input directly embedded in the query string.
    *   **How DBAL Contributes:** DBAL provides methods like `Connection::executeQuery()` and `Connection::exec()` that allow developers to execute arbitrary SQL. If user input is concatenated directly into these strings, it creates a direct SQL injection vulnerability.
    *   **Example:**
        ```php
        $username = $_GET['username'];
        $sql = "SELECT * FROM users WHERE username = '" . $username . "'"; // Vulnerable!
        $statement = $conn->executeQuery($sql);
        ```
    *   **Impact:**  Full database compromise, including data exfiltration, modification, and deletion. Potential for remote code execution on the database server in some configurations.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Always use parameterized queries (prepared statements) with bound parameters.** DBAL provides methods like `Connection::prepare()` and `Statement::bindValue()` for this.
        *   **Avoid string concatenation for building SQL queries with user input.**

## Attack Surface: [SQL Injection via Untrusted Data in Identifiers](./attack_surfaces/sql_injection_via_untrusted_data_in_identifiers.md)

*   **Description:** Using user-provided data directly as database identifiers (table names, column names, etc.) in DQL or raw SQL queries.
    *   **How DBAL Contributes:** If the application dynamically constructs queries where table or column names are derived from user input without proper whitelisting or escaping, DBAL will execute these potentially malicious queries.
    *   **Example:**
        ```php
        $tableName = $_GET['table'];
        $sql = "SELECT * FROM " . $tableName; // Potentially vulnerable if $tableName is not validated
        $statement = $conn->executeQuery($sql);
        ```
    *   **Impact:**  Can lead to unauthorized access to different tables, information disclosure, or even modification of unintended data.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Strictly whitelist allowed identifier values.**  Do not directly use user input for table or column names.
        *   If dynamic identifiers are absolutely necessary, use a predefined mapping or a very restrictive validation process.

## Attack Surface: [Insecure Storage of Database Connection Details](./attack_surfaces/insecure_storage_of_database_connection_details.md)

*   **Description:** Storing database credentials (username, password) in easily accessible locations like code or configuration files without proper encryption.
    *   **How DBAL Contributes:** DBAL requires connection parameters to establish a database connection. If these parameters are stored insecurely, attackers can easily retrieve them and gain unauthorized access to the database.
    *   **Example:**
        ```php
        // Insecure: Credentials directly in code
        $conn = DriverManager::getConnection([
            'driver' => 'pdo_mysql',
            'user' => 'myuser',
            'password' => 'mysecretpassword',
            'dbname' => 'mydb',
        ]);
        ```
    *   **Impact:**  Full database compromise, potentially leading to data breaches, data manipulation, and service disruption.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Store credentials securely using environment variables with restricted access.**
        *   **Utilize secure configuration management tools or secret management services.**
        *   **Avoid hardcoding credentials directly in the application code.**

