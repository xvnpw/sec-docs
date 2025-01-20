# Attack Surface Analysis for ccgus/fmdb

## Attack Surface: [SQL Injection](./attack_surfaces/sql_injection.md)

*   **Description:** Attackers inject malicious SQL code into application queries, potentially allowing them to read, modify, or delete data, bypass security measures, or even execute arbitrary commands on the database server.
    *   **How fmdb Contributes:** `fmdb` provides methods for executing SQL queries, and if developers directly embed user-provided input into these queries without proper sanitization or parameterization, it creates a direct pathway for SQL injection.
    *   **Example:**
        ```objectivec
        NSString *userInput = ...; // User-provided input
        NSString *query = [NSString stringWithFormat:@"SELECT * FROM users WHERE username = '%@'", userInput];
        [db executeQuery:query];
        ```
        If `userInput` is `' OR '1'='1`, the query becomes `SELECT * FROM users WHERE username = '' OR '1'='1'`, which will return all users.
    *   **Impact:** Critical. Can lead to complete compromise of the database, including data breaches, data manipulation, and denial of service.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Always use parameterized queries or prepared statements.** `fmdb` provides methods like `executeUpdate:withArgumentsInArray:` and `executeQuery:withArgumentsInArray:` which prevent SQL injection by treating user input as data, not executable code.
        *   Avoid using string formatting (e.g., `stringWithFormat:`) to construct SQL queries with user input.
        *   Implement input validation to restrict the types and formats of data accepted from users.

## Attack Surface: [Database Path Manipulation](./attack_surfaces/database_path_manipulation.md)

*   **Description:** Attackers manipulate the path to the database file, potentially allowing them to access or modify unintended database files or create new ones in arbitrary locations.
    *   **How fmdb Contributes:** `fmdb` requires specifying the path to the database file when creating an `FMDatabase` object. If this path is constructed using unsanitized user input or external configuration that is vulnerable to manipulation, it can lead to this vulnerability.
    *   **Example:**
        ```objectivec
        NSString *dbPathInput = ...; // User-provided input or external config
        NSString *dbPath = [NSString stringWithFormat:@"/app/data/%@.sqlite", dbPathInput];
        FMDatabase *db = [FMDatabase databaseWithPath:dbPath];
        ```
        If `dbPathInput` is `../../../../sensitive_data`, the application might try to open a database in an unintended location.
    *   **Impact:** High. Could lead to unauthorized access to sensitive data, modification of critical application data, or denial of service if the application tries to access or create files in restricted areas.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Avoid constructing database paths using user-provided input.** If necessary, use a limited set of predefined, validated options.
        *   **Store database files in secure locations with restricted permissions.** Ensure that only the application has the necessary read and write access.
        *   **Sanitize and validate any external configuration used to determine the database path.**

