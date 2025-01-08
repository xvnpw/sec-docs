# Attack Surface Analysis for ccgus/fmdb

## Attack Surface: [SQL Injection](./attack_surfaces/sql_injection.md)

*   **Description:** Attackers inject malicious SQL code into database queries, potentially allowing them to bypass security measures, access unauthorized data, modify data, or even execute arbitrary code on the database server (though less likely with SQLite's architecture).
    *   **How FMDB Contributes to the Attack Surface:** `fmdb` provides methods for executing raw SQL queries. If developers directly embed user-provided data into these queries without proper sanitization or using parameterized queries (prepared statements), it creates a direct pathway for SQL injection.
    *   **Example:** An application constructs a query like `NSString *query = [NSString stringWithFormat:@"SELECT * FROM users WHERE username = '%@'", userInput];` where `userInput` comes directly from user input. An attacker could enter `'; DROP TABLE users; --` as `userInput`.
    *   **Impact:** Data breach, data manipulation, data deletion, potential denial of service.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Always use parameterized queries (prepared statements) provided by `fmdb` (e.g., `-[FMDatabase executeUpdate:withArgumentsInArray:]` or `-[FMDatabase executeQuery:withArgumentsInArray:]`).** This ensures that user-provided values are treated as data, not executable code.
        *   **Avoid string formatting or concatenation to build SQL queries with user input.**
        *   **Implement input validation and sanitization on the application side before passing data to `fmdb`.** This can help catch some basic injection attempts, but should not be the primary defense.

## Attack Surface: [Database File Path Manipulation](./attack_surfaces/database_file_path_manipulation.md)

*   **Description:** Attackers manipulate the path to the SQLite database file used by the application. This could allow them to access sensitive data in a different database file, overwrite the application's database with a malicious one, or potentially cause denial of service by pointing to a non-existent or inaccessible file.
    *   **How FMDB Contributes to the Attack Surface:** `fmdb` requires the application to provide the path to the database file when creating an `FMDatabase` object (e.g., `[FMDatabase databaseWithPath:@"/path/to/database.sqlite"]`). If this path is derived from user input or external configuration without proper validation, it becomes vulnerable.
    *   **Example:** An application allows users to specify a "profile name" which is then used to construct the database path like `/data/profiles/[profile name].sqlite`. An attacker could provide a malicious profile name like `../../../../sensitive_data.sqlite` to try and access a different file.
    *   **Impact:** Unauthorized access to sensitive data, data corruption, denial of service.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Never directly use user input to construct the database file path.**
        *   **Use a fixed, predefined path for the database file within the application's secure storage.**
        *   **If dynamic database paths are absolutely necessary, implement strict validation and sanitization of any input used to construct the path. Use whitelisting of allowed characters or patterns.**
        *   **Ensure proper file system permissions are set on the database file and its directory to restrict access.**

