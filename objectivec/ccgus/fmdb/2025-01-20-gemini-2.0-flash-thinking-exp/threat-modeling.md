# Threat Model Analysis for ccgus/fmdb

## Threat: [SQL Injection Vulnerability](./threats/sql_injection_vulnerability.md)

*   **Description:** An attacker crafts malicious SQL queries by injecting code through unsanitized user input that is directly incorporated into FMDB query execution methods. This allows the attacker to manipulate the database beyond the application's intended functionality by exploiting how FMDB executes provided SQL.
    *   **Impact:** Unauthorized access to sensitive data managed by FMDB, modification or deletion of data within the SQLite database accessed by FMDB, and potential compromise of data integrity.
    *   **Affected FMDB Component:** Query execution methods (e.g., `executeQuery:`, `executeUpdate:`, `executeUpdate:withArgumentsInArray:`, `executeQuery:withArgumentsInDictionary:`, `executeUpdate:withArgumentsInDictionary:`), specifically when used with direct string formatting for query construction.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Always use parameterized queries or prepared statements:** Utilize FMDB's methods that accept arguments separately from the SQL string (e.g., `executeQuery:withArgumentsInArray:`).
        *   **Avoid string concatenation for building SQL queries:** Never directly embed user input into SQL strings passed to FMDB's query execution methods.

## Threat: [Database File Path Traversal](./threats/database_file_path_traversal.md)

*   **Description:** An attacker manipulates the file path provided to FMDB when opening the SQLite database. By using relative paths or special characters, they might be able to instruct FMDB to access or modify database files outside the intended directory, exploiting FMDB's file access mechanisms.
    *   **Impact:** Access to sensitive data in other databases managed by the application, modification or deletion of critical application data stored in unintended database files accessed via FMDB.
    *   **Affected FMDB Component:** Methods for opening the database (e.g., `databaseWithPath:`).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Use absolute paths for database files:** Avoid using relative paths when initializing FMDB to prevent path manipulation.
        *   **Restrict file system permissions:** Ensure the application user has access only to the intended database file and directory, limiting the scope of potential traversal.
        *   **Validate and sanitize the database file path:** If the database path is derived from user input or configuration, rigorously validate and sanitize it before passing it to FMDB's database opening methods.

