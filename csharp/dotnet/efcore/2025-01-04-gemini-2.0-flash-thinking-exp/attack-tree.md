# Attack Tree Analysis for dotnet/efcore

Objective: Attacker's Goal: Gain unauthorized access to sensitive data managed by the application through exploiting vulnerabilities in or related to EF Core.

## Attack Tree Visualization

```
*   Compromise Application Data via EF Core Exploitation **
    *   OR Query Manipulation (SQL Injection) **
        *   AND Inject Malicious SQL in Where/FirstOrDefault/SingleOrDefault Clauses ***
            *   OR Directly in String Interpolation **
            *   OR Through Untrusted Input in Parameterized Queries (if not handled correctly) ***
        *   AND Inject Malicious SQL in Raw SQL Queries ***
            *   OR Directly within `context.Database.ExecuteSqlRaw` or similar **
    *   OR Configuration and Deployment Vulnerabilities ***
        *   AND Expose Database Connection String ***
            *   OR Hardcoded in Configuration Files **
            *   OR Stored Insecurely in Environment Variables **
```


## Attack Tree Path: [Inject Malicious SQL in Where/FirstOrDefault/SingleOrDefault Clauses](./attack_tree_paths/inject_malicious_sql_in_wherefirstordefaultsingleordefault_clauses.md)

This path involves injecting malicious SQL code into the `Where`, `FirstOrDefault`, or `SingleOrDefault` clauses of EF Core queries. These clauses are commonly used for filtering data based on user input.
    *   **Directly in String Interpolation:** This sub-path occurs when developers directly embed untrusted user input into the SQL query string using string interpolation. This makes the application highly vulnerable to SQL injection as the injected code is directly executed by the database.
    *   **Through Untrusted Input in Parameterized Queries (if not handled correctly):** This sub-path occurs when developers intend to use parameterized queries (a secure practice), but make mistakes in how parameters are handled or still construct parts of the query dynamically using untrusted input. This can bypass the intended protection of parameterized queries.

## Attack Tree Path: [Inject Malicious SQL in Raw SQL Queries](./attack_tree_paths/inject_malicious_sql_in_raw_sql_queries.md)

This path involves injecting malicious SQL code when the application uses raw SQL queries through methods like `context.Database.ExecuteSqlRaw`.
    *   **Directly within `context.Database.ExecuteSqlRaw` or similar:** If user-provided data is directly concatenated or interpolated into the raw SQL string passed to these methods without proper sanitization or parameterization, it becomes a direct SQL injection vulnerability.

## Attack Tree Path: [Expose Database Connection String](./attack_tree_paths/expose_database_connection_string.md)

This path focuses on the exposure of the database connection string, which contains credentials necessary to access the database.
    *   **Hardcoded in Configuration Files:** This sub-path occurs when the connection string is directly embedded in configuration files (e.g., `appsettings.json`, `web.config`) without proper encryption or protection. If these files are accessible (e.g., through misconfigured web server or source code exposure), the connection string can be easily retrieved.
    *   **Stored Insecurely in Environment Variables:** This sub-path occurs when the connection string is stored in environment variables without proper security considerations. While better than hardcoding in some cases, environment variables can still be exposed through various means, especially in shared hosting environments or if the application's environment is compromised.

