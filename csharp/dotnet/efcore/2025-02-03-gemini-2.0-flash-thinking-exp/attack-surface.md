# Attack Surface Analysis for dotnet/efcore

## Attack Surface: [SQL Injection](./attack_surfaces/sql_injection.md)

*   **Description:** Exploiting vulnerabilities by injecting malicious SQL code into database queries, leading to unauthorized database access and manipulation.
*   **EF Core Contribution:** EF Core, while promoting parameterized queries, allows developers to use raw SQL queries or dynamic LINQ construction which, if not handled carefully, can introduce SQL injection vulnerabilities. Specifically:
    *   `FromSqlRaw`, `ExecuteSqlRaw`, and `FromSqlInterpolated` when used with unsanitized user input.
    *   Dynamic LINQ queries built from user input without proper validation.
*   **Example:**
    ```csharp
    // Vulnerable code using string interpolation in FromSqlRaw
    string userInput = GetUserInput(); // Assume this gets unsanitized input like \'; DROP TABLE Users; --\'
    var users = context.Users.FromSqlRaw($"SELECT * FROM Users WHERE Username = '{userInput}'").ToList();
    ```
*   **Impact:**
    *   Unauthorized data access (reading sensitive data).
    *   Data modification (updating or deleting data).
    *   Data breach (exfiltration of data).
    *   Potential command execution on the database server in severe cases.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strictly use parameterized queries:** Favor `FromSqlInterpolated` or `ExecuteSqlInterpolated` for raw SQL queries, which inherently handle parameterization.
    *   **Completely avoid string concatenation and interpolation of user input directly into SQL queries.**
    *   **Prioritize using LINQ and EF Core's query building features** to abstract away direct SQL construction and benefit from built-in parameterization.
    *   **Implement server-side input validation and sanitization** even when using parameterized queries as a defense-in-depth measure.
    *   **Conduct regular code reviews specifically looking for potential SQL injection points**, especially in areas dealing with user input and database interactions.

## Attack Surface: [Database Migration Misconfigurations](./attack_surfaces/database_migration_misconfigurations.md)

*   **Description:** Insecure configuration or execution of EF Core database migrations, potentially leading to database schema manipulation, data corruption, or backdoor creation.
*   **EF Core Contribution:** EF Core's migration feature automates database schema updates. Misconfigurations in how migrations are managed and applied can create security risks. Specifically:
    *   Automated migration application in production without review or control.
    *   Migrations containing insecure or malicious SQL scripts.
    *   Overly permissive database credentials used for migration execution.
*   **Example:**
    *   Setting up an automated deployment pipeline that automatically applies EF Core migrations to the production database without manual review or testing in a staging environment. This could allow a compromised migration to be deployed directly to production.
*   **Impact:**
    *   Database schema manipulation (unauthorized changes to database structure).
    *   Data corruption (data loss or integrity issues due to schema changes).
    *   Potential backdoor creation (introduction of malicious stored procedures or triggers via migrations).
    *   Denial of Service (disrupting database operations through schema changes).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Implement a secure and controlled migration process:**
        *   **Mandatory review and approval of migrations** before application to production environments.
        *   **Utilize separate environments (development, staging, production)** and thoroughly test migrations in staging before production deployment.
        *   **Avoid automatic migration application in production.** Implement manual triggers or controlled deployment pipelines for migrations.
    *   **Secure migration scripts:**
        *   **Rigorous code review of migration scripts** to identify and eliminate any potential security vulnerabilities, including SQL injection risks within migrations themselves.
        *   **Use parameterized SQL within migrations** where dynamic values are needed.
        *   **Adhere to secure coding practices** when developing migration logic.
    *   **Employ least privilege database credentials for migrations:** Grant migration accounts only the minimum necessary permissions to alter the database schema, avoiding full administrative privileges.
    *   **Implement migration version control and rollback mechanisms** to easily revert unintended or malicious migrations.
    *   **Maintain audit logs of all migration executions** for traceability and security monitoring.

## Attack Surface: [Connection String Exposure](./attack_surfaces/connection_string_exposure.md)

*   **Description:** Insecure storage and management of database connection strings, which contain sensitive credentials required to access the database.
*   **EF Core Contribution:** EF Core applications rely on connection strings to establish database connections. Insecure handling of these strings directly exposes the application to database compromise.
*   **Example:**
    *   Hardcoding connection strings directly within the application's source code, making them easily accessible in version control or compiled binaries.
    *   Storing connection strings in plain text configuration files deployed with the application, vulnerable to access via web server vulnerabilities or misconfigurations.
*   **Impact:**
    *   Full database compromise.
    *   Data breach (unauthorized access to all data within the database).
    *   Data manipulation (malicious modification or deletion of data).
    *   Denial of Service (disruption of database availability).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Absolutely avoid hardcoding connection strings in source code.**
    *   **Utilize secure storage mechanisms for connection strings, such as environment variables or dedicated secrets management solutions** (e.g., Azure Key Vault, HashiCorp Vault, AWS Secrets Manager).
    *   **Encrypt connection strings in configuration files** if local storage is unavoidable.
    *   **Restrict access to configuration files and secrets management systems** using robust access control mechanisms and permissions.
    *   **Prevent committing connection strings to version control systems.** Employ environment-specific configuration and secure deployment pipelines.

