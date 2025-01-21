# Attack Surface Analysis for jeremyevans/sequel

## Attack Surface: [SQL Injection via Raw SQL Interpolation](./attack_surfaces/sql_injection_via_raw_sql_interpolation.md)

*   **Attack Surface:** SQL Injection via Raw SQL Interpolation
    *   **Description:** Attackers can inject malicious SQL code into database queries by manipulating user-provided input that is directly embedded into raw SQL strings.
    *   **How Sequel Contributes:** Sequel allows developers to construct queries using string interpolation (e.g., `dataset.where("name = '#{user_input}'")`). If `user_input` is not properly sanitized, it can introduce SQL injection vulnerabilities.
    *   **Example:**
        ```ruby
        username = params[:username] # User input from a web request
        users.where("username = '#{username}'").first
        ```
        If `params[:username]` is `' OR '1'='1'`, the resulting SQL becomes `SELECT * FROM users WHERE username = '' OR '1'='1'`, bypassing authentication.
    *   **Impact:** Full database compromise, data breaches, data manipulation, unauthorized access, denial of service.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Always use parameterized queries:** Sequel's prepared statements (`?` placeholders) and the `where(column: value)` syntax automatically escape user input, preventing SQL injection.
        *   **Avoid string interpolation for user input:**  Never directly embed user-provided data into raw SQL strings.
        *   **Input validation and sanitization:** While not a primary defense against SQL injection, validate and sanitize user input to prevent unexpected characters or patterns.

## Attack Surface: [SQL Injection via Unsafe `literal` Usage](./attack_surfaces/sql_injection_via_unsafe__literal__usage.md)

*   **Attack Surface:** SQL Injection via Unsafe `literal` Usage
    *   **Description:**  While Sequel's `literal` method is intended for escaping, incorrect or incomplete usage can still lead to SQL injection if the input isn't fully sanitized before being passed to `literal`.
    *   **How Sequel Contributes:** Sequel provides the `literal` method, which developers might mistakenly believe is a foolproof sanitization mechanism. If used improperly or without prior sanitization, it can still be vulnerable.
    *   **Example:**
        ```ruby
        search_term = params[:search]
        # Incorrectly assuming literal is enough without prior checks
        users.where("name LIKE #{Sequel.lit(search_term)}")
        ```
        If `search_term` contains malicious SQL, `literal` might not escape it sufficiently depending on the context and database.
    *   **Impact:** Similar to raw SQL injection, potentially leading to database compromise.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Prefer parameterized queries:**  Even when dealing with more complex conditions, explore if parameterized queries can be used.
        *   **Thoroughly sanitize input before using `literal`:** If `literal` is necessary, ensure the input has been rigorously validated and sanitized against SQL injection patterns *before* passing it to `literal`.
        *   **Understand the limitations of `literal`:**  Don't rely on it as a sole defense against SQL injection for all types of input.

## Attack Surface: [Exposure of Database Credentials in Logs](./attack_surfaces/exposure_of_database_credentials_in_logs.md)

*   **Attack Surface:** Exposure of Database Credentials in Logs
    *   **Description:** Database credentials (usernames, passwords) can be unintentionally exposed in application logs if Sequel's logging is configured to output raw SQL queries containing connection details.
    *   **How Sequel Contributes:** Sequel's logging functionality can be configured to log all executed SQL queries. If the connection string includes credentials and this logging is enabled without proper redaction, it creates a risk.
    *   **Example:**  Sequel's logger outputting a query like: `SELECT * FROM users -- Connection: postgres://user:password@host:port/database`
    *   **Impact:** Credential compromise, allowing attackers to directly access the database.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Avoid embedding credentials in connection strings:** Use environment variables or secure configuration management tools to store and retrieve credentials.
        *   **Redact sensitive information in logs:** Configure Sequel's logger or a separate logging mechanism to filter out or mask sensitive data like passwords from logged queries.
        *   **Secure log storage:** Ensure that application logs are stored securely with appropriate access controls.

## Attack Surface: [Migration Vulnerabilities (Malicious Migration Files)](./attack_surfaces/migration_vulnerabilities__malicious_migration_files_.md)

*   **Attack Surface:** Migration Vulnerabilities (Malicious Migration Files)
    *   **Description:** If Sequel's migration feature is used without proper security, malicious migration files could be introduced and executed, leading to arbitrary SQL execution.
    *   **How Sequel Contributes:** Sequel's migration system executes SQL code defined in migration files. If these files are not properly vetted or are sourced from untrusted locations, they can be exploited.
    *   **Example:** A migration file containing `DB.run('DROP TABLE users;')`.
    *   **Impact:** Database compromise, data loss, data manipulation.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Secure migration file storage and access:** Ensure migration files are stored securely and only authorized personnel can modify them.
        *   **Code review for migrations:**  Treat migration files as code and subject them to thorough code review before execution.
        *   **Automated testing of migrations:** Implement tests to verify the intended behavior of migrations and detect any unexpected changes.
        *   **Control migration execution:**  Restrict who can execute database migrations in production environments.

