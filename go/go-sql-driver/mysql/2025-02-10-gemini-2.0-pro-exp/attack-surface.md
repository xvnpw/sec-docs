# Attack Surface Analysis for go-sql-driver/mysql

## Attack Surface: [SQL Injection](./attack_surfaces/sql_injection.md)

*   **Description:** Attackers inject malicious SQL code into database queries by manipulating user-supplied input that is directly incorporated into SQL statements.
*   **How MySQL Contributes:** MySQL, like most relational databases, is inherently vulnerable to SQL injection if queries are constructed insecurely. The driver itself doesn't *cause* SQL injection, but improper use of the driver enables it.
*   **Example:**
    ```go
    // Vulnerable Code:
    username := userInput // Assume userInput comes from a web form
    query := "SELECT * FROM users WHERE username = '" + username + "'"
    rows, err := db.Query(query)
    // ...

    // Attacker input:  ' OR '1'='1
    // Resulting query: SELECT * FROM users WHERE username = '' OR '1'='1'
    ```
    This would return all users, bypassing authentication.
*   **Impact:** Data breaches (reading sensitive data), data modification (altering or deleting data), privilege escalation (gaining administrative access), denial of service (making the database unavailable), and potentially remote code execution on the database server.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Parameterized Queries (Prepared Statements):** This is the *primary* defense. Use placeholders (`?` in `go-sql-driver/mysql`) in your SQL queries and pass the user-supplied data as separate arguments to `db.Query()`, `db.Exec()`, `db.QueryRow()`, etc.  The driver then handles escaping and data type conversions safely.
        ```go
        // Secure Code:
        username := userInput
        rows, err := db.Query("SELECT * FROM users WHERE username = ?", username)
        // ...
        ```
    *   **Stored Procedures:** Encapsulate SQL logic within the database, reducing the need to construct dynamic SQL in the application code.  This can limit the scope of potential injection attacks.
    *   **Least Privilege Principle:** Ensure that database users have only the minimum necessary permissions.  Don't use a single, highly privileged user for all database operations.  Create separate users with restricted access for different application components.
    *   **Input Validation (Defense in Depth):** While not a primary defense against SQL injection, validating user input *before* it reaches the database layer can help prevent some attacks and improve overall security. Use a whitelist approach (allow only known-good characters/patterns) whenever possible.

## Attack Surface: [Insecure Connection Configuration](./attack_surfaces/insecure_connection_configuration.md)

*   **Description:** Establishing a connection to the MySQL server without proper encryption or certificate validation.
*   **How MySQL Contributes:** MySQL supports both encrypted (TLS/SSL) and unencrypted connections. The driver allows the developer to configure the connection security.
*   **Example:** Using `tls=false` or `tls=skip-verify` in the Data Source Name (DSN).
    ```
    db, err := sql.Open("mysql", "user:password@tcp(hostname:3306)/dbname?tls=false") // Insecure
    db, err := sql.Open("mysql", "user:password@tcp(hostname:3306)/dbname?tls=skip-verify") // Insecure
    ```
*   **Impact:** Man-in-the-Middle (MitM) attacks, where an attacker can intercept the connection, steal credentials, and read or modify data transmitted between the application and the database.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Enforce TLS Encryption:** Always use `tls=true` in the DSN, or configure a custom TLS configuration with a trusted Certificate Authority (CA).
    *   **Certificate Validation:**  *Never* use `tls=skip-verify` in production. This disables certificate validation, making the connection vulnerable even with TLS enabled.
    *   **Network Segmentation:**  Isolate the database server on a separate network segment to limit exposure to potential attackers.
    *   **Firewall Rules:**  Restrict access to the MySQL port (default: 3306) to only authorized clients.

## Attack Surface: [Credential Exposure](./attack_surfaces/credential_exposure.md)

*   **Description:** Storing database credentials (username, password, host) insecurely, making them vulnerable to theft.
*   **How MySQL Contributes:** MySQL requires authentication, and the driver needs these credentials to connect. The vulnerability lies in *how* the application manages these credentials.
*   **Example:** Hardcoding credentials directly in the Go source code.
    ```go
    // Vulnerable Code:
    db, err := sql.Open("mysql", "myuser:mypassword@tcp(localhost:3306)/mydb")
    ```
*   **Impact:** If the source code is compromised (e.g., through a repository leak, insider threat), attackers gain access to the database.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Environment Variables:** Store credentials in environment variables, which are read by the application at runtime.
    *   **Configuration Files (Securely):** Use a configuration file (e.g., YAML, JSON, TOML) *outside* of the version-controlled codebase, and ensure it has appropriate file permissions (read-only by the application user).
    *   **Secrets Management Solutions:** Employ a dedicated secrets management service like HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, or Google Cloud Secret Manager. These services provide secure storage, access control, and auditing for sensitive data.
    *   **Principle of Least Privilege (Database Side):** Use database users with the minimum necessary privileges.

## Attack Surface: [Multi-Statement Execution (If Enabled)](./attack_surfaces/multi-statement_execution__if_enabled_.md)

* **Description:** If `multiStatements=true` is enabled in the DSN, a single query string can contain multiple SQL statements separated by semicolons.
    * **How MySQL Contributes:** MySQL supports multi-statement execution, but it must be explicitly enabled. The driver allows enabling this feature via the DSN.
    * **Example:**
    ```
    db, err := sql.Open("mysql", "user:password@tcp(hostname:3306)/dbname?multiStatements=true") // Potentially dangerous
    // ...
    userInput := "'; DROP TABLE users; --"
    _, err = db.Exec("SELECT * FROM products WHERE id = '" + userInput) //Vulnerable even with some sanitization
    ```
    * **Impact:** Increases the potential impact of SQL injection. An attacker could inject multiple malicious statements, even if basic sanitization is in place.
    * **Risk Severity:** High (if enabled)
    * **Mitigation Strategies:**
        * **Avoid `multiStatements=true`:** Do not enable this feature unless absolutely necessary.
        * **Stored Procedures:** If multiple statements are required, use stored procedures to encapsulate the logic on the server-side.
        * **Extremely Careful Input Validation (if unavoidable):** If `multiStatements=true` *must* be used, implement extremely rigorous input validation and sanitization, even with parameterized queries. This is still a high-risk situation.

