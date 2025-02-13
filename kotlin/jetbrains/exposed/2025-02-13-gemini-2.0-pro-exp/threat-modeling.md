# Threat Model Analysis for jetbrains/exposed

## Threat: [SQL Injection via Raw SQL](./threats/sql_injection_via_raw_sql.md)

*   **Threat:** SQL Injection via Raw SQL
    *   **Description:** An attacker crafts malicious input that, when incorporated into a raw SQL query executed through Exposed's `exec` or similar functions, alters the query's logic.  This bypasses the intended protections of the DSL and allows the attacker to execute arbitrary SQL commands. The attacker exploits the lack of proper parameterization or escaping when raw SQL is used *within* Exposed's API.
    *   **Impact:** Complete database compromise, data breach, data modification, denial of service, potential remote code execution on the database server.
    *   **Exposed Component Affected:** `exec`, `execAndGet`, `prepareSQL`, any function that allows direct execution of raw SQL strings.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Primary:** Avoid raw SQL whenever possible. Use Exposed's DSL for all database interactions.
        *   **If raw SQL is unavoidable:** Use parameterized queries *exclusively*.  Use `?` placeholders and pass values as a separate list.  *Never* concatenate user input directly into the SQL string.
        *   Implement strict input validation and sanitization *before* any data is used, even with parameterized queries (defense in depth).
        *   Use static analysis tools to detect potential SQL injection vulnerabilities.
        *   Regularly update Exposed to the latest version.

## Threat: [SQL Injection via DSL Vulnerability](./threats/sql_injection_via_dsl_vulnerability.md)

*   **Threat:** SQL Injection via DSL Vulnerability
    *   **Description:** A vulnerability *within* Exposed's DSL itself allows an attacker to craft input that bypasses the DSL's built-in protections and injects malicious SQL. This would require a bug in Exposed's escaping or query building logic, making it less likely than raw SQL injection but still a significant risk.
    *   **Impact:** Similar to raw SQL injection: database compromise, data breach, data modification, denial of service.
    *   **Exposed Component Affected:** Any DSL function used for querying or modifying data (e.g., `select`, `insert`, `update`, `delete`, `join`, etc.).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Keep Exposed updated to the latest version to receive security patches promptly.
        *   Implement robust input validation and sanitization as a defense-in-depth measure.
        *   Monitor security advisories and community forums related to Exposed for any reported vulnerabilities.
        *   Consider using a Web Application Firewall (WAF) with rules to detect and block common SQL injection patterns.

## Threat: [Elevation of Privilege via Overly Permissive Database User](./threats/elevation_of_privilege_via_overly_permissive_database_user.md)

*   **Threat:** Elevation of Privilege via Overly Permissive Database User
    *   **Description:** The application connects to the database *through Exposed* using a user account that has more privileges than necessary. While not a vulnerability *within* Exposed itself, the framework is the mechanism by which this overly permissive connection is established. If an attacker compromises the application, they inherit these excessive privileges *via the Exposed connection*.
    *   **Impact:** Complete database compromise, data breach, data modification, potential for further attacks.
    *   **Exposed Component Affected:** `Database.connect` (the credentials used in the connection, as managed by Exposed).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Implement the principle of least privilege. Create a dedicated database user account for the application with *only* the minimum necessary permissions (e.g., `SELECT`, `INSERT`, `UPDATE`, `DELETE` on specific tables and columns).
        *   *Never* use the database superuser account for the application in production.
        *   Regularly review and audit database user permissions.

## Threat: [Bypassing Application Authorization via Direct Database Access](./threats/bypassing_application_authorization_via_direct_database_access.md)

* **Threat:** Bypassing Application Authorization via Direct Database Access
    * **Description:** If an attacker obtains the database credentials used by *Exposed* (e.g., through a configuration file leak, social engineering, or another vulnerability), they can connect directly to the database, bypassing the application's authorization logic. While not a vulnerability *in* Exposed, the framework is the component that *uses* these credentials, making it a relevant factor.
    * **Impact:** Data breach, data modification, unauthorized access.
    * **Exposed Component Affected:** `Database.connect` (the credentials used in the connection, as managed by Exposed).
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        *   Securely store database credentials. *Never* hardcode them in the source code. Use environment variables, secrets management services (e.g., HashiCorp Vault, AWS Secrets Manager), or encrypted configuration files.
        *   Implement robust application-level authorization checks.
        *   Consider using database-level security features like row-level security (RLS) to enforce access controls even if the application is bypassed.
        *   Implement network security measures (firewalls, network segmentation) to restrict direct access to the database server.

