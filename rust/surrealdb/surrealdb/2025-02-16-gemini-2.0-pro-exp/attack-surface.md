# Attack Surface Analysis for surrealdb/surrealdb

## Attack Surface: [SurrealQL Injection](./attack_surfaces/surrealql_injection.md)

*   **Description:** Attackers inject malicious SurrealQL code through unsanitized user inputs, manipulating database queries to gain unauthorized access, modify data, or execute commands.
*   **SurrealDB Contribution:** SurrealDB's query language, SurrealQL, is susceptible to injection attacks if user input is not handled correctly. This is a *direct* consequence of using SurrealDB and its query language.
*   **Example:**
    ```surrealql
    -- Vulnerable code (assuming 'userInput' is directly from a user)
    LET $username = $userInput;
    SELECT * FROM user WHERE username = $username;

    -- Attacker input:  ' OR 1=1; --
    -- Resulting query: SELECT * FROM user WHERE username = '' OR 1=1; --  (Selects all users)
    ```
*   **Impact:** Complete database compromise, data theft, data modification, data deletion, potential server compromise (depending on SurrealDB's configuration and permissions).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Parameterized Queries:** *Always* use parameterized queries or prepared statements provided by the SurrealDB client library. This is the primary defense and is directly related to how you interact with SurrealDB.
    *   **ORM/Query Builder:** If available and suitable, use an ORM or query builder that handles parameterization automatically (and is designed for SurrealDB).
    *   **Least Privilege:** Ensure the database user connecting to SurrealDB has only the necessary permissions. Configure this *within* SurrealDB.

## Attack Surface: [Authentication Bypass](./attack_surfaces/authentication_bypass.md)

*   **Description:** Attackers circumvent SurrealDB's authentication mechanisms to gain unauthorized access to the database.
*   **SurrealDB Contribution:** This directly involves vulnerabilities *within* SurrealDB's authentication logic (JWT handling, session management, or its built-in authentication features).
*   **Example:** An attacker discovers a flaw in how SurrealDB validates JWT tokens, allowing them to forge a valid token. Or, a bug in SurrealDB's password verification logic is exploited.
*   **Impact:** Unauthorized access to data, potential for data modification, deletion, or denial of service.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Keep Software Updated:** Regularly update SurrealDB to the latest version to patch any known authentication vulnerabilities *in the database itself*.
    *   **Strong Configuration:** Use strong, randomly generated secrets for JWT signing *within SurrealDB's configuration*. Configure secure session management (timeouts, invalidation) *within SurrealDB*.
    *   **Multi-Factor Authentication (MFA):** If supported *by SurrealDB*, enable MFA.

## Attack Surface: [Improperly Configured Permissions](./attack_surfaces/improperly_configured_permissions.md)

*   **Description:** Overly permissive user roles or misconfigured access controls *within SurrealDB* allow unauthorized access or modification of data.
*   **SurrealDB Contribution:** This is entirely dependent on how SurrealDB's permission system (using `DEFINE USER`, `DEFINE SCOPE`, `DEFINE TABLE`) is configured. It's a direct result of using SurrealDB's built-in access control features.
*   **Example:** A user account is granted `SELECT * FROM *` permission within SurrealDB, allowing access to all data.
*   **Impact:** Data breaches, unauthorized data modification, potential for privilege escalation.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Principle of Least Privilege:** Grant users *only* the minimum necessary permissions *within SurrealDB*. Use `DEFINE USER`, `DEFINE SCOPE`, and `DEFINE TABLE` statements.
    *   **Regular Audits:** Periodically review user accounts and permissions *within SurrealDB*.
    *   **Role-Based Access Control (RBAC):** Define roles with specific permissions *within SurrealDB* and assign users to those roles.
    *   **Disable Default Accounts:** Disable or change the passwords of default accounts *within SurrealDB* immediately after installation.

## Attack Surface: [Resource Exhaustion (DoS) - *Targeting SurrealDB Directly*](./attack_surfaces/resource_exhaustion__dos__-_targeting_surrealdb_directly.md)

*   **Description:** Attackers craft malicious queries or send a large number of requests *specifically designed to overwhelm SurrealDB*.
*   **SurrealDB Contribution:** This targets the inherent limitations of the SurrealDB database engine itself. While any database can be DoSed, the specifics of how SurrealDB handles resource allocation and query processing are directly relevant.
*   **Example:** An attacker submits a query with deeply nested joins that are known to be inefficient in SurrealDB. Or, an attacker exploits a bug in SurrealDB's query optimizer to cause excessive resource consumption.
*   **Impact:** Database unavailability, application downtime.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Query Timeouts:** Configure query timeouts *within SurrealDB's configuration* to prevent long-running queries.
    *   **Resource Limits:** Set limits on memory usage, connection counts, and other resources *within SurrealDB's configuration*.
    *   **Monitoring:** Monitor SurrealDB's resource usage and set up alerts for unusual activity *specific to SurrealDB*.

## Attack Surface: [Vulnerabilities in Embedded Functions](./attack_surfaces/vulnerabilities_in_embedded_functions.md)

*   **Description:** Attackers exploit vulnerabilities in JavaScript functions *embedded within SurrealDB* to execute malicious code.
*   **SurrealDB Contribution:** This is a direct consequence of using SurrealDB's feature that allows embedding JavaScript functions *within the database itself*.
*   **Example:** An embedded function within SurrealDB uses `eval()` with user-supplied input, allowing for code injection *within the database context*.
*   **Impact:** Code execution within the database context, potential for data breaches, data modification, or denial of service.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Secure Coding Practices:** Follow secure coding practices when writing embedded functions *for SurrealDB*. Avoid unsafe functions.
    *   **Input Validation:** Strictly validate and sanitize any input used within embedded functions *within SurrealDB*.
    *   **Sandboxing/Isolation:** If SurrealDB provides options, explore sandboxing or isolating embedded functions to limit their access.
    *   **Code Review:** Thoroughly review and test embedded functions *specifically for use within SurrealDB*.

