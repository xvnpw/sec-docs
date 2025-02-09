# Attack Surface Analysis for metabase/metabase

## Attack Surface: [1. SQL Injection (via Native Queries or Question Builder)](./attack_surfaces/1__sql_injection__via_native_queries_or_question_builder_.md)

*Description:* Attackers inject malicious SQL code into database queries, potentially gaining unauthorized access to data, modifying data, or even executing commands on the database server.
*How Metabase Contributes:* Metabase provides the interface (Question Builder and *especially* Native Queries) for users to interact with databases. Vulnerabilities in Metabase's query handling, database drivers, or insufficient input sanitization (particularly in native queries) create the *direct* opportunity for SQL injection.
*Example:* An attacker crafts a malicious string in a native query filter that bypasses Metabase's sanitization and includes additional SQL commands (e.g., `'; DROP TABLE users; --`).
*Impact:* Complete database compromise, data exfiltration, data modification, denial of service.
*Risk Severity:* **Critical**
*Mitigation Strategies:*
    *   **Developers:**
        *   Minimize/eliminate the use of native queries. If unavoidable, implement *extremely* rigorous, layered input validation and sanitization, treating *all* user-supplied input as potentially malicious.  This is *beyond* what Metabase might do by default.
        *   Ensure Metabase and all database drivers are *always* up-to-date.
        *   Employ a Web Application Firewall (WAF) with robust SQL injection protection.
    *   **Users/Administrators:**
        *   *Strictly* limit native query usage to highly trusted, experienced users with a strong understanding of SQL injection risks.
        *   Grant database users connected to Metabase the *absolute minimum* necessary privileges (read-only where possible, limited to specific tables/views).  This is a *critical* defense-in-depth measure.
        *   Regularly audit database logs for suspicious queries (looking for unexpected commands, unusual query patterns).
        *   Enable and actively monitor Metabase's audit logs.

## Attack Surface: [2. Unauthorized Data Access (via Public Sharing/Embedding)](./attack_surfaces/2__unauthorized_data_access__via_public_sharingembedding_.md)

*Description:* Sensitive data is exposed to unauthorized individuals through improperly configured public sharing links or embedded dashboards.
*How Metabase Contributes:* Metabase *directly* provides the features for public sharing and embedding. Misconfiguration or insufficient access controls on *these Metabase features* are the direct cause of this vulnerability.
*Example:* A dashboard containing confidential financial data is accidentally shared publicly with a link that is subsequently indexed by a search engine.
*Impact:* Data breach, reputational damage, regulatory non-compliance.
*Risk Severity:* **High**
*Mitigation Strategies:*
    *   **Developers:**
        *   If embedding Metabase, implement robust authentication and authorization *within your own application* to control access. Do *not* rely solely on Metabase's embedding security features.
    *   **Users/Administrators:**
        *   Avoid public sharing for sensitive data. Use it *extremely* sparingly, if at all.
        *   Use strong, unique, and regularly rotated tokens for embedded dashboards.  Treat these tokens as sensitive credentials.
        *   Regularly audit *all* existing public links and embedded dashboards, revoking access immediately when no longer needed.
        *   Implement a mandatory review process *before* any dashboard is shared publicly or embedded.
        *   Clearly communicate the risks of public sharing to all Metabase users.

## Attack Surface: [3. Authentication Bypass/Weak Authentication](./attack_surfaces/3__authentication_bypassweak_authentication.md)

*Description:* Attackers gain access to Metabase without valid credentials due to weak password policies, brute-force attacks, or vulnerabilities in Metabase's authentication mechanisms.
*How Metabase Contributes:* Metabase *directly* handles user authentication (or integrates with external systems). Weaknesses in Metabase's implementation or misconfiguration of these integrations are the direct vulnerability.
*Example:* An attacker uses a common password list to successfully brute-force a Metabase user account with a weak password.
*Impact:* Unauthorized access to Metabase, potential data exfiltration, data modification, or further attacks.
*Risk Severity:* **High**
*Mitigation Strategies:*
    *   **Developers:**
        *   If integrating with SSO/LDAP, ensure the integration is configured securely, following best practices and the principle of least privilege.  Regularly audit the integration.
    *   **Users/Administrators:**
        *   Enforce *strong* password policies (length, complexity, mandatory rotation).
        *   Implement account lockout policies after a small number of failed login attempts.
        *   Enable multi-factor authentication (MFA) if supported by Metabase and your authentication provider. This is a *highly* effective mitigation.
        *   Regularly audit user accounts and permissions.
        *   Actively monitor login logs for suspicious activity (failed login attempts, logins from unusual locations).

## Attack Surface: [4. Privilege Escalation (within Metabase)](./attack_surfaces/4__privilege_escalation__within_metabase_.md)

*Description:* A user with limited privileges within Metabase exploits a vulnerability to gain higher privileges.
*How Metabase Contributes:* Metabase *directly* implements a role-based access control system. Bugs in this Metabase system or misconfigurations are the direct cause of this vulnerability.
*Example:* A user with "view-only" access to a specific dashboard discovers a vulnerability in Metabase that allows them to modify the dashboard's query and access data from other tables.
*Impact:* Unauthorized data access, data modification, potential compromise of other Metabase components.
*Risk Severity:* **High**
*Mitigation Strategies:*
    *   **Developers:**
        *   Thoroughly test *all* user roles and permissions within Metabase to ensure they are enforced correctly.  This requires rigorous testing.
        *   Keep Metabase updated to the latest version to benefit from security patches.
    *   **Users/Administrators:**
        *   Strictly follow the principle of least privilege when assigning roles and permissions. Grant users *only* the access they absolutely need.
        *   Regularly review and audit user permissions, especially for users with elevated privileges.

## Attack Surface: [5. Vulnerable Dependencies](./attack_surfaces/5__vulnerable_dependencies.md)

*Description:* Metabase relies on third-party libraries, and vulnerabilities in these libraries can be exploited.
*How Metabase Contributes:* Metabase's attack surface *directly* includes the attack surface of all its dependencies. The choice of dependencies and their versions is a direct Metabase responsibility.
*Example:* A vulnerability is discovered in a logging library used by Metabase, allowing for remote code execution.
*Impact:* Varies widely, potentially ranging from information disclosure to complete system compromise (depending on the specific dependency and vulnerability).
*Risk Severity:* **High** (can be Critical)
*Mitigation Strategies:*
    * **Developers:**
        * Use Software Composition Analysis (SCA) tools to identify and track vulnerable dependencies *within Metabase*.
        * Establish a process for promptly updating dependencies when security patches are released. This is a *critical* part of secure development.
    * **Users/Administrators:**
        * Keep Metabase updated to the latest version. Metabase updates often include updates to bundled dependencies. This is the *primary* mitigation for users.
        * Subscribe to Metabase security advisories to be alerted to critical vulnerabilities.

