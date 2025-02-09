# Mitigation Strategies Analysis for metabase/metabase

## Mitigation Strategy: [Strict Database User Permissions (Principle of Least Privilege)](./mitigation_strategies/strict_database_user_permissions__principle_of_least_privilege_.md)

*   **Description:**
    1.  **Identify Data Needs:** Within Metabase, analyze which questions, dashboards, and collections *actually* require access to specific database tables and views. Document this.
    2.  **Create Dedicated User (Database-Side):** This is technically outside Metabase, but *essential* for Metabase security. Create a database user *specifically* for Metabase.
    3.  **Grant Minimal Permissions (Database-Side):** Grant *only* `SELECT` on the necessary tables/views. *No* `INSERT`, `UPDATE`, `DELETE`, etc., unless absolutely required (and then, use a *separate* user with highly restricted write permissions).
    4.  **Configure Metabase Connection:** In Metabase's Admin Panel > Databases, configure the connection to your database using the dedicated, low-privilege user created in step 2.
    5.  **Test Within Metabase:** Verify that existing dashboards and questions function correctly.  Attempt to create new questions accessing unauthorized data – this should fail.
    6.  **Regular Audits (Database-Side):** Regularly audit the database user's permissions.

*   **Threats Mitigated:**
    *   **Data Breach (Severity: Critical):** Limits data access if Metabase is compromised.
    *   **Data Modification/Destruction (Severity: Critical):** Prevents data alteration/deletion through Metabase.
    *   **Privilege Escalation (Severity: High):** Limits database privilege escalation.

*   **Impact:**
    *   **Data Breach:** Risk reduction: Very High.
    *   **Data Modification/Destruction:** Risk reduction: Very High (potentially eliminates the risk).
    *   **Privilege Escalation:** Risk reduction: High.

*   **Currently Implemented:** Partially. Dedicated user exists, but with overly broad `SELECT` permissions.

*   **Missing Implementation:** User permissions need restriction to *only* necessary tables. Regular audits are not scheduled.

## Mitigation Strategy: [Secure Metabase Application Configuration](./mitigation_strategies/secure_metabase_application_configuration.md)

*   **Description:**
    1.  **Application Database Password (Metabase Setup):** During Metabase setup (or via environment variables), set a *strong, unique* password for the Metabase application database.  Prefer PostgreSQL/MySQL over the default H2 for production.
    2.  **Public Sharing (Admin Panel):** In Metabase's Admin Panel > Settings > General, *disable* "Public Sharing" by default.
    3.  **Embedding (Admin Panel):** In Metabase's Admin Panel > Settings > Embedding in other Applications, *disable* "Unauthenticated Embedding." If embedding is needed, use "Signed Embedding" and generate a strong secret key (store this key *outside* of Metabase, e.g., in environment variables).
    4.  **Session Timeout (Admin Panel):** In Metabase's Admin Panel > Settings > General, set a reasonable "Session Timeout" (e.g., 30 minutes).
    5.  **Audit Logs (Admin Panel):** In Metabase's Admin Panel > Settings > Audit, ensure audit logging is *enabled*. Configure external log collection if possible.
    6.  **Disable Unused Features (Admin Panel):** In Metabase's Admin Panel, disable any unused features, especially database drivers you're not using.

*   **Threats Mitigated:**
    *   **Unauthorized Access (Severity: High):** Strong passwords and session timeouts protect the Metabase interface.
    *   **Data Exposure (Severity: High):** Disabling public sharing and unauthenticated embedding prevents accidental data leaks.
    *   **Session Hijacking (Severity: Medium):** Session timeouts reduce the hijacking window.
    *   **Reconnaissance (Severity: Low):** Disabling unused features reduces the attack surface.

*   **Impact:**
    *   **Unauthorized Access:** Risk reduction: High.
    *   **Data Exposure:** Risk reduction: High.
    *   **Session Hijacking:** Risk reduction: Medium.
    *   **Reconnaissance:** Risk reduction: Low.

*   **Currently Implemented:** Mostly. HTTPS, session timeout, and public sharing are configured correctly. Application database uses PostgreSQL with a strong password.

*   **Missing Implementation:** Unauthenticated embedding is enabled. Audit log analysis is not automated. Unused features haven't been reviewed.

## Mitigation Strategy: [Careful Management of User Permissions *Within* Metabase](./mitigation_strategies/careful_management_of_user_permissions_within_metabase.md)

*   **Description:**
    1.  **Groups (Admin Panel):** In Metabase's Admin Panel > People, create user groups based on roles (e.g., "Marketing," "Sales," "Analysts").
    2.  **Collections (Metabase Interface):** Organize dashboards and questions into logical collections.
    3.  **Permissions (Admin Panel & Collections):**
        *   In the Admin Panel > Permissions, assign data access permissions to groups for each database. Use the principle of least privilege.
        *   For each collection, set permissions (View, Edit, Curate) for each group.
    4.  **Data Sandboxing (Enterprise Edition, Admin Panel):** If using Metabase Enterprise, explore data sandboxing (Admin Panel > Permissions > Data Sandboxing) to restrict access at the row/column level based on user attributes.
    5.  **Regular Reviews (Admin Panel):** Regularly review user and group permissions in the Admin Panel > People and Admin Panel > Permissions.

*   **Threats Mitigated:**
    *   **Unauthorized Data Access (Severity: Medium):** Controls access *within* Metabase.
    *   **Accidental Data Modification (Severity: Medium):** Limits accidental changes.
    *   **Insider Threats (Severity: Medium):** Reduces potential damage from malicious insiders.

*   **Impact:**
    *   **Unauthorized Data Access:** Risk reduction: Medium.
    *   **Accidental Data Modification:** Risk reduction: Medium.
    *   **Insider Threats:** Risk reduction: Medium.

*   **Currently Implemented:** Partially. Basic groups and collections exist, but not granular enough.

*   **Missing Implementation:** Group structure needs refinement. Collection usage is inconsistent. Regular permission reviews are not scheduled. Data sandboxing should be evaluated.

## Mitigation Strategy: [Secure Custom SQL Queries](./mitigation_strategies/secure_custom_sql_queries.md)

*   **Description:**
    1.  **Restrict Access (Admin Panel):** In Metabase's Admin Panel > Permissions, *restrict* the ability to write custom SQL queries to a small, trusted group of users. This is a per-database permission.
    2.  **Parameterized Queries (User Training & Metabase Features):** Train users who *do* have custom SQL access to *always* use parameterized queries. Metabase's query builder helps with this, but users must understand the concept.
    3.  **Code Review (Process, Outside Metabase):** Ideally, implement a code review process for custom SQL.
    4.  **Limit Complexity (Informal Guidance):** Advise users to avoid overly complex queries.
    5.  **Use Views (Informal Guidance):** Encourage the use of database views instead of complex custom SQL.

*   **Threats Mitigated:**
    *   **SQL Injection (Severity: Critical):** Parameterized queries are the *key* defense.
    *   **Data Breach (Severity: High):** SQL injection can lead to data breaches.
    *   **Data Modification/Destruction (Severity: High):** SQL injection can modify/delete data.
    *   **Denial of Service (Severity: Medium):** Poorly written queries can cause performance issues.

*   **Impact:**
    *   **SQL Injection:** Risk reduction: Very High (with correct parameterized query usage).
    *   **Data Breach:** Risk reduction: High.
    *   **Data Modification/Destruction:** Risk reduction: High.
    *   **Denial of Service:** Risk reduction: Medium.

*   **Currently Implemented:** Partially. Custom SQL access is restricted. Users are generally aware of parameterized queries.

*   **Missing Implementation:** Formal parameterized query training is needed. Code review is not implemented. Complexity limits and view encouragement are informal.

## Mitigation Strategy: [Stay Updated (Patches and Upgrades)](./mitigation_strategies/stay_updated__patches_and_upgrades_.md)

*   **Description:**
    1.  **Monitor (External):** Subscribe to Metabase release announcements.
    2.  **Test (External Staging Environment):** Test updates *thoroughly* in a staging environment before applying to production.
    3.  **Backup (External):** Back up the Metabase application database *before* upgrading.
    4.  **Apply (Metabase Interface/Process):** Use Metabase's built-in upgrade mechanism (or your deployment process) to apply updates promptly.

*   **Threats Mitigated:**
    *   **Exploitation of Known Vulnerabilities (Severity: Varies, potentially Critical):** Updates patch security vulnerabilities.

*   **Impact:**
    *   **Exploitation of Known Vulnerabilities:** Risk reduction: High.

*   **Currently Implemented:** Partially. Updates are applied periodically, but without a formal process.

*   **Missing Implementation:** Formal monitoring, testing, and backup procedures are needed.

## Mitigation Strategy: [Secure Handling of Secrets](./mitigation_strategies/secure_handling_of_secrets.md)

*   **Description:**
    1. **Identify Secrets:** Identify all sensitive information that Metabase needs to access (e.g., database passwords, API keys, embedding secrets).
    2. **Use Environment Variables:** Configure Metabase to read secrets from environment variables. This is done *outside* of the Metabase UI, typically during deployment. For example, set `MB_DB_CONNECTION_URI` instead of configuring the database connection details directly in the UI.
    3. **Secrets Management System (Optional, Outside Metabase):** Consider using a secrets manager (e.g., HashiCorp Vault).
    4. **Restrict Access (Outside Metabase):** Limit access to environment variables or the secrets manager.

*   **Threats Mitigated:**
    *   **Credential Exposure (Severity: High):** Prevents secrets from being exposed in configuration files.
    *   **Unauthorized Access (Severity: High):** Protects credentials needed to access databases.

*   **Impact:**
    *   **Credential Exposure:** Risk reduction: Very High.
    *   **Unauthorized Access:** Risk reduction: High.

*   **Currently Implemented:** Partially. Database credentials use environment variables.

*   **Missing Implementation:** The embedding secret is hardcoded. A secrets manager should be evaluated.

