# Attack Surface Analysis for filp/whoops

## Attack Surface: [Information Disclosure: Server-Side Code](./attack_surfaces/information_disclosure_server-side_code.md)

*   **Description:**  Exposure of the application's source code, revealing internal logic, algorithms, and potentially sensitive operations.
*   **How Whoops Contributes:** `whoops` *directly* displays code snippets surrounding the error location, exposing the source code.
*   **Example:** An error in a database query function might reveal the SQL query, table structure, and even hardcoded database credentials within the displayed code snippet.
*   **Impact:** Attackers can gain understanding of the application's internals, identify vulnerabilities, and potentially discover secrets.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Disable in Production (Primary):** Use environment variables (e.g., `APP_ENV`) to conditionally load `whoops` only in development environments.  Ensure deployment scripts set `APP_ENV=production`.  This is the *absolute most critical* mitigation.
    *   **Code Review:** Regularly review code for hardcoded secrets and sensitive logic.
    *   **Secrets Management:** Use a dedicated secrets management solution.

## Attack Surface: [Information Disclosure: Environment Variables](./attack_surfaces/information_disclosure_environment_variables.md)

*   **Description:**  Exposure of the server's environment variables, which often contain sensitive configuration data.
*   **How Whoops Contributes:** `whoops` often *directly* includes a section displaying all environment variables.
*   **Example:** The environment variables might reveal database connection strings, API keys, or secret keys.
*   **Impact:**  Direct access to credentials allowing attackers to compromise databases, external services, or the entire server.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Disable in Production (Primary):**  Ensure `whoops` is never active in production.
    *   **Secrets Management:**  Use a secrets management solution.
    *   **Environment Variable Audit:**  Regularly audit environment variables.
    *   **Least Privilege:** Grant only necessary permissions to the application's user account.

## Attack Surface: [Information Disclosure: Request Data](./attack_surfaces/information_disclosure_request_data.md)

*   **Description:**  Exposure of details about the incoming HTTP request, including headers, cookies, and parameters.
*   **How Whoops Contributes:** `whoops` *directly* displays request information, potentially revealing sensitive data.
*   **Example:**  Session cookies, CSRF tokens, or user-submitted data (potentially including credentials due to application flaws) could be exposed.
*   **Impact:**  Exposure of user credentials, session tokens, leading to account compromise or session hijacking.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Disable in Production (Primary):**  Ensure `whoops` is disabled.
    *   **Input Validation and Sanitization:** Implement robust input validation *before* data is used or displayed.
    *   **Secure Cookie Handling:**  Use `HttpOnly` and `Secure` flags for cookies.
    *   **CSRF Protection:** Implement robust CSRF protection.

## Attack Surface: [Information Disclosure: Database Queries](./attack_surfaces/information_disclosure_database_queries.md)

*   **Description:**  Exposure of the full SQL query that caused an error.
*   **How Whoops Contributes:** `whoops` can *directly* display the executed SQL query.
*   **Example:** An error might show the complete `SELECT` statement, including table and column names.
*   **Impact:** Attackers gain insight into the database schema, potentially identifying sensitive data or crafting SQL injection attacks.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Disable in Production (Primary):** Disable `whoops`.
    *   **Parameterized Queries/Prepared Statements:**  Always use parameterized queries.
    *   **Database User Permissions:**  Grant the application's database user only minimum necessary privileges.

**Overriding Principle:**  The presence of `whoops` in a production environment is, in itself, a critical vulnerability.  The primary mitigation for *all* of these risks is to ensure it is completely disabled. The other mitigations are important security best practices, but they are secondary to disabling `whoops`.

