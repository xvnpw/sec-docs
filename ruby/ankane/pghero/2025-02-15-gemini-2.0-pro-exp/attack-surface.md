# Attack Surface Analysis for ankane/pghero

## Attack Surface: [Authentication Bypass](./attack_surfaces/authentication_bypass.md)

*   **Description:**  Accessing PgHero without proper authentication, circumventing the main application's security controls.
*   **How PgHero Contributes:** PgHero is often mounted as a separate Rack application, which, if misconfigured, can be accessed directly without going through the application's authentication.
*   **Example:**  An attacker navigates directly to `/pghero` and gains access to the dashboard without needing to log in to the main application.
*   **Impact:**  Unauthorized access to sensitive database performance data, potential for further attacks based on revealed information.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Integrate Authentication:** Ensure PgHero is *always* protected by the application's primary authentication mechanism.  Use middleware or routing constraints to enforce this.  For example, in Rails, use `authenticate` blocks within the route definition for PgHero.
    *   **Route Constraints:** Use route constraints to restrict access based on user roles or IP addresses.
    *   **Never Expose Directly:**  Never expose PgHero directly to the public internet without authentication.

## Attack Surface: [Weak Authentication Credentials](./attack_surfaces/weak_authentication_credentials.md)

*   **Description:**  Using default, easily guessable, or weak passwords for PgHero's authentication.
*   **How PgHero Contributes:** PgHero's authentication is often configured separately from the main application (e.g., via environment variables), increasing the risk of weak credentials being used.
*   **Example:**  PgHero is configured with the default username/password combination (if any exists in older versions) or a simple password like "password123".
*   **Impact:**  Unauthorized access to the PgHero dashboard, leading to information disclosure and potential for further attacks.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strong Passwords:** Enforce strong, unique passwords for PgHero.  Use a password manager.
    *   **Credential Rotation:** Regularly rotate PgHero's credentials.
    *   **Multi-Factor Authentication (MFA):** If possible, integrate PgHero with an MFA solution. This is often achievable by integrating with the main application's authentication, which might already support MFA.

## Attack Surface: [Insufficient Authorization](./attack_surfaces/insufficient_authorization.md)

*   **Description:**  All authenticated users having access to PgHero, even those with low privileges within the main application.
*   **How PgHero Contributes:**  PgHero provides access to sensitive database information that should only be available to authorized personnel.
*   **Example:**  A regular user of the application, after logging in, can access `/pghero` and view database performance metrics.
*   **Impact:**  Information disclosure; potential for privilege escalation within the application.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Role-Based Access Control (RBAC):** Implement RBAC within the application and restrict PgHero access to specific roles (e.g., "admin", "developer").
    *   **Authorization Libraries:** Use authorization libraries like CanCanCan or Pundit to manage access control consistently.
    *   **Conditional Access:**  Use conditional logic within the application to determine whether a user should have access to PgHero based on their role or other attributes.

## Attack Surface: [Running Query Disclosure](./attack_surfaces/running_query_disclosure.md)

*   **Description:**  Exposure of currently executing SQL queries, potentially including sensitive data in query parameters.
*   **How PgHero Contributes:** PgHero's features often include displaying running or recently executed queries.
*   **Example:**  An attacker views the "Running Queries" section of PgHero and sees a query containing a user's email address or other PII.
*   **Impact:**  Data breach; potential violation of privacy regulations.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Restrict Access:**  Again, controlling access to PgHero is paramount.
    *   **Parameterized Queries:**  *Always* use parameterized queries (prepared statements) to prevent sensitive data from appearing directly in query strings.  This is a fundamental security best practice, not just for PgHero.
    *   **Avoid Sensitive Data in Queries:**  Refactor application logic to avoid including sensitive data directly in queries whenever possible.

## Attack Surface: [Potential for Query Execution (Configuration Dependent)](./attack_surfaces/potential_for_query_execution__configuration_dependent_.md)

*   **Description:**  The possibility, depending on configuration, for PgHero to be used to execute arbitrary SQL queries.
*   **How PgHero Contributes:** While primarily read-only, some configurations or older versions *might* have features that could be abused to execute queries.
*   **Example:**  An attacker exploits a misconfigured "Explain" feature or a hidden debugging endpoint to run arbitrary SQL commands.
*   **Impact:**  Complete database compromise; data theft, modification, or deletion.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Read-Only User:**  Use a read-only database user for PgHero's connection to the database.  This is the *most important* mitigation for this risk.
    *   **Configuration Review:**  *Thoroughly* review PgHero's configuration and ensure that *no* features allow arbitrary query execution.
    *   **Disable Unnecessary Features:**  Disable any PgHero features that are not strictly required.
    *   **Auditing:** Regularly audit PgHero's configuration and database permissions.

