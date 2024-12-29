*   **Threat:** Mass Assignment Vulnerability via Controller Parameters
    *   **Description:** An attacker could manipulate HTTP request parameters to modify model attributes that were not intended to be updated. This is done by including extra parameters in the request that correspond to model fields. The attacker might be able to change sensitive data, bypass authorization checks, or cause unexpected application behavior.
    *   **Impact:** Unauthorized modification of data, potentially leading to data corruption, privilege escalation, or other unintended consequences.
    *   **Affected Component:** `Hanami::Controller::Params`, Model update methods (e.g., `update`).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Implement strong parameter filtering and whitelisting within controllers using `params.permit`.
        *   Define specific permitted attributes for model updates.
        *   Avoid directly assigning request parameters to model attributes without validation.

*   **Threat:** Cross-Site Scripting (XSS) via Unescaped Output in Templates
    *   **Description:** An attacker could inject malicious scripts into the application's views if user-supplied data is rendered without proper escaping. This script could then be executed in the browsers of other users, potentially stealing cookies, redirecting users, or performing other malicious actions on their behalf.
    *   **Impact:** Compromise of user accounts, data theft, defacement of the application.
    *   **Affected Component:** `Hanami::View::Helpers::EscapeHelper`, template rendering engine (e.g., ERB, Haml).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Consistently use Hanami's built-in escaping mechanisms (e.g., `h.escape`) when rendering user-provided data in templates.
        *   Review custom helpers for potential XSS vulnerabilities.
        *   Consider using Content Security Policy (CSP) to further mitigate XSS risks.

*   **Threat:** Server-Side Template Injection (SSTI) if Using Custom Template Engines Insecurely
    *   **Description:** If developers integrate custom template engines or use Hanami's built-in engine in an unconventional way that allows direct execution of code within templates, an attacker could inject malicious code that is executed on the server. This could lead to complete server compromise.
    *   **Impact:** Remote code execution, full server compromise.
    *   **Affected Component:** `Hanami::View`, template rendering engine integration.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Avoid allowing user input to directly influence template code.
        *   If using custom template engines, ensure they are securely configured and hardened against SSTI.
        *   Restrict the use of dynamic template compilation based on user input.

*   **Threat:** Insecure Query Construction leading to SQL Injection (if using raw SQL or custom queries)
    *   **Description:** While Hanami's ORM (Hanami::Model) generally protects against SQL injection, developers using raw SQL queries or constructing complex queries manually without proper sanitization could introduce vulnerabilities. An attacker could inject malicious SQL code that manipulates the database, potentially leading to data breaches, data modification, or denial of service.
    *   **Impact:** Data breach, data manipulation, denial of service.
    *   **Affected Component:** `Hanami::Model::Adapters::SqlAdapter`, raw SQL execution methods.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Prefer using Hanami::Model's query builder for database interactions.
        *   If raw SQL is necessary, use parameterized queries or prepared statements to prevent SQL injection.
        *   Thoroughly validate and sanitize any user input used in SQL queries.

*   **Threat:** Misconfiguration of CSRF Protection
    *   **Description:** Hanami provides built-in CSRF protection. However, if it's not correctly configured (e.g., disabled globally or for specific actions where it's needed) or if exceptions are not handled properly, an attacker could potentially perform actions on behalf of a logged-in user without their knowledge.
    *   **Impact:** Unauthorized actions performed on behalf of legitimate users, potentially leading to data modification, financial loss, or other harmful consequences.
    *   **Affected Component:** `Hanami::Middleware::CSRFProtection`, form helpers.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Ensure CSRF protection is enabled globally or for relevant actions.
        *   Verify that CSRF tokens are correctly included in forms and requests.
        *   Review any exceptions or whitelisting rules for potential vulnerabilities.

*   **Threat:** Insecure Session Management Configuration
    *   **Description:** Misconfiguration of session management, such as using insecure session storage (e.g., client-side cookies without proper encryption or signing) or weak session IDs, could allow attackers to hijack user sessions. This could grant them unauthorized access to user accounts and their data.
    *   **Impact:** Session hijacking, unauthorized access to user accounts and data.
    *   **Affected Component:** `Hanami::Controller::Session`, session storage mechanisms.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Use secure session storage mechanisms (e.g., database-backed sessions, encrypted cookies with strong keys).
        *   Ensure strong and unpredictable session IDs are generated.
        *   Configure appropriate session timeouts and security flags (e.g., `HttpOnly`, `Secure`).

*   **Threat:** Default Secret Keys and Credentials
    *   **Description:** Failing to change default secret keys used for signing cookies, generating CSRF tokens, or other cryptographic operations can allow attackers to forge or tamper with data. This could compromise the integrity and security of the application.
    *   **Impact:** Ability to forge cookies, bypass CSRF protection, potentially gain unauthorized access.
    *   **Affected Component:** `Hanami::Config`, various security-related components relying on secret keys.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Immediately change all default secret keys and credentials during application setup.
        *   Store secrets securely and avoid hardcoding them in the codebase (use environment variables or secure vault solutions).