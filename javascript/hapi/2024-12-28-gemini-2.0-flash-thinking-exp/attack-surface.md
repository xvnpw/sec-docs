*   **Attack Surface:** Route Parameter Injection
    *   **Description:**  Malicious or unexpected input is injected into route parameters, potentially leading to unintended actions or information disclosure.
    *   **How Hapi Contributes to the Attack Surface:** Hapi's routing mechanism directly exposes route parameters to handler functions, making them susceptible if not properly validated or sanitized before use in database queries, file system operations, or external API calls.
    *   **Example:** A route defined as `/users/{id}` where the `id` parameter is directly used in a database query like `SELECT * FROM users WHERE id = '{id}'`. An attacker could inject `' OR '1'='1` to bypass authentication or access unauthorized data.
    *   **Impact:** Data breaches, unauthorized access, application errors, potential for command injection depending on how the parameter is used.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Input Validation:** Use Joi (Hapi's recommended validation library) to strictly define the expected format and type of route parameters.
        *   **Parameter Sanitization:** Sanitize route parameters before using them in sensitive operations.
        *   **Parameterized Queries:** When using databases, always use parameterized queries or prepared statements to prevent SQL injection.
        *   **Principle of Least Privilege:** Ensure the application's database user has only the necessary permissions.

*   **Attack Surface:** Authentication Scheme Vulnerabilities (Plugin-Based)
    *   **Description:** Vulnerabilities within the authentication schemes implemented as Hapi plugins can compromise user authentication.
    *   **How Hapi Contributes to the Attack Surface:** Hapi's authentication system relies heavily on plugins. If a chosen authentication plugin has security flaws, the entire application's authentication can be compromised.
    *   **Example:** An authentication plugin might use a weak hashing algorithm for passwords, making them susceptible to brute-force attacks. Another plugin might have vulnerabilities in its token generation or validation logic.
    *   **Impact:** Unauthorized access to user accounts, data breaches, impersonation.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Choose Reputable and Well-Audited Plugins:** Select authentication plugins that are actively maintained, well-documented, and have a good security track record.
        *   **Regularly Update Plugins:** Keep authentication plugins updated to benefit from security patches.
        *   **Review Plugin Code (if possible):** If using custom or less common plugins, review their code for potential security vulnerabilities.
        *   **Implement Strong Password Policies:** Enforce strong password requirements for users.

*   **Attack Surface:** Authorization Logic Flaws
    *   **Description:** Incorrectly implemented authorization logic within route handlers or using Hapi's `access` option can lead to authorization bypasses.
    *   **How Hapi Contributes to the Attack Surface:** Hapi provides mechanisms for implementing authorization, but the responsibility for correct implementation lies with the developer. Flaws in this logic can expose protected resources.
    *   **Example:** A route intended only for administrators might have an authorization check that incorrectly evaluates user roles, allowing regular users to access administrative functions.
    *   **Impact:** Unauthorized access to sensitive data or functionalities, privilege escalation.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Centralized Authorization Logic:** Implement authorization logic in a centralized and reusable manner to ensure consistency and reduce the risk of errors.
        *   **Role-Based Access Control (RBAC):** Implement a robust RBAC system to manage user permissions effectively.
        *   **Thorough Testing:** Thoroughly test authorization logic with various user roles and scenarios to identify potential bypasses.
        *   **Principle of Least Privilege:** Grant users only the necessary permissions to perform their tasks.

*   **Attack Surface:** Vulnerable Plugins (General)
    *   **Description:** Using outdated or vulnerable Hapi plugins can introduce security flaws into the application.
    *   **How Hapi Contributes to the Attack Surface:** Hapi's plugin architecture encourages the use of community-developed plugins. While beneficial, this also means the security of the application depends on the security of its plugins.
    *   **Example:** A plugin used for data sanitization might have a vulnerability that allows attackers to bypass the sanitization process. A logging plugin might have a flaw that allows attackers to inject malicious log entries.
    *   **Impact:** Wide range of potential impacts depending on the vulnerability in the plugin, including remote code execution, data breaches, and denial of service.
    *   **Risk Severity:** Medium to Critical (depending on the plugin and vulnerability - including here as it can be critical)
    *   **Mitigation Strategies:**
        *   **Regularly Update Plugins:** Keep all Hapi plugins updated to the latest versions to patch known vulnerabilities.
        *   **Choose Reputable Plugins:** Select plugins that are actively maintained, well-documented, and have a good security reputation.
        *   **Security Audits of Plugins:** Consider performing security audits of critical plugins, especially those handling sensitive data.
        *   **Monitor for Security Advisories:** Stay informed about security advisories related to Hapi plugins.