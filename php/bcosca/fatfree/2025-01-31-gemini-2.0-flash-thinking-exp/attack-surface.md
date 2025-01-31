# Attack Surface Analysis for bcosca/fatfree

## Attack Surface: [Server-Side Template Injection (SSTI)](./attack_surfaces/server-side_template_injection__ssti_.md)

*   **Description:** Exploiting vulnerabilities in the template engine to inject malicious code that executes on the server.
*   **How Fat-Free Contributes:** F3's built-in template engine, using tags like `{{ @variable }}` and `{{ function() }}`, directly processes template code. If user-controlled input is incorporated into templates without proper sanitization, F3's template engine becomes the execution vector for injected code.
*   **Example:**
    *   **Vulnerable Code:**  `$f3->set('template', 'Hello {{ $_GET["name"] }}'); echo Template::instance()->render('template');`
    *   **Attack Payload:** `?name={{ system('whoami') }}`
    *   **Explanation:** The attacker injects `{{ system('whoami') }}` as the `name` parameter. F3's template engine interprets and executes this injected code, running the `whoami` command on the server.
*   **Impact:**  **Critical**. Full server compromise, arbitrary code execution, data breaches, denial of service.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Parameterize Template Variables:** Treat user input as data, not code. Avoid dynamically constructing template strings with user input.
    *   **Output Encoding/Escaping:** Utilize F3's template engine's escaping mechanisms to automatically encode output based on context, preventing interpretation of injected code.
    *   **Input Validation and Sanitization:** Validate and sanitize user input before using it in templates as a defense-in-depth measure, even with output escaping.

## Attack Surface: [SQL Injection Vulnerabilities](./attack_surfaces/sql_injection_vulnerabilities.md)

*   **Description:** Exploiting vulnerabilities in database queries to inject malicious SQL code, allowing unauthorized data access, modification, or deletion.
*   **How Fat-Free Contributes:** While F3 provides database abstraction and encourages parameterized queries through its `DB\SQL` and `DB\Cortex` classes, developers can bypass these secure methods and directly use `$db->exec()` with raw SQL.  Improperly constructed queries using string concatenation with user input directly leverage F3's database interaction capabilities for malicious purposes.
*   **Example:**
    *   **Vulnerable Code:** `$username = $_GET['username']; $sql = "SELECT * FROM users WHERE username = '$username'"; $result = $f3->get('DB')->exec($sql);`
    *   **Attack Payload:** `?username='; DELETE FROM users; --`
    *   **Explanation:** The attacker injects SQL code that is directly passed to the database engine via F3's `$db->exec()` method, leading to unintended database operations.
*   **Impact:** **Critical**. Data breaches, data loss, data manipulation, unauthorized access to sensitive information, denial of service.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Parameterized Queries (Prepared Statements):**  Always use parameterized queries or prepared statements offered by F3's database classes. This prevents user input from being interpreted as SQL code.
    *   **ORM/Database Abstraction:** Utilize F3's ORM features (`DB\Cortex`) to further abstract database interactions and minimize raw SQL usage.
    *   **Input Validation and Sanitization:** Validate and sanitize user input before using it in database queries, even when using parameterized queries, as a secondary security layer.

## Attack Surface: [File Inclusion Vulnerabilities](./attack_surfaces/file_inclusion_vulnerabilities.md)

*   **Description:** Exploiting vulnerabilities to include arbitrary files, potentially leading to code execution or sensitive data disclosure.
*   **How Fat-Free Contributes:** If developers use F3's routing or view rendering mechanisms to dynamically determine file paths based on user input and then use PHP's `include()` or `require()` functions, it can lead to file inclusion.  F3's flexibility in handling views and routing can be misused if path construction is not carefully managed.
*   **Example:**
    *   **Vulnerable Code:** `$page = $_GET['page']; include('views/' . $page . '.php');`
    *   **Attack Payload (LFI):** `?page=../../../../etc/passwd`
    *   **Explanation:** The attacker manipulates the `page` parameter, which is directly used in a file path within an `include()` statement. F3's routing or controller logic might facilitate passing this user input to the vulnerable `include()` call.
*   **Impact:** **High to Critical**. Sensitive data disclosure (LFI), remote code execution (RFI if `allow_url_include` is enabled, though discouraged).
*   **Risk Severity:** **High** (can be Critical with RFI or execution of included files)
*   **Mitigation Strategies:**
    *   **Avoid Dynamic File Paths:**  Do not construct file paths based on user input. Use a whitelist of allowed files or predefined paths for views and includes.
    *   **Input Validation:**  Strictly validate user input if dynamic file paths are unavoidable. Sanitize input to prevent path traversal attempts.
    *   **Restrict File Access Permissions:** Configure file system permissions to limit access to sensitive files and directories by the web server process.

## Attack Surface: [Configuration Exposure and Misconfiguration (Debug Mode)](./attack_surfaces/configuration_exposure_and_misconfiguration__debug_mode_.md)

*   **Description:** Exposing sensitive information through misconfiguration, specifically by leaving debug mode enabled in production.
*   **How Fat-Free Contributes:** F3's `DEBUG` configuration setting controls the level of error reporting and debugging information displayed. Setting `DEBUG` to `3` in production environments, as facilitated by F3's configuration system, exposes detailed error messages, internal paths, and potentially sensitive variables to users.
*   **Example:**
    *   **Misconfiguration:** `DEBUG=3` is set in the F3 configuration file in a production environment.
    *   **Attack Scenario:** An application error occurs. F3 displays a detailed error page to the user, revealing server paths, code snippets, and potentially database connection details or other sensitive information.
*   **Impact:** **High**. Sensitive information disclosure (internal paths, code structure, potentially credentials in error messages), aiding attackers in further exploitation.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Disable Debug Mode in Production:** Ensure `DEBUG` is set to `0` in production environments. Use different configuration settings for development and production.
    *   **Secure Configuration Files:** Protect F3 configuration files from public access using web server configurations and file system permissions.

## Attack Surface: [Session Management Vulnerabilities (Configuration & Implementation)](./attack_surfaces/session_management_vulnerabilities__configuration_&_implementation_.md)

*   **Description:** Weaknesses in session handling that can lead to session hijacking or fixation, potentially allowing account takeover.
*   **How Fat-Free Contributes:** F3 provides session management through the `\Session` class.  While F3 offers session functionality, developers are responsible for secure configuration and implementation.  Default session configurations or neglecting to implement session fixation protection within an F3 application can create vulnerabilities.
*   **Example:**
    *   **Vulnerability:**  Application fails to regenerate session IDs after user login (session fixation).
    *   **Attack Scenario:** An attacker tricks a user into using a known session ID. After the user logs in, the attacker reuses the same session ID to gain access to the user's account.
*   **Impact:** **High**. Account takeover, unauthorized access to user data and functionality, privilege escalation.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Session Fixation Protection:** Implement session ID regeneration after user authentication within the F3 application logic.
    *   **Secure Session Configuration:** Configure F3's session handling to use strong session IDs and secure session storage mechanisms.
    *   **HTTPS:** Enforce HTTPS to protect session cookies from network sniffing.
    *   **`session.cookie_httponly` and `session.cookie_secure` (PHP Configuration):** Ensure these PHP directives are enabled for enhanced session cookie security, which F3 applications rely on.

