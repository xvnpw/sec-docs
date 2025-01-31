# Attack Surface Analysis for bcit-ci/codeigniter

## Attack Surface: [Configuration File Exposure (`config/config.php`, `config/database.php`)](./attack_surfaces/configuration_file_exposure___configconfig_php____configdatabase_php__.md)

*   **Description:** Sensitive configuration files containing database credentials, encryption keys, and other secrets are accessible to unauthorized users.
*   **CodeIgniter Contribution:** CodeIgniter centralizes configuration in these specific, well-known files within the `application/config` directory, making them prime targets if web server access is misconfigured.
*   **Example:** A misconfigured web server allows direct access to `https://example.com/application/config/database.php`, revealing database username, password, and database name.
*   **Impact:** Full database compromise, data breaches, application takeover, and potential lateral movement to other systems.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Restrict Web Server Access:** Configure the web server to deny direct access to the `application` directory and its subdirectories, including `config`.
    *   **Move Configuration Outside Web Root:** If possible, move configuration files outside the web root entirely and load them programmatically.
    *   **File Permissions:** Ensure strict file permissions on configuration files (e.g., 600 or 400) to prevent unauthorized read access by the web server user.

## Attack Surface: [Debug Mode Enabled in Production (`ENVIRONMENT = 'development'`)](./attack_surfaces/debug_mode_enabled_in_production___environment_=_'development'__.md)

*   **Description:** Debug mode is left enabled in a production environment, exposing detailed error messages and potentially sensitive information.
*   **CodeIgniter Contribution:** CodeIgniter's `ENVIRONMENT` constant in `index.php` directly controls debug output. The framework's default setup and ease of development might lead developers to forget to switch to `'production'` before deployment.
*   **Example:** An application error in production displays a detailed stack trace, revealing file paths, database query details, and potentially variable values to a regular user.
*   **Impact:** Information disclosure, aiding attackers in understanding application internals, identifying vulnerabilities, and crafting targeted attacks.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Set `ENVIRONMENT = 'production'`:** Ensure the `ENVIRONMENT` constant in `index.php` is set to `'production'` for production deployments.
    *   **Error Logging:** Implement robust error logging to capture errors for debugging purposes without displaying them to users. Review logs regularly.

## Attack Surface: [Weak Encryption Key (`encryption_key`)](./attack_surfaces/weak_encryption_key___encryption_key__.md)

*   **Description:** A weak or default encryption key is used in `config.php`, compromising the security of encrypted data.
*   **CodeIgniter Contribution:** CodeIgniter's security features, such as session encryption and data encryption, rely on the `encryption_key` defined in `config.php`. A weak key directly weakens these security mechanisms provided by the framework.
*   **Example:** An attacker brute-forces session cookies encrypted with a weak `encryption_key`, gaining unauthorized access to user accounts.
*   **Impact:** Session hijacking, data breaches if sensitive data is encrypted, and compromise of security features relying on encryption.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Generate Strong Encryption Key:** Use a cryptographically secure random string generator to create a strong, unique `encryption_key`.
    *   **Key Rotation:** Consider periodically rotating the encryption key, especially if compromise is suspected.

## Attack Surface: [Insufficient Input Validation and Sanitization](./attack_surfaces/insufficient_input_validation_and_sanitization.md)

*   **Description:** User inputs are not properly validated and sanitized, leading to injection vulnerabilities.
*   **CodeIgniter Contribution:** While CodeIgniter *provides* input validation libraries and the Input class for sanitization, it *relies* on developers to actively and correctly implement these features in their controllers and models. Neglecting to use these CodeIgniter tools effectively leads to vulnerabilities.
*   **Example:** A user input field in a form is not sanitized using CodeIgniter's Input class, allowing an attacker to inject JavaScript code that executes in other users' browsers (XSS). Or, unsanitized input used in a database query (without using CodeIgniter's Query Builder or parameterized queries) leads to SQL Injection.
*   **Impact:** Cross-Site Scripting (XSS), SQL Injection, Command Injection, and other input-based attacks, leading to data breaches, account compromise, and system takeover.
*   **Risk Severity:** **High** to **Critical** (depending on the vulnerability type)
*   **Mitigation Strategies:**
    *   **Use CodeIgniter Input Class:** Utilize CodeIgniter's Input class (`$this->input`) for retrieving and sanitizing user inputs.
    *   **Input Validation:** Implement robust input validation rules using CodeIgniter's Form Validation library to ensure data conforms to expected formats and constraints.
    *   **Parameterized Queries/ORMs:** Use parameterized queries or CodeIgniter's Query Builder/ORM to prevent SQL Injection. Avoid direct string concatenation of user input in SQL queries.

## Attack Surface: [CSRF Protection Misconfiguration or Disabled](./attack_surfaces/csrf_protection_misconfiguration_or_disabled.md)

*   **Description:** CSRF protection is disabled or improperly configured, making the application vulnerable to Cross-Site Request Forgery attacks.
*   **CodeIgniter Contribution:** CodeIgniter offers built-in CSRF protection that is configured within `config/config.php`.  Developers must explicitly enable and configure this *CodeIgniter feature*. Disabling or misconfiguring it directly removes a security layer provided by the framework.
*   **Example:** An attacker crafts a malicious website that tricks a logged-in user into unknowingly submitting a form on the vulnerable CodeIgniter application, performing actions like changing their password or making unauthorized transactions.
*   **Impact:** Unauthorized actions performed on behalf of authenticated users, leading to account compromise, data manipulation, and financial loss.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Enable CSRF Protection:** Ensure CSRF protection is enabled in `config/config.php` by setting `$config['csrf_protection'] = TRUE;`.
    *   **Use CSRF Tokens:** Use CodeIgniter's form helper (`form_open()`) or manually include CSRF tokens in forms and AJAX requests to leverage CodeIgniter's CSRF protection mechanism.

## Attack Surface: [Outdated CodeIgniter Version](./attack_surfaces/outdated_codeigniter_version.md)

*   **Description:** Running an outdated version of CodeIgniter with known security vulnerabilities.
*   **CodeIgniter Contribution:**  CodeIgniter, like any software, has vulnerabilities that are discovered and patched over time. Using an outdated version means the application remains vulnerable to *known vulnerabilities specific to older CodeIgniter versions*.
*   **Example:** A publicly disclosed Remote Code Execution vulnerability exists in CodeIgniter version 3.x. An attacker exploits this vulnerability to gain control of the server.
*   **Impact:** Remote Code Execution, data breaches, denial of service, and a wide range of other impacts depending on the specific vulnerabilities.
*   **Risk Severity:** **Critical** to **High** (depending on the vulnerability)
*   **Mitigation Strategies:**
    *   **Regularly Update CodeIgniter:** Keep CodeIgniter updated to the latest stable version to patch known security vulnerabilities. Follow CodeIgniter's security advisories and release notes.
    *   **Dependency Management:** If using Composer, manage CodeIgniter and its dependencies using Composer and keep them updated.

