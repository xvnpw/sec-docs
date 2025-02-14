# Attack Surface Analysis for bcit-ci/codeigniter

## Attack Surface: [Unvalidated Input (Beyond XSS) - Leveraging CodeIgniter's Input Class Inadequately](./attack_surfaces/unvalidated_input__beyond_xss__-_leveraging_codeigniter's_input_class_inadequately.md)

*   **Description:**  Failure to perform comprehensive input validation beyond basic XSS filtering provided by CodeIgniter's `input` class, leading to injection vulnerabilities (SQLi, command injection) and logic errors.  This is *specifically* about not using CodeIgniter's validation tools effectively.
*   **CodeIgniter Contribution:**  The `input` class offers basic filtering (e.g., `$this->input->post('something', TRUE)` for XSS), but *does not* enforce data types, lengths, formats, or business rules. Developers must *actively* use the Form Validation library or custom validation, and often fail to do so comprehensively.
*   **Example:**  A developer uses `$this->input->post('user_id')` without further validation, assuming it will be an integer. An attacker provides `1; DROP TABLE users;--`, leading to SQL injection.
*   **Impact:**  Data corruption, data loss, unauthorized data access, complete system compromise (depending on the injection type).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Mandatory Use of Form Validation Library:**  Enforce the use of CodeIgniter's Form Validation library for *all* form fields and any user-supplied data. Define strict rules for data types, lengths, formats, and allowed values.
    *   **Prepared Statements/Query Builder (with Caution):**  *Always* use CodeIgniter's Active Record or Query Builder for database interactions.  However, be aware that even these can be misused; avoid direct concatenation of user input within query building methods.
    *   **Input Sanitization (Type-Specific):**  Sanitize input *after* validation, using appropriate functions for the expected data type (e.g., `intval()` for integers, `floatval()` for floats). This is a secondary defense.
    *   **Whitelist Validation:**  Whenever possible, validate against a *whitelist* of allowed values, rather than attempting to blacklist malicious input.

## Attack Surface: [Over-Reliance on CodeIgniter's XSS Filter (and Ignoring Output Encoding)](./attack_surfaces/over-reliance_on_codeigniter's_xss_filter__and_ignoring_output_encoding_.md)

*   **Description:**  The incorrect assumption that CodeIgniter's built-in XSS filter (`$this->input->post('something', TRUE)` or the global filter) provides complete XSS protection, leading to a neglect of proper output encoding.
*   **CodeIgniter Contribution:**  CodeIgniter provides an XSS filter, but its documentation and common usage patterns can lead developers to believe it's a complete solution, which it is not. The existence of the filter can create a false sense of security.
*   **Example:**  A developer uses `$this->input->post('comment', TRUE)` to filter user comments and then displays them directly in an HTML page without using `html_escape()`. An attacker crafts a bypass for the filter, injecting malicious JavaScript.
*   **Impact:**  Session hijacking, defacement, phishing, malware distribution.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Prioritize Output Encoding:**  *Always* use context-appropriate output encoding (e.g., `html_escape()` for HTML, `htmlspecialchars()` in attributes) when displaying *any* user-supplied data, *regardless* of whether the input was filtered. This is the *primary* defense against XSS.
    *   **Selective XSS Filtering:**  Use the CodeIgniter XSS filter selectively, only where it's deemed necessary, and *never* globally.  Understand its limitations.
    *   **Content Security Policy (CSP):** Implement a strong CSP as a defense-in-depth measure to limit the impact of successful XSS attacks.

## Attack Surface: [Unrestricted File Uploads (Misusing CodeIgniter's File Uploading Class)](./attack_surfaces/unrestricted_file_uploads__misusing_codeigniter's_file_uploading_class_.md)

*   **Description:**  Improper configuration of CodeIgniter's File Uploading Class, allowing attackers to upload malicious files.
*   **CodeIgniter Contribution:**  The File Uploading Class provides the *mechanism* for file uploads, but its security depends entirely on the developer's configuration choices.  The default settings are not secure.
*   **Example:**  A developer uses the File Uploading Class but fails to set `$config['allowed_types']`. An attacker uploads a PHP shell script (e.g., `shell.php`) and executes it on the server.
*   **Impact:**  Complete system compromise, data theft, malware distribution.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strictly Limit Allowed File Types:**  Use `$config['allowed_types']` to define a *whitelist* of allowed file extensions (e.g., `gif|jpg|png`).  Never rely on blacklisting.
    *   **Sanitize File Names (Using CodeIgniter's Helper):**  *Always* use `$this->security->sanitize_filename()` to remove potentially dangerous characters from uploaded file names.  Strongly consider generating unique, random file names on the server.
    *   **Enforce File Size Limits:**  Use `$config['max_size']` to prevent denial-of-service attacks via excessively large file uploads.
    *   **Store Files Outside Web Root:**  Store uploaded files in a directory that is *not* directly accessible from the web. This is crucial.
    *   **Validate File Content (Beyond Extension):**  If possible, validate the *actual content* of the file, not just the extension (e.g., using a library to check image headers for image uploads).

## Attack Surface: [Session Fixation (Due to CodeIgniter's Default Behavior)](./attack_surfaces/session_fixation__due_to_codeigniter's_default_behavior_.md)

*   **Description:**  Vulnerability to session fixation attacks because CodeIgniter does *not* automatically regenerate the session ID after a user successfully authenticates.
*   **CodeIgniter Contribution:**  CodeIgniter's session management library provides the functionality, but the *responsibility* for regenerating the session ID after login rests solely with the developer.  This is a common oversight.
*   **Example:**  An attacker sets a user's session ID to a known value (e.g., via a crafted URL).  When the user logs in, the attacker can then use that same session ID to hijack the user's session.
*   **Impact:**  Session hijacking, unauthorized access to user accounts and data.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Mandatory Session Regeneration:**  *Always* call `$this->session->sess_regenerate()` immediately after a successful user login. This is the single most important mitigation.
    *   **HTTPS Enforcement:**  Ensure the entire application, especially login and session-related pages, uses HTTPS to prevent session ID interception over the network.

## Attack Surface: [Disabled or Misconfigured CSRF Protection (Ignoring CodeIgniter's Built-in Feature)](./attack_surfaces/disabled_or_misconfigured_csrf_protection__ignoring_codeigniter's_built-in_feature_.md)

*   **Description:**  Vulnerability to Cross-Site Request Forgery (CSRF) attacks due to either disabling CodeIgniter's built-in protection or failing to properly include CSRF tokens in forms.
*   **CodeIgniter Contribution:** CodeIgniter *provides* built-in CSRF protection, but it's not enabled by default, and developers must actively use it (either via `form_open()` or manual token inclusion).
*   **Example:** A developer disables CSRF protection (`$config['csrf_protection'] = FALSE;`) or creates forms without using `form_open()` or manually adding the CSRF token. An attacker can then forge requests on behalf of authenticated users.
*   **Impact:** Unauthorized actions performed on behalf of the user (e.g., changing passwords, making purchases, deleting data).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Enable CSRF Protection:** Set `$config['csrf_protection'] = TRUE;` in `config.php`. This is essential.
    *   **Use `form_open()` Consistently:** Use CodeIgniter's `form_open()` helper function to automatically include the CSRF token in all forms. This is the preferred method.
    *   **Manual Token Inclusion (If Necessary):** If `form_open()` cannot be used, manually add the CSRF token to forms using `$this->security->get_csrf_token_name()` and `$this->security->get_csrf_hash()`.
    *   **Token Verification (Automatic):** CodeIgniter automatically verifies the CSRF token on POST requests when protection is enabled. Ensure this verification is not bypassed.

## Attack Surface: [Exposed Database Credentials (Due to Default Configuration File)](./attack_surfaces/exposed_database_credentials__due_to_default_configuration_file_.md)

*   **Description:** Storing database credentials directly within the `database.php` file, which, if misconfigured or if the server is compromised, can lead to credential exposure.
*   **CodeIgniter Contribution:** CodeIgniter, by default, uses the `database.php` file for database configuration. This is a standard practice, but it places the onus on the developer/administrator to secure this file properly.
*   **Example:** An attacker gains read access to the server's file system and obtains the database credentials from `application/config/database.php`.
*   **Impact:** Complete database compromise, data theft, data modification, potential for further system compromise.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Environment Variables (Primary):** Store database credentials (and other sensitive configuration) in *environment variables*, not directly in `database.php`. CodeIgniter can then read these variables.
    *   **Secure Configuration Management:** Use a dedicated, secure configuration management system (e.g., HashiCorp Vault, AWS Secrets Manager, Azure Key Vault) to store and manage sensitive credentials.
    *   **Restrictive File Permissions:** If, for some reason, environment variables or a secrets manager cannot be used, ensure that `database.php` has the *most restrictive file permissions possible* (e.g., readable only by the web server user and no one else). This is a last resort.

