# Attack Surface Analysis for bcit-ci/codeigniter

## Attack Surface: [Exposed Configuration Files](./attack_surfaces/exposed_configuration_files.md)

Description: Sensitive configuration files, such as `config.php` and `database.php`, containing database credentials, encryption keys, and other application secrets, are accessible to unauthorized users.
CodeIgniter Contribution: CodeIgniter relies on these files for core application configuration. The default project structure places these files within the application directory, making them potentially accessible if not properly secured.
Example: An attacker exploits a directory traversal vulnerability to access `example.com/application/config/database.php` and retrieves database credentials, leading to database compromise.
Impact: Critical. Full database compromise, application takeover, data breaches, complete information disclosure.
Risk Severity: Critical
Mitigation Strategies:
*   Restrict File Permissions: Set strict file permissions on configuration files, ensuring only the web server user can read them.
*   Move Configuration Directory (Advanced):  If feasible, move the entire `application/config` directory outside the web root.
*   Web Server Configuration: Configure the web server (e.g., Apache, Nginx) to explicitly deny access to the `application/config` directory and its contents.
*   Environment Variables: Utilize environment variables to store sensitive configuration data instead of directly embedding them in configuration files.

## Attack Surface: [Debug Mode Enabled in Production](./attack_surfaces/debug_mode_enabled_in_production.md)

Description: CodeIgniter's debug mode, intended for development and troubleshooting, remains enabled in a production (live) environment.
CodeIgniter Contribution: CodeIgniter's `ENVIRONMENT` constant in `index.php` controls debug mode.  Developers must explicitly set it to `'production'` for live sites, but forgetting to do so is a common misconfiguration.
Example: A user encounters an application error on a production website. With debug mode enabled, CodeIgniter displays a detailed error page revealing file paths, database query details, and potentially sensitive internal application information.
Impact: High. Information disclosure, path disclosure aiding further attacks, revealing application logic and database structure, potentially leading to more targeted attacks.
Risk Severity: High
Mitigation Strategies:
*   Set `ENVIRONMENT` to `production`:  Ensure the `ENVIRONMENT` constant in `index.php` is set to `'production'` before deploying to any live environment.
*   Custom Error Handling: Implement custom error handling to log errors securely without exposing sensitive details to end-users in production.
*   Automated Deployment Checks: Include automated checks in deployment pipelines to verify that debug mode is disabled in production configurations.

## Attack Surface: [Insecure Session Management Configuration](./attack_surfaces/insecure_session_management_configuration.md)

Description: CodeIgniter's session management is configured with insecure settings, making sessions vulnerable to hijacking or fixation attacks.
CodeIgniter Contribution: CodeIgniter provides session libraries and configuration options in `config.php`.  Default settings might not be secure enough for production, and developers need to explicitly configure secure options.
Example: Session cookies are not set with the `HttpOnly` and `Secure` flags. An attacker performs a Cross-Site Scripting (XSS) attack to steal the session cookie and impersonate a legitimate user.
Impact: High. Session hijacking, unauthorized access to user accounts, account takeover, ability to perform actions as the compromised user, data manipulation.
Risk Severity: High
Mitigation Strategies:
*   Configure Secure Session Settings in `config.php`:
    *   `sess_cookie_secure`: Set to `TRUE` to ensure cookies are only sent over HTTPS.
    *   `sess_http_only`: Set to `TRUE` to prevent client-side JavaScript access to session cookies.
    *   `sess_regenerate_destroy`: Set to `TRUE` to regenerate session IDs upon each page load or after a certain time, reducing session fixation risks.
    *   `sess_match_ip`: Consider setting to `TRUE` (with caution as it can cause issues for users with dynamic IPs) to further restrict session validity to the originating IP address.
    *   Use a strong and unique `encryption_key` for session data encryption.
*   Choose Secure Session Storage: Consider using database or Redis session storage instead of file-based sessions for improved security and scalability.

## Attack Surface: [Missing or Misconfigured CSRF Protection](./attack_surfaces/missing_or_misconfigured_csrf_protection.md)

Description: Cross-Site Request Forgery (CSRF) protection, designed to prevent unauthorized actions on behalf of authenticated users, is either not enabled or improperly configured in the CodeIgniter application.
CodeIgniter Contribution: CodeIgniter provides built-in CSRF protection that is disabled by default. Developers must explicitly enable it in `config.php` and use CodeIgniter's form helpers or manually include CSRF tokens in forms.
Example: CSRF protection is disabled. An attacker crafts a malicious website that contains a form submitting to the vulnerable CodeIgniter application. When a logged-in user visits the attacker's website, the form is automatically submitted, performing actions on the CodeIgniter application (e.g., changing user email, transferring funds) without the user's consent or knowledge.
Impact: High. Unauthorized actions performed on behalf of legitimate users, data manipulation, state changes, potential financial loss, reputational damage.
Risk Severity: High
Mitigation Strategies:
*   Enable CSRF Protection in `config.php`: Set `$config['csrf_protection'] = TRUE;`.
*   Use CodeIgniter Form Helpers or CSRF Tokens: Utilize CodeIgniter's form helpers (e.g., `form_open()`) which automatically include CSRF tokens, or manually include CSRF tokens using `get_csrf_token_name()` and `get_csrf_hash()` in all forms that modify data.
*   Test CSRF Protection: Thoroughly test that CSRF protection is functioning correctly by attempting to submit forms from external sites without valid CSRF tokens.
*   AJAX CSRF Handling: If using AJAX, ensure CSRF tokens are correctly included in AJAX requests (e.g., in headers or request data) and validated on the server-side.

