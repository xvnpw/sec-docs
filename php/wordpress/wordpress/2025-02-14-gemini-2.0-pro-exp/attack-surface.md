# Attack Surface Analysis for wordpress/wordpress

## Attack Surface: [Unpatched Core, Plugins, or Themes](./attack_surfaces/unpatched_core__plugins__or_themes.md)

*   **Description:**  Exploitation of known vulnerabilities in outdated WordPress core software, plugins, or themes.
*   **How WordPress Contributes:** WordPress's modular architecture (core, plugins, themes) creates multiple points of potential vulnerability.  The large number of third-party plugins and themes increases the likelihood of unpatched vulnerabilities.  WordPress's popularity makes it a frequent target.
*   **Example:** An attacker uses a publicly known exploit for an outdated version of a popular plugin to inject malicious code and gain control of the website.
*   **Impact:** Complete site compromise, data theft, defacement, malware distribution, SEO poisoning.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Automated Updates:** Enable automatic updates for core, plugins, and themes (especially minor and security releases).
    *   **Staging Environment:** Test major updates in a staging environment before deploying to production.
    *   **Vulnerability Scanning:** Regularly scan for known vulnerabilities using security plugins or external tools.
    *   **Plugin/Theme Selection:** Choose reputable, actively maintained plugins and themes.
    *   **Remove Unused Components:** Deactivate and delete any unused plugins and themes.

## Attack Surface: [Brute-Force Login Attacks (wp-login.php)](./attack_surfaces/brute-force_login_attacks__wp-login_php_.md)

*   **Description:**  Automated attempts to guess usernames and passwords by repeatedly trying different combinations.
*   **How WordPress Contributes:** WordPress has a well-known default login page (`wp-login.php`), making it a predictable target for brute-force attacks.  The standard login mechanism is exposed by default.
*   **Example:** An attacker uses a botnet to try thousands of common username/password combinations against `wp-login.php`.
*   **Impact:** Unauthorized access to the WordPress dashboard, leading to complete site control.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Limit Login Attempts:** Use plugins (e.g., Limit Login Attempts Reloaded) or server-level configurations to block IPs after a certain number of failed attempts.
    *   **Strong Passwords:** Enforce strong, unique passwords for all user accounts.
    *   **Two-Factor Authentication (2FA):** Implement 2FA for all users, especially administrators.
    *   **Rename Login URL:** Change the default `wp-login.php` URL using a plugin (e.g., WPS Hide Login).
    *   **CAPTCHA:** Use a CAPTCHA on the login form to deter automated bots.

## Attack Surface: [XML-RPC Attacks](./attack_surfaces/xml-rpc_attacks.md)

*   **Description:**  Exploitation of the XML-RPC interface to bypass login restrictions, perform brute-force attacks, or cause denial-of-service.
*   **How WordPress Contributes:** WordPress includes XML-RPC functionality by default, which can be abused if not properly secured.  This is a WordPress-specific API.
*   **Example:** An attacker uses XML-RPC's `system.multicall` method to try thousands of password combinations in a single request, bypassing typical login attempt limits.
*   **Impact:** Brute-force login success, denial-of-service, potential for other exploits.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Disable XML-RPC:** If not needed, disable XML-RPC completely using a plugin (e.g., Disable XML-RPC) or server-level configuration (.htaccess).
    *   **Restrict Access:** If XML-RPC is required, restrict access to specific IP addresses or use a plugin to limit its functionality.
    *   **WAF Rules:** Implement Web Application Firewall (WAF) rules to block malicious XML-RPC requests.

## Attack Surface: [Unprotected Uploads Directory (Script Execution)](./attack_surfaces/unprotected_uploads_directory__script_execution_.md)

*   **Description:**  Attackers uploading and executing malicious scripts (e.g., PHP files) in the `wp-content/uploads` directory.
*   **How WordPress Contributes:** WordPress allows users to upload files, and the default uploads directory (`wp-content/uploads`) is a known location.  WordPress's handling of uploads needs specific security configurations.
*   **Example:** An attacker uploads a PHP shell script disguised as an image file and then accesses it directly via its URL to gain control of the server.
*   **Impact:** Remote code execution, complete site compromise.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **.htaccess Protection:** Use an `.htaccess` file in the `uploads` directory to prevent the execution of scripts (e.g., `php_flag engine off` for PHP files).
    *   **File Type Validation:** Implement strict server-side file type validation, checking the actual file content, not just the extension.
    *   **Rename Uploaded Files:** Rename uploaded files to random, unpredictable names.
    *   **Content-Type Headers:** Serve uploaded files with the correct `Content-Type` headers to prevent browser misinterpretation.

## Attack Surface: [Exposed wp-config.php](./attack_surfaces/exposed_wp-config_php.md)

*   **Description:** The `wp-config.php` file contains sensitive database credentials and other configuration settings. If exposed, attackers gain full control.
*   **How WordPress Contributes:** This file is essential for WordPress operation, and its default location is well-known. It's a core WordPress file.
*   **Example:** An attacker finds `wp-config.php` accessible via a misconfigured web server and obtains the database credentials.
*   **Impact:** Complete site compromise, database access, data theft.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Move wp-config.php:** Move `wp-config.php` one level above the web root (if possible).
    *   **Server Configuration:** Ensure your web server is configured to prevent direct access to `wp-config.php` (usually handled by default, but verify).
    *   **File Permissions:** Set restrictive file permissions on `wp-config.php` (e.g., 600 or 640).

