# Threat Model Analysis for getgrav/grav

## Threat: [Plugin Remote Code Execution (RCE) via Unvalidated Input](./threats/plugin_remote_code_execution__rce__via_unvalidated_input.md)

*   **Threat:** Plugin Remote Code Execution (RCE) via Unvalidated Input

    *   **Description:** An attacker exploits a vulnerability in a third-party Grav plugin that doesn't properly sanitize or validate user-supplied input. The attacker crafts a malicious request (e.g., a form submission, a URL parameter) containing PHP code, which the plugin then executes. This could be due to insecure use of `eval()`, `include()`, `require()`, or similar functions, or improper handling of file uploads.
    *   **Impact:** Complete server compromise. The attacker gains full control over the web server and can execute arbitrary commands, steal data, install malware, and pivot to other systems.
    *   **Grav Component Affected:** A specific, vulnerable third-party plugin.  The vulnerability lies within the plugin's PHP code (e.g., a controller, a helper function, or a Twig extension).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Plugin Selection:** Only install plugins from trusted sources and with a strong security track record.
        *   **Code Review:** If possible, review the plugin's source code for insecure input handling practices before installation.
        *   **Regular Updates:** Keep the plugin updated to the latest version to patch any known vulnerabilities.
        *   **Input Validation & Sanitization (Developer):** Plugin developers *must* rigorously validate and sanitize all user-supplied input before using it in any potentially dangerous context. Use appropriate PHP functions for escaping and filtering data.
        *   **Web Application Firewall (WAF):** A WAF can help detect and block malicious requests, but it's not a substitute for secure coding.

## Threat: [Direct File Modification via Compromised FTP/SFTP (Impacting Grav Files)](./threats/direct_file_modification_via_compromised_ftpsftp__impacting_grav_files_.md)

*   **Threat:** Direct File Modification via Compromised FTP/SFTP (Impacting Grav Files)

    *   **Description:** An attacker gains access to the server's file system and *directly modifies Grav's files*.  This is distinct from general file system compromise because the *target* is the Grav installation. The attacker injects malicious code into Markdown files (`.md`), PHP files (within plugins or themes), or configuration files (`.yaml`).  The compromised FTP/SFTP account, while a general vulnerability, is the *means* to the Grav-specific threat.
    *   **Impact:** RCE, site defacement, data modification/deletion, complete site compromise. The attacker can effectively take full control of the website.
    *   **Grav Component Affected:** Any file within the Grav installation, including Markdown files (`user/pages/`), PHP files (within `user/plugins/`, `user/themes/`, or even `system/` if write permissions are misconfigured), and configuration files (`user/config/`).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Strong Authentication:** Use strong, unique passwords for all FTP/SFTP accounts.  Prefer SSH keys over passwords for SSH access.
        *   **Restricted Access:** Limit FTP/SFTP access to only authorized users and IP addresses.
        *   **File System Permissions:** Implement strict file system permissions. The web server user should only have write access to the necessary directories (e.g., `user/pages/`, `user/data/`, `cache/`, `logs/`).  Other directories should be read-only for the web server user.
        *   **File Integrity Monitoring:** Use a file integrity monitoring system (e.g., a security plugin, Tripwire, AIDE) to detect unauthorized file changes.
        *   **Regular Backups:** Maintain frequent, off-site backups to allow for recovery from file tampering.

## Threat: [Admin Panel Brute-Force Attack](./threats/admin_panel_brute-force_attack.md)

*   **Threat:** Admin Panel Brute-Force Attack

    *   **Description:** An attacker attempts to guess the password for a Grav admin account by repeatedly submitting login attempts with different username/password combinations. This targets Grav's built-in authentication.
    *   **Impact:** Unauthorized access to the Grav admin panel, leading to complete site compromise. The attacker can modify content, install malicious plugins, change configuration settings, and potentially gain access to the server.
    *   **Grav Component Affected:** The Grav admin panel login functionality (specifically, the authentication logic within `system/src/Grav/Common/User/User.php` and related files, although direct modification of these files is not the attack vector).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Strong Passwords:** Enforce strong, unique passwords for all admin accounts.
        *   **Two-Factor Authentication (2FA):** Implement 2FA for the Grav admin panel (available via plugins).
        *   **Rate Limiting/Account Lockout:** Use a plugin (e.g., "Login" plugin with appropriate configuration) or web server configuration to limit login attempts and lock out accounts after multiple failed attempts.
        *   **IP Restriction:** If feasible, restrict access to the admin panel to specific IP addresses.

## Threat: [Unpatched Grav Core Vulnerability](./threats/unpatched_grav_core_vulnerability.md)

*   **Threat:**  Unpatched Grav Core Vulnerability

    *   **Description:** An attacker exploits a known security vulnerability in an outdated version of the Grav *core*.  This is a direct threat to Grav itself.
    *   **Impact:** Varies depending on the specific vulnerability, but could range from information disclosure to RCE.
    *   **Grav Component Affected:** The Grav core itself (files within the `system/` directory). The specific vulnerable component depends on the nature of the vulnerability (e.g., a specific class, function, or template).
    *   **Risk Severity:** High to Critical (depending on the vulnerability)
    *   **Mitigation Strategies:**
        *   **Regular Updates:** Keep the Grav core updated to the latest stable release.  Grav's admin panel provides update notifications.
        *   **Security Advisories:** Monitor Grav's security advisories and announcements for information about newly discovered vulnerabilities.
        *   **Staging Environment:** Test updates in a staging environment before deploying them to the production site.

## Threat: [Twig Template Injection in a Custom Theme or Plugin](./threats/twig_template_injection_in_a_custom_theme_or_plugin.md)

* **Threat:** Twig Template Injection in a Custom Theme or Plugin

    * **Description:** If a custom theme or plugin uses user-supplied data directly within Twig templates without proper escaping, an attacker could inject malicious Twig code. This is similar to XSS, but specific to the Twig templating engine *within Grav*. While Grav's core and well-written plugins should handle this correctly, custom code might introduce vulnerabilities.
    * **Impact:**  Potentially RCE (if the attacker can execute PHP code through Twig), data leakage, or manipulation of the rendered output.
    * **Grav Component Affected:**  A custom Twig template within a theme (`user/themes/yourtheme/templates/`) or a plugin that uses Twig rendering.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **Auto-Escaping:** Ensure that Twig's auto-escaping feature is enabled (it usually is by default).
        * **Manual Escaping:** If you need to output raw HTML, use Twig's `raw` filter *very* carefully and only after thoroughly sanitizing the input.
        * **Context-Specific Escaping:** Use the appropriate escaping filter for the context (e.g., `escape('html')`, `escape('js')`, `escape('css')`, `escape('url')`).
        * **Code Review:** Carefully review any custom Twig templates for potential injection vulnerabilities.
        * **Developer Best Practices:** Developers should be familiar with Twig's security guidelines and avoid using user input directly in templates without proper escaping.

