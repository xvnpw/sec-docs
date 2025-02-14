# Threat Model Analysis for drupal/core

## Threat: [Unpatched Core Vulnerability Exploitation](./threats/unpatched_core_vulnerability_exploitation.md)

*   **Description:** An attacker exploits a known, publicly disclosed vulnerability in Drupal Core that has not been patched. The attacker might use a publicly available exploit or develop their own based on the vulnerability details. They could inject malicious code, modify data, or gain full control of the site. This is the most direct and severe threat to Drupal Core itself.
*   **Impact:** Complete site compromise, data breach (including user data, content, and configuration), defacement, malware distribution, potential use of the server for malicious purposes (e.g., sending spam, launching attacks on other systems).
*   **Affected Core Component:** Varies depending on the specific vulnerability. Could affect any core module, subsystem (e.g., Form API, Database API, User authentication), or core file.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Immediate Patching:** Apply security updates released by the Drupal Security Team as soon as they are available.  Prioritize critical and high-severity updates.
    *   **Automated Updates (with Caution):** Consider using automated update tools (e.g., Drush, Composer) but *always* test updates thoroughly in a staging environment before deploying to production.  Automated updates without testing can break the site.
    *   **Security Advisories:** Subscribe to the Drupal Security Team's mailing list and RSS feed to receive timely notifications of vulnerabilities.
    *   **Web Application Firewall (WAF):** A WAF can help block some exploit attempts, but it's not a substitute for patching.

## Threat: [Misconfiguration of Input/Output Filters (Text Formats) *leading to XSS within Core*](./threats/misconfiguration_of_inputoutput_filters__text_formats__leading_to_xss_within_core.md)

*   **Description:** While contributed modules can exacerbate this, Drupal Core's text format system itself, if misconfigured, allows an attacker (typically an authenticated user with elevated, but not necessarily administrative, privileges) to inject malicious JavaScript (XSS) through core content creation mechanisms. This is distinct from a module introducing XSS; this is about misusing *core's* filtering.
*   **Impact:** Cross-site scripting (XSS) attacks, potentially leading to session hijacking, defacement, or further privilege escalation if an administrator's session is compromised. The impact is limited by the context of the XSS, but within core, it can be significant.
*   **Affected Core Component:** Filter module, Text Formats and Editors system (`filter.format.*.yml`). Specifically, the configuration of filters and allowed HTML tags within core text formats.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Restrict "Full HTML":**  Never allow untrusted users to use the "Full HTML" text format. This is a core configuration issue.
    *   **Configure "Filtered HTML":**  Carefully configure the "Filtered HTML" text format (and any custom formats) to allow only safe HTML tags and attributes.  Review the default settings and tighten them as needed.
    *   **Use a Dedicated XSS Filter:**  Ensure that a robust XSS filter (like the one provided by Drupal Core) is enabled and properly configured. This is a core feature.
    *   **Input Validation:** While all input should be validated, focus on ensuring that core's input validation mechanisms for text formats are correctly applied.
    *   **Output Encoding:**  Always encode output properly to prevent XSS vulnerabilities. Drupal Core generally handles this, but configuration errors can break it.

## Threat: [Insecure Direct Object Reference (IDOR) in Core APIs](./threats/insecure_direct_object_reference__idor__in_core_apis.md)

*   **Description:** An attacker manipulates parameters in *core* API requests (e.g., node IDs, user IDs in REST or JSON:API endpoints provided by *core*) to access or modify data they should not have access to. This occurs when Drupal *core's* access control checks are insufficient or bypassed. This is specifically about vulnerabilities in core's API endpoints, not custom code or contributed modules.
*   **Impact:** Unauthorized data access, data modification, potential for privilege escalation (if, for example, user account data can be modified).
*   **Affected Core Component:** REST API (core module), JSON:API (core module), potentially other core API endpoints.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Robust Access Control:** Ensure that all *core* API endpoints perform thorough access control checks. Use Drupal's built-in access control system (e.g., `entity_access()`, `$entity->access()`). This is about ensuring core's mechanisms are used correctly.
    *   **Input Validation:** Validate all user-supplied input to core API endpoints, including object IDs, to ensure they are valid and within expected ranges.
    *   **Don't Rely on Obscurity:** Do not rely on the obscurity of object IDs to prevent unauthorized access.
    *   **Testing:** Thoroughly test *core* API endpoints for IDOR vulnerabilities using tools like Burp Suite or OWASP ZAP.

## Threat: [Weak or Default Database Credentials](./threats/weak_or_default_database_credentials.md)

* **Description:** The attacker gains access to the Drupal database because the database user account has a weak password or uses the default credentials provided by the database software. While not *strictly* a core code vulnerability, the `settings.php` file, managed by core, is where these credentials reside, making it a core-related configuration issue.
    * **Impact:** Complete database compromise, data breach, potential for site takeover (if the attacker can modify the database to create an administrative user).
    * **Affected Core Component:** Database connection settings in `settings.php` (a core-managed file).
    * **Risk Severity:** Critical
    * **Mitigation Strategies:**
        * **Strong Passwords:** Use strong, unique passwords for all database user accounts.
        * **Change Default Credentials:** Immediately change any default database credentials after installation.
        * **Database User Permissions:** Grant the Drupal database user only the minimum necessary permissions (e.g., SELECT, INSERT, UPDATE, DELETE on the Drupal database). Do not grant administrative privileges to the Drupal database user.
        * **Separate Database User:** Use a separate database user account for Drupal, distinct from any other applications or services.

## Threat: [File Upload Vulnerabilities (Unrestricted File Upload) *within Core's File Handling*](./threats/file_upload_vulnerabilities__unrestricted_file_upload__within_core's_file_handling.md)

*   **Description:** An attacker uploads a malicious file (e.g., a PHP script) through a *core* file upload field (e.g., a core image field or file field on a content type) that is misconfigured. This is about the *core* file handling mechanisms being improperly configured, not a vulnerability in a contributed module.
*   **Impact:** Remote code execution, complete site compromise, data breach.
*   **Affected Core Component:** File module, file upload fields provided by core, file system handling within core.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **File Extension Whitelisting:** *Strictly* restrict file uploads to a specific, minimal list of allowed file extensions (e.g., `.jpg`, `.png`, `.pdf`). *Never* allow executable file extensions (e.g., `.php`, `.exe`, `.sh`). This is a core configuration setting.
    *   **File Content Validation:** Validate the content of uploaded files to ensure they match the expected file type. For example, check the MIME type and file signature. Drupal Core provides functions for this; ensure they are used.
    *   **Store Uploaded Files Outside the Web Root:** Store uploaded files in a directory that is not directly accessible from the web. This is a best practice, and core provides mechanisms to manage this.
    *   **Rename Uploaded Files:** Rename uploaded files to prevent attackers from guessing the file name and accessing it directly. Core provides options for this.
    *   **Use a Secure File Upload Library:** Drupal Core *provides* secure file upload functionality; the key is to configure and use it correctly.

