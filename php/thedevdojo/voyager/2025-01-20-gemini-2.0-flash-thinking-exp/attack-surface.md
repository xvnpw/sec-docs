# Attack Surface Analysis for thedevdojo/voyager

## Attack Surface: [Admin Authentication Bypass/Brute-Force](./attack_surfaces/admin_authentication_bypassbrute-force.md)

* **Description:** Attackers attempt to bypass the login mechanism or guess admin credentials to gain unauthorized access to the Voyager admin panel.
* **How Voyager Contributes:** Voyager provides a dedicated login route and form, making it a direct target for authentication attacks. Default credentials (if not changed) are a significant vulnerability.
* **Example:** An attacker uses a password cracking tool to try common password combinations against the `/admin/login` route.
* **Impact:** Full compromise of the admin panel, allowing attackers to manage data, users, and potentially execute arbitrary code.
* **Risk Severity:** Critical
* **Mitigation Strategies:**
    * Change Default Credentials: Immediately change the default username and password during installation.
    * Implement Strong Password Policies: Enforce strong, unique passwords for admin accounts.
    * Enable Multi-Factor Authentication (MFA): Add an extra layer of security beyond username and password.
    * Implement Account Lockout Policies:  Temporarily lock accounts after a certain number of failed login attempts.
    * Rate Limiting on Login Attempts:  Limit the number of login attempts from a single IP address within a specific timeframe.

## Attack Surface: [SQL Injection via Database Management Interface](./attack_surfaces/sql_injection_via_database_management_interface.md)

* **Description:** Attackers inject malicious SQL code through the Voyager's database management tools to manipulate or extract data from the underlying database.
* **How Voyager Contributes:** Voyager provides an interface to execute raw SQL queries or interact with the database schema. If input is not properly sanitized, it can be exploited for SQL injection.
* **Example:** An attacker uses the "Database" section in Voyager to execute a crafted SQL query that drops a critical table or extracts sensitive user data.
* **Impact:** Data breach, data corruption, denial of service, potential for remote code execution depending on database privileges.
* **Risk Severity:** Critical
* **Mitigation Strategies:**
    * Restrict Access to Database Management: Limit access to the "Database" section to only highly trusted administrators.
    * Input Sanitization and Validation:  Ensure all user input within the database management interface is thoroughly sanitized and validated before being used in SQL queries.
    * Use Parameterized Queries (if custom queries are allowed):  This prevents SQL injection by treating user input as data, not executable code.
    * Regular Security Audits:  Review the database management interface for potential vulnerabilities.

## Attack Surface: [Unrestricted File Upload leading to Remote Code Execution](./attack_surfaces/unrestricted_file_upload_leading_to_remote_code_execution.md)

* **Description:** Attackers upload malicious files (e.g., PHP scripts, web shells) through Voyager's media manager, which can then be executed on the server.
* **How Voyager Contributes:** Voyager's media manager allows file uploads. If proper restrictions on file types and content are not in place, it becomes a vector for malicious uploads.
* **Example:** An attacker uploads a PHP script disguised as an image through the media manager. They then access this script directly via its URL, executing arbitrary code on the server.
* **Impact:** Full server compromise, data breach, website defacement, malware distribution.
* **Risk Severity:** Critical
* **Mitigation Strategies:**
    * Restrict Allowed File Types:  Configure Voyager to only allow specific, safe file types for upload.
    * Content Verification: Implement server-side checks to verify the actual content of uploaded files, not just the extension.
    * Rename Uploaded Files:  Rename uploaded files to prevent direct execution.
    * Store Uploaded Files Outside the Webroot:  Store uploaded files in a directory that is not directly accessible via the web server.
    * Disable Script Execution in Upload Directories: Configure the web server to prevent the execution of scripts in the upload directory.

## Attack Surface: [Cross-Site Scripting (XSS) via BREAD Customization or Menu Builder](./attack_surfaces/cross-site_scripting__xss__via_bread_customization_or_menu_builder.md)

* **Description:** Attackers inject malicious scripts into Voyager's BREAD (CRUD builder) configurations or menu items, which are then executed in the browsers of other administrators.
* **How Voyager Contributes:** Voyager allows customization of BREAD interfaces and menu items, potentially allowing the inclusion of unsanitized HTML or JavaScript.
* **Example:** An attacker adds a malicious JavaScript payload within a BREAD field label or a menu item's name. When another admin views this section, the script executes, potentially stealing their session cookies.
* **Impact:** Session hijacking, account takeover, defacement of the admin panel, redirection to malicious sites.
* **Risk Severity:** High
* **Mitigation Strategies:**
    * Input Sanitization:  Thoroughly sanitize all user input when creating or modifying BREAD configurations and menu items.
    * Output Encoding:  Encode output when displaying BREAD data and menu items in the admin panel to prevent the execution of malicious scripts.
    * Content Security Policy (CSP): Implement a strong CSP to restrict the sources from which the browser can load resources, mitigating XSS attacks.

## Attack Surface: [Mass Assignment Vulnerabilities via BREAD Forms](./attack_surfaces/mass_assignment_vulnerabilities_via_bread_forms.md)

* **Description:** Attackers manipulate form submissions in Voyager's BREAD interfaces to modify database fields that were not intended to be directly editable.
* **How Voyager Contributes:** Voyager automatically generates forms based on database models. If models are not properly protected with `$fillable` or `$guarded` attributes, attackers can inject data into unintended fields.
* **Example:** An attacker modifies the HTML of a BREAD edit form to include a hidden field for an `is_admin` column and sets it to `true`, potentially granting themselves administrative privileges.
* **Impact:** Privilege escalation, data manipulation, unauthorized access to sensitive information.
* **Risk Severity:** High
* **Mitigation Strategies:**
    * Properly Define `$fillable` and `$guarded` Attributes:  Explicitly define which model attributes can be mass-assigned in your Laravel models.
    * Input Validation:  Validate all input received from BREAD forms on the server-side to ensure only expected data is being processed.
    * Review BREAD Configurations:  Carefully review the generated forms and ensure they only expose the necessary fields for editing.

## Attack Surface: [Exposure of Sensitive Information via Settings Management](./attack_surfaces/exposure_of_sensitive_information_via_settings_management.md)

* **Description:** Sensitive information, such as API keys or database credentials, might be stored and accessible through Voyager's settings management interface.
* **How Voyager Contributes:** Voyager provides a centralized location to manage application settings, which could inadvertently store sensitive data. If access controls are weak, this information could be exposed.
* **Example:** An attacker gains access to the Voyager settings and finds API keys or database credentials stored in plain text, allowing them to compromise external services or the database.
* **Impact:** Data breach, compromise of external services, unauthorized access to critical resources.
* **Risk Severity:** High
* **Mitigation Strategies:**
    * Store Sensitive Information Securely: Avoid storing sensitive information directly in Voyager's settings. Use environment variables or dedicated secret management solutions.
    * Restrict Access to Settings Management: Limit access to the "Settings" section to only highly trusted administrators.
    * Encrypt Sensitive Settings (if stored in Voyager): If sensitive data must be stored in Voyager's settings, ensure it is properly encrypted.

## Attack Surface: [Remote Code Execution via Code Editor (if enabled)](./attack_surfaces/remote_code_execution_via_code_editor__if_enabled_.md)

* **Description:** Attackers exploit the built-in code editor (if enabled) to directly modify application code, leading to arbitrary code execution on the server.
* **How Voyager Contributes:** Voyager offers an optional code editor feature for directly editing files within the admin panel. If not properly secured, this is a direct path to RCE.
* **Example:** An attacker gains access to the Voyager admin panel and uses the code editor to modify a core application file, injecting malicious code that is then executed.
* **Impact:** Full server compromise, data breach, website defacement, malware distribution.
* **Risk Severity:** Critical
* **Mitigation Strategies:**
    * Disable the Code Editor:  Unless absolutely necessary, disable the built-in code editor feature. This is the most effective mitigation.
    * Restrict Access to Code Editor: If the code editor is required, strictly limit access to only highly trusted administrators and implement strong authentication and authorization measures.
    * Regular Security Audits:  Monitor the code editor's usage and access logs for suspicious activity.

