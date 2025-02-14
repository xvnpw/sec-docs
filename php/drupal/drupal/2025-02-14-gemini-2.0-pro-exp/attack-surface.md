# Attack Surface Analysis for drupal/drupal

## Attack Surface: [Unpatched Core/Module Vulnerabilities](./attack_surfaces/unpatched_coremodule_vulnerabilities.md)

*   **Description:** Exploitation of known vulnerabilities in Drupal core or contributed modules due to failure to apply security updates.
*   **How Drupal Contributes:** Drupal's modular architecture and reliance on a vast ecosystem of contributed modules increase the potential for vulnerabilities. The frequent release of security advisories necessitates constant vigilance.  The sheer number of modules used on a typical site expands the attack surface considerably.
*   **Example:** An attacker exploits a known SQL injection vulnerability in a popular contributed module (e.g., a vulnerability similar to those found in Views or other widely-used modules) to gain access to the database.
*   **Impact:** Complete site compromise, data theft, data modification, defacement, malware distribution.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Automated Updates:** Implement automated security updates for Drupal core and contributed modules using tools like `drush updb`, Composer, or Drupal's built-in update manager. Configure automatic email notifications for available updates.
    *   **Security Monitoring:** Subscribe to Drupal security advisories (drupal.org/security) and actively monitor for new vulnerabilities. Use security scanning tools that specifically check for Drupal vulnerabilities.
    *   **Module Selection:** Prioritize well-maintained modules with a good security track record. Minimize the number of modules used. Regularly review installed modules and remove any that are unnecessary or unmaintained.
    *   **Dependency Management:** Use Composer to manage dependencies and keep them updated. Regularly run `composer outdated` and address any outdated packages.
    *   **Staging Environment:** Always test updates in a staging environment before deploying to production.

## Attack Surface: [Misconfigured Module Permissions](./attack_surfaces/misconfigured_module_permissions.md)

*   **Description:** Incorrectly configured permissions within Drupal modules, granting excessive privileges to users or roles.
*   **How Drupal Contributes:** Drupal's granular permission system, while powerful, can be complex to configure correctly. *Modules often introduce their own permissions*, increasing the potential for misconfiguration and making this a Drupal-specific concern.  The interaction between core permissions and module-specific permissions is a key area of risk.
*   **Example:** A module that allows file uploads is configured to grant "upload files" permission to the "authenticated user" role. An attacker registers an account and uploads a malicious PHP file, achieving remote code execution.
*   **Impact:** Privilege escalation, unauthorized access to data or functionality, potential for complete site compromise.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Principle of Least Privilege:** Grant only the minimum necessary permissions to each user role. Avoid granting broad permissions to the "authenticated user" role.  Carefully review the permissions provided by each installed module.
    *   **Regular Permission Audits:** Conduct regular audits of user roles and permissions, paying close attention to permissions introduced by contributed modules.
    *   **Security Reviews:** Perform security reviews of module configurations, focusing on permissions and access control settings.  This should be part of the module selection and update process.
    *   **Testing:** Thoroughly test module functionality with different user roles to ensure that permissions are enforced correctly.

## Attack Surface: [Form API Misuse (CSRF & Form Tampering)](./attack_surfaces/form_api_misuse__csrf_&_form_tampering_.md)

*   **Description:** Improper use of Drupal's Form API, leading to vulnerabilities like Cross-Site Request Forgery (CSRF) or form tampering.
*   **How Drupal Contributes:** While Drupal's Form API *provides* built-in protection against CSRF and form tampering, custom form implementations or contributed modules might *not utilize these features correctly*, or might introduce new forms that bypass standard protections. This makes it a Drupal-specific attack surface.
*   **Example:** A custom module implements a form that allows users to update their profile information. The form does not include a CSRF token. An attacker crafts a malicious link that, when clicked by a logged-in user, changes their email address to the attacker's.
*   **Impact:** Unauthorized actions performed on behalf of a logged-in user, data modification, account takeover.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Use Form API Correctly:** Always use the Form API's built-in validation and sanitization functions. Avoid relying on client-side validation alone.  Ensure all forms that modify data use the Form API.
    *   **CSRF Tokens:** Ensure that all forms that modify data include CSRF tokens (`form_token`). Verify that these tokens are properly validated on the server using `$form_state->get('form_token')`.
    *   **`#access` Property:** Use the `#access` property in form elements to control visibility and prevent unauthorized manipulation.  Restrict access to sensitive form elements based on user roles and permissions.
    *   **Server-Side Validation:** Always perform validation on the server-side, even if client-side validation is also used.

## Attack Surface: [Render API Misuse (XSS)](./attack_surfaces/render_api_misuse__xss_.md)

*   **Description:** Incorrect handling of user-generated content within Drupal's Render API, leading to Cross-Site Scripting (XSS) vulnerabilities.
*   **How Drupal Contributes:** Drupal's Render API is *specifically* responsible for rendering content, and improper output escaping can introduce XSS vulnerabilities, especially in custom themes or modules that override or extend rendering logic.  The interaction between Drupal's rendering pipeline and contributed code is the key risk area.
*   **Example:** A custom module displays user comments without properly escaping them. An attacker posts a comment containing malicious JavaScript code, which is executed in the browsers of other users who view the comment.
*   **Impact:** Session hijacking, data theft, defacement, malware distribution, phishing attacks.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Use `#markup` and `#plain_text` Appropriately:** Use `#markup` for trusted HTML and `#plain_text` for untrusted text. Avoid using `#markup` with user-generated content unless absolutely necessary and after thorough sanitization (e.g., using `\Drupal\Component\Utility\Xss::filter()`).
    *   **Twig Autoescaping:** Ensure that Twig autoescaping is enabled in your theme's `*.info.yml` file (`twig.config: { autoescape: true }`) and used correctly in templates.  Use the `|raw` filter sparingly and only for trusted content.
    *   **Content Security Policy (CSP):** Implement a Content Security Policy (CSP) to mitigate the impact of XSS vulnerabilities by restricting the sources from which scripts can be loaded.
    * **Input filtering:** Use Drupal's built-in input filters and text formats to sanitize user input before it is stored or displayed.

## Attack Surface: [Database API Misuse (SQL Injection)](./attack_surfaces/database_api_misuse__sql_injection_.md)

*   **Description:** Improper use of the database abstraction layer, leading to SQL injection.
*   **How Drupal Contributes:** While Drupal provides a secure database API, direct SQL queries or incorrect usage *within custom modules or themes* can bypass these protections, making this a Drupal-specific concern. The risk is primarily in code that *doesn't* use the provided API correctly.
*   **Example:** A custom module uses `db_query()` with string concatenation to build a SQL query, incorporating user-supplied data without proper escaping.
*   **Impact:** Data theft, data modification, database corruption, potential for complete site compromise.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Use Database API:** Always use the Drupal database API (e.g., `\Drupal::database()->select()`, `\Drupal::database()->insert()`, etc.) for database interactions. Avoid direct SQL queries whenever possible.
    *   **Entity Query API:** For querying entities, use the Entity Query API, which provides a higher level of abstraction and security.
    *   **Placeholders:** If you must use `db_query()`, always use placeholders for user-supplied data.  Never concatenate user input directly into SQL queries. Example: `\Drupal::database()->query("SELECT * FROM {users} WHERE name = :name", [':name' => $user_input]);`
    * **Input Validation:** Validate all user input before using it in database queries, even when using placeholders.

## Attack Surface: [Insecure File Uploads (via Modules)](./attack_surfaces/insecure_file_uploads__via_modules_.md)

*   **Description:** Modules that handle file uploads without proper restrictions on file types, sizes, or upload locations.
*   **How Drupal Contributes:** Many *contributed modules* provide file upload functionality, and these modules may have vulnerabilities if not configured securely or if they contain bugs. This is a Drupal-specific risk because it's tied to the module ecosystem.
*   **Example:** A module allows users to upload images but does not restrict the file types. An attacker uploads a PHP file disguised as an image, achieving remote code execution.
*   **Impact:** Remote code execution, complete site compromise.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **File Type Whitelisting:** Implement strict file type whitelisting, allowing only specific file extensions (e.g., `.jpg`, `.png`, `.gif`). Use Drupal's built-in file validation functions and the `file_validate_extensions` validator.
    *   **File Size Limits:** Enforce reasonable file size limits to prevent denial-of-service attacks. Use Drupal's file validation functions and the `file_validate_size` validator.
    *   **Upload Location:** Store uploaded files outside the web root or in a directory that is not directly accessible via the web server. Use Drupal's `private://` stream wrapper for sensitive files.
    *   **File Name Sanitization:** Sanitize file names to prevent directory traversal attacks and other file system vulnerabilities. Use Drupal's `file_munge_filename` function.
    *   **Virus Scanning:** Integrate virus scanning into the file upload process, ideally using a server-side solution.

