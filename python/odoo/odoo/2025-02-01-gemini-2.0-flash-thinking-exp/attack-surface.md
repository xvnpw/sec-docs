# Attack Surface Analysis for odoo/odoo

## Attack Surface: [Server-Side Template Injection (SSTI) in QWeb](./attack_surfaces/server-side_template_injection__ssti__in_qweb.md)

*   **Description:** Attackers inject malicious code into server-side QWeb templates, which is then executed by the QWeb template engine, leading to arbitrary Python code execution on the Odoo server.
*   **Odoo Contribution:** Odoo's core framework utilizes QWeb as its templating engine. Custom modules or modifications to core modules that improperly handle user input within QWeb templates directly introduce SSTI vulnerabilities due to Odoo's template rendering mechanism.
*   **Example:** A custom Odoo module takes user input for a product description and directly embeds it into a QWeb template without sanitization. An attacker injects `{{ object.os.system('rm -rf /') }}` as part of the product description. When Odoo renders the template, this code executes on the Odoo server, potentially deleting critical system files.
*   **Impact:** **Critical**. Full server compromise, data breach, denial of service, and complete control over the Odoo instance.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Developers:**
        *   **Strict Input Sanitization for QWeb:**  Thoroughly sanitize all user inputs before embedding them into QWeb templates using Odoo's provided sanitization functions or libraries specifically designed for SSTI prevention in QWeb.
        *   **Secure QWeb Template Design:** Design QWeb templates to minimize dynamic content insertion and avoid directly embedding user input where possible.
        *   **Regular QWeb Template Security Review:**  Carefully review all QWeb templates, especially in custom modules, for potential injection points during development and security audits.
    *   **Users:**
        *   **Module Source Code Audit (QWeb Templates):** If possible, review the source code of custom Odoo modules before installation, specifically examining QWeb templates for unsafe user input handling.
        *   **Report Suspicious Application Behavior:** Report any unexpected application behavior or errors that might indicate a potential SSTI exploit attempt.

## Attack Surface: [Unrestricted File Upload](./attack_surfaces/unrestricted_file_upload.md)

*   **Description:** Attackers upload malicious files to the Odoo server due to insufficient restrictions in Odoo's file upload functionalities. These files can be executed or exploited to compromise the Odoo instance or the underlying server.
*   **Odoo Contribution:** Odoo core and many modules (e.g., Documents, Attachments, Website Builder) provide file upload features. Vulnerabilities arise when Odoo modules, either core or custom, lack proper file type validation, size limits, or secure storage mechanisms for uploaded files.
*   **Example:** An Odoo custom module allows users to upload attachments to records without proper file type validation. An attacker uploads a Python web shell disguised as a PDF. If the Odoo server or web server is misconfigured or vulnerable, this web shell could be executed, granting the attacker control.
*   **Impact:** **High**. Remote code execution on the Odoo server, web shell deployment, data exfiltration, potential for lateral movement within the network.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Developers:**
        *   **Robust File Type Validation in Odoo Modules:** Implement strict file type validation within Odoo modules based on file content (magic numbers) and not just file extensions. Use allowlists of permitted file types enforced within Odoo's backend logic.
        *   **File Size Limits in Odoo:** Enforce reasonable file size limits within Odoo's file upload handlers to prevent denial-of-service and large file uploads.
        *   **Secure File Storage Configuration in Odoo:** Configure Odoo to store uploaded files outside of the web server's document root and ensure files are served through a secure, controlled mechanism, ideally managed by Odoo's framework.
        *   **Input Sanitization for Filenames in Odoo:** Sanitize filenames processed by Odoo to prevent path traversal vulnerabilities and other file system exploits when handling uploaded files.
    *   **Users:**
        *   **Restrict File Upload Permissions in Odoo:** Limit file upload permissions within Odoo to only necessary user roles and groups using Odoo's access control features.
        *   **Regularly Monitor Odoo Uploaded Files:** Implement monitoring of uploaded files within Odoo for suspicious content or filenames through Odoo's administrative interfaces or custom monitoring tools.

## Attack Surface: [Authentication and Authorization Bypass](./attack_surfaces/authentication_and_authorization_bypass.md)

*   **Description:** Attackers bypass Odoo's authentication or authorization mechanisms to gain unauthorized access to the Odoo application or escalate privileges within Odoo, allowing actions they are not permitted to perform.
*   **Odoo Contribution:** Odoo's security model is centrally managed through its authentication system and Access Control Lists (ACLs). Vulnerabilities or misconfigurations in Odoo's core authentication framework or within custom modules' ACL implementations directly lead to authentication and authorization bypass risks.
*   **Example:** A vulnerability in a custom Odoo module's authentication logic, or a flaw in Odoo's core authentication handling, allows an attacker to craft a specific request that bypasses the login process and grants them administrative privileges within Odoo. They can then access sensitive data, modify configurations, or perform administrative actions within the Odoo system.
*   **Impact:** **Critical to High**. Unauthorized access to sensitive data within Odoo, data breaches, privilege escalation to administrator level within Odoo, potential for complete compromise of the Odoo application and its data.
*   **Risk Severity:** **High to Critical** (depending on the level of access gained and the sensitivity of the Odoo instance)
*   **Mitigation Strategies:**
    *   **Developers:**
        *   **Secure Authentication Implementation in Odoo Modules:**  Follow secure coding practices when implementing authentication mechanisms in custom Odoo modules, strictly adhering to Odoo's built-in authentication framework and security guidelines.
        *   **Robust ACL Configuration in Odoo:**  Carefully configure Odoo's ACLs to enforce granular access control and prevent privilege escalation. Regularly review and audit ACL configurations within Odoo using Odoo's security administration tools.
        *   **Leverage Odoo's Multi-Factor Authentication (MFA):** Implement and enforce MFA for critical Odoo user accounts and functionalities using Odoo's MFA capabilities or compatible extensions to add an extra layer of security to Odoo logins.
    *   **Users:**
        *   **Enforce Strong Passwords in Odoo:** Enforce strong, unique password policies for all Odoo users using Odoo's password management features and avoid password reuse across different systems.
        *   **Regular Password Rotation in Odoo:** Encourage and enforce regular password changes for Odoo users to minimize the impact of compromised credentials.
        *   **Monitor Odoo User Activity for Anomalies:** Monitor Odoo user activity logs for suspicious login attempts, unauthorized access patterns, or privilege escalation attempts using Odoo's logging and auditing features.

## Attack Surface: [ORM Injection](./attack_surfaces/orm_injection.md)

*   **Description:** Attackers manipulate database queries through vulnerabilities in Odoo's Object-Relational Mapping (ORM) layer. This can lead to unauthorized data access or modification within the Odoo database.
*   **Odoo Contribution:** Odoo's architecture relies heavily on its ORM to interact with the PostgreSQL database. While designed to mitigate direct SQL injection, vulnerabilities in Odoo's ORM implementation itself or improper ORM query construction in custom Odoo modules can still lead to ORM injection vulnerabilities.
*   **Example:** A custom Odoo module constructs an ORM query using unsanitized user input directly within a `domain` filter. An attacker crafts a malicious input that manipulates the intended query logic, allowing them to bypass Odoo's access controls and retrieve or modify data in the Odoo database that they should not have access to.
*   **Impact:** **Medium to High**. Data breaches within the Odoo database, unauthorized data modification, potential for data corruption or integrity issues within Odoo.
*   **Risk Severity:** **High** (depending on the sensitivity and volume of data exposed or modified within Odoo)
*   **Mitigation Strategies:**
    *   **Developers:**
        *   **Parameterization of Odoo ORM Queries:**  Always use parameterized queries or Odoo's ORM methods that automatically handle parameterization when incorporating user input into ORM queries within Odoo modules. Strictly avoid string concatenation to build ORM queries.
        *   **Input Validation Before ORM Queries in Odoo:** Validate all user inputs before using them in Odoo ORM queries to ensure they conform to expected formats and prevent malicious injection attempts. Implement input validation within Odoo's backend logic.
        *   **ORM Security Review for Odoo Modules:**  Conduct thorough security reviews of all ORM queries in custom Odoo modules to identify and remediate potential ORM injection vulnerabilities during development and security testing.
    *   **Users:**
        *   **Module Source Code Audit (ORM Queries):** If feasible, review the source code of custom Odoo modules, specifically examining how database queries are constructed using Odoo's ORM, looking for potential unsafe handling of user input.
        *   **Report Suspicious Data Access within Odoo:** Report any unexpected data access or modifications observed within the Odoo application that might indicate an ORM injection exploit.

