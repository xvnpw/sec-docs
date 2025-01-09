# Attack Surface Analysis for odoo/odoo

## Attack Surface: [Server-Side Template Injection (SSTI) via QWeb](./attack_surfaces/server-side_template_injection__ssti__via_qweb.md)

**Description:** Attackers can inject malicious code into QWeb templates, leading to arbitrary code execution on the server.

**How Odoo Contributes:** Odoo uses QWeb as its primary templating engine for rendering web pages and reports. Improperly sanitized data passed to QWeb can be interpreted as code.

**Example:** A user-controlled input field (e.g., a product description) is directly rendered in a QWeb template without proper escaping. An attacker could input `{{ ''.__class__.__mro__[2].__subclasses__()[408]('/bin/bash -c "whoami"').read() }}` to execute commands on the server.

**Impact:** Complete server compromise, data breach, denial of service.

**Risk Severity:** Critical

**Mitigation Strategies:**

*   Strict Input Validation and Sanitization: Sanitize all user-provided data before rendering it in QWeb templates. Use Odoo's built-in sanitization functions where appropriate.
*   Contextual Output Encoding: Encode data based on the context where it's being used in the template (e.g., HTML escaping).
*   Regular Security Audits: Review QWeb templates for potential injection vulnerabilities.

## Attack Surface: [SQL Injection through Odoo's ORM or Custom Queries](./attack_surfaces/sql_injection_through_odoo's_orm_or_custom_queries.md)

**Description:** Attackers can inject malicious SQL code into database queries, allowing them to manipulate or extract data.

**How Odoo Contributes:** While Odoo's ORM provides some protection, vulnerabilities can arise from:

*   Improper use of the ORM, especially when constructing dynamic queries based on user input.
*   Direct execution of unsanitized SQL queries within custom modules or methods.

**Example:** A custom search function in a module directly concatenates user input into an SQL `WHERE` clause: `cr.execute("SELECT * FROM my_table WHERE name = '" + user_input + "'")`. An attacker could input `' OR 1=1 --` to bypass the intended filter.

**Impact:** Data breach, data manipulation, privilege escalation.

**Risk Severity:** High

**Mitigation Strategies:**

*   Use Odoo's ORM Securely: Rely on the ORM's methods for querying and data manipulation. Avoid constructing raw SQL queries where possible.
*   Parameterize Queries: When raw SQL is necessary, always use parameterized queries to prevent SQL injection.
*   Input Validation: Validate and sanitize user input before using it in database queries.
*   Regular Code Reviews: Review custom modules and code for potential SQL injection vulnerabilities.

## Attack Surface: [Cross-Site Scripting (XSS) due to Improper Output Encoding](./attack_surfaces/cross-site_scripting__xss__due_to_improper_output_encoding.md)

**Description:** Attackers can inject malicious scripts into web pages viewed by other users.

**How Odoo Contributes:** Odoo renders dynamic content based on user input and data from the database. If output is not properly encoded, malicious scripts can be injected.

**Example:** A user can add a product review containing `<script>alert('XSS')</script>`. If this review is displayed on the product page without proper HTML escaping, the script will execute in other users' browsers.

**Impact:** Account compromise, session hijacking, defacement, redirection to malicious sites.

**Risk Severity:** High

**Mitigation Strategies:**

*   Contextual Output Encoding: Encode data based on the context where it's being displayed (e.g., HTML escaping for web pages, JavaScript escaping for JavaScript contexts). Odoo's QWeb provides mechanisms for this.
*   Content Security Policy (CSP): Implement and configure CSP headers to restrict the sources from which the browser is allowed to load resources, reducing the impact of XSS.
*   Regular Security Audits: Identify and fix areas where user-generated content is displayed without proper encoding.

## Attack Surface: [Insecure Direct Object References (IDOR) in URLs or API Endpoints](./attack_surfaces/insecure_direct_object_references__idor__in_urls_or_api_endpoints.md)

**Description:** Attackers can manipulate object IDs in URLs or API requests to access resources belonging to other users.

**How Odoo Contributes:** Odoo uses predictable IDs for records in URLs and API endpoints. If authorization checks are insufficient, attackers can potentially access or modify data they shouldn't.

**Example:** A URL like `/web/dataset/call_button/sale.order/123/action_confirm` allows access to order ID 123. An attacker might try changing the ID to `/web/dataset/call_button/sale.order/124/action_confirm` to access another user's order.

**Impact:** Unauthorized data access, data modification, privilege escalation.

**Risk Severity:** High

**Mitigation Strategies:**

*   Implement Robust Authorization Checks: Ensure that every request to access or modify a resource includes proper authorization checks to verify the user's permissions.
*   Use Non-Sequential or UUIDs for IDs (where feasible): While challenging to implement retroactively, using non-sequential IDs can make it harder to guess valid object references.
*   Indirect Object References: Instead of exposing direct database IDs, use a mapping or token system to represent resources.

## Attack Surface: [Authentication and Authorization Bypass in Custom Modules](./attack_surfaces/authentication_and_authorization_bypass_in_custom_modules.md)

**Description:** Vulnerabilities in custom-developed modules can bypass Odoo's standard authentication and authorization mechanisms.

**How Odoo Contributes:** Odoo provides a framework for extending its functionality through modules. If developers don't implement security best practices, they can introduce vulnerabilities.

**Example:** A custom module exposes an API endpoint that doesn't properly check user permissions before allowing access to sensitive data.

**Impact:** Unauthorized access to data and functionalities, privilege escalation.

**Risk Severity:** High

**Mitigation Strategies:**

*   Follow Odoo's Security Guidelines: Adhere to Odoo's recommended practices for authentication and authorization when developing custom modules.
*   Use Odoo's Access Rights System: Leverage Odoo's built-in access control mechanisms (ir.model.access) to manage permissions.
*   Regular Security Reviews and Code Audits: Thoroughly review custom module code for potential security flaws.

## Attack Surface: [Insecure File Upload Handling](./attack_surfaces/insecure_file_upload_handling.md)

**Description:** Attackers can upload malicious files that can be executed on the server or used for other attacks.

**How Odoo Contributes:** Odoo allows users to upload files as attachments or through other functionalities. Improper handling of these uploads can create vulnerabilities.

**Example:** An attacker uploads a PHP web shell disguised as an image. If the server allows execution of PHP files in the upload directory, the attacker can gain remote control.

**Impact:** Remote code execution, server compromise, defacement.

**Risk Severity:** Critical

**Mitigation Strategies:**

*   Validate File Types: Restrict allowed file types based on application needs. Don't rely solely on client-side validation.
*   Sanitize File Names: Rename uploaded files to prevent path traversal or execution vulnerabilities.
*   Store Uploaded Files Outside the Web Root: Prevent direct access to uploaded files by storing them in a location not directly accessible by the web server.
*   Implement Antivirus Scanning: Scan uploaded files for malware.

