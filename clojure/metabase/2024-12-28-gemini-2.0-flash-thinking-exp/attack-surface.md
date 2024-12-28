*   **Attack Surface: SQL Injection through Native Queries**
    *   Description: Attackers can inject malicious SQL code into native queries executed by Metabase.
    *   How Metabase Contributes: Metabase allows users with appropriate permissions to write and execute native SQL queries against connected databases. If input sanitization or parameterization is insufficient, this opens the door for SQL injection.
    *   Example: A user with "Data Access" permission crafts a native query like `SELECT * FROM Users WHERE username = 'admin' OR '1'='1'; --` which bypasses authentication.
    *   Impact: Unauthorized access to sensitive data, data modification, or even complete database compromise depending on the permissions of the Metabase database user.
    *   Risk Severity: Critical
    *   Mitigation Strategies:
        *   Principle of Least Privilege: Grant only necessary database permissions to the Metabase database user.
        *   Parameterization/Prepared Statements: Encourage and enforce the use of parameterized queries where possible within native queries.
        *   Input Validation and Sanitization: Implement robust input validation and sanitization on any user-provided input that is incorporated into native queries.
        *   Regular Security Audits: Conduct regular security audits of native queries and Metabase configurations.

*   **Attack Surface: Cross-Site Scripting (XSS) in User-Generated Content**
    *   Description: Malicious scripts can be injected into dashboards, questions, or visualizations created by users, potentially allowing them to be executed in other users' browsers.
    *   How Metabase Contributes: Metabase allows users to create and share interactive content. If input sanitization is insufficient when rendering this content, XSS vulnerabilities can arise.
    *   Example: A user creates a dashboard with a text card containing `<script>alert('XSS')</script>`. When another user views this dashboard, the script executes in their browser.
    *   Impact: Session hijacking, cookie theft, redirection to malicious sites, defacement of dashboards, and potentially gaining access to other users' Metabase accounts.
    *   Risk Severity: High
    *   Mitigation Strategies:
        *   Output Encoding: Implement proper output encoding (escaping) of user-generated content before rendering it in the browser.
        *   Content Security Policy (CSP): Configure a strong CSP to restrict the sources from which the browser can load resources, mitigating the impact of XSS.
        *   Regular Security Audits: Regularly audit the application for potential XSS vulnerabilities.

*   **Attack Surface: Insecure Embedding Implementation**
    *   Description: When embedding Metabase dashboards or questions in other applications, improper configuration can expose sensitive data or functionalities.
    *   How Metabase Contributes: Metabase provides features for embedding content via iframes or signed URLs. Misconfiguration of these features can lead to security issues.
    *   Example: An iframe embedding a Metabase dashboard lacks proper authentication checks, allowing unauthorized users to view the embedded content.
    *   Impact: Unauthorized access to sensitive data displayed in embedded dashboards or questions. Potential for clickjacking attacks if the embedding is not properly secured.
    *   Risk Severity: High
    *   Mitigation Strategies:
        *   Require Authentication for Embedded Content: Ensure that embedded content requires authentication and authorization checks.
        *   Use Signed URLs with Expiration: Utilize signed URLs with appropriate expiration times to limit the window of opportunity for unauthorized access.
        *   Implement Frame Options and CSP: Configure `X-Frame-Options` and CSP headers to prevent clickjacking and control the embedding context.
        *   Regularly Review Embedding Configurations: Periodically review the configurations of embedded Metabase content.

*   **Attack Surface: Default or Weak Administrative Credentials**
    *   Description: Using default or easily guessable administrative credentials provides a straightforward entry point for attackers.
    *   How Metabase Contributes: Metabase, like many applications, has an initial setup process where administrative credentials are created. If these are not changed or are weak, it's a significant vulnerability.
    *   Example: An attacker uses the default username "admin" and a common password like "password" to log in to the Metabase administrative interface.
    *   Impact: Complete compromise of the Metabase instance, including access to all data sources, user accounts, and settings.
    *   Risk Severity: Critical
    *   Mitigation Strategies:
        *   Enforce Strong Password Policies: Implement and enforce strong password policies for all user accounts, especially administrative accounts.
        *   Mandatory Password Change on First Login: Require users to change default passwords upon their first login.
        *   Multi-Factor Authentication (MFA): Enable MFA for administrative accounts to add an extra layer of security.

*   **Attack Surface: Server-Side Request Forgery (SSRF) via Data Sources**
    *   Description: If Metabase allows specifying arbitrary hosts or ports when configuring data sources, attackers could potentially use the Metabase server to make requests to internal resources or external services.
    *   How Metabase Contributes: Metabase needs to connect to various data sources. If the configuration process doesn't properly validate or restrict the target hosts, SSRF is possible.
    *   Example: An attacker configures a data source pointing to an internal service on the network (e.g., `http://internal-server:8080`), potentially gaining access to resources not directly exposed to the internet.
    *   Impact: Access to internal resources, port scanning of internal networks, potential for data exfiltration from internal systems, and in some cases, remote code execution on internal systems.
    *   Risk Severity: High
    *   Mitigation Strategies:
        *   Whitelist Allowed Hosts/Ports: Implement a strict whitelist of allowed hosts and ports for data source connections.
        *   Disable or Restrict Network Access for Metabase Server: Limit the network access of the Metabase server to only necessary resources.
        *   Input Validation and Sanitization: Thoroughly validate and sanitize any user-provided input related to data source configuration.