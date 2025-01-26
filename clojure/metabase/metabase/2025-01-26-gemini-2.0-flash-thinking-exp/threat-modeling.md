# Threat Model Analysis for metabase/metabase

## Threat: [Insufficient Data Access Controls within Metabase](./threats/insufficient_data_access_controls_within_metabase.md)

Description: Attacker exploits misconfigured Metabase permissions to access datasets or database connections they shouldn't. They can view, query, and potentially export sensitive data by bypassing intended access restrictions.
Impact: Unauthorized access to sensitive data, data breach, privacy violations, compliance violations (e.g., GDPR, HIPAA).
Affected Metabase Component: Permissions System, Data Model, Database Connections.
Risk Severity: High
Mitigation Strategies:
    * Regularly review and audit Metabase data permissions.
    * Implement principle of least privilege when granting data access.
    * Segment data access based on user roles and responsibilities.
    * Use Metabase groups and granular permissions to control access to specific datasets and databases.
    * Document and enforce a clear data access policy within Metabase.

## Threat: [Privilege Escalation within Metabase](./threats/privilege_escalation_within_metabase.md)

Description: Attacker exploits vulnerabilities in Metabase's authorization logic or API to elevate their user privileges. They could gain admin access or higher data access rights, allowing them to control Metabase settings, access all data, or potentially compromise the underlying system.
Impact: Full compromise of Metabase application, unauthorized access to all data, potential data manipulation or deletion, denial of service, further attacks on connected systems.
Affected Metabase Component: User Management, API Endpoints, Authorization Logic.
Risk Severity: Critical
Mitigation Strategies:
    * Keep Metabase updated to the latest version to patch known vulnerabilities.
    * Regularly audit user roles and permissions.
    * Implement robust input validation and sanitization in Metabase API and user interface.
    * Follow secure coding practices during Metabase customization or plugin development.
    * Implement security monitoring and intrusion detection systems to detect suspicious activity.

## Threat: [Data Exposure through API Access](./threats/data_exposure_through_api_access.md)

Description: Attacker exploits unsecured or improperly secured Metabase API access. They can use API endpoints to retrieve sensitive data, modify Metabase configurations, or potentially gain control of the application if API authentication or authorization is weak or vulnerable.
Impact: Unauthorized data access, data manipulation, system compromise, denial of service.
Affected Metabase Component: REST API, API Authentication, API Authorization.
Risk Severity: High
Mitigation Strategies:
    * Secure Metabase API access with strong authentication mechanisms (e.g., API keys, OAuth 2.0).
    * Implement proper API authorization to control access to specific API endpoints and data.
    * Rate limit API requests to prevent brute-force attacks and denial of service.
    * Monitor API access logs for suspicious activity.
    * Disable or restrict API access if not required.

## Threat: [SQL Injection (Indirect via Metabase Features)](./threats/sql_injection__indirect_via_metabase_features_.md)

Description: Attacker exploits vulnerabilities in Metabase's query generation, parameter handling, or custom SQL features to inject malicious SQL code. This could allow them to bypass security controls, access unauthorized data, modify data, or potentially execute arbitrary code on the database server.
Impact: Data breach, data manipulation, unauthorized access, potential database server compromise.
Affected Metabase Component: Query Builder, Custom SQL Feature, Parameter Handling, Database Driver.
Risk Severity: High
Mitigation Strategies:
    * Keep Metabase updated to the latest version to patch potential vulnerabilities.
    * Carefully review and sanitize user inputs used in custom SQL queries or parameterized queries.
    * Use parameterized queries and prepared statements whenever possible to prevent SQL injection.
    * Implement input validation and sanitization on all user-provided data used in query construction.
    * Regularly security test Metabase deployments, especially custom SQL features.

## Threat: [Vulnerabilities in Metabase Software](./threats/vulnerabilities_in_metabase_software.md)

Description: Attacker exploits known or zero-day vulnerabilities in the Metabase application itself. This could allow them to gain unauthorized access, execute arbitrary code on the Metabase server, or cause denial of service.
Impact: Full compromise of Metabase application, data breach, data manipulation, denial of service, potential compromise of underlying infrastructure.
Affected Metabase Component: Core Application Code, Libraries, Dependencies.
Risk Severity: Critical
Mitigation Strategies:
    * Keep Metabase updated to the latest version and apply security patches promptly.
    * Subscribe to Metabase security advisories and mailing lists.
    * Implement a vulnerability management program to regularly scan for and address vulnerabilities.
    * Harden the Metabase server operating system and infrastructure.
    * Use a web application firewall (WAF) to protect against common web attacks.

## Threat: [Insecure Metabase Configuration](./threats/insecure_metabase_configuration.md)

Description: Running Metabase with insecure default configurations or misconfigurations that weaken security. This includes using default credentials, running in debug mode in production, or disabling security features, making it easier for attackers to compromise the application.
Impact: Unauthorized access, system compromise, data breach, denial of service.
Affected Metabase Component: Configuration Settings, Deployment Process, Security Features.
Risk Severity: High
Mitigation Strategies:
    * Change default administrative credentials immediately upon installation.
    * Disable debug mode in production environments.
    * Enable and properly configure security features like HTTPS, Content Security Policy (CSP), and HTTP Strict Transport Security (HSTS).
    * Follow Metabase security best practices and hardening guides.
    * Regularly review and audit Metabase configuration settings.

