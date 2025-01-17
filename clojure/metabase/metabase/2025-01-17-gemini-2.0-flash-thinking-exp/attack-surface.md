# Attack Surface Analysis for metabase/metabase

## Attack Surface: [Weak Metabase User Authentication](./attack_surfaces/weak_metabase_user_authentication.md)

*   **Description:**  Metabase user accounts with weak passwords or lacking multi-factor authentication can be compromised, granting attackers access to Metabase's functionalities and potentially connected data sources.
    *   **How Metabase Contributes:** Metabase manages its own user authentication (or integrates with external systems). Weaknesses in its password policy enforcement or lack of mandatory MFA directly contribute to this risk.
    *   **Example:** An attacker brute-forces a Metabase user's password and gains access to view sensitive dashboards and query data.
    *   **Impact:** Unauthorized access to sensitive data, modification of dashboards and questions, potential for further attacks on connected databases.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Enforce strong password policies within Metabase (minimum length, complexity, expiration).
        *   Enable and enforce multi-factor authentication (MFA) for all Metabase users.
        *   Integrate with a robust identity provider (IdP) for centralized authentication and stronger security controls.
        *   Regularly review and audit Metabase user accounts and permissions.

## Attack Surface: [Insecure Storage of Database Credentials](./attack_surfaces/insecure_storage_of_database_credentials.md)

*   **Description:** Metabase stores credentials for connecting to external databases. If these credentials are stored insecurely, attackers gaining access to the Metabase server could retrieve them.
    *   **How Metabase Contributes:** Metabase's design requires storing database connection details. The security of this storage mechanism is critical.
    *   **Example:** An attacker gains access to the Metabase server's file system or database and retrieves plaintext database credentials, allowing them to directly access the connected databases.
    *   **Impact:** Full compromise of connected databases, including data breaches, data manipulation, and denial of service.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Utilize Metabase's built-in encryption for database credentials.
        *   Consider using environment variables or secrets management tools to store and manage database credentials outside of Metabase's configuration files.
        *   Restrict access to the Metabase server and its configuration files.
        *   Regularly audit the security of the Metabase server and its storage mechanisms.

## Attack Surface: [Insufficient Authorization Controls within Metabase](./attack_surfaces/insufficient_authorization_controls_within_metabase.md)

*   **Description:**  Flaws in Metabase's permission system can allow users to access data or functionalities they shouldn't, leading to data breaches or unauthorized actions.
    *   **How Metabase Contributes:** Metabase's role is to manage access to data through its permission model. Weaknesses or misconfigurations in this model directly create this attack surface.
    *   **Example:** A user with "viewer" permissions is able to bypass restrictions and access sensitive data intended only for "admin" users due to a flaw in permission enforcement within Metabase.
    *   **Impact:** Unauthorized access to sensitive data, potential for data manipulation or deletion, violation of data privacy regulations.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Carefully configure Metabase's collection and group permissions, adhering to the principle of least privilege.
        *   Regularly review and audit Metabase's permission settings to ensure they are correctly configured.
        *   Test permission configurations thoroughly within Metabase to identify potential bypasses.
        *   Educate users on Metabase's permission model and their responsibilities.

## Attack Surface: [Indirect SQL Injection via Metabase's Query Builder or Custom Expressions](./attack_surfaces/indirect_sql_injection_via_metabase's_query_builder_or_custom_expressions.md)

*   **Description:** While Metabase aims to prevent direct SQL injection, vulnerabilities in its query building logic or the handling of custom expressions could allow attackers to inject malicious SQL that is executed on the connected databases.
    *   **How Metabase Contributes:** Metabase's functionality of translating user actions into database queries introduces the possibility of flaws in this translation process.
    *   **Example:** An attacker crafts a malicious custom expression that, when processed by Metabase, results in the execution of arbitrary SQL on the connected database, allowing them to extract data or modify the database.
    *   **Impact:** Full compromise of connected databases, including data breaches, data manipulation, and denial of service.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Keep Metabase updated to the latest version to benefit from security patches in Metabase's query processing engine.
        *   Carefully review and sanitize any user input that is used in custom expressions or filters within Metabase.
        *   Limit the use of custom expressions to trusted users within Metabase.
        *   Monitor database logs for suspicious query activity originating from Metabase.

## Attack Surface: [Server-Side Request Forgery (SSRF) via Data Source Connections](./attack_surfaces/server-side_request_forgery__ssrf__via_data_source_connections.md)

*   **Description:**  If Metabase's data source connection functionality is not properly secured, an attacker might be able to leverage it to make requests to internal or external resources that Metabase has access to.
    *   **How Metabase Contributes:** Metabase's ability to connect to various data sources and potentially interact with them introduces this risk if not properly controlled within Metabase's connection handling.
    *   **Example:** An attacker manipulates a data source connection setting within Metabase or leverages a vulnerability in Metabase to make requests to internal network resources, potentially accessing sensitive internal services or data.
    *   **Impact:** Access to internal resources, potential for further attacks on internal systems, information disclosure.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Restrict the network access of the Metabase server to only necessary resources.
        *   Carefully configure data source connections within Metabase and limit the types of connections allowed.
        *   Implement network segmentation to isolate the Metabase server.
        *   Monitor Metabase's network activity for unusual outbound connections.

## Attack Surface: [Vulnerabilities in Metabase's API](./attack_surfaces/vulnerabilities_in_metabase's_api.md)

*   **Description:**  Security flaws in Metabase's API endpoints could allow attackers to perform unauthorized actions, access sensitive data, or disrupt the service.
    *   **How Metabase Contributes:** Metabase exposes an API for programmatic interaction. Vulnerabilities in this API are directly attributable to Metabase's codebase.
    *   **Example:** An attacker exploits an API vulnerability in Metabase to bypass authentication and retrieve a list of all users and their permissions.
    *   **Impact:** Unauthorized access to data and functionalities within Metabase, potential for data manipulation or deletion, denial of service of Metabase.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Keep Metabase updated to the latest version to benefit from security patches in its API.
        *   Implement proper authentication and authorization for all Metabase API endpoints.
        *   Rate limit API requests to prevent abuse of the Metabase API.
        *   Regularly audit the security of Metabase's API endpoints.

