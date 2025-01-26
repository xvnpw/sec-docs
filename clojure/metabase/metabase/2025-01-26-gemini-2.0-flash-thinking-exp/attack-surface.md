# Attack Surface Analysis for metabase/metabase

## Attack Surface: [Default Administrative Credentials/Weak Default Settings](./attack_surfaces/default_administrative_credentialsweak_default_settings.md)

**Description:** Metabase, upon initial installation, might have default credentials or weak default configurations that are easily guessable or publicly known.
**Metabase Contribution:** Metabase needs initial setup, and if not properly secured during this phase, default settings can be exploited.
**Example:** An attacker uses default username "admin" and password "metabase" (or similar common defaults) to log in to an unconfigured Metabase instance.
**Impact:** Full administrative access to Metabase, allowing configuration changes, data access, and potentially access to connected databases.
**Risk Severity:** **Critical**
**Mitigation Strategies:**
*   Immediately change default administrative credentials during initial setup.
*   Enforce strong password policies for all users.
*   Review and harden default security settings as per Metabase documentation.
*   Disable or remove any unnecessary default accounts.

## Attack Surface: [Insecure Database Connection String Storage](./attack_surfaces/insecure_database_connection_string_storage.md)

**Description:** Database connection strings, containing sensitive credentials, might be stored insecurely within Metabase's configuration files or database.
**Metabase Contribution:** Metabase needs to store connection details to access data sources. If this storage is compromised, database access is at risk.
**Example:** An attacker gains access to the Metabase server's filesystem and reads a configuration file containing plaintext database credentials.
**Impact:** Direct access to backend databases, potentially leading to data breaches, data manipulation, or denial of service on the database.
**Risk Severity:** **Critical**
**Mitigation Strategies:**
*   Encrypt database connection strings within Metabase configuration.
*   Use environment variables or secrets management solutions to store and retrieve database credentials instead of hardcoding them in configuration files.
*   Restrict access to Metabase server's filesystem and configuration files using appropriate permissions.
*   Regularly rotate database credentials.

## Attack Surface: [Cross-Site Scripting (XSS) Vulnerabilities](./attack_surfaces/cross-site_scripting__xss__vulnerabilities.md)

**Description:** Metabase might be vulnerable to XSS if it doesn't properly sanitize user-supplied input when rendering dashboards, visualizations, or user interface elements.
**Metabase Contribution:** Metabase allows users to create dashboards and visualizations, potentially incorporating user-provided data or configurations that, if not sanitized, can lead to XSS.
**Example:** An attacker injects malicious JavaScript code into a dashboard title or a custom field formula. When another user views the dashboard, the script executes in their browser, potentially stealing session cookies or redirecting them to a malicious site.
**Impact:** Session hijacking, account takeover, defacement, redirection to malicious websites, information disclosure.
**Risk Severity:** **High**
**Mitigation Strategies:**
*   Implement robust input validation and output encoding/escaping for all user-supplied data displayed in Metabase.
*   Utilize Content Security Policy (CSP) to restrict the sources from which the browser can load resources, mitigating the impact of XSS.
*   Regularly scan Metabase for XSS vulnerabilities using automated security scanning tools.
*   Educate users about the risks of copy-pasting untrusted code into Metabase.

## Attack Surface: [Authorization Bypass Vulnerabilities](./attack_surfaces/authorization_bypass_vulnerabilities.md)

**Description:** Flaws in Metabase's permission model or its implementation could allow users to bypass authorization checks and access data or functionalities they are not intended to access.
**Metabase Contribution:** Metabase has a complex permission system to control access to data and features. Vulnerabilities in this system can lead to unauthorized access.
**Example:** A user with "viewer" permissions is able to craft a specific API request or manipulate URL parameters to access administrative dashboards or data sources they should not have access to.
**Impact:** Unauthorized data access, data breaches, privilege escalation, potential for data manipulation or deletion.
**Risk Severity:** **High**
**Mitigation Strategies:**
*   Thoroughly review and test Metabase's permission model and access controls.
*   Implement principle of least privilege, granting users only the necessary permissions.
*   Regularly audit user permissions and access logs.
*   Keep Metabase updated to patch known authorization bypass vulnerabilities.

## Attack Surface: [Publicly Accessible Embedding Features (Misconfigured)](./attack_surfaces/publicly_accessible_embedding_features__misconfigured_.md)

**Description:** If embedding features are enabled and not properly secured, sensitive dashboards or data visualizations could be unintentionally exposed publicly.
**Metabase Contribution:** Metabase offers embedding features to share dashboards. Misconfiguration of these features can lead to unintended public exposure.
**Example:** A user enables public embedding for a dashboard containing sensitive financial data without proper authentication or access controls. The public link is indexed by search engines, making the data accessible to anyone.
**Impact:** Data leaks, exposure of sensitive business information, reputational damage, regulatory compliance violations.
**Risk Severity:** **High**
**Mitigation Strategies:**
*   Carefully consider the security implications before enabling public embedding.
*   Implement strong authentication and authorization mechanisms for embedded dashboards, even if intended for external access.
*   Use signed embedding URLs with short expiration times to limit the window of exposure.
*   Regularly review and audit publicly embedded dashboards to ensure they are intended for public access and properly secured.

## Attack Surface: [API Authentication and Authorization Flaws](./attack_surfaces/api_authentication_and_authorization_flaws.md)

**Description:** Vulnerabilities in Metabase's API authentication and authorization mechanisms could allow unauthorized access to API endpoints.
**Metabase Contribution:** Metabase exposes a comprehensive API for data retrieval and management. Weaknesses in API security can be exploited.
**Example:** An attacker discovers a vulnerability in the API authentication process that allows them to bypass authentication and access API endpoints without valid credentials.
**Impact:** Unauthorized data access, data manipulation, denial of service, potential for remote code execution if API vulnerabilities are severe.
**Risk Severity:** **High**
**Mitigation Strategies:**
*   Enforce strong API authentication mechanisms (e.g., API keys, OAuth 2.0).
*   Implement robust API authorization checks to ensure users can only access authorized resources.
*   Regularly audit and test API security.
*   Apply rate limiting and input validation to API endpoints to prevent abuse and injection attacks.

## Attack Surface: [Server-Side Request Forgery (SSRF)](./attack_surfaces/server-side_request_forgery__ssrf_.md)

**Description:** If Metabase features involve making requests to external resources, vulnerabilities could arise allowing an attacker to perform SSRF attacks.
**Metabase Contribution:** Metabase might have features that fetch data from external URLs or use webhooks, potentially creating SSRF opportunities if not implemented securely.
**Example:** An attacker manipulates a feature that fetches data from a URL to point to an internal server or service. Metabase server then makes a request to this internal resource, potentially exposing internal information or allowing the attacker to interact with internal systems.
**Impact:** Access to internal resources, information disclosure, potential for further attacks on internal systems, denial of service.
**Risk Severity:** **Medium** to **High** (depending on internal network exposure)
**Mitigation Strategies:**
*   Sanitize and validate all user-provided URLs used in Metabase features.
*   Implement allow-lists for allowed destination hosts or protocols for outbound requests.
*   Disable or restrict features that involve making external requests if not strictly necessary.
*   Network segmentation to limit the impact of SSRF attacks on internal networks.

