# Threat Model Analysis for elmah/elmah

## Threat: [Sensitive Data Exposure in Logs](./threats/sensitive_data_exposure_in_logs.md)

*   **Description:** ELMAH logs detailed error information, and if not properly configured or if applications are not carefully developed, sensitive information can be inadvertently included in these logs. Attackers who gain access to these logs (through unauthorized dashboard access or compromised log storage) can then retrieve this sensitive data. This can happen if developers log exceptions that contain credentials, PII, internal paths, or other confidential information.
*   **Impact:** Confidentiality breach, potential identity theft, data privacy violations, exposure of internal system details, further exploitation of exposed credentials.
*   **ELMAH Component Affected:** Logging Module, Log Storage (depending on configured storage mechanism), ELMAH Dashboard.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Implement robust input validation and output encoding in the application to prevent sensitive data from being processed and potentially logged.
    *   Sanitize error messages and stack traces within the application code to remove or mask sensitive information before ELMAH logs them.
    *   Configure ELMAH to filter specific parameters or data patterns from logs using custom filters or by modifying the logging process.
    *   Regularly review error logs to identify and remediate instances of sensitive data logging.
    *   Educate developers on secure coding practices and the importance of avoiding logging sensitive information.

## Threat: [Unauthorized ELMAH Dashboard Access](./threats/unauthorized_elmah_dashboard_access.md)

*   **Description:** The ELMAH dashboard (`elmah.axd`) provides a web interface to view error logs. If not properly secured, attackers can bypass authentication and authorization controls to access this dashboard. By accessing the dashboard, attackers can view all logged error details, potentially gaining insights into application vulnerabilities, sensitive data, and system internals. Attackers might attempt to access the dashboard by guessing or brute-forcing the URL, or exploiting misconfigurations in web server access controls.
*   **Impact:** Confidentiality breach (exposure of all logged error data), potential information disclosure leading to further attacks, availability impact if attackers use the dashboard to cause disruption.
*   **ELMAH Component Affected:** `Elmah.axd` Handler (HTTP Handler), ELMAH Dashboard UI.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Implement strong authentication and authorization for the `elmah.axd` handler using ASP.NET's built-in security features (e.g., `<authorization>` section in `web.config`, roles, policies).
    *   Change the default `elmah.axd` path to a less predictable name to deter casual discovery.
    *   Disable the ELMAH dashboard in production environments if it is not actively used for monitoring.
    *   Enforce HTTPS for all access to the ELMAH dashboard to protect authentication credentials and log data in transit.

