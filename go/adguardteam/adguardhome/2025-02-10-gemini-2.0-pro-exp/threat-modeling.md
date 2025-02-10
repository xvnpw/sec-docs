# Threat Model Analysis for adguardteam/adguardhome

## Threat: [API Endpoint Spoofing](./threats/api_endpoint_spoofing.md)

*   **Description:** An attacker crafts a malicious server that mimics the AdGuard Home API. They then trick the application into connecting to this fake API endpoint, potentially through a phishing attack, DNS hijacking (if the application doesn't use a fixed IP/hostname), or by exploiting a misconfiguration in the application's network settings.
    *   **Impact:** The application sends sensitive data (e.g., API keys, configuration requests, usage data) to the attacker. The attacker can also send manipulated responses, causing the application to behave incorrectly (e.g., bypassing filters, using malicious DNS settings). This could lead to data breaches, application malfunction, and loss of user trust.
    *   **Affected Component:** AdGuard Home API (specifically, the endpoint exposed for external communication, likely `/control/*` endpoints). The application's API client is also affected.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **AdGuard Home-Side:** Ensure TLS is enabled and configured with a valid certificate. Consider using a reverse proxy (like Nginx) to handle TLS termination and provide additional security.
        *   **Application-Side:** Implement strict TLS certificate validation, including hostname verification and certificate pinning (if feasible). Use a well-vetted HTTPS library. Avoid hardcoding the API endpoint; use a secure configuration mechanism. Implement robust error handling for API communication failures.

## Threat: [Unauthorized Configuration Modification](./threats/unauthorized_configuration_modification.md)

*   **Description:** An attacker gains access to the AdGuard Home web interface or configuration file (e.g., `AdGuardHome.yaml`) through weak credentials, a vulnerability in the web interface, or by exploiting a misconfigured access control list. The attacker then modifies the filtering rules, upstream DNS servers, or other settings.
    *   **Impact:** The attacker can disable filtering, redirect traffic to malicious websites, add their own filtering rules to block legitimate services, or change DNS settings to point to malicious DNS servers. This can lead to malware infections, data breaches, service disruption, and privacy violations.
    *   **Affected Component:** AdGuard Home Web Interface (`/control/` endpoints), Configuration File (`AdGuardHome.yaml`), Filtering Engine (rules processing), DNS Proxy (upstream server configuration).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **AdGuard Home-Side:** Use strong, unique passwords for the web interface. Enable multi-factor authentication if available. Restrict access to the web interface to trusted networks using firewall rules. Regularly audit the configuration file for unauthorized changes. Implement file integrity monitoring for `AdGuardHome.yaml`. Consider running AGH in a restricted environment (e.g., a container with limited permissions).
        *   **Operational:** Implement a robust change management process for AGH configuration.

## Threat: [DNS Response Spoofing (Upstream)](./threats/dns_response_spoofing__upstream_.md)

*   **Description:** AdGuard Home relies on upstream DNS servers. An attacker compromises one of these upstream servers or performs a DNS cache poisoning attack against it. The upstream server then returns spoofed DNS records to AdGuard Home.
    *   **Impact:** AdGuard Home, and consequently the application, receives incorrect DNS information. This can lead to the application connecting to malicious servers, resulting in malware infections, data theft, or phishing attacks.
    *   **Affected Component:** DNS Proxy (upstream server communication and response handling), potentially the Filtering Engine (if it relies on domain names for filtering).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **AdGuard Home-Side:** Enable DNSSEC validation in AdGuard Home. Configure AGH to use reputable and trusted upstream DNS servers that support DNSSEC (e.g., Quad9, Cloudflare DNS, Google Public DNS). Use multiple upstream servers for redundancy. Monitor AGH logs for DNSSEC validation failures.
        *   **Operational:** Stay informed about the security posture of chosen upstream DNS providers.

## Threat: [Query Log Information Disclosure](./threats/query_log_information_disclosure.md)

*   **Description:** AdGuard Home's query logs, if enabled, contain a record of all DNS queries processed. An attacker gains unauthorized access to these logs (e.g., through a compromised web interface, direct file access, or a vulnerability in the logging mechanism).
    *   **Impact:** The attacker can see which domains the application (and potentially its users) are accessing. This can reveal sensitive information about user behavior, internal network structure, and the application's functionality. This is a significant privacy violation.
    *   **Affected Component:** Query Logging module (responsible for writing and storing query logs), Web Interface (if it provides access to query logs), File System (where logs are stored).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **AdGuard Home-Side:** Disable query logging if it's not strictly necessary. If enabled, restrict access to the query logs to authorized users/processes. Implement strong access controls on the log files. Configure log rotation and retention policies to minimize the amount of data stored. Consider anonymizing or pseudonymizing the logs. Encrypt the log files at rest.
        *   **Operational:** Regularly review and audit access to query logs.

## Threat: [Denial of Service (DoS) against AdGuard Home](./threats/denial_of_service__dos__against_adguard_home.md)

*   **Description:** An attacker floods AdGuard Home with a large number of DNS requests, exceeding its capacity to process them. This can be a simple flood attack or a more sophisticated attack targeting specific DNS records or features.
    *   **Impact:** AdGuard Home becomes unresponsive, preventing the application from resolving DNS queries. This effectively disables the application's network connectivity and any functionality that relies on DNS resolution.
    *   **Affected Component:** DNS Proxy (request handling), potentially the entire AdGuard Home instance.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **AdGuard Home-Side:** Enable rate limiting in AdGuard Home to restrict the number of requests from a single client or IP address. Configure appropriate resource limits (CPU, memory, connections). Use a robust DNS server implementation that is resistant to common DoS attacks.
        *   **Infrastructure:** Deploy AdGuard Home behind a load balancer or firewall that can filter malicious traffic. Consider using a DNS firewall or DDoS protection service. Monitor AGH's resource usage and performance.

## Threat: [API Authentication Bypass](./threats/api_authentication_bypass.md)

*   **Description:** An attacker discovers a vulnerability in the AdGuard Home API authentication mechanism (e.g., a flaw in the API key validation, a session management issue, or a bypass of authentication checks). They are then able to make API requests without valid credentials.
    *   **Impact:** The attacker can access and modify AdGuard Home's configuration, potentially disabling filtering, redirecting traffic, or extracting sensitive information. This is similar to unauthorized configuration modification but specifically targets the API.
    *   **Affected Component:** AdGuard Home API (authentication and authorization logic, specifically `/control/*` endpoints).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **AdGuard Home-Side:** Use strong, randomly generated API keys. Implement robust session management with secure cookies and timeouts. Thoroughly validate all API requests, including authentication tokens and authorization checks. Regularly review and update the API authentication code. Follow secure coding practices to prevent common vulnerabilities (e.g., OWASP Top 10).
        *   **Application-Side:** Securely store and manage API keys. Avoid hardcoding API keys in the application code.

## Threat: [Privilege Escalation within AdGuard Home](./threats/privilege_escalation_within_adguard_home.md)

*   **Description:** An attacker exploits a vulnerability in AdGuard Home (e.g., a buffer overflow, a code injection flaw, or a misconfiguration) to gain elevated privileges on the system running AGH. This could allow them to execute arbitrary code with the privileges of the AdGuard Home process, potentially leading to root access.
    *   **Impact:** The attacker gains full control of the system running AdGuard Home, allowing them to access sensitive data, modify system configurations, install malware, and potentially compromise other systems on the network.
    *   **Affected Component:** Potentially any component of AdGuard Home, depending on the specific vulnerability.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **AdGuard Home-Side:** Keep AdGuard Home updated to the latest version to patch known vulnerabilities. Run AdGuard Home with the least necessary privileges (e.g., as a non-root user). Use a containerized environment (e.g., Docker) to isolate AGH from the host system. Implement security hardening measures on the host system (e.g., SELinux, AppArmor, firewall).
        *   **Operational:** Regularly perform vulnerability scans and penetration testing on the system running AdGuard Home.

## Threat: [Tampering with AdGuard Home Updates](./threats/tampering_with_adguard_home_updates.md)

*   **Description:** An attacker intercepts or manipulates the update process for AdGuard Home. This could involve compromising the update server, injecting malicious code into an update package, or tricking AGH into installing a downgraded or modified version.
    *   **Impact:** AdGuard Home runs a compromised or outdated version, potentially introducing new vulnerabilities or disabling security features. This could lead to any of the other threats becoming exploitable.
    *   **Affected Component:** AdGuard Home's update mechanism (code responsible for downloading, verifying, and installing updates).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        * **AdGuard Home-Side:** Use HTTPS for update downloads. Verify the digital signature of update packages. Implement rollback mechanisms to revert to a previous version if an update fails or causes issues.
        * **Operational:** Monitor the integrity of the update server and distribution channels.

