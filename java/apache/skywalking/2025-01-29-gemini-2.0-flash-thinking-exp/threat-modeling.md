# Threat Model Analysis for apache/skywalking

## Threat: [Agent Compromise leading to Monitored Application Compromise](./threats/agent_compromise_leading_to_monitored_application_compromise.md)

*   **Description:** An attacker compromises a SkyWalking agent deployed within a monitored application by exploiting agent vulnerabilities, supply chain attacks, or gaining access to the application environment. Once compromised, the attacker can manipulate the monitored application by injecting malicious code, altering application logic, or exfiltrating sensitive data.
    *   **Impact:**
        *   **Integrity:** Monitored application behavior is altered, potentially leading to data corruption or unexpected functionality.
        *   **Confidentiality:** Sensitive data within the monitored application environment is exposed and potentially exfiltrated.
        *   **Availability:** The monitored application becomes unstable, experiences denial of service, or is taken offline due to malicious actions.
    *   **Affected SkyWalking Component:** SkyWalking Language Agents
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Regularly update SkyWalking agents to the latest versions.
        *   Implement strong access controls and security hardening on application environments.
        *   Enforce secure communication (gRPC with TLS) between agents and OAP server.
        *   Consider agent integrity checks and signature verification.
        *   Employ application-level firewalls or intrusion detection systems.

## Threat: [Agent Exposing Sensitive Data from Monitored Application](./threats/agent_exposing_sensitive_data_from_monitored_application.md)

*   **Description:** SkyWalking agents, if misconfigured or if the monitored application logs sensitive information, might inadvertently collect and transmit sensitive data (e.g., API keys, passwords, PII) as telemetry data to the OAP server and UI.
    *   **Impact:**
        *   **Confidentiality:** Sensitive data from the monitored application is exposed to unauthorized parties with access to SkyWalking telemetry data, potentially leading to data breaches and compliance violations.
    *   **Affected SkyWalking Component:** SkyWalking Language Agents, OAP Server, SkyWalking UI
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Carefully review and configure agent data collection rules to prevent capturing sensitive data.
        *   Implement data masking or redaction within the agent or OAP server.
        *   Educate developers on secure logging practices.
        *   Regularly audit collected telemetry data for sensitive information.

## Threat: [OAP Server Compromise](./threats/oap_server_compromise.md)

*   **Description:** An attacker compromises the SkyWalking OAP server by exploiting vulnerabilities in the OAP software, OS, or through network attacks. A compromised OAP server grants access to all collected telemetry data and control over the monitoring system.
    *   **Impact:**
        *   **Integrity:** Attackers can tamper with monitoring data, inject false data, or disable monitoring.
        *   **Confidentiality:** All sensitive telemetry data collected from monitored applications is exposed.
        *   **Availability:** The OAP server can be disabled, disrupting monitoring services, or used as a launchpad for further attacks.
    *   **Affected SkyWalking Component:** SkyWalking OAP Server
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Regularly update OAP server software and OS.
        *   Implement strong access controls and network segmentation for the OAP server.
        *   Harden the OAP server OS and disable unnecessary services.
        *   Use secure communication (TLS/SSL) for all OAP server interfaces.
        *   Implement intrusion detection and prevention systems (IDS/IPS).
        *   Regularly audit OAP server security configurations and access logs.

## Threat: [UI Compromise](./threats/ui_compromise.md)

*   **Description:** The SkyWalking UI is compromised through web application vulnerabilities like XSS, CSRF, or insecure authentication. Attackers can gain unauthorized access to telemetry data, manipulate the UI, or inject malicious scripts into user sessions.
    *   **Impact:**
        *   **Integrity:** The UI can be defaced, manipulated to display false data, or used to inject malicious scripts.
        *   **Confidentiality:** Sensitive telemetry data displayed in the UI becomes accessible to attackers.
        *   **Availability:** The UI can be disabled, disrupting access to monitoring information.
    *   **Affected SkyWalking Component:** SkyWalking UI
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Regularly update the SkyWalking UI to patch web application vulnerabilities.
        *   Implement standard web application security best practices (input validation, output encoding, CSRF protection, secure authentication).
        *   Use Content Security Policy (CSP) to mitigate XSS attacks.
        *   Deploy the UI behind a Web Application Firewall (WAF).

## Threat: [Storage Backend Compromise](./threats/storage_backend_compromise.md)

*   **Description:** The storage backend used by SkyWalking (e.g., Elasticsearch) is compromised by exploiting vulnerabilities in the storage software, OS, or through network access. Attackers gain access to all stored telemetry data.
    *   **Impact:**
        *   **Integrity:** Attackers can corrupt or delete stored telemetry data, leading to loss of historical monitoring information.
        *   **Confidentiality:** All stored telemetry data, potentially including sensitive information, is exposed.
        *   **Availability:** The storage service can be disrupted, leading to loss of monitoring data and impacting OAP server functionality.
    *   **Affected SkyWalking Component:** Storage Backend (Elasticsearch, etc.)
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Harden the storage backend system according to vendor security best practices.
        *   Implement strong access controls and authentication for the storage backend.
        *   Use network segmentation to isolate the storage backend.
        *   Encrypt data at rest and in transit within the storage backend.
        *   Regularly back up storage data.

## Threat: [Data Leakage from Storage Backend](./threats/data_leakage_from_storage_backend.md)

*   **Description:** A misconfigured or insecure storage backend exposes telemetry data to unauthorized access due to overly permissive access controls, public access, or storage software vulnerabilities.
    *   **Impact:**
        *   **Confidentiality:** Telemetry data stored in the backend, potentially including sensitive information, is disclosed to unauthorized parties, leading to data breaches and compliance violations.
    *   **Affected SkyWalking Component:** Storage Backend
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Properly configure access controls and authentication for the storage backend.
        *   Regularly audit storage backend security configurations.
        *   Ensure data at rest encryption is enabled and properly configured.
        *   Monitor storage backend access logs for suspicious activity.

## Threat: [Misconfiguration of SkyWalking Components (Severe Misconfigurations)](./threats/misconfiguration_of_skywalking_components__severe_misconfigurations_.md)

*   **Description:** Severe misconfigurations of SkyWalking components (agents, OAP server, UI, storage backend) introduce critical vulnerabilities, leading to significant security breaches or service disruptions. Examples include exposing sensitive ports publicly, using default credentials, or disabling essential security features.
    *   **Impact:**
        *   **Integrity:** Inaccurate monitoring data, system instability.
        *   **Availability:** Service disruptions, system outages.
        *   **Confidentiality:** Data leakage, unauthorized access to sensitive information.
    *   **Affected SkyWalking Component:** All SkyWalking Components (Configuration)
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Thoroughly follow SkyWalking security best practices and configuration guidelines.
        *   Implement Infrastructure-as-Code (IaC) for consistent and auditable deployments.
        *   Regularly review and audit SkyWalking configurations.
        *   Provide security training to personnel managing SkyWalking.

