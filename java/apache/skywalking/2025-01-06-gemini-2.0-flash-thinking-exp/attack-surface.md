# Attack Surface Analysis for apache/skywalking

## Attack Surface: [Agent Configuration Exploitation](./attack_surfaces/agent_configuration_exploitation.md)

*   **Description:** Attackers gain unauthorized access to the SkyWalking agent's configuration file.
    *   **How SkyWalking Contributes to the Attack Surface:** The agent relies on a configuration file (e.g., `agent.config`) that dictates its behavior, including where to send data and security settings.
    *   **Example:** An attacker gains access to the `agent.config` file and modifies the `collector.servers` address to point to their malicious collector, redirecting all telemetry data.
    *   **Impact:** Leakage of sensitive application data to an attacker-controlled system, potential for injecting malicious data back into the system if the attacker's collector is compromised, and disruption of legitimate monitoring.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Secure the agent configuration file with appropriate file system permissions, ensuring only authorized users can read and modify it.
        *   Avoid storing sensitive credentials directly in the configuration file. Consider using environment variables or secure vault solutions.
        *   Implement monitoring and alerting for changes to the agent configuration file.

## Attack Surface: [Collector (OAP) API Vulnerabilities](./attack_surfaces/collector__oap__api_vulnerabilities.md)

*   **Description:** Vulnerabilities exist in the APIs exposed by the SkyWalking OAP for receiving data from agents and potentially for UI interactions.
    *   **How SkyWalking Contributes to the Attack Surface:** The OAP exposes APIs as the central point for receiving and processing monitoring data. These APIs become targets for attacks if not properly secured.
    *   **Example:** An attacker discovers an unauthenticated API endpoint on the OAP that allows them to query sensitive monitoring data. Another example could be an injection vulnerability in an API used by the UI to retrieve data, allowing for unauthorized data access or manipulation.
    *   **Impact:** Unauthorized access to sensitive monitoring data, potential for data manipulation or deletion, and in severe cases, remote code execution on the OAP server.
    *   **Risk Severity:** High to Critical (depending on the specific vulnerability)
    *   **Mitigation Strategies:**
        *   Implement robust authentication and authorization mechanisms for all OAP APIs.
        *   Thoroughly validate and sanitize all input received by the OAP APIs to prevent injection attacks (e.g., SQL injection, NoSQL injection).
        *   Regularly audit and pen-test the OAP APIs for security vulnerabilities.
        *   Keep the SkyWalking OAP updated to the latest version to patch known vulnerabilities.

## Attack Surface: [Insecure Communication Channels](./attack_surfaces/insecure_communication_channels.md)

*   **Description:** Communication between SkyWalking components (agent to OAP, UI to OAP) is not properly secured.
    *   **How SkyWalking Contributes to the Attack Surface:** SkyWalking involves network communication between different components. If this communication is not encrypted, it becomes vulnerable to eavesdropping and manipulation.
    *   **Example:** Communication between the agent and the OAP uses plain HTTP. An attacker on the network can intercept the telemetry data being sent, potentially revealing sensitive application information. Similarly, unencrypted communication between the UI and OAP could expose monitoring data.
    *   **Impact:** Confidentiality breach (exposure of sensitive application or monitoring data), potential for man-in-the-middle attacks where data is intercepted and modified.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Enforce the use of HTTPS/TLS for communication between the UI and the OAP.
        *   Configure agents to communicate with the OAP using secure protocols like gRPC with TLS.
        *   Ensure proper certificate validation is enabled to prevent man-in-the-middle attacks.

