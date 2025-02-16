# Attack Surface Analysis for tikv/tikv

## Attack Surface: [Unauthorized Access to Placement Driver (PD)](./attack_surfaces/unauthorized_access_to_placement_driver__pd_.md)

*   **Description:**  Direct, unauthorized access to the PD, allowing manipulation of cluster metadata and control.
*   **How TiKV Contributes:** PD is the central control plane *of TiKV*; its exposure is inherent to TiKV's architecture and is a TiKV-specific component.
*   **Example:** An attacker gains access to the PD's default port (2379) without authentication and issues commands to remove legitimate TiKV nodes, causing data loss.
*   **Impact:** Complete cluster compromise, data loss, data unavailability, potential data exfiltration.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Network Segmentation:** Isolate the PD within a private network, accessible only to trusted components (TiKV nodes, authorized management tools).  Use firewalls and network access control lists (ACLs).
    *   **Authentication & Authorization:**  Enable strong authentication (e.g., TLS client certificates, strong passwords) and authorization (RBAC) for all PD access.
    *   **Regular Auditing:**  Monitor PD access logs for suspicious activity.  Implement intrusion detection systems (IDS).
    *   **Rate Limiting:** Implement rate limiting on the PD API.
    *   **Keep PD Updated:** Regularly update PD to the latest version.

## Attack Surface: [Unauthorized Access to TiKV Nodes](./attack_surfaces/unauthorized_access_to_tikv_nodes.md)

*   **Description:** Direct, unauthorized access to individual TiKV nodes, allowing data read/write/modification.
*   **How TiKV Contributes:** TiKV nodes store the actual data; their exposure is a *direct* risk to data integrity and confidentiality, and they are core TiKV components.
*   **Example:** An attacker gains access to a TiKV node's gRPC port (20160) and directly reads raw data, bypassing application-level security.
*   **Impact:** Data exfiltration, data tampering, data corruption, denial of service.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Network Segmentation:**  Isolate TiKV nodes within a private network. Use firewalls and ACLs.
    *   **Authentication & Authorization:** Enable strong authentication (e.g., TLS client certificates) and authorization for all TiKV node access.
    *   **Encryption at Rest:**  Enable encryption at rest for data stored on TiKV nodes.
    *   **Regular Auditing:** Monitor TiKV node access logs.
    *   **Rate Limiting:** Implement rate limiting on the TiKV API.
    *   **Keep TiKV Updated:** Regularly update TiKV nodes.

## Attack Surface: [Man-in-the-Middle (MitM) Attacks on TiKV Communication](./attack_surfaces/man-in-the-middle__mitm__attacks_on_tikv_communication.md)

*   **Description:** Interception and modification of communication *between TiKV components* (PD-TiKV, TiKV-TiKV) or between clients and TiKV.
*   **How TiKV Contributes:** TiKV relies on network communication *for its distributed operation*; insecure communication *between its core components* is a direct vulnerability.
*   **Example:** An attacker intercepts communication between a TiKV node and the PD, modifying region location information.
*   **Impact:** Data corruption, data inconsistency, denial of service, data exfiltration.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Mutual TLS (mTLS):**  Require mTLS for *all* communication between TiKV components and between clients and TiKV.
    *   **Network Segmentation:** Provides an additional layer of defense.
    *   **Certificate Pinning:** Consider certificate pinning.

## Attack Surface: [Denial of Service (DoS) against PD or TiKV Nodes](./attack_surfaces/denial_of_service__dos__against_pd_or_tikv_nodes.md)

*   **Description:** Overwhelming the PD or TiKV nodes with requests, making them unavailable.
*   **How TiKV Contributes:**  TiKV's distributed nature means that DoS attacks can impact the entire cluster or specific regions.  The PD and TiKV nodes are *direct targets*.
*   **Example:** An attacker floods the PD with requests, preventing it from managing regions.
*   **Impact:** Data unavailability, service disruption.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Rate Limiting:** Implement robust rate limiting on both PD and TiKV nodes.
    *   **Network Segmentation & Firewalls:**  Limit access.
    *   **Resource Limits:** Configure resource limits for TiKV processes.
    *   **Load Balancing:**  Distribute client requests across multiple TiKV nodes.
    *   **Monitoring & Alerting:**  Detect and respond to DoS attacks quickly.
    *   **Traffic Shaping/Filtering:** Prioritize legitimate requests.

## Attack Surface: [Insecure Configuration (TiKV-Specific)](./attack_surfaces/insecure_configuration__tikv-specific_.md)

*   **Description:** Misconfigurations *of TiKV itself*, such as disabling security features or using default credentials.  This is distinct from general system misconfiguration.
*   **How TiKV Contributes:** TiKV provides many configuration options; incorrect settings *within TiKV's configuration* create vulnerabilities.
*   **Example:** Running TiKV without enabling authentication or TLS *within the TiKV configuration*.
*   **Impact:** Varies, but can range from data exfiltration to complete system compromise.
*   **Risk Severity:** High (potentially Critical)
*   **Mitigation Strategies:**
    *   **Follow Security Best Practices:**  Adhere to the official TiKV security documentation.
    *   **Use Configuration Management Tools:**  Automate TiKV configuration.
    *   **Regular Configuration Audits:**  Periodically review TiKV configurations.
    *   **Principle of Least Privilege:**  Grant only necessary permissions.

