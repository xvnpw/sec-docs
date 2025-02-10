# Attack Surface Analysis for hashicorp/consul

## Attack Surface: [Unauthorized Access to Consul Agents (HTTP API/CLI)](./attack_surfaces/unauthorized_access_to_consul_agents__http_apicli_.md)

*   **1. Unauthorized Access to Consul Agents (HTTP API/CLI)**

    *   **Description:** Attackers gain unauthorized access to Consul agents, allowing them to query, modify, or disrupt the Consul cluster and registered services.
    *   **Consul Contribution:** Consul's HTTP API and CLI provide powerful interfaces for interacting with the cluster. If these are exposed without authentication or with weak ACLs, they become direct attack vectors.
    *   **Example:** An attacker accesses the `/v1/kv/` endpoint on a publicly exposed Consul agent without authentication and retrieves sensitive configuration data.
    *   **Impact:** Data breaches (secrets, configuration), service disruption, potential for complete cluster compromise.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Enable and Enforce ACLs:** Implement a "deny by default" ACL policy. Create granular ACL rules. Use ACL tokens for all agent interactions.
        *   **Require TLS:** Configure Consul to use HTTPS for all API communication (`verify_incoming`, `verify_outgoing`, `verify_server_hostname`). Use valid TLS certificates.
        *   **Network Segmentation:** Restrict network access to Consul agent ports (8500, 8501, etc.) using firewalls. Only allow access from trusted networks.
        *   **Regular Auditing:** Regularly review and audit ACL rules and agent configurations.

## Attack Surface: [Malicious Service Registration](./attack_surfaces/malicious_service_registration.md)

*   **2. Malicious Service Registration**

    *   **Description:** Attackers register rogue services with Consul, potentially redirecting legitimate traffic.
    *   **Consul Contribution:** Consul's service registration mechanism, if not properly secured via ACLs, allows any client with network access to register services.
    *   **Example:** An attacker registers a service named "payments-api" that points to their own malicious server, redirecting clients.
    *   **Impact:** Man-in-the-middle attacks, data theft, service disruption.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Strict ACLs for Service Registration:** Use ACLs to restrict service registration to authorized clients and services. Require specific tokens with `service:write` permissions.
        *   **Service Health Checks:** Implement robust health checks. Consul will automatically deregister unhealthy services.
        *   **Intentions (Consul Connect):** Use Consul Intentions to define explicit service-to-service communication rules.
        *   **Monitoring and Alerting:** Monitor service registrations for suspicious activity.

## Attack Surface: [Gossip Protocol Exploitation (Serf)](./attack_surfaces/gossip_protocol_exploitation__serf_.md)

*   **3. Gossip Protocol Exploitation (Serf)**

    *   **Description:** Attackers exploit the Serf gossip protocol to inject malicious nodes, disrupt the cluster, or eavesdrop.
    *   **Consul Contribution:** Consul relies on the Serf gossip protocol for cluster membership and failure detection. This protocol, if unencrypted and accessible, is an attack vector.
    *   **Example:** An attacker joins the Consul cluster's gossip network and injects false information about node status.
    *   **Impact:** Cluster instability, denial of service, potential for data corruption.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Gossip Encryption:** Enable encryption for Serf communication using the `encrypt` configuration option (gossip encryption key).
        *   **Network Segmentation:** Restrict network access to the Serf ports (8301 TCP/UDP) to only other Consul servers.
        *   **Regular Key Rotation:** Rotate the gossip encryption key periodically.

## Attack Surface: [Raft Consensus Protocol Compromise](./attack_surfaces/raft_consensus_protocol_compromise.md)

*   **4. Raft Consensus Protocol Compromise**

    *   **Description:** Attackers compromise the Raft consensus protocol, potentially gaining control of the Consul cluster.
    *   **Consul Contribution:** Consul uses Raft for data replication and leader election. Compromising Raft gives control over the cluster's state.
    *   **Example:** An attacker gains access to a majority of Consul servers, allowing them to forge consensus and modify the cluster's state.
    *   **Impact:** Complete cluster compromise, data manipulation, denial of service.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **TLS for Raft:** Enable TLS for Raft communication (`verify_incoming`, etc.).
        *   **Network Segmentation:** Strictly limit network access to the Raft port (8300 TCP) to only other Consul servers.
        *   **Strong Server Security:** Harden the operating systems of Consul servers.
        *   **Autopilot:** Utilize Consul's Autopilot features.

## Attack Surface: [Sensitive Data Exposure in KV Store](./attack_surfaces/sensitive_data_exposure_in_kv_store.md)

*   **5. Sensitive Data Exposure in KV Store**

    *   **Description:** Attackers gain unauthorized read access to the Consul Key/Value (KV) store.
    *   **Consul Contribution:** Consul's KV store is used for configuration data. If not properly secured with ACLs, it can be a source of data breaches.
    *   **Example:** An attacker with read access to the KV store retrieves database credentials.
    *   **Impact:** Data breaches, unauthorized access to other systems.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Granular ACLs for KV Access:** Use ACLs to restrict access to specific keys and prefixes within the KV store.
        *   **Secrets Management Integration:** Avoid storing highly sensitive secrets directly in the KV store. Use a dedicated secrets management solution (like HashiCorp Vault).
        *   **Data Validation:** Always validate and sanitize data retrieved from the KV store.
        *   **Encryption at Rest (Indirect):** Encrypt sensitive data *before* storing it in Consul.

