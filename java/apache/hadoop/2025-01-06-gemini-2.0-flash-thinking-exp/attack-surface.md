# Attack Surface Analysis for apache/hadoop

## Attack Surface: [Insecure Default Configurations](./attack_surfaces/insecure_default_configurations.md)

*   **Attack Surface:** Insecure Default Configurations
    *   **Description:** Hadoop components (like NameNode, DataNodes, ResourceManager) often have default configurations that lack strong authentication or authorization, or have well-known default credentials.
    *   **How Hadoop Contributes to the Attack Surface:** Hadoop's initial setup often prioritizes ease of deployment over security, leading to permissive default settings.
    *   **Example:**  A new Hadoop cluster is deployed without changing the default administrative web UI credentials. An attacker can access the UI and gain full control over the cluster.
    *   **Impact:** Complete compromise of the Hadoop cluster, including data access, modification, deletion, and potential for using the cluster for malicious activities (e.g., cryptojacking).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Change all default administrative passwords immediately after deployment.
        *   Enable strong authentication mechanisms like Kerberos.
        *   Review and harden default configurations for all Hadoop components.
        *   Disable unnecessary services and ports.

## Attack Surface: [Lack of or Weak Authentication and Authorization](./attack_surfaces/lack_of_or_weak_authentication_and_authorization.md)

*   **Attack Surface:** Lack of or Weak Authentication and Authorization
    *   **Description:**  Insufficient or poorly implemented authentication and authorization mechanisms allow unauthorized users or processes to access Hadoop resources and data.
    *   **How Hadoop Contributes to the Attack Surface:** While Hadoop supports strong authentication like Kerberos, it's not always enabled or configured correctly, leaving systems vulnerable. Older versions had less granular authorization models.
    *   **Example:**  A user is granted overly broad permissions in HDFS, allowing them to access sensitive data belonging to other users or applications.
    *   **Impact:** Unauthorized data access, modification, or deletion; resource abuse; potential for privilege escalation.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Implement and enforce Kerberos authentication for all Hadoop components.
        *   Utilize Hadoop's Access Control Lists (ACLs) for fine-grained authorization in HDFS.
        *   Configure YARN queue access controls to restrict resource usage.
        *   Regularly review and audit user permissions and access controls.

## Attack Surface: [Unencrypted Data in Transit](./attack_surfaces/unencrypted_data_in_transit.md)

*   **Attack Surface:** Unencrypted Data in Transit
    *   **Description:** Communication between Hadoop components (e.g., NameNode to DataNode, client to cluster) is not encrypted, allowing attackers to eavesdrop and intercept sensitive data.
    *   **How Hadoop Contributes to the Attack Surface:** Hadoop's internal communication protocols might not have encryption enabled by default, requiring explicit configuration.
    *   **Example:** An attacker on the network can capture packets between a client and the Hadoop cluster, revealing sensitive data being processed or stored.
    *   **Impact:** Confidentiality breach, exposure of sensitive data, potential for man-in-the-middle attacks.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Enable encryption for RPC communication between Hadoop daemons using protocols like SASL with encryption.
        *   Use HTTPS for accessing Hadoop web UIs.
        *   Consider using network-level encryption (e.g., TLS/SSL) for all communication within the Hadoop cluster.

## Attack Surface: [Insecure Data Serialization/Deserialization](./attack_surfaces/insecure_data_serializationdeserialization.md)

*   **Attack Surface:** Insecure Data Serialization/Deserialization
    *   **Description:** Flaws in how Hadoop serializes and deserializes data (e.g., using Java serialization) can be exploited to execute arbitrary code or manipulate data.
    *   **How Hadoop Contributes to the Attack Surface:** Hadoop uses serialization for inter-process communication and data storage, making it a potential attack vector.
    *   **Example:** An attacker crafts a malicious serialized object that, when deserialized by a Hadoop component, executes arbitrary code on the server.
    *   **Impact:** Remote code execution, data corruption, denial of service.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Avoid using Java serialization if possible. Prefer safer alternatives like Protocol Buffers or Avro.
        *   If Java serialization is necessary, carefully validate and sanitize deserialized data.
        *   Keep Hadoop and its dependencies updated to patch known serialization vulnerabilities.

## Attack Surface: [Exposure of Hadoop Daemons to Untrusted Networks](./attack_surfaces/exposure_of_hadoop_daemons_to_untrusted_networks.md)

*   **Attack Surface:** Exposure of Hadoop Daemons to Untrusted Networks
    *   **Description:** Hadoop daemons (e.g., NameNode, DataNodes) are directly accessible from untrusted networks without proper firewalling or network segmentation.
    *   **How Hadoop Contributes to the Attack Surface:** Hadoop's distributed nature requires network communication, but improper network configuration can expose these services.
    *   **Example:** The NameNode's RPC port is exposed to the internet, allowing attackers to attempt to directly connect and exploit potential vulnerabilities.
    *   **Impact:** Direct attacks on Hadoop services, potential for remote code execution, denial of service.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Implement strong firewall rules to restrict access to Hadoop daemons to only trusted networks and hosts.
        *   Use network segmentation to isolate the Hadoop cluster from external networks.
        *   Avoid exposing Hadoop ports directly to the internet.

