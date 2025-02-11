# Attack Surface Analysis for apache/kafka

## Attack Surface: [Unauthorized Broker Access](./attack_surfaces/unauthorized_broker_access.md)

*   **Description:** Attackers gain direct access to Kafka brokers without proper authentication.
*   **Kafka Contribution:** Brokers expose network ports for client and inter-broker communication.  Kafka's security features (authentication, authorization) must be explicitly enabled and configured.
*   **Example:** An attacker scans for open Kafka ports (default 9092) and connects without credentials, gaining access to all topics if no authentication is enforced (e.g., `allow.everyone.if.no.acl.found=true` is set).
*   **Impact:** Complete data breach (reading all messages), data manipulation (producing malicious messages), denial of service (deleting topics, exhausting resources).
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Network Segmentation:** Isolate Kafka brokers on a dedicated network segment with strict firewall rules, allowing access *only* from authorized clients and other brokers.  This is a *network-level* control, but essential for Kafka security.
    *   **Mandatory Authentication:** Enforce strong authentication using SASL/Kerberos or mTLS.  *Explicitly disable* `allow.everyone.if.no.acl.found=true`.
    *   **Regular Port Scanning:** Conduct regular port scans to detect any unauthorized open ports on the broker hosts.

## Attack Surface: [Plaintext Data Transmission](./attack_surfaces/plaintext_data_transmission.md)

*   **Description:** Data transmitted between clients and brokers, or *between brokers*, is not encrypted.
*   **Kafka Contribution:** Kafka supports both plaintext and TLS-encrypted communication.  The default configuration may *not* enforce TLS.  Inter-broker communication is often overlooked.
*   **Example:** An attacker uses a network sniffer to capture Kafka traffic *between brokers*, revealing sensitive message data replicated across the cluster.
*   **Impact:** Data breach (eavesdropping on sensitive information), credential theft (if SASL is used without TLS), man-in-the-middle attacks.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Mandatory TLS:** Enforce TLS encryption for *all* client-broker and *inter-broker* communication.  Configure brokers and clients with valid certificates.  Use `security.inter.broker.protocol=SSL` (or `SASL_SSL`).
    *   **Configuration Validation:** Regularly validate Kafka configurations (using automated tools if possible) to ensure TLS is enabled and enforced for *all* listeners.
    *   **Disable Plaintext Listeners:** *Explicitly disable* any plaintext listeners on the brokers.  Ensure no `listeners` configuration uses `PLAINTEXT`.

## Attack Surface: [Weak or Misconfigured Authentication/Authorization](./attack_surfaces/weak_or_misconfigured_authenticationauthorization.md)

*   **Description:** Insufficiently strong authentication mechanisms or poorly configured authorization rules (ACLs) allow unauthorized access to topics.
*   **Kafka Contribution:** Kafka provides authentication (SASL, mTLS) and authorization (ACLs) mechanisms, but they must be properly configured.  Misconfiguration is a common source of vulnerabilities.
*   **Example:** ACLs are too permissive, granting all users (or a large group of users) read/write access to all topics, or to sensitive topics they shouldn't access.  A weak SASL mechanism (e.g., SCRAM-SHA-256 with short passwords) is used.
*   **Impact:** Data breach, data manipulation, unauthorized topic creation/deletion.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Strong Authentication:** Use SASL/Kerberos with strong password policies (and keytab management for Kerberos) or mTLS with properly managed certificates (and a robust PKI).  Prefer SASL/SCRAM-SHA-512 or Kerberos.
    *   **Fine-Grained ACLs:** Implement granular Access Control Lists (ACLs) to restrict access to specific topics and operations based on client identity.  Follow the principle of least privilege *meticulously*.  Use specific principal names, not wildcards, whenever possible.
    *   **Regular ACL Audits:** Regularly review and audit ACLs to ensure they are correctly configured and reflect current security requirements.  Automate this process if possible.

## Attack Surface: [Unsecured ZooKeeper/KRaft Access](./attack_surfaces/unsecured_zookeeperkraft_access.md)

*   **Description:** Attackers gain unauthorized access to ZooKeeper or KRaft, allowing them to manipulate cluster metadata.
*   **Kafka Contribution:** ZooKeeper/KRaft is the *critical* metadata store for Kafka, controlling broker configurations, topic information, and consumer group offsets.  Its security is paramount.
*   **Example:** An attacker connects to an exposed ZooKeeper port (default 2181) without authentication and deletes critical znodes, causing the Kafka cluster to become unstable or unavailable.  With KRaft, an attacker might join an unsecured quorum.
*   **Impact:** Cluster instability, denial of service, potential data loss, potential compromise of brokers (by manipulating their configurations).
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Network Isolation:** Isolate ZooKeeper/KRaft on a *separate* network segment, accessible *only* to Kafka brokers.  This is crucial.
    *   **Authentication:** Enforce strong authentication for ZooKeeper/KRaft access (SASL).  For KRaft, ensure inter-controller communication is secured with TLS and authentication.
    *   **TLS Encryption:** Use TLS encryption for *all* communication with ZooKeeper/KRaft.
    *   **Regular Audits:** Regularly audit ZooKeeper/KRaft access logs (and configuration changes).  Monitor for unauthorized access attempts.

