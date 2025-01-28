# Attack Surface Analysis for etcd-io/etcd

## Attack Surface: [Unauthenticated Client API Access (Critical)](./attack_surfaces/unauthenticated_client_api_access__critical_.md)

*   **Description:** Exposure of etcd's client API (gRPC or HTTP) without requiring authentication, allowing anyone with network access to interact with etcd.
*   **etcd Contribution:** etcd can be configured to listen on network interfaces and serve client requests without mandatory authentication.
*   **Example:** etcd is deployed with the client API exposed on a public IP without TLS client certificates or username/password authentication. Attackers can read, modify, or delete data.
*   **Impact:** Full compromise of application data, configuration, and potential denial of service.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Enable Authentication:** Configure etcd to require authentication using TLS client certificates or username/password.
    *   **Network Segmentation:** Restrict network access to the etcd client API using firewalls or network policies.

## Attack Surface: [Insecure Client-to-etcd Communication (No TLS) (High)](./attack_surfaces/insecure_client-to-etcd_communication__no_tls___high_.md)

*   **Description:** Communication between applications and the etcd client API is not encrypted using TLS, exposing data in transit.
*   **etcd Contribution:** etcd supports both TLS and non-TLS client API communication. If TLS is not configured, communication is in plain text.
*   **Example:** Applications connect to etcd over HTTP instead of HTTPS. MitM attackers can intercept communication and steal sensitive data like secrets.
*   **Impact:** Confidentiality breach, potential credential theft, data tampering.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Enable TLS for Client API:** Configure etcd to use TLS for the client API and ensure applications connect using HTTPS or gRPC with TLS.
    *   **Certificate Management:** Implement proper certificate management for TLS certificates.

## Attack Surface: [Unauthenticated Peer Communication (Critical)](./attack_surfaces/unauthenticated_peer_communication__critical_.md)

*   **Description:** Communication between etcd cluster members (peers) is not authenticated, allowing rogue nodes to potentially join the cluster.
*   **etcd Contribution:** etcd cluster members communicate for consensus. Lack of peer authentication allows unauthorized nodes to participate.
*   **Example:** etcd cluster deployed without peer TLS authentication. Attackers can launch a rogue etcd instance and join the cluster, gaining control.
*   **Impact:** Cluster compromise, data corruption, denial of service, potential data exfiltration.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Enable Peer TLS Authentication:** Configure etcd to use peer TLS certificates for authentication and encryption of peer communication.
    *   **Network Segmentation:** Isolate the etcd cluster network from untrusted networks.

## Attack Surface: [Insecure Peer-to-Peer Communication (No TLS) (High)](./attack_surfaces/insecure_peer-to-peer_communication__no_tls___high_.md)

*   **Description:** Communication between etcd cluster members (peers) is not encrypted using TLS, exposing cluster-internal data in transit.
*   **etcd Contribution:** etcd supports both TLS and non-TLS for peer communication. Without TLS, peer communication is in plain text.
*   **Example:** Peer communication in an etcd cluster happens over plain TCP. MitM attackers can eavesdrop on sensitive data exchanged between members.
*   **Impact:** Confidentiality breach of cluster internal data, potential for cluster disruption.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Enable TLS for Peer Communication:** Configure etcd to use TLS for peer communication.
    *   **Certificate Management:** Implement proper certificate management for peer TLS certificates.

## Attack Surface: [Weak or Misconfigured Authentication Mechanisms (High)](./attack_surfaces/weak_or_misconfigured_authentication_mechanisms__high_.md)

*   **Description:** Using weak passwords, default credentials, or insecure credential storage for etcd authentication.
*   **etcd Contribution:** etcd provides authentication mechanisms, but their security depends on user configuration and credential management.
*   **Example:** Using default username/password for etcd or storing credentials in plain text configuration files. Attackers gaining access can bypass authentication.
*   **Impact:** Unauthorized access to etcd, data compromise.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Strong Passwords:** Enforce strong password policies for etcd users.
    *   **Secure Credential Storage:** Use secrets management systems or environment variables for storing credentials, avoid plain text storage.
    *   **Regular Credential Rotation:** Implement a process for regularly rotating etcd credentials.

## Attack Surface: [Insufficient or Misconfigured Authorization (RBAC) (High)](./attack_surfaces/insufficient_or_misconfigured_authorization__rbac___high_.md)

*   **Description:** RBAC in etcd is not properly configured, leading to overly permissive access and potential unauthorized actions.
*   **etcd Contribution:** etcd offers RBAC for access control. Misconfiguration can lead to security vulnerabilities.
*   **Example:** Granting overly broad permissions to application roles in etcd RBAC, allowing unintended data access or modification.
*   **Impact:** Unauthorized data access, data modification, potential privilege escalation.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Principle of Least Privilege:** Implement RBAC based on least privilege, granting only necessary permissions.
    *   **Regular RBAC Review:** Periodically review and audit RBAC configurations.
    *   **Stay Updated:** Keep etcd updated to patch potential RBAC vulnerabilities.

## Attack Surface: [Lack of Data at Rest Encryption (High)](./attack_surfaces/lack_of_data_at_rest_encryption__high_.md)

*   **Description:** etcd's data directory on disk is not encrypted, leaving data vulnerable to physical access.
*   **etcd Contribution:** etcd stores data persistently. Lack of data at rest encryption exposes data to physical access threats.
*   **Example:** Attackers gain physical access to an etcd server or backups and can directly read sensitive data from the unencrypted data directory.
*   **Impact:** Confidentiality breach of all data stored in etcd.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Enable Data at Rest Encryption:** Configure etcd to encrypt its data directory at rest.
    *   **Secure Backup Storage:** Encrypt etcd backups and store them securely.

## Attack Surface: [Denial of Service (DoS) via API Abuse (High)](./attack_surfaces/denial_of_service__dos__via_api_abuse__high_.md)

*   **Description:** Attackers overload the etcd client API with excessive requests, causing resource exhaustion and service disruption.
*   **etcd Contribution:** etcd's client API can be targeted for DoS if not protected.
*   **Example:** Attackers send a large volume of requests to the etcd API, overwhelming resources and making it unresponsive.
*   **Impact:** Application downtime, service disruption.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Rate Limiting:** Implement rate limiting on the etcd client API.
    *   **Authentication and Authorization:** Use authentication and authorization to limit API access.
    *   **Resource Monitoring and Alerting:** Monitor etcd resource usage and set up alerts for potential DoS attacks.
    *   **Network Segmentation:** Restrict access to the etcd API to trusted networks.

