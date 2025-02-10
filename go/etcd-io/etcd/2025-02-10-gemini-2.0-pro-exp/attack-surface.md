# Attack Surface Analysis for etcd-io/etcd

## Attack Surface: [Unauthorized Cluster Access (Client API)](./attack_surfaces/unauthorized_cluster_access__client_api_.md)

*   **Description:** Attackers gaining unauthorized access to the etcd client API (typically port 2379).
*   **How etcd Contributes:** etcd exposes a network API for clients to interact with the data store. This API is the primary target for unauthorized access.
*   **Example:** An attacker scans for open port 2379, finds an etcd instance without authentication, and uses `etcdctl` or a custom client to read, write, or delete data.
*   **Impact:** Complete data compromise (read, write, delete), cluster disruption, potential for further lateral movement within the network.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Network Segmentation:** Place etcd on a private network, accessible *only* to authorized application servers. Use firewalls (host and network) to enforce this.
    *   **mTLS Authentication:**  Require mutual TLS (mTLS) for *all* client connections. Clients must present a valid certificate signed by a trusted CA. This prevents unauthorized clients from connecting.
    *   **RBAC (Role-Based Access Control):** Enable etcd's RBAC. Define granular roles (e.g., "read-only-prefix-X", "write-prefix-Y") and assign them to clients. Avoid using a single, all-powerful user.
    *   **Strong Password/Key Management:** If using username/password authentication (less secure than mTLS), use strong, unique passwords and manage them securely (e.g., using a secrets manager). Rotate passwords regularly.
    *   **Rate Limiting:** Implement rate limiting (at the network level or using etcd's built-in features) to prevent brute-force attacks and DoS.
    *   **Auditing:** Enable etcd's audit logging and integrate it with a SIEM or security monitoring system.

## Attack Surface: [Unauthorized Cluster Access (Peer API)](./attack_surfaces/unauthorized_cluster_access__peer_api_.md)

*   **Description:** Attackers gaining access to the etcd peer API (typically port 2380), used for inter-cluster communication.
*   **How etcd Contributes:** etcd uses a separate API for communication between cluster members. Compromising this allows an attacker to join the cluster.
*   **Example:** An attacker discovers an etcd cluster with an exposed peer API and uses it to inject a malicious node into the cluster, disrupting consensus or stealing data.
*   **Impact:** Cluster compromise, data corruption, denial of service, potential for data exfiltration.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strict Network Segmentation:** Isolate the peer network *even more strictly* than the client network. Only etcd nodes should communicate on this network.
    *   **Mandatory mTLS:**  *Always* require mutual TLS (mTLS) for peer communication. This ensures only authorized nodes can join.
    *   **Firewall Rules:** Use strict firewall rules to limit communication on the peer port to only the known IP addresses of other etcd cluster members.

## Attack Surface: [Data Exposure at Rest](./attack_surfaces/data_exposure_at_rest.md)

*   **Description:** Attackers gaining access to the underlying storage where etcd data is stored.
*   **How etcd Contributes:** etcd stores its data on disk (or in a cloud volume). If this storage is not protected, the data is vulnerable.
*   **Example:** An attacker gains access to a server's file system and reads the etcd data directory directly, bypassing etcd's authentication and authorization.
*   **Impact:** Complete data compromise (read access to all data stored in etcd).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Disk Encryption:** Use full-disk encryption (e.g., LUKS, BitLocker, cloud provider encryption) to protect the etcd data directory.
    *   **Application-Level Encryption:** For highly sensitive data, encrypt the *values* before storing them in etcd. This adds a layer of protection even if etcd is compromised.

## Attack Surface: [Snapshot Exposure](./attack_surfaces/snapshot_exposure.md)

*   **Description:** Unauthorized access to etcd snapshots, which contain a full copy of the cluster's data.
*   **How etcd Contributes:** etcd allows taking snapshots for backup and recovery. These snapshots are a prime target for attackers.
*   **Example:** An attacker finds an etcd snapshot stored in an insecurely configured S3 bucket and downloads it, gaining access to the entire dataset.
*   **Impact:** Complete data compromise (read access to all data stored in etcd at the time of the snapshot).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Secure Storage:** Store snapshots in a secure location with restricted access (e.g., encrypted object storage with strict IAM policies).
    *   **Snapshot Encryption:** Encrypt the snapshots themselves using a strong encryption key.
    *   **Retention Policies:** Implement a policy for rotating and deleting old snapshots to minimize the exposure window.

## Attack Surface: [Outdated etcd Version](./attack_surfaces/outdated_etcd_version.md)

*   **Description:** Running an old version of etcd with known vulnerabilities.
*   **How etcd Contributes:** Like all software, etcd has had security vulnerabilities discovered and patched over time.
*   **Example:** An attacker exploits a known vulnerability in an outdated etcd version to gain unauthorized access to the cluster.
*   **Impact:** Varies depending on the vulnerability, but can range from data leaks to complete cluster compromise.
*   **Risk Severity:** High (depending on the specific vulnerabilities)
*   **Mitigation Strategies:**
    *   **Regular Updates:** Stay up-to-date with the latest etcd releases and apply security patches promptly. Subscribe to etcd security announcements.
    *   **Vulnerability Scanning:** Use vulnerability scanning tools to identify outdated etcd instances and known vulnerabilities.

## Attack Surface: [Leaked Credentials](./attack_surfaces/leaked_credentials.md)

*   **Description:** etcd client credentials (certificates, usernames/passwords) are compromised.
*   **How etcd Contributes:** etcd relies on credentials for authentication. If these are leaked, attackers can impersonate legitimate clients.
*   **Example:** A developer accidentally commits etcd client certificates to a public GitHub repository.
*   **Impact:** Unauthorized access to the etcd cluster, with the privileges of the compromised credentials.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Secure Credential Management:** Use a secrets manager (e.g., HashiCorp Vault, AWS Secrets Manager) to store and manage etcd credentials. *Never* hardcode credentials in code or configuration files.
    *   **Short-Lived Credentials:** Use short-lived credentials and rotate them frequently.
    *   **Least Privilege:** Grant only the minimum necessary permissions to each client (using RBAC).

