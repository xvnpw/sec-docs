# Attack Surface Analysis for pingcap/tidb

## Attack Surface: [PD Cluster Compromise](./attack_surfaces/pd_cluster_compromise.md)

*   **Description:**  Full control over the TiDB cluster's metadata and scheduling, achieved by compromising the Placement Driver (PD).
*   **How TiDB Contributes:** PD is the central control plane *of TiDB*. Its compromise means complete control over the database.  This is inherent to TiDB's architecture.
*   **Example:** An attacker exploits a vulnerability in the PD's etcd component to gain remote code execution, then uses this access to manipulate cluster metadata, redirecting traffic or deleting data.
*   **Impact:** Complete cluster compromise, data loss, data modification, denial of service, data exfiltration.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strong Authentication & Authorization:** Enforce TLS with mutual authentication (client certificates) for *all* PD communication (both internal and external).  Use strong, unique passwords and regularly rotate them.  Implement RBAC (Role-Based Access Control) within PD.
    *   **Network Segmentation:** Isolate the PD cluster on a dedicated, highly restricted network segment.  Use strict firewall rules to limit access to *only* essential components (TiDB servers, TiKV instances, and authorized management tools).  No direct external access.
    *   **Regular Patching:** Keep PD, etcd, and *all* dependencies up-to-date with the latest security patches.  Subscribe to TiDB security advisories.  Automated patching is highly recommended.
    *   **Auditing & Monitoring:** Enable detailed audit logging for *all* PD operations.  Monitor PD logs and metrics for suspicious activity (e.g., unusual configuration changes, failed authentication attempts).  Integrate with a SIEM system.
    *   **Intrusion Detection/Prevention:** Deploy intrusion detection/prevention systems (IDS/IPS) to monitor network traffic to and from the PD cluster.

## Attack Surface: [TiKV Data Compromise](./attack_surfaces/tikv_data_compromise.md)

*   **Description:** Unauthorized access to, modification of, or deletion of data stored within TiKV instances.
*   **How TiDB Contributes:** TiKV is the distributed key-value storage layer *of TiDB*.  It holds the actual data.  This is a core component of TiDB.
*   **Example:** An attacker gains access to a TiKV instance due to a misconfigured firewall rule, allowing them to connect directly to the TiKV port (20160) and use the TiKV API to read or modify data.
*   **Impact:** Data loss, data modification, data exfiltration, denial of service.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strong Authentication & Authorization:** Similar to PD, enforce TLS with mutual authentication for *all* TiKV communication.  Use strong, unique passwords.
    *   **Network Segmentation:** Isolate TiKV instances on a dedicated network segment, *separate* from the application tier and the PD cluster.  Use strict firewall rules.  No direct external access.
    *   **Data at Rest Encryption:** Encrypt data stored on TiKV instances using strong encryption algorithms (e.g., AES-256).  Implement robust key management practices, including key rotation and secure key storage (e.g., using a KMS).
    *   **Regular Patching:** Keep TiKV and its dependencies (including gRPC) up-to-date.  Automated patching is highly recommended.
    *   **Auditing & Monitoring:** Enable audit logging for TiKV data access. Monitor for unusual data access patterns. Integrate with a SIEM.

## Attack Surface: [TiDB Server SQL Injection (TiDB-Specific)](./attack_surfaces/tidb_server_sql_injection__tidb-specific_.md)

*   **Description:** Exploiting vulnerabilities in the *TiDB server's* SQL parsing or execution to gain unauthorized access or manipulate data, going beyond standard SQL injection defenses.
*   **How TiDB Contributes:** TiDB has its *own* SQL dialect and parser, which, while largely MySQL-compatible, may have subtle differences or unique features that could be exploited. This is specific to the TiDB server component.
*   **Example:** An attacker crafts a malicious SQL query that exploits a bug in how TiDB handles a specific function or a difference in its parser compared to MySQL, bypassing standard parameterized query protections.
*   **Impact:** Data loss, data modification, data exfiltration, privilege escalation, denial of service.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Strict Parameterized Queries:** *Exclusively* use parameterized queries (prepared statements) for *all* SQL interactions with the TiDB server.  Never construct SQL queries using string concatenation with user-supplied data.  This is the primary defense and is crucial for interacting with TiDB.
    *   **Input Validation:** While parameterized queries are the main defense, implement strict input validation as a secondary layer of security, specifically tailored to the expected data types and formats used by your application when interacting with TiDB.
    *   **Least Privilege:** Grant TiDB users only the minimum necessary privileges within the TiDB database.  Avoid using the `root` user for application connections.  This limits the impact of a successful SQL injection.
    *   **Regular Code Reviews:** Conduct regular security-focused code reviews of application code that interacts with *TiDB*, specifically looking for potential SQL injection vulnerabilities.
    *   **Web Application Firewall (WAF):** Deploy a WAF configured to detect and block SQL injection attempts, ideally with rules tailored to TiDB's SQL dialect if possible.

## Attack Surface: [TiDB Server Denial of Service (DoS)](./attack_surfaces/tidb_server_denial_of_service__dos_.md)

*   **Description:** Overwhelming the *TiDB server* or cluster with requests, making it unavailable to legitimate users.
*   **How TiDB Contributes:** TiDB's distributed architecture, while designed for scalability, can be susceptible to DoS attacks if not properly configured and protected. The *TiDB server* is the entry point for client connections.
*   **Example:** An attacker sends a large number of highly complex queries that consume excessive resources on the TiDB server and TiKV instances, causing the database to become unresponsive.  Alternatively, they could exploit lock contention specific to TiDB's transaction handling.
*   **Impact:** Service unavailability, data unavailability.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Rate Limiting:** Implement rate limiting on client connections and queries to the *TiDB server*, both at the application level and potentially at the network level (e.g., using a load balancer or firewall).
    *   **Query Timeouts:** Set reasonable timeouts for all queries executed against the *TiDB server* to prevent long-running queries from consuming resources indefinitely.
    *   **Resource Quotas:** Configure resource quotas (CPU, memory) for TiDB users within the *TiDB server* configuration to prevent any single user from monopolizing resources.
    *   **Connection Pooling:** Use properly configured connection pooling to manage database connections to the *TiDB server* efficiently and prevent connection exhaustion.
    *   **Slow Query Log:** Monitor the *TiDB server's* slow query log to identify and optimize inefficient queries that could contribute to DoS.
    *   **Load Balancing:** Distribute traffic across multiple *TiDB server* instances using a load balancer.

