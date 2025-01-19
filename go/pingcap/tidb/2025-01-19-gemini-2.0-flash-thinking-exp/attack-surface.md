# Attack Surface Analysis for pingcap/tidb

## Attack Surface: [SQL Injection](./attack_surfaces/sql_injection.md)

**Description:** Attackers inject malicious SQL code into application queries to manipulate the database.

**How TiDB Contributes:** TiDB, as the SQL database, is the target of these injections. If the application doesn't properly sanitize input before sending it to TiDB, it becomes vulnerable.

**Example:** An application takes a user-provided username and directly embeds it in a SQL query like `SELECT * FROM users WHERE username = '` + user_input + `'`. A malicious user could input `' OR '1'='1` to bypass authentication.

**Impact:** Data breaches, data modification or deletion, unauthorized access, potential for remote code execution (though less common with modern database systems).

**Risk Severity:** Critical

**Mitigation Strategies:**
*   **Use Parameterized Queries (Prepared Statements):** This is the most effective way to prevent SQL injection by treating user input as data, not executable code.
*   **Principle of Least Privilege:** Grant database users only the necessary permissions to perform their tasks. Avoid using overly permissive accounts.
*   **Regular Security Audits:** Review application code and database configurations for potential SQL injection vulnerabilities.

## Attack Surface: [Weak Authentication and Authorization](./attack_surfaces/weak_authentication_and_authorization.md)

**Description:**  Insufficiently strong authentication mechanisms or poorly configured authorization rules allow unauthorized access to the database.

**How TiDB Contributes:** TiDB manages user accounts and permissions. Weak default passwords, lack of strong password policies, or misconfigured grants directly contribute to this attack surface.

**Example:** Using the default `root` user with a simple or default password, or granting `ALL PRIVILEGES` to a user who only needs read access.

**Impact:** Unauthorized data access, data modification or deletion, potential for complete database compromise.

**Risk Severity:** High

**Mitigation Strategies:**
*   **Enforce Strong Password Policies:** Require complex passwords and regular password changes.
*   **Use Strong Authentication Methods:** Consider using more robust authentication methods beyond simple passwords, such as multi-factor authentication (MFA) if supported by the connection method.
*   **Implement the Principle of Least Privilege:** Grant users only the necessary permissions for their roles.
*   **Regularly Review and Audit User Permissions:** Ensure that permissions are still appropriate and remove unnecessary grants.
*   **Disable Default Accounts:** Change or disable default administrative accounts with weak default credentials.

## Attack Surface: [Unencrypted Inter-Node Communication (TiKV)](./attack_surfaces/unencrypted_inter-node_communication__tikv_.md)

**Description:** Data transmitted between TiKV nodes is not encrypted, allowing attackers on the network to eavesdrop on sensitive information.

**How TiDB Contributes:** TiDB relies on TiKV for distributed storage. If the communication between TiKV nodes is not secured, it exposes data in transit.

**Example:** An attacker on the same network as the TiDB cluster intercepts data being replicated between TiKV nodes, potentially revealing sensitive customer information.

**Impact:** Confidentiality breach, exposure of sensitive data.

**Risk Severity:** High

**Mitigation Strategies:**
*   **Enable TLS Encryption for TiKV Communication:** Configure TiKV to use TLS for all inter-node communication.
*   **Secure the Network Environment:** Implement network segmentation and access controls to limit access to the TiDB cluster's network.

## Attack Surface: [Unsecured PD API](./attack_surfaces/unsecured_pd_api.md)

**Description:** The Placement Driver (PD) API, used for cluster management, is not properly secured, allowing unauthorized access to administrative functions.

**How TiDB Contributes:** PD is a core component of TiDB. An unsecured PD API allows attackers to manipulate the cluster's configuration and potentially disrupt operations.

**Example:** An attacker gains access to the PD API and reconfigures data placement rules, leading to data unavailability or concentrating data on compromised nodes.

**Impact:** Cluster instability, data unavailability, potential data loss or corruption, denial of service.

**Risk Severity:** Critical

**Mitigation Strategies:**
*   **Secure PD API Access:** Implement strong authentication and authorization for accessing the PD API.
*   **Restrict Network Access to PD:** Limit network access to the PD API to authorized administrators and monitoring systems.
*   **Regularly Review PD Configurations:** Ensure that PD configurations are secure and follow best practices.

## Attack Surface: [Unsecured TiCDC Change Feed](./attack_surfaces/unsecured_ticdc_change_feed.md)

**Description:** The stream of data changes captured by TiCDC is not properly secured, allowing unauthorized access to sensitive data being replicated.

**How TiDB Contributes:** TiCDC is a TiDB component that streams data changes. If this stream is not secured, it becomes an attack vector.

**Example:** An attacker intercepts the TiCDC change feed and reads sensitive customer transactions being replicated to an analytics database.

**Impact:** Confidentiality breach, exposure of sensitive data.

**Risk Severity:** High

**Mitigation Strategies:**
*   **Encrypt TiCDC Communication:** Ensure that communication channels used by TiCDC are encrypted (e.g., using TLS).
*   **Implement Authentication and Authorization for TiCDC Consumers:**  Require authentication and authorization for any system or application consuming the TiCDC change feed.
*   **Secure Storage of Change Data:** If the change data is persisted, ensure that the storage is properly secured.

