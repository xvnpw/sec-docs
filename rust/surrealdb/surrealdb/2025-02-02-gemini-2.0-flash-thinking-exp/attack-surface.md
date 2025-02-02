# Attack Surface Analysis for surrealdb/surrealdb

## Attack Surface: [SurrealQL Injection](./attack_surfaces/surrealql_injection.md)

*   **Description:** Exploiting vulnerabilities in dynamically constructed SurrealQL queries to manipulate SurrealDB database operations. This is a direct consequence of using SurrealDB's query language, SurrealQL, without proper input handling.
*   **SurrealDB Contribution:** SurrealDB's core functionality relies on SurrealQL.  Improper handling of user input within SurrealQL queries directly opens this attack vector.
*   **Example:** An application uses user-provided table names directly in a SurrealQL query like `SELECT * FROM ${tableName} WHERE ...`.  An attacker could inject malicious SurrealQL by providing a crafted `tableName` value, potentially leading to unauthorized data access or modification.
*   **Impact:** Data breach, unauthorized data modification or deletion, privilege escalation within SurrealDB, potential for limited server-side command execution depending on SurrealDB features and vulnerabilities.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Mandatory Parameterized Queries:**  *Always* use parameterized queries or prepared statements offered by SurrealDB client drivers. This is the primary defense against SurrealQL injection.
    *   **Strict Input Validation (Defense-in-depth):**  Validate and sanitize user inputs *before* they are used in *any* part of a SurrealQL query, even when using parameterization, as a secondary security layer. Focus on validating data types and formats expected by your SurrealQL queries.
    *   **Principle of Least Privilege (SurrealDB Users):**  Grant SurrealDB database users used by the application only the *minimum* necessary permissions required for their specific functions. This limits the damage an attacker can do even if injection is successful.

## Attack Surface: [Weak or Misconfigured SurrealDB Authentication](./attack_surfaces/weak_or_misconfigured_surrealdb_authentication.md)

*   **Description:** Exploiting weaknesses in SurrealDB's built-in authentication mechanisms or misconfigurations to bypass access controls and gain unauthorized access to the SurrealDB instance. This directly targets SurrealDB's security features.
*   **SurrealDB Contribution:** SurrealDB provides its own authentication and authorization system.  Vulnerabilities arise from weak credentials, insecure configuration of these systems, or flaws in SurrealDB's implementation.
*   **Example:** Using default or easily guessable passwords for SurrealDB administrative users (like `root`), failing to properly configure role-based access control in SurrealDB, or exposing SurrealDB's authentication endpoints without proper protection.
*   **Impact:** Complete unauthorized access to the SurrealDB database, full data breach, data manipulation, potential for denial of service, and in severe cases, compromise of the underlying server if vulnerabilities allow for escalation.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Enforce Strong Credentials:**  Mandate strong, unique passwords for *all* SurrealDB users. Utilize key-based authentication where supported by SurrealDB for enhanced security. Regularly rotate credentials.
    *   **Principle of Least Privilege (SurrealDB Roles & Users):**  Implement and strictly enforce role-based access control within SurrealDB. Create specific roles with minimal necessary permissions and assign users to these roles. Avoid using overly permissive built-in roles in application contexts.
    *   **Secure Authentication Configuration:**  Follow SurrealDB's official security guidelines for authentication configuration. Disable default accounts if possible, enforce strong authentication methods, and regularly review and audit authentication settings.
    *   **Regular Security Audits (SurrealDB Configuration):** Periodically audit SurrealDB's authentication and authorization configurations to identify and remediate any weaknesses or misconfigurations.

## Attack Surface: [Unsecured Network Exposure of SurrealDB Server](./attack_surfaces/unsecured_network_exposure_of_surrealdb_server.md)

*   **Description:** Gaining unauthorized network access to the SurrealDB server due to improper network security configurations, making the SurrealDB service directly reachable from untrusted networks. This is about how SurrealDB is deployed and made accessible.
*   **SurrealDB Contribution:** SurrealDB operates as a network server, listening on specific ports.  Default configurations or lack of network security measures can lead to direct exposure.
*   **Example:** Running a SurrealDB server with its default port (e.g., 8000 or 8080) directly exposed to the public internet without any firewall or network segmentation, allowing anyone on the internet to attempt connections and exploit potential vulnerabilities in SurrealDB or its configuration.
*   **Impact:** Unauthorized access to the SurrealDB database, data breach, denial of service, potential for server compromise if network-level vulnerabilities are exploited.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Network Segmentation (Mandatory):**  Deploy SurrealDB servers within a private, isolated network segment.  Do *not* expose SurrealDB directly to the public internet.
    *   **Strict Firewall Rules:**  Configure firewalls to *strictly* limit access to SurrealDB ports. Allow connections *only* from authorized and trusted sources (e.g., application servers within the same private network, specific administrator IPs for management).
    *   **Enforce Secure Protocols (TLS/SSL):**  Ensure *all* network communication with SurrealDB is encrypted using TLS/SSL. Configure SurrealDB to enforce secure connection protocols and reject insecure connections.
    *   **Regular Security Audits (Network Infrastructure):**  Periodically review network configurations, firewall rules, and network segmentation related to SurrealDB to ensure they remain effective and secure.

