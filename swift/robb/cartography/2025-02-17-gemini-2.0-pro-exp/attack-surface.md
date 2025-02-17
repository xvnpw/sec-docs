# Attack Surface Analysis for robb/cartography

## Attack Surface: [1. Unauthorized Access to Neo4j Database](./attack_surfaces/1__unauthorized_access_to_neo4j_database.md)

*   **Description:** Direct, unauthorized access to the Neo4j database containing all collected infrastructure data.
    *   **How Cartography Contributes:** Cartography *uses* Neo4j as its central data store. The database's exposure and the data within it are a direct consequence of using Cartography. This is Cartography's primary data storage mechanism.
    *   **Example:** An attacker discovers the Neo4j database exposed on a public IP address without authentication, allowing them to run arbitrary Cypher queries.
    *   **Impact:** Complete compromise of all infrastructure data collected by Cartography, including cloud resource configurations, relationships, and potentially sensitive metadata. This can lead to further attacks on the underlying infrastructure.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Network Isolation:** Place the Neo4j database on a private network segment, accessible *only* to the Cartography server and authorized applications. Use firewalls and security groups to strictly control access.
        *   **Strong Authentication:** Enforce strong, unique passwords for the Neo4j database. Disable default accounts. Consider using a secrets management solution.
        *   **Authorization:** Implement role-based access control (RBAC) within Neo4j to limit what different users/applications can query.
        *   **Encryption in Transit:** Use TLS/SSL to encrypt all communication between Cartography, the application, and the Neo4j database.
        *   **Encryption at Rest:** Encrypt the Neo4j database files on disk.
        *   **Regular Auditing:** Regularly audit Neo4j access logs and configurations.
        *   **Vulnerability Management:** Keep Neo4j updated to the latest version to patch known vulnerabilities.

## Attack Surface: [2. Compromise of Cloud Provider Credentials](./attack_surfaces/2__compromise_of_cloud_provider_credentials.md)

*   **Description:** An attacker gains access to the credentials (IAM roles/users) that Cartography uses to access cloud providers (AWS, GCP, Azure).
    *   **How Cartography Contributes:** Cartography *requires* these credentials to function.  Its entire purpose is to connect to cloud providers and ingest data. The scope and permissions of these credentials are *directly* tied to Cartography's configuration and intended use.
    *   **Example:** An attacker steals the AWS access key and secret key used by Cartography, granting them read access to all resources Cartography is configured to monitor.
    *   **Impact:** The attacker gains broad read access to the organization's cloud infrastructure, potentially allowing them to discover vulnerabilities, exfiltrate data, or prepare for further attacks.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Principle of Least Privilege:** Grant Cartography the *absolute minimum* necessary permissions. Use narrowly scoped IAM roles with specific resource-level permissions. Avoid granting broad permissions like `ReadOnlyAccess`.
        *   **Credential Rotation:** Regularly rotate the credentials used by Cartography. Automate this process where possible.
        *   **Secrets Management:** Store credentials securely using a secrets management solution (e.g., AWS Secrets Manager, HashiCorp Vault). Do *not* hardcode credentials in configuration files or code.
        *   **Monitoring and Alerting:** Monitor cloud provider audit logs (e.g., AWS CloudTrail) for suspicious activity related to Cartography's credentials.
        *   **Multi-Factor Authentication (MFA):** If possible, enable MFA for the IAM user or role used by Cartography (though this is often not directly applicable to service accounts).
        *   **Use Instance Profiles/Managed Identities:** Whenever possible, use instance profiles (AWS), managed identities (Azure), or workload identity (GCP) instead of long-lived credentials.

## Attack Surface: [3. Supply Chain Attack on Cartography Dependencies](./attack_surfaces/3__supply_chain_attack_on_cartography_dependencies.md)

*   **Description:** A vulnerability in a third-party Python library used by Cartography, or a malicious library introduced through a compromised dependency, is exploited.
    *   **How Cartography Contributes:** Cartography, as a Python application, *inherently* relies on external dependencies.  The specific set of dependencies and their versions are a direct part of Cartography's codebase and build process.
    *   **Example:** A vulnerability is discovered in a Python library used by Cartography for parsing AWS responses, allowing an attacker to execute arbitrary code on the Cartography server.
    *   **Impact:** Potential for complete compromise of the Cartography server, leading to access to the Neo4j database and cloud provider credentials.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Dependency Scanning:** Use software composition analysis (SCA) tools to regularly scan Cartography's dependencies for known vulnerabilities.
        *   **Vulnerability Management:** Keep all dependencies up-to-date with the latest security patches.
        *   **Dependency Pinning:** Pin dependencies to specific versions to prevent unexpected updates that might introduce vulnerabilities. Use a `requirements.txt` or similar mechanism.
        *   **Code Review:** Review Cartography's code and its dependencies for potential security issues.
        *   **Use Virtual Environments:** Isolate Cartography's dependencies using Python virtual environments to prevent conflicts and reduce the impact of a compromised dependency.

## Attack Surface: [4. Data Poisoning (Modification of Cartography Data)](./attack_surfaces/4__data_poisoning__modification_of_cartography_data_.md)

*   **Description:** An attacker gains write access to the Neo4j database and modifies the data, potentially masking malicious activity or triggering incorrect alerts.
    *   **How Cartography Contributes:** The integrity of Cartography's data *within its chosen database (Neo4j)* is crucial for its effectiveness.  The attack directly targets the data Cartography collects and manages.
    *   **Example:** An attacker modifies relationships between resources in the Neo4j database to hide a compromised EC2 instance.
    *   **Impact:** Misleading security analysis, delayed incident response, and potential for further compromise due to incorrect information.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **All mitigations for "Unauthorized Access to Neo4j Database" apply here, with an even stronger emphasis on preventing *write* access.**
        *   **Data Integrity Monitoring:** Implement mechanisms to detect unauthorized modifications to the Neo4j database. This could involve comparing snapshots of the data or using audit logging features.
        *   **Regular Backups:** Maintain regular, secure backups of the Neo4j database to allow for restoration in case of data corruption or malicious modification.

