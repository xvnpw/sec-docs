# Mitigation Strategies Analysis for apache/hadoop

## Mitigation Strategy: [Implement HDFS Encryption (Transparent Data Encryption - TDE or Encryption Zones)](./mitigation_strategies/implement_hdfs_encryption__transparent_data_encryption_-_tde_or_encryption_zones_.md)

*   **Mitigation Strategy:** HDFS Encryption (TDE or Encryption Zones)
*   **Description:**
    1.  **Choose Encryption Method:** Decide between TDE (cluster-wide encryption) or Encryption Zones (directory-level encryption), both are Hadoop features. Encryption Zones offer more granular control within HDFS.
    2.  **Configure Hadoop Key Management Server (KMS):** Install and configure KMS, a Hadoop component, to securely manage encryption keys. This involves setting up KMS users, access policies, and key rotation strategies within the Hadoop ecosystem.
    3.  **Create Encryption Zone (if using Encryption Zones):** Use the `hdfs crypto` command-line tool, a Hadoop utility, to create Encryption Zones on directories containing sensitive data. Specify the encryption key and KMS provider, both Hadoop components.
    4.  **Configure TDE (if using TDE):** Enable TDE in `hdfs-site.xml`, a Hadoop configuration file, by setting `dfs.encryption.key.provider.uri` to the KMS URI and configuring other related Hadoop properties.
    5.  **Verify Encryption:** Write test data to encrypted areas and verify that data at rest is indeed encrypted by examining the storage layer directly (if possible in your environment) or by attempting to access it without proper authorization using Hadoop tools.
    6.  **Key Rotation:** Implement a regular key rotation schedule for encryption keys managed by KMS, a Hadoop best practice, to enhance security over time.
*   **List of Threats Mitigated:**
    *   **Data Breach due to Physical Media Theft (High Severity):** If physical storage media (disks, tapes) containing HDFS data is stolen, the data remains encrypted and unreadable to unauthorized parties due to Hadoop's encryption.
    *   **Insider Threat - Unauthorized Data Access at Storage Layer (High Severity):** Malicious insiders with physical access to storage infrastructure cannot directly read sensitive data from disk because of Hadoop's encryption mechanisms.
    *   **Compromised DataNodes - Data Leakage (Medium Severity):** If a DataNode is compromised, attackers cannot easily extract sensitive data from the local disk storage without the encryption keys managed by Hadoop KMS.
*   **Impact:**
    *   **Data Breach due to Physical Media Theft:** High Risk Reduction. Effectively eliminates the risk of data exposure from physical media theft through Hadoop's encryption.
    *   **Insider Threat - Unauthorized Data Access at Storage Layer:** High Risk Reduction. Significantly reduces the risk from malicious insiders with physical access due to Hadoop's data encryption.
    *   **Compromised DataNodes - Data Leakage:** Medium Risk Reduction. Reduces the risk, but if attackers compromise KMS (Hadoop component) or gain access to keys through other means within the Hadoop environment, the encryption can be bypassed.
*   **Currently Implemented:** No
*   **Missing Implementation:** HDFS data at rest is currently unencrypted across the entire Hadoop cluster. This leaves sensitive data vulnerable to physical media theft, insider threats, and potential breaches of DataNodes. Hadoop's Encryption Zones should be implemented for directories containing PII and confidential business data.

## Mitigation Strategy: [Utilize HDFS Access Control Lists (ACLs)](./mitigation_strategies/utilize_hdfs_access_control_lists__acls_.md)

*   **Mitigation Strategy:** HDFS Access Control Lists (ACLs)
*   **Description:**
    1.  **Identify Sensitive Data:** Determine which directories and files in HDFS, a Hadoop component, contain sensitive data requiring granular access control.
    2.  **Define Access Control Requirements:**  For each sensitive data location within HDFS, define which users and groups should have read, write, or execute permissions. Follow the principle of least privilege within the Hadoop context.
    3.  **Set ACLs using `hdfs dfs -setfacl` command:** Use the `hdfs dfs -setfacl` command-line tool, a Hadoop command, to set ACLs on directories and files in HDFS.  Specify user or group permissions (read, write, execute) and apply default ACLs for new files and directories created within a directory, all within Hadoop's ACL framework.
    4.  **Verify ACLs using `hdfs dfs -getfacl` command:** Use the `hdfs dfs -getfacl` command, another Hadoop command, to verify that ACLs are correctly set and applied as intended within HDFS.
    5.  **Regularly Review and Update ACLs:** Periodically review and update HDFS ACLs to reflect changes in user roles, data access requirements, and organizational structure within the Hadoop environment.
    6.  **Automate ACL Management (Optional):** For large-scale Hadoop deployments, consider automating ACL management using scripts or tools integrated with identity management systems, leveraging Hadoop's ACL capabilities.
*   **List of Threats Mitigated:**
    *   **Unauthorized Data Access by Internal Users (Medium Severity):** Prevents users from accessing data in HDFS they are not authorized to see, even if they have general access to the Hadoop cluster, using Hadoop's ACL mechanism.
    *   **Privilege Escalation - Data Access (Medium Severity):** Limits the impact of privilege escalation attacks within Hadoop by ensuring that even if an attacker gains access with some privileges, they are still restricted by HDFS ACLs on sensitive data.
    *   **Data Modification or Deletion by Unauthorized Users (Medium Severity):** Prevents unauthorized users from modifying or deleting critical data in HDFS using Hadoop's access control.
*   **Impact:**
    *   **Unauthorized Data Access by Internal Users:** Medium Risk Reduction. Significantly reduces the risk of accidental or intentional unauthorized data access by internal users within Hadoop using HDFS ACLs.
    *   **Privilege Escalation - Data Access:** Medium Risk Reduction. Limits the damage from privilege escalation within Hadoop by restricting data access even with elevated privileges through HDFS ACLs.
    *   **Data Modification or Deletion by Unauthorized Users:** Medium Risk Reduction. Protects data integrity and availability in HDFS by controlling write and delete access using Hadoop ACLs.
*   **Currently Implemented:** Partially implemented. Basic POSIX permissions are in place for HDFS, but Hadoop ACLs are not extensively used.
*   **Missing Implementation:** Fine-grained Hadoop ACLs are not consistently applied across HDFS, especially for newly created datasets and directories. Hadoop ACLs should be implemented for all directories containing sensitive customer data, financial records, and proprietary information within HDFS.

## Mitigation Strategy: [Enable RPC Encryption](./mitigation_strategies/enable_rpc_encryption.md)

*   **Mitigation Strategy:** RPC Encryption (using SASL with Kerberos and encryption) - Hadoop Feature
*   **Description:**
    1.  **Enable Kerberos Authentication (Prerequisite):** Ensure Kerberos authentication, a core Hadoop security feature, is fully implemented and functional for the Hadoop cluster.
    2.  **Configure `core-site.xml`:** In `core-site.xml`, a central Hadoop configuration file, on all Hadoop nodes (NameNode, DataNodes, ResourceManager, NodeManagers, Clients), set the following properties to enable Hadoop RPC encryption:
        *   `hadoop.rpc.protection` to `privacy` (for encryption and integrity) or `integrity` (for integrity only, less secure). `privacy` is recommended for strong Hadoop security.
        *   `hadoop.security.authentication` to `kerberos`.
    3.  **Configure `hdfs-site.xml`, `yarn-site.xml`, `mapred-site.xml`, `hbase-site.xml`, etc.:**  Ensure that service-specific Hadoop configuration files also inherit or explicitly set `hadoop.rpc.protection` and `hadoop.security.authentication` to be consistent with `core-site.xml` for consistent Hadoop-wide RPC encryption.
    4.  **Restart Hadoop Services:** Restart all Hadoop services (NameNode, DataNodes, ResourceManager, NodeManagers, etc.) for the Hadoop configuration changes to take effect and enable RPC encryption.
    5.  **Verify RPC Encryption:** Monitor network traffic between Hadoop components using network analysis tools (e.g., Wireshark) to confirm that Hadoop RPC communication is encrypted. Look for encrypted protocols like GSSAPI/Kerberos in Hadoop network traffic.
*   **List of Threats Mitigated:**
    *   **Eavesdropping on Network Communication (High Severity):** Prevents attackers from intercepting and reading sensitive data transmitted between Hadoop components over the network by using Hadoop's RPC encryption.
    *   **Man-in-the-Middle Attacks (High Severity):** Makes it significantly harder for attackers to perform man-in-the-middle attacks within the Hadoop cluster by encrypting communication and providing authentication through Hadoop's security features.
    *   **Credential Sniffing during RPC (Medium Severity):** Protects Kerberos tickets and other authentication credentials from being sniffed during Hadoop RPC communication.
*   **Impact:**
    *   **Eavesdropping on Network Communication:** High Risk Reduction. Effectively eliminates the risk of eavesdropping on Hadoop RPC communication through Hadoop's encryption.
    *   **Man-in-the-Middle Attacks:** High Risk Reduction.  Significantly reduces the risk of successful man-in-the-middle attacks within Hadoop due to RPC encryption and authentication.
    *   **Credential Sniffing during RPC:** Medium Risk Reduction. Protects credentials in transit during Hadoop RPC, but Kerberos itself (Hadoop integration) is the primary defense against credential compromise.
*   **Currently Implemented:** No
*   **Missing Implementation:** Hadoop RPC communication between Hadoop components is currently unencrypted. This exposes sensitive data and credentials to potential eavesdropping and man-in-the-middle attacks within the Hadoop network. Hadoop RPC encryption should be enabled for all Hadoop services.

## Mitigation Strategy: [Integrate with Kerberos for Strong Authentication](./mitigation_strategies/integrate_with_kerberos_for_strong_authentication.md)

*   **Mitigation Strategy:** Kerberos Authentication - Hadoop Integration
*   **Description:**
    1.  **Install and Configure Kerberos KDC:** Set up a Kerberos Key Distribution Center (KDC) in your environment, which Hadoop will integrate with for authentication. This involves installing Kerberos server software, configuring realms, and setting up administrative principals.
    2.  **Create Hadoop Service Principals:** Create Kerberos service principals for each Hadoop service (NameNode, DataNode, ResourceManager, NodeManager, etc.) in the KDC. These principals are used by Hadoop services for Kerberos authentication.
    3.  **Generate Keytab Files:** Generate keytab files for each Hadoop service principal. Keytabs securely store the service principal's long-term key and are used by Hadoop services for authentication.
    4.  **Distribute Keytab Files:** Securely distribute keytab files to the respective Hadoop servers. Ensure keytab files are protected with appropriate file system permissions on Hadoop nodes.
    5.  **Configure Hadoop for Kerberos:** Configure Hadoop services to use Kerberos authentication by setting properties in `core-site.xml`, `hdfs-site.xml`, `yarn-site.xml`, etc., Hadoop configuration files.  Key properties include `hadoop.security.authentication` to `kerberos`, `hadoop.security.authorization` to `true`, and specifying Kerberos realm and KDC settings within Hadoop configuration.
    6.  **Configure Clients for Kerberos:** Configure Hadoop clients (command-line tools, applications) to use Kerberos authentication. This typically involves obtaining Kerberos tickets using `kinit` before accessing Hadoop services, ensuring Kerberos integration for all Hadoop interactions.
    7.  **Restart Hadoop Services:** Restart all Hadoop services for Kerberos authentication to be enabled within the Hadoop cluster.
    8.  **Test Kerberos Authentication:** Test Kerberos authentication by accessing Hadoop services using Kerberized clients and verifying that authentication is successful, confirming proper Hadoop Kerberos integration.
*   **List of Threats Mitigated:**
    *   **Weak Password-Based Authentication (High Severity):** Replaces reliance on potentially weak passwords with strong Kerberos tickets for authentication to Hadoop services.
    *   **Replay Attacks (Medium Severity):** Kerberos tickets used in Hadoop have a limited lifespan, mitigating the risk of replay attacks using stolen credentials within the Hadoop environment.
    *   **Password Guessing and Brute-Force Attacks (High Severity):** Makes password guessing and brute-force attacks against Hadoop services ineffective as authentication is ticket-based through Kerberos integration.
    *   **Unauthorized Access due to Stolen Credentials (Medium Severity):** Reduces the risk of unauthorized access to Hadoop if user passwords are compromised, as Kerberos tickets are required for service access.
*   **Impact:**
    *   **Weak Password-Based Authentication:** High Risk Reduction. Eliminates the vulnerability of weak passwords for Hadoop service authentication by using Kerberos.
    *   **Replay Attacks:** Medium Risk Reduction. Reduces the risk of replay attacks within Hadoop, but ticket compromise is still a potential concern.
    *   **Password Guessing and Brute-Force Attacks:** High Risk Reduction. Effectively mitigates password-based attacks against Hadoop services through Kerberos integration.
    *   **Unauthorized Access due to Stolen Credentials:** Medium Risk Reduction. Reduces the risk, but if Kerberos tickets are stolen or compromised, unauthorized access to Hadoop is still possible until the ticket expires.
*   **Currently Implemented:** Yes, Kerberos authentication is implemented for the Hadoop cluster.
*   **Missing Implementation:** Kerberos is implemented for core Hadoop services, but some auxiliary tools and applications interacting with Hadoop might not be fully Kerberized, potentially creating authentication gaps in the Hadoop ecosystem. Ensure all components accessing Hadoop are Kerberos-aware.

## Mitigation Strategy: [Implement Fine-Grained Authorization with Apache Ranger](./mitigation_strategies/implement_fine-grained_authorization_with_apache_ranger.md)

*   **Mitigation Strategy:** Apache Ranger for Fine-Grained Authorization - Hadoop Ecosystem Tool
*   **Description:**
    1.  **Install and Configure Apache Ranger:** Install and configure Apache Ranger components (Ranger Admin, Ranger Agents) in your Hadoop environment. Ranger is designed to work with Hadoop.
    2.  **Integrate Ranger Agents with Hadoop Services:** Deploy Ranger agents to Hadoop services (HDFS, Hive, YARN, HBase, etc.) that need fine-grained authorization. Configure agents to communicate with the Ranger Admin server, establishing Ranger's role in Hadoop authorization.
    3.  **Define Ranger Policies:** Use the Ranger Admin UI or API to define authorization policies specifically for Hadoop resources. Policies specify access rules based on users, groups, roles, data attributes (e.g., HDFS paths, Hive databases/tables), and actions (read, write, execute, etc.) within the Hadoop context.
    4.  **Test Ranger Policies:** Thoroughly test Ranger policies to ensure they enforce the desired access control rules for Hadoop resources and do not inadvertently block legitimate Hadoop access.
    5.  **Centralized Policy Management:** Manage all Hadoop authorization policies centrally through the Ranger Admin UI, providing a unified view of Hadoop access control.
    6.  **Auditing with Ranger:** Ranger provides centralized auditing of access requests and policy enforcement decisions within Hadoop. Review Ranger audit logs for Hadoop security monitoring and compliance.
    7.  **Policy Versioning and Rollback:** Utilize Ranger's policy versioning features to track policy changes and rollback to previous versions if needed for Hadoop authorization policies.
*   **List of Threats Mitigated:**
    *   **Insufficient Authorization Controls (Medium Severity):** Addresses limitations of basic POSIX permissions and ACLs in Hadoop by providing more expressive and centralized authorization policies through Ranger.
    *   **Data Breaches due to Over-Permissive Access (Medium Severity):** Prevents accidental or intentional data breaches in Hadoop caused by overly broad access permissions, enforced by Ranger.
    *   **Compliance Violations (Medium Severity):** Helps meet compliance requirements (e.g., GDPR, HIPAA) for Hadoop data by enforcing granular access control and providing audit trails through Ranger.
    *   **Privilege Escalation - Data Access (Medium Severity):** Limits the impact of privilege escalation in Hadoop by enforcing fine-grained policies even if an attacker gains elevated privileges, using Ranger's authorization framework.
*   **Impact:**
    *   **Insufficient Authorization Controls:** Medium Risk Reduction. Significantly improves authorization capabilities for Hadoop compared to basic permissions by using Ranger.
    *   **Data Breaches due to Over-Permissive Access:** Medium Risk Reduction. Reduces the risk of data breaches in Hadoop by enforcing stricter access control with Ranger.
    *   **Compliance Violations:** Medium Risk Reduction. Helps achieve and maintain compliance with data privacy regulations for Hadoop data using Ranger.
    *   **Privilege Escalation - Data Access:** Medium Risk Reduction. Limits data access in Hadoop even with escalated privileges, but policy misconfiguration in Ranger can still be a risk.
*   **Currently Implemented:** Partially implemented. Ranger is deployed and integrated with HDFS and Hive, but policies are not comprehensive across all Hadoop services.
*   **Missing Implementation:** Ranger policies are not fully defined and enforced across all Hadoop services (e.g., YARN, HBase).  Policies need to be expanded to cover all sensitive Hadoop data assets and user roles, and regularly reviewed and updated.  Ranger integration with custom applications accessing Hadoop might also be missing.

