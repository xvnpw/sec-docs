# Attack Surface Analysis for apache/hadoop

## Attack Surface: [Unauthenticated Access to HDFS/YARN](./attack_surfaces/unauthenticated_access_to_hdfsyarn.md)

*   **Description:**  Attackers can access HDFS data or submit YARN applications without proper authentication.
*   **How Hadoop Contributes:** Hadoop's services (NameNode, DataNodes, ResourceManager, NodeManagers) expose RPC interfaces and web UIs that can be accessed directly.  Without authentication, these are open targets.
*   **Example:** An attacker uses `hdfs dfs -ls /` to list the root directory of HDFS without credentials, or submits a YARN application via the REST API without authentication.
*   **Impact:**  Complete data breach (confidentiality), data modification/deletion (integrity), and cluster unavailability (availability).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Enable Kerberos Authentication:**  This is *mandatory*. Configure Kerberos correctly, including strong keytab management and regular key rotation.  Ensure all Hadoop services and client tools are configured to use Kerberos.
    *   **Disable Anonymous Access:** Explicitly disable any anonymous access options in Hadoop configuration files (e.g., `dfs.namenode.http-address`, `yarn.resourcemanager.webapp.address`, and related settings).

## Attack Surface: [Weak or Misconfigured HDFS Permissions (ACLs)](./attack_surfaces/weak_or_misconfigured_hdfs_permissions__acls_.md)

*   **Description:**  Incorrectly configured HDFS permissions allow unauthorized users to access or modify data.
*   **How Hadoop Contributes:** HDFS uses a POSIX-like permission model and ACLs.  Mismanagement of these *Hadoop-specific* features leads to vulnerabilities.
*   **Example:**  A sensitive HDFS directory has permissions set to `777`, allowing any user (even unauthenticated ones if Kerberos is off) to read/write/delete data.
*   **Impact:**  Data breach (confidentiality), data modification (integrity).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Principle of Least Privilege:** Grant *only* the minimum necessary HDFS permissions. Avoid overly permissive settings.
    *   **Regular Audits:** Periodically review HDFS permissions using Hadoop tools (`hdfs dfs -ls`, `hdfs dfs -getfacl`) to identify and correct misconfigurations.
    *   **Use ACLs Carefully:** Understand the implications of default and extended ACLs within HDFS.

## Attack Surface: [NameNode/ResourceManager Single Point of Failure (DoS)](./attack_surfaces/namenoderesourcemanager_single_point_of_failure__dos_.md)

*   **Description:**  Attacks targeting the NameNode (HDFS) or ResourceManager (YARN) can disrupt the entire cluster.
*   **How Hadoop Contributes:** These are *core Hadoop components*. Their failure renders HDFS or YARN unusable. This is inherent to their design.
*   **Example:**  An attacker floods the NameNode with `create file` requests, causing it to become unresponsive.  Or, an attacker overwhelms the ResourceManager with application submissions.
*   **Impact:**  Complete cluster unavailability (availability).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **NameNode High Availability (HA):** Configure NameNode HA with a standby NameNode and a Quorum Journal Manager (QJM) or shared edits. This is a *Hadoop-specific* configuration.
    *   **ResourceManager High Availability (HA):** Configure ResourceManager HA with a standby ResourceManager. This is a *Hadoop-specific* configuration.
    *   **Hadoop-Specific Rate Limiting:** Implement rate limiting on the NameNode and ResourceManager RPC interfaces *using Hadoop's configuration options* (e.g., `dfs.namenode.rpc.ratelimit`).

## Attack Surface: [DataNode Compromise (Data Exfiltration/Manipulation) - *When TDE is not used*](./attack_surfaces/datanode_compromise__data_exfiltrationmanipulation__-_when_tde_is_not_used.md)

*   **Description:** Attackers gain access to DataNodes and directly manipulate or steal *unencrypted* data blocks.
*   **How Hadoop Contributes:** DataNodes store the raw data blocks. Without HDFS Transparent Data Encryption (TDE), this data is in plain text, making it vulnerable if the DataNode is compromised.  The *lack of TDE* is the Hadoop-specific aspect.
*   **Example:** An attacker gains shell access to a DataNode and reads the raw data block files.
*   **Impact:** Data breach (confidentiality), data corruption (integrity).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **HDFS Data at Rest Encryption (TDE):** Enable HDFS TDE. This is the *primary Hadoop-specific mitigation*. It encrypts data blocks on DataNodes, requiring a secure Key Management Server (KMS).

## Attack Surface: [Malicious MapReduce/Spark Jobs](./attack_surfaces/malicious_mapreducespark_jobs.md)

*   **Description:**  Attackers submit jobs with malicious code that attempts to exploit the cluster.
*   **How Hadoop Contributes:** Hadoop's distributed processing frameworks (MapReduce, Spark) allow users to execute code on cluster nodes. This is *inherent to Hadoop's functionality*.
*   **Example:** A malicious MapReduce job attempts to read files outside of its designated input directory or to execute system commands.
*   **Impact:** Data breach, data corruption, resource exhaustion, arbitrary code execution (all within the context of the Hadoop cluster).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **User Isolation (Hadoop-Specific):** Run jobs under different user accounts with limited privileges *within the Hadoop environment*. Use YARN's containerization features to isolate jobs. This leverages Hadoop's security model.
    *   **Resource Quotas (Hadoop-Specific):** Enforce resource quotas *using Hadoop's configuration* to prevent malicious jobs from consuming excessive resources.
    * **Input Validation (Hadoop Context):** Validate input *within the MapReduce/Spark job itself*, ensuring it only accesses authorized HDFS paths.

