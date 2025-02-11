# Attack Tree Analysis for apache/hadoop

Objective: Gain Unauthorized Access to Data and/or Execute Arbitrary Code on Hadoop Cluster

## Attack Tree Visualization

                                     Attacker's Goal:
                                     Gain Unauthorized Access to Data and/or Execute Arbitrary Code on Hadoop Cluster
                                                     |
          -------------------------------------------------------------------------------------------------
          |                                                               |
  1. Compromise HDFS (Data Access)                                2. Compromise YARN (Code Execution/Resource Control)
          |                                                               |
  -------------------------                                       -------------------------------------------------
  |                                                               |                               |
1a. Weak Authentication                                       2a. Weak Authentication/        2c. Rogue YARN Application
    to HDFS [HIGH RISK]                                          Authorization to YARN [HIGH RISK]  (Malicious Container) [HIGH RISK]
    |                                                               |                               |
  -----                                                           -----                           -----
  |   |                                                           |   |                           |
1a1 1a2                                                         2a1 2a2                         2c1
Kerb  No                                                          Kerb  No                          App
Weak  Auth {CRITICAL}                                             Weak  Auth {CRITICAL}             Sub-
      (e.g.,                                                      (e.g.,                          mit
      Simple                                                      Simple)                         Mal-
      Auth) [HIGH RISK]                                                                           icious
                                                                                                  Code

## Attack Tree Path: [1. Compromise HDFS (Data Access) - [HIGH RISK]](./attack_tree_paths/1__compromise_hdfs__data_access__-__high_risk_.md)

*   **Overall Description:** This attack vector focuses on directly accessing data stored in the Hadoop Distributed File System (HDFS) by exploiting weaknesses in authentication.
*   **1a. Weak Authentication to HDFS - [HIGH RISK]**
    *   **Description:** Attackers exploit weak or absent authentication mechanisms to gain unauthorized access to HDFS.
    *   **1a1. Kerberos Weaknesses - {CRITICAL}**
        *   **Description:**  Attackers target vulnerabilities or misconfigurations in the Kerberos authentication system, which is the primary security mechanism for Hadoop.
        *   **Potential Attack Methods:**
            *   Exploiting weak Kerberos keys.
            *   Compromising the Key Distribution Center (KDC).
            *   Exploiting misconfigured SPNEGO (Simple and Protected GSSAPI Negotiation Mechanism).
            *   Bypassing Kerberos authentication entirely due to configuration errors.
        *   **Impact:** Complete cluster compromise, as Kerberos is the foundation of Hadoop security.
        *   **Mitigation:**
            *   Use strong, randomly generated Kerberos keys.
            *   Implement robust key management practices, including regular key rotation.
            *   Secure the KDC and restrict access to it.
            *   Properly configure SPNEGO and ensure it's enforced.
            *   Regularly audit Kerberos configurations.
    *   **1a2. No Authentication (Simple Auth) - [HIGH RISK]**
        *   **Description:** Attackers directly access HDFS without providing any credentials because the system is configured with simple authentication (which essentially means no authentication) or no authentication at all.
        *   **Potential Attack Methods:**
            *   Directly accessing HDFS data through the NameNode or DataNode interfaces.
            *   Using Hadoop command-line tools without providing credentials.
        *   **Impact:**  Full and unrestricted access to all data stored in HDFS.
        *   **Mitigation:**
            *   Disable simple authentication in production environments.
            *   Enforce strong authentication using Kerberos.
            *   Restrict network access to HDFS components.

## Attack Tree Path: [2. Compromise YARN (Code Execution/Resource Control) - [HIGH RISK]](./attack_tree_paths/2__compromise_yarn__code_executionresource_control__-__high_risk_.md)

*   **Overall Description:** This attack vector focuses on gaining control over the Hadoop cluster's resources and executing arbitrary code through the Yet Another Resource Negotiator (YARN).

*   **2a. Weak Authentication/Authorization to YARN - [HIGH RISK]**
    *   **Description:** Attackers exploit weak or absent authentication and authorization mechanisms in YARN to submit malicious jobs or gain unauthorized access to cluster resources.
    *   **2a1. Kerberos Weaknesses (YARN) - {CRITICAL}**
        *   **Description:** Similar to HDFS Kerberos weaknesses, attackers target vulnerabilities or misconfigurations in YARN's Kerberos implementation.
        *   **Potential Attack Methods:** (Same as 1a1)
        *   **Impact:**  Unauthorized job submission and potential control over cluster resources.
        *   **Mitigation:** (Same as 1a1)
    *   **2a2. No Authentication (Simple Auth - YARN) - [HIGH RISK]**
        *   **Description:** Attackers submit jobs to YARN without providing any credentials because YARN is configured with simple authentication or no authentication.
        *   **Potential Attack Methods:**
            *   Using the YARN command-line interface or REST API to submit jobs without authentication.
        *   **Impact:**  Allows anyone to submit and execute jobs on the cluster, potentially leading to data exfiltration, system disruption, or resource exhaustion.
        *   **Mitigation:**
            *   Disable simple authentication in production environments.
            *   Enforce strong authentication using Kerberos.
            *   Implement strict authorization policies to control access to YARN resources.

*   **2c. Rogue YARN Application (Malicious Container) - [HIGH RISK]**
    *   **Description:** Attackers submit a seemingly legitimate YARN application that contains malicious code.  When the application is executed within a container, the malicious code performs unauthorized actions.
    *   **2c1. Application Submission (Malicious Code)**
        *   **Description:** The core of this attack is crafting and submitting a YARN application that, when executed, carries out the attacker's objectives.
        *   **Potential Attack Methods:**
            *   Submitting a MapReduce job with malicious mapper or reducer code.
            *   Submitting a Spark application with malicious code.
            *   Using any YARN-compatible framework to execute malicious code.
        *   **Impact:**  Highly variable, depending on the malicious code.  Could range from data exfiltration to complete system compromise.
        *   **Mitigation:**
            *   Implement strict controls on YARN application submission.  Require authentication and authorization for submitting applications.
            *   Validate and sanitize application code before execution.  Use static analysis tools to detect potential vulnerabilities.
            *   Use containerization technologies (e.g., Docker) to isolate applications and limit their privileges.  Restrict container access to system resources.
            *   Implement resource quotas and monitoring to detect and prevent malicious resource consumption.
            *   Regularly audit application logs for suspicious activity.

