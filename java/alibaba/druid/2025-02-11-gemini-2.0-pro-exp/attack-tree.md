# Attack Tree Analysis for alibaba/druid

Objective: Exfiltrate Data / Disrupt Druid Availability

## Attack Tree Visualization

```
                                      +-------------------------------------------------+
                                      |  Exfiltrate Data / Disrupt Druid Availability  |
                                      +-------------------------------------------------+
                                                       |
          +----------------------------------------------------------------------------------------------------------------+
          |                                                                                                                |
+-------------------------+                                                                                +-------------------------+
|  Exploit Druid          |                                                                                |  Abuse Druid Features   |
|  Vulnerabilities        |                                                                                |  / Misconfigurations    |
+-------------------------+                                                                                +-------------------------+
          |                                                                                                                |
+---------+                                                                                                  +---------+---------+---------+
| CVE-    |                                                                                                  | Unauth  | Weak    | Overly  |
| 2021-   |                                                                                                  | Access  | Auth    | Permiss-|
| 25646   |                                                                                                  | to      | Config  | ive     |
| (RCE)   |                                                                                                  | APIs    |         | JMX/    |
| [CRITICAL]|                                                                                                  | [HIGH-  | [HIGH-  | SQL     |
|         |                                                                                                  | RISK]   | RISK]   | [HIGH-  |
+---------+                                                                                                  +---------+---------+---------+
          |                                                                                                                |         |         |
**+---------+**                                                                                                   **+---------+** **+---------+** +---------+
**| Exploit |**                                                                                                   **| Lack of |** **| Use     |** | Configure|
**| WebLogic|**                                                                                                   **| Input   |** **| Default |** | Druid to|
**| Deserial|**                                                                                                   **| Valid-  |** **| Creds   |** | Access  |
**| ization |**                                                                                                   **| ation   |** **| [CRITICAL]|** | External|
**| (if     |**                                                                                                   **| on      |** **|         |** | Systems |
**| present)|**                                                                                                   **| Druid   |** **|         |** | (e.g.,  |
**| [HIGH-  |**                                                                                                   **| SQL     |** **|         |** | S3,     |
**|  RISK]  |**                                                                                                   **| Queries |** **|         |** | HDFS)   |
**+---------+**                                                                                                   **| [HIGH-  |** **|         |** | [HIGH-  |
                                                                                                                    **|  RISK]  |** **|         |** |  RISK]  |
                                                                                                                    **+---------+** **+---------+** +---------+
                                                                                                                                  |
                                                                                                                        +---------------------+
                                                                                                                        |  Abuse JavaScript   |
                                                                                                                        |  Task Execution     |
                                                                                                                        |  (if enabled and    |
                                                                                                                        |   misconfigured)    |
                                                                                                                        |  [CRITICAL]         |
                                                                                                                        +---------------------+
                                                                                                                                  |
                                                                                                                        +---------------------+
                                                                                                                        |  Execute Arbitrary  |
                                                                                                                        |  JavaScript Code    |
                                                                                                                        |  (RCE) [CRITICAL]   |
                                                                                                                        +---------------------+
```

## Attack Tree Path: [Critical Nodes](./attack_tree_paths/critical_nodes.md)

*   **CVE-2021-25646 (RCE):**
    *   **Description:** Unsafe deserialization in `druid-web-console` allows remote code execution.
    *   **Likelihood:** Medium (If unpatched and exposed) / Low (If patched or mitigated)
    *   **Impact:** Very High (Complete system compromise)
    *   **Effort:** Low (Public exploits available)
    *   **Skill Level:** Intermediate
    *   **Detection Difficulty:** Medium (IDS/IPS might detect, but sophisticated attackers can evade)
    *   **Mitigation:** Apply the patch for CVE-2021-25646 *immediately*. If patching is impossible, disable the web console (`druid.web.console.enabled=false`). Restrict network access.

*   **Use Default Creds:**
    *   **Description:** Using default credentials for Druid or any of its dependencies.
    *   **Likelihood:** Medium (Unfortunately common)
    *   **Impact:** Very High (Complete compromise)
    *   **Effort:** Very Low
    *   **Skill Level:** Novice
    *   **Detection Difficulty:** Easy (If detected, but often goes unnoticed initially)
    *   **Mitigation:** Change *all* default credentials immediately after installation.

*   **Abuse JavaScript Task Execution (and subsequent RCE):**
    *   **Description:**  Druid's JavaScript task execution feature, if enabled and misconfigured, allows attackers to execute arbitrary JavaScript code, leading to RCE.
    *   **Likelihood:** Low (If disabled, as recommended) / High (If enabled and misconfigured)
    *   **Impact:** Very High (RCE)
    *   **Effort:** Medium
    *   **Skill Level:** Advanced
    *   **Detection Difficulty:** Hard (Requires deep inspection of task definitions and execution)
    *   **Mitigation:** Disable the JavaScript task execution feature (`druid.javascript.enabled=false`) unless absolutely required. If required, restrict access to trusted users and implement sandboxing.

## Attack Tree Path: [High-Risk Paths](./attack_tree_paths/high-risk_paths.md)

*   **Exploit WebLogic/Jackson Deserialization --> ... (RCE):**
    *   **Description:** If Druid is deployed within a vulnerable WebLogic environment or uses vulnerable Jackson versions for data binding, deserialization vulnerabilities can be exploited for RCE.
    *   **Likelihood:** Medium (If vulnerable versions are present)
    *   **Impact:** Very High (RCE)
    *   **Effort:** Medium (Public exploits may exist)
    *   **Skill Level:** Intermediate to Advanced
    *   **Detection Difficulty:** Medium
    *   **Mitigation:** Ensure WebLogic is patched and Jackson is updated to safe versions. Avoid using untrusted data in deserialization.

*   **Unauthenticated Access to APIs --> Data Exfiltration / Cluster Control:**
    *   **Description:**  If Druid's APIs are not properly secured, an attacker can directly interact with the cluster without authentication, leading to data theft or control over the cluster.
    *   **Likelihood:** Medium (If misconfigured)
    *   **Impact:** High (Data exfiltration, cluster control)
    *   **Effort:** Low
    *   **Skill Level:** Novice to Intermediate
    *   **Detection Difficulty:** Medium (API logs, access patterns)
    *   **Mitigation:** *Always* require authentication for all Druid APIs. Use strong authentication (API keys, OAuth 2.0) and RBAC.

*   **Weak Authentication Configuration --> Credential Compromise --> Data Exfiltration / Cluster Control:**
    *   **Description:** Using weak passwords, default credentials, or easily guessable API keys makes credential compromise highly likely, leading to data theft or control over the cluster.
    *   **Likelihood:** Medium (Common mistake)
    *   **Impact:** High (Credential compromise)
    *   **Effort:** Low (Brute-force, credential stuffing)
    *   **Skill Level:** Novice
    *   **Detection Difficulty:** Medium (Failed login attempts)
    *   **Mitigation:** Change default credentials, enforce strong password policies, use a password manager, and rotate API keys regularly.

*   **Overly Permissive JMX/SQL --> Data Exfiltration / Cluster Control:**
    *   **Description:** Misconfigured JMX or SQL access grants attackers excessive privileges, allowing them to steal data or control the cluster.
    *   **Likelihood:** Medium (If misconfigured)
    *   **Impact:** High (Data exfiltration, cluster control)
    *   **Effort:** Low to Medium
    *   **Skill Level:** Intermediate
    *   **Detection Difficulty:** Medium (Audit logs, query monitoring)
    *   **Mitigation:** Disable JMX if unnecessary. Secure JMX with strong authentication/authorization. Use Druid's SQL authorization to restrict access.

*   **Lack of Input Validation on Druid SQL Queries --> SQL Injection --> Data Exfiltration / Data Manipulation:**
    *   **Description:**  If Druid SQL queries are not properly validated, attackers can inject malicious code, leading to data theft or manipulation.
    *   **Likelihood:** Medium (Common vulnerability)
    *   **Impact:** High (SQL injection, data manipulation)
    *   **Effort:** Low to Medium
    *   **Skill Level:** Intermediate
    *   **Detection Difficulty:** Medium (SQL query logs, WAF)
    *   **Mitigation:** Implement strict input validation. Use parameterized queries or prepared statements. Sanitize user input.

*   **Configure Druid to Access External Systems --> Access to sensitive data in external systems:**
    *   **Description:** If Druid is configured to access external systems (S3, HDFS) with compromised credentials, attackers can access those resources.
    *   **Likelihood:** Low to Medium (Depends on configuration)
    *   **Impact:** High (Access to sensitive data in external systems)
    *   **Effort:** Medium
    *   **Skill Level:** Intermediate
    *   **Detection Difficulty:** Medium (CloudTrail logs, access patterns)
    *   **Mitigation:** Use the principle of least privilege. Grant Druid only minimum necessary permissions. Use IAM roles or service accounts. Audit access permissions.

