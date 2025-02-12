# Attack Tree Analysis for serverless/serverless

Objective: Exfiltrate sensitive data and/or disrupt service availability of a serverless application deployed using the Serverless Framework.

## Attack Tree Visualization

                                     +-------------------------------------------------+
                                     | Exfiltrate Data AND/OR Disrupt Service Availability |
                                     +-------------------------------------------------+
                                                      |
         +--------------------------------------------------------------------------------+
         |                                                                                |
+---------------------+                                                +--------------------------+
|  Data Exfiltration  |                                                |  Lateral Movement/Escalation|
+---------------------+                                                +--------------------------+
         |                                                                                |
+--------+--------+                                                                 +--------+
|1. Leaked        |                                                                 |9.  Abuse|
|   Secrets/      |                                                                 |   IAM   |
|   Credentials   |                                                                 |Permissions|
+--------+--------+                                                                 +--------+
         |                                                                                |
+--------+--------+                                                                 +------+
|                 |                                                                 |      |
|2. Function     |                                                                 |9a.   |
|   Code         |                                                                 |Overly|
|   Injection    |                                                                 |Permis-|
+--------+--------+                                                                 |sive  |
         |                                                                                |Roles |
+--------+--------+                                                                 +------+
|3.  Vulnerable|
|Dependencies|
+--------+--------+
         |
+--------+--------+
|1a.  Exposed    |
|     in          |
|     Source      |
|     Code        |
+--------+--------+
         |
+--------+--------+
|1b.  Hardcoded  |
|     Secrets    |
|     in Code    |
+--------+--------+
         |
+--------+--------+
|1c.  Exposed    |
|     in          |
|     Environment|
|     Variables   |
+--------+--------+
         |
+--------+--------+
|1d.  Exposed    |
|     in          |
|     Serverless  |
|     Framework   |
|     Config      |
+--------+--------+
         |
+-----------------+
|5. Resource      |
|   Exhaustion    |
+-----------------+
         |
+--------+
|5b.   |
|Billing|
|Attack |
+--------+

## Attack Tree Path: [1. Leaked Secrets/Credentials](./attack_tree_paths/1__leaked_secretscredentials.md)

*   **Overall Description:** This category encompasses various ways an attacker can obtain sensitive information like API keys, database credentials, or other secrets due to developer mistakes or insecure configurations.

*   **1a. Exposed in Source Code:**
    *   **Description:** Secrets are accidentally committed to a source code repository (e.g., GitHub, GitLab).
    *   **Likelihood:** Medium
    *   **Impact:** High
    *   **Effort:** Low
    *   **Skill Level:** Low
    *   **Detection Difficulty:** Medium

*   **1b. Hardcoded Secrets in Code:**
    *   **Description:** Secrets are directly embedded within the Lambda function code.
    *   **Likelihood:** Medium
    *   **Impact:** High
    *   **Effort:** Medium
    *   **Skill Level:** Medium
    *   **Detection Difficulty:** High

*   **1c. Exposed in Environment Variables (Misconfigured):**
    *   **Description:** Environment variables containing secrets are set insecurely or exposed through logs/errors.
    *   **Likelihood:** Medium
    *   **Impact:** High
    *   **Effort:** Medium
    *   **Skill Level:** Medium
    *   **Detection Difficulty:** Medium

*   **1d. Exposed in Serverless Framework Config (serverless.yml):**
    *   **Description:** Secrets are directly placed within the `serverless.yml` file.
    *   **Likelihood:** Medium
    *   **Impact:** High
    *   **Effort:** Low
    *   **Skill Level:** Low
    *   **Detection Difficulty:** Medium

## Attack Tree Path: [2. Function Code Injection](./attack_tree_paths/2__function_code_injection.md)

*   **Description:** An attacker injects malicious code into a Lambda function, gaining control over its execution.
*   **Likelihood:** Medium
*   **Impact:** High
*   **Effort:** High
*   **Skill Level:** High
*   **Detection Difficulty:** High

## Attack Tree Path: [3. Vulnerable Dependencies](./attack_tree_paths/3__vulnerable_dependencies.md)

*   **Description:** The Lambda function uses third-party libraries with known vulnerabilities that an attacker can exploit.
*   **Likelihood:** High
*   **Impact:** Medium to High (depends on the specific vulnerability)
*   **Effort:** Low to Medium
*   **Skill Level:** Low to Medium
*   **Detection Difficulty:** Medium

## Attack Tree Path: [5. Resource Exhaustion (Critical Node)](./attack_tree_paths/5__resource_exhaustion__critical_node_.md)

*    **5b. Billing Attack:**
    *   **Description:** An attacker triggers excessive function invocations, leading to high cloud provider bills.
    *   **Likelihood:** Low
    *   **Impact:** High
    *   **Effort:** Medium to High
    *   **Skill Level:** Medium
    *   **Detection Difficulty:** Medium

## Attack Tree Path: [9. Abuse IAM Permissions (High-Risk Path)](./attack_tree_paths/9__abuse_iam_permissions__high-risk_path_.md)

*   **9a. Overly Permissive Roles:**
    *   **Description:** The Lambda function's IAM role has excessive permissions, allowing an attacker to access other resources if the function is compromised.
    *   **Likelihood:** Medium
    *   **Impact:** High
    *   **Effort:** Low (if the function is already compromised)
    *   **Skill Level:** Medium
    *   **Detection Difficulty:** Medium

