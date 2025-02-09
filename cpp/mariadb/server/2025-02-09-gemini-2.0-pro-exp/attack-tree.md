# Attack Tree Analysis for mariadb/server

Objective: Gain unauthorized access to, modify, or exfiltrate data, or disrupt availability.

## Attack Tree Visualization

Goal: Gain unauthorized access to, modify, or exfiltrate data, or disrupt availability.

├── 1.  Unauthorized Data Access/Modification
│   ├── 1.1 SQL Injection (Exploiting Server-Side Parsing/Processing) [HIGH RISK]
│   │   ├── 1.1.1.1 Exploit vulnerabilities in stored procedures/functions. [CRITICAL]
│   │   └── 1.1.2.1  Exploit how stored data is later used in unsanitized queries. [CRITICAL]
│   ├── 1.2  Authentication Bypass / Weak Authentication
│   │   └── 1.2.2.1  Target default accounts (e.g., 'root' with no password). [CRITICAL]
│   ├── 1.3  Privilege Escalation
│   │   ├── 1.3.2.1  Inject code into procedures running as a higher-privileged user. [CRITICAL]
│   │   └── 1.3.3.1 Load malicious UDFs to execute arbitrary code. [CRITICAL]
│
├── 2.  Denial of Service (DoS)
│   ├── 2.1  Resource Exhaustion
│   │   └── 2.1.1.1  Flood the server with connection requests. [CRITICAL]
│
└── 3.  Code Execution (Most Severe)
    ├── 3.1  Exploit vulnerabilities in UDFs (as in 1.3.3). [CRITICAL]
    └── 3.3 Exploit vulnerabilities in plugins.
        └── 3.3.1 Load malicious plugin. [CRITICAL]

## Attack Tree Path: [1. Unauthorized Data Access/Modification](./attack_tree_paths/1__unauthorized_data_accessmodification.md)

*   **1.1 SQL Injection (Exploiting Server-Side Parsing/Processing) [HIGH RISK]**
    *   **Description:**  Attackers inject malicious SQL code into input fields that are not properly sanitized by the application or the MariaDB server. This allows them to bypass security checks and execute arbitrary SQL commands.
    *   **Sub-Vectors:**
        *   **1.1.1.1 Exploit vulnerabilities in stored procedures/functions. [CRITICAL]**
            *   **Description:** Stored procedures and functions, if not carefully written, can be vulnerable to SQL injection.  If user input is directly concatenated into SQL strings within the procedure, an attacker can inject malicious code.
            *   **Likelihood:** Medium
            *   **Impact:** High
            *   **Effort:** Medium
            *   **Skill Level:** Intermediate
            *   **Detection Difficulty:** Medium
        *   **1.1.2.1 Exploit how stored data is later used in unsanitized queries. [CRITICAL]**
            *   **Description:** Second-order SQL injection occurs when data that was previously stored (and potentially considered "safe") is later used in a SQL query without proper sanitization.  An attacker might inject malicious data that is initially stored without causing harm, but later triggers an injection when used in a different context.
            *   **Likelihood:** Medium
            *   **Impact:** High
            *   **Effort:** Medium
            *   **Skill Level:** Intermediate
            *   **Detection Difficulty:** Hard

*   **1.2 Authentication Bypass / Weak Authentication**
    *   **Sub-Vectors:**
        *   **1.2.2.1 Target default accounts (e.g., 'root' with no password). [CRITICAL]**
            *   **Description:** Attackers attempt to gain access by using default credentials (e.g., 'root' with a blank password or a well-known default password) that have not been changed during installation or configuration.
            *   **Likelihood:** High (if defaults are not changed)
            *   **Impact:** High
            *   **Effort:** Low
            *   **Skill Level:** Novice
            *   **Detection Difficulty:** Easy

*   **1.3 Privilege Escalation**
    *   **Sub-Vectors:**
        *   **1.3.2.1 Inject code into procedures running as a higher-privileged user. [CRITICAL]**
            *   **Description:** If an attacker can inject code into a stored procedure that runs with higher privileges (e.g., a procedure that modifies system tables), they can gain those elevated privileges. This often involves exploiting SQL injection vulnerabilities within the stored procedure itself.
            *   **Likelihood:** Medium
            *   **Impact:** High
            *   **Effort:** Medium
            *   **Skill Level:** Intermediate
            *   **Detection Difficulty:** Hard
        *   **1.3.3.1 Load malicious UDFs to execute arbitrary code. [CRITICAL]**
            *   **Description:** User-Defined Functions (UDFs) allow extending MariaDB's functionality with custom code.  If an attacker can load a malicious UDF, they can execute arbitrary code on the server with the privileges of the MariaDB process.
            *   **Likelihood:** Low
            *   **Impact:** Very High
            *   **Effort:** High
            *   **Skill Level:** Advanced
            *   **Detection Difficulty:** Hard

## Attack Tree Path: [2. Denial of Service (DoS)](./attack_tree_paths/2__denial_of_service__dos_.md)

*   **2.1 Resource Exhaustion**
    *   **Sub-Vectors:**
        *   **2.1.1.1 Flood the server with connection requests. [CRITICAL]**
            *   **Description:** Attackers send a large number of connection requests to the MariaDB server, overwhelming its ability to handle legitimate connections. This prevents legitimate users from accessing the database.
            *   **Likelihood:** High
            *   **Impact:** Medium
            *   **Effort:** Low
            *   **Skill Level:** Novice
            *   **Detection Difficulty:** Easy

## Attack Tree Path: [3. Code Execution (Most Severe)](./attack_tree_paths/3__code_execution__most_severe_.md)

*   **3.1 Exploit vulnerabilities in UDFs (as in 1.3.3). [CRITICAL]**
    *   **Description:** (Same as 1.3.3.1)
    *   **Likelihood:** Low
    *   **Impact:** Very High
    *   **Effort:** High
    *   **Skill Level:** Advanced
    *   **Detection Difficulty:** Hard

* **3.3 Exploit vulnerabilities in plugins.**
    * **Sub-Vectors:**
        *   **3.3.1 Load malicious plugin. [CRITICAL]**
            *   **Description:** Similar to UDFs, plugins extend MariaDB functionality.  A malicious plugin can execute arbitrary code with the privileges of the MariaDB process.
            *   **Likelihood:** Low
            *   **Impact:** Very High
            *   **Effort:** High
            *   **Skill Level:** Advanced
            *   **Detection Difficulty:** Hard

