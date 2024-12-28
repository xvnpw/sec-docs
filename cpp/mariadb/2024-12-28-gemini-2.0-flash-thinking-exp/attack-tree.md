Okay, here's the sub-tree containing only the High-Risk Paths and Critical Nodes, along with the requested details.

**Title:** High-Risk Paths and Critical Nodes in MariaDB Attack Tree

**Attacker's Goal:** Gain unauthorized access to sensitive application data, manipulate application data, or disrupt application availability by exploiting vulnerabilities within the MariaDB database.

**Sub-Tree:**

```
└── Compromise Application Using MariaDB
    ├── [CRITICAL NODE] Exploit MariaDB Authentication/Authorization Weaknesses
    │   ├── [CRITICAL NODE] Brute-force MariaDB Credentials
    │   ├── [CRITICAL NODE] [HIGH-RISK PATH] Exploit Default MariaDB Credentials
    ├── [CRITICAL NODE] Exploit MariaDB Data Handling Vulnerabilities
    │   ├── [CRITICAL NODE] [HIGH-RISK PATH] Exploit SQL Injection Vulnerabilities within Stored Procedures/Functions
    ├── [CRITICAL NODE] [HIGH-RISK PATH] Exploit MariaDB Network/Communication Issues
    │   ├── [HIGH-RISK PATH] Man-in-the-Middle (MITM) Attack on MariaDB Connection
    │   ├── [CRITICAL NODE] [HIGH-RISK PATH] Denial of Service (DoS) Attack Targeting MariaDB Server
    ├── [CRITICAL NODE] Exploit MariaDB Configuration/Management Weaknesses
    │   ├── [CRITICAL NODE] [HIGH-RISK PATH] Exploit Insecure Default MariaDB Configuration
    │   ├── [CRITICAL NODE] [HIGH-RISK PATH] Exploit Weak MariaDB User Permissions
    │   ├── [CRITICAL NODE] [HIGH-RISK PATH] Exploit Insecure Remote Access Configuration
    ├── [CRITICAL NODE] Exploit MariaDB Server-Side Vulnerabilities
    │   ├── [CRITICAL NODE] Exploit Known Common Vulnerabilities and Exposures (CVEs) in MariaDB
```

**Detailed Breakdown of Attack Vectors for High-Risk Paths and Critical Nodes:**

**Exploit MariaDB Authentication/Authorization Weaknesses (Critical Node):**

*   This represents a category of attacks targeting the mechanisms used to verify the identity and privileges of users connecting to the MariaDB server. Successful exploitation grants unauthorized access.

**Brute-force MariaDB Credentials (Critical Node):**

*   Attackers attempt to guess valid usernames and passwords by systematically trying different combinations. Success grants unauthorized access to the database.

**Exploit Default MariaDB Credentials (Critical Node & High-Risk Path):**

*   Many MariaDB installations come with default usernames and passwords. If these are not changed, attackers can easily gain initial access to the database server. This path is high-risk due to its ease of exploitation and potential for immediate high impact.

**Exploit MariaDB Data Handling Vulnerabilities (Critical Node):**

*   This category encompasses attacks that exploit flaws in how MariaDB processes and manages data. Successful exploitation can lead to data breaches, manipulation, or corruption.

**Exploit SQL Injection Vulnerabilities within Stored Procedures/Functions (Critical Node & High-Risk Path):**

*   Attackers inject malicious SQL code into inputs that are processed by stored procedures or functions. If not properly sanitized, this code can be executed by the database, allowing attackers to bypass security measures, access or modify data, or even execute operating system commands. This path is high-risk due to the potential for significant data compromise.

**Exploit MariaDB Network/Communication Issues (High-Risk Path):**

*   This path focuses on vulnerabilities in the communication channels between the application and the MariaDB server.

**Man-in-the-Middle (MITM) Attack on MariaDB Connection (High-Risk Path):**

*   Attackers intercept communication between the application and the MariaDB server, potentially stealing credentials or sensitive data being transmitted. This path is high-risk due to the potential for credential compromise and data breaches.

**Denial of Service (DoS) Attack Targeting MariaDB Server (Critical Node & High-Risk Path):**

*   Attackers overwhelm the MariaDB server with requests, making it unavailable to legitimate users. This path is high-risk due to its potential to disrupt application availability, and it's a critical node because it directly impacts service.

**Exploit MariaDB Configuration/Management Weaknesses (Critical Node):**

*   This category involves exploiting insecure configurations or management practices of the MariaDB server.

**Exploit Insecure Default MariaDB Configuration (Critical Node & High-Risk Path):**

*   Default MariaDB configurations may have security weaknesses. Attackers can exploit these weaknesses to gain unauthorized access or escalate privileges. This path is high-risk due to the commonality of default configurations and the ease of exploitation.

**Exploit Weak MariaDB User Permissions (Critical Node & High-Risk Path):**

*   If database users are granted excessive privileges, attackers who compromise a low-privilege account can potentially escalate their privileges and gain broader access to the database. This path is high-risk because it allows for privilege escalation and broader data access.

**Exploit Insecure Remote Access Configuration (Critical Node & High-Risk Path):**

*   If remote access to the MariaDB server is not properly restricted, attackers from untrusted networks can attempt to connect and exploit vulnerabilities. This path is high-risk as it opens the database to external threats.

**Exploit MariaDB Server-Side Vulnerabilities (Critical Node):**

*   This category involves exploiting vulnerabilities within the MariaDB server software itself.

**Exploit Known Common Vulnerabilities and Exposures (CVEs) in MariaDB (Critical Node):**

*   Attackers exploit publicly known vulnerabilities in specific versions of MariaDB for which patches may exist but haven't been applied. This is a critical node because successful exploitation can lead to severe consequences like remote code execution.