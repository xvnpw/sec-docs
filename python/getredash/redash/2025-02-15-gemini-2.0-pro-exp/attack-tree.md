# Attack Tree Analysis for getredash/redash

Objective: Exfiltrate Data OR Execute Arbitrary Code on Redash Server

## Attack Tree Visualization

```
                                     +-------------------------------------------------+
                                     |  Exfiltrate Data OR Execute Arbitrary Code on   |
                                     |                 Redash Server                   |
                                     +-------------------------------------------------+
                                                  /                 |                 \
                                                 /                  |                  \
          +--------------------------------+   +---------------------+   +--------------------------------+
          |  1. Compromise Data Source   |   | **2. Compromise Redash**|   | 3. Compromise Redash Server   |
          |       Credentials    [!]     |   |   **Application**     |   |        Infrastructure        |
          +--------------------------------+   +---------------------+   +--------------------------------+
                 /                                     /       |                      |
                /                                    /        |                      |
+-------------+                            +--------+ +-------+          +-------+
| 1.1 Weak  |                            | **2.1**| |  2.2   |          |  3.3   |
|  Data     |                            | **Query**| |  User |          |**3rd** |
|  Source  |                            |**Param**| |  Imper|          |**Party**|
|  Creds   |                            | **Vuln**| | sonat|          |**Libs** |
|    [!]    |                            |   [!]  | |  [!]  |          |**Vuln** |
+-------------+                            +--------+ +-------+          +-------+
                                                  |        |                  |
                                                  |        |                  |
                                                  |        |       +--------------------------------+
                                                  |        |       |**3.3.1 Unpatched Vulnerability**|
                                                  |        |       |      **in a Dependency**       |
                                                  |        |       |            **[!]**             |
                                                  |        |       +--------------------------------+
                                                  |        |
                                                  |        +--------------------------------+
                                                  |        | 2.2.1 Weak/Default Admin       |
                                                  |        |       Credentials              |
                                                  |        |            [!]                |
                                                  |        +--------------------------------+
                                                  |
                                                  +--------------------------------+
                                                  |**2.1.1 SQL Injection via Query**|
                                                  |      **Parameters (Redash)**    |
                                                  |            **[!]**             |
                                                  +--------------------------------+
```

## Attack Tree Path: [Path 1](./attack_tree_paths/path_1.md)

**Compromise Redash Application ---> Query Parameterization Vulnerabilities ---> SQL Injection via Query Parameters (Redash)**

## Attack Tree Path: [Path 2](./attack_tree_paths/path_2.md)

**Compromise Redash Server Infrastructure ---> 3rd Party Libs Vuln ---> Unpatched Vulnerability in a Dependency**

## Attack Tree Path: [Path 3](./attack_tree_paths/path_3.md)

**Compromise Data Source Credentials ---> Weak Data Source Credentials**

## Attack Tree Path: [Path 4](./attack_tree_paths/path_4.md)

**Compromise Redash Application ---> User Impersonation ---> Weak/Default Admin Credentials**

