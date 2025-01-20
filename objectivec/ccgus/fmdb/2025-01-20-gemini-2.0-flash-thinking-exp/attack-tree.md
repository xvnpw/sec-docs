# Attack Tree Analysis for ccgus/fmdb

Objective: Gain unauthorized access, manipulate data, or disrupt the application by exploiting FMDB.

## Attack Tree Visualization

```
Compromise Application via FMDB Exploitation [CRITICAL NODE]
└── AND: Exploit FMDB Weakness
    ├── OR: SQL Injection via FMDB [HIGH-RISK PATH START]
    │   └── Inject Malicious SQL through String Formatting [CRITICAL NODE]
    │       └── Leverage insufficient escaping in FMDB methods (e.g., `executeQuery:withArgumentsInArray:`)
    │           └── Inject control characters or SQL keywords within arguments
    └── OR: Database File Manipulation [HIGH-RISK PATH START] [CRITICAL NODE]
        └── Direct Database File Access
            └── Gain unauthorized access to the SQLite database file [CRITICAL NODE]
                ├── Exploit insecure file permissions on the database file
                └── Exploit vulnerabilities in the operating system or file system
            └── Modify the database file directly [CRITICAL NODE]
                └── Inject malicious data or schema changes
```


## Attack Tree Path: [High-Risk Path 1: SQL Injection via FMDB](./attack_tree_paths/high-risk_path_1_sql_injection_via_fmdb.md)

* Inject Malicious SQL through String Formatting [CRITICAL NODE]:
    * This attack vector exploits the potential for developers to construct SQL queries using string formatting or concatenation instead of strictly relying on FMDB's parameterized query methods.
    * Leverage insufficient escaping in FMDB methods (e.g., `executeQuery:withArgumentsInArray:`): Even when using FMDB methods that accept arguments, if the arguments are not properly handled or escaped internally by FMDB in all scenarios, vulnerabilities can arise.
        * Inject control characters or SQL keywords within arguments: Attackers can craft input strings containing characters like single quotes ('), semicolons (;), or SQL keywords (e.g., `UNION`, `DROP`) to manipulate the intended SQL query structure. This can lead to unauthorized data access, modification, or even the execution of arbitrary SQL commands.

## Attack Tree Path: [High-Risk Path 2: Database File Manipulation](./attack_tree_paths/high-risk_path_2_database_file_manipulation.md)

* Database File Manipulation [CRITICAL NODE]: This path focuses on directly interacting with the SQLite database file, bypassing the application's intended access methods.
    * Direct Database File Access:
        * Gain unauthorized access to the SQLite database file [CRITICAL NODE]: This is a critical step that allows the attacker to directly interact with the database file.
            * Exploit insecure file permissions on the database file: If the database file is stored with overly permissive file system permissions, an attacker with access to the server or file system can directly read or modify the file.
            * Exploit vulnerabilities in the operating system or file system:  Operating system or file system vulnerabilities could allow an attacker to gain unauthorized access to files, including the database file.
        * Modify the database file directly [CRITICAL NODE]: Once access is gained, the attacker can directly alter the database file.
            * Inject malicious data or schema changes: Attackers can use SQLite tools or scripting to directly insert malicious data, modify existing data, add new users with administrative privileges, or alter the database schema to introduce vulnerabilities that can be exploited later through the application.

