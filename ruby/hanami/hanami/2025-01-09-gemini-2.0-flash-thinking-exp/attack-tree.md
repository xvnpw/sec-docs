# Attack Tree Analysis for hanami/hanami

Objective: Attacker's Goal: To gain unauthorized access to sensitive data or execute arbitrary code on the server hosting the Hanami application by exploiting weaknesses or vulnerabilities within the Hanami framework itself (focusing on high-risk areas).

## Attack Tree Visualization

```
Compromise Hanami Application [CRITICAL NODE]
├─── Gain Unauthorized Access to Sensitive Data [HIGH RISK PATH]
│   ├─── Exploit Hanami's Action Vulnerabilities [HIGH RISK PATH]
│   │   └── Missing Authorization Checks in Actions [CRITICAL NODE, HIGH RISK PATH]
│   ├─── Exploit Hanami's Entity/Repository Vulnerabilities [HIGH RISK PATH]
│   │   └── Insecure Query Construction (Hanami::Model) [CRITICAL NODE]
│   └─── Exploit Hanami's Configuration Vulnerabilities [HIGH RISK PATH]
│       └── Exposure of Sensitive Configuration Data [CRITICAL NODE, HIGH RISK PATH]
└─── Execute Arbitrary Code on the Server [CRITICAL NODE, HIGH RISK PATH]
    ├─── Exploit Hanami's Action Vulnerabilities (leading to code execution) [HIGH RISK PATH]
    │   └── Command Injection via Parameter Handling [CRITICAL NODE]
    └─── Exploit Vulnerabilities in Hanami's Dependencies (Specific to Hanami's ecosystem) [HIGH RISK PATH]
        └── Vulnerabilities in Used Gems [CRITICAL NODE]
```


## Attack Tree Path: [Gain Unauthorized Access to Sensitive Data [HIGH RISK PATH]](./attack_tree_paths/gain_unauthorized_access_to_sensitive_data__high_risk_path_.md)

- This path represents the attacker's goal of accessing data they are not authorized to view or manipulate. It encompasses vulnerabilities that directly lead to data breaches.

    Exploit Hanami's Action Vulnerabilities [HIGH RISK PATH]:
    - Attackers target weaknesses in how Hanami actions handle requests and enforce authorization.
        - Missing Authorization Checks in Actions [CRITICAL NODE, HIGH RISK PATH]:
            - Attack Vector: Attackers directly access actions that handle sensitive data or operations without proper authentication or authorization checks.
            - Example: Accessing an action that displays user profiles by simply changing the user ID in the route, without the action verifying the current user's permissions.

    Exploit Hanami's Entity/Repository Vulnerabilities [HIGH RISK PATH]:
    - Attackers exploit flaws in how Hanami interacts with the database.
        - Insecure Query Construction (Hanami::Model) [CRITICAL NODE]:
            - Attack Vector: Attackers inject malicious SQL code into input fields or parameters that are used to construct database queries.
            - Example: Providing a malicious string in a search field that, when used in a database query, allows the attacker to extract all user credentials.

    Exploit Hanami's Configuration Vulnerabilities [HIGH RISK PATH]:
    - Attackers target weaknesses in how the Hanami application is configured.
        - Exposure of Sensitive Configuration Data [CRITICAL NODE, HIGH RISK PATH]:
            - Attack Vector: Attackers gain access to configuration files (like `.env`) or environment variables that contain sensitive information like database credentials, API keys, or secret keys.
            - Example: Discovering a publicly accessible `.env` file on the server containing database credentials, which can then be used to directly access the database.

## Attack Tree Path: [Execute Arbitrary Code on the Server [CRITICAL NODE, HIGH RISK PATH]](./attack_tree_paths/execute_arbitrary_code_on_the_server__critical_node__high_risk_path_.md)

- This path represents the attacker's goal of running their own code on the server hosting the Hanami application, leading to full system compromise.

    Exploit Hanami's Action Vulnerabilities (leading to code execution) [HIGH RISK PATH]:
    - Attackers target weaknesses in how Hanami actions process input, allowing them to execute commands on the server.
        - Command Injection via Parameter Handling [CRITICAL NODE]:
            - Attack Vector: Attackers inject malicious commands into parameters that are then used in system calls or to execute external processes.
            - Example: Providing a command like ``; rm -rf /`` in an input field that is used in a system call, potentially deleting all files on the server.

    Exploit Vulnerabilities in Hanami's Dependencies (Specific to Hanami's ecosystem) [HIGH RISK PATH]:
    - Attackers exploit known vulnerabilities in the Ruby gems that the Hanami application depends on.
        - Vulnerabilities in Used Gems [CRITICAL NODE]:
            - Attack Vector: Attackers leverage publicly known vulnerabilities in specific gems used by the Hanami application.
            - Example: A vulnerable version of a JSON parsing gem could be exploited by sending a specially crafted JSON payload that allows the attacker to execute arbitrary code.

