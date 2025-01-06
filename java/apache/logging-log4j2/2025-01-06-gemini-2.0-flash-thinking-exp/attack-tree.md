# Attack Tree Analysis for apache/logging-log4j2

Objective: Achieve Remote Code Execution (RCE) on the application server or gain unauthorized access to sensitive data by exploiting vulnerabilities within the Log4j2 library.

## Attack Tree Visualization

```
* Compromise Application via Log4j2 Exploitation (AND)
    * *** High-Risk Path *** Exploit Message Formatting Vulnerabilities (OR)
        * **CRITICAL NODE** Inject Malicious JNDI Lookup String (Log4Shell - CVE-2021-44228, etc.) (AND)
            * Inject via HTTP Headers (e.g., User-Agent, X-Forwarded-For)
            * Inject via HTTP Parameters (GET/POST)
            * Inject via Other Input Fields (e.g., form data, API requests)
            * Inject via Data Logged from External Sources (e.g., database, other services)
    * Manipulate Log4j2 Configuration (OR)
        * **CRITICAL NODE** Gain Access to Log4j2 Configuration File (e.g., log4j2.xml, log4j2.properties) (AND)
            * Exploit File Inclusion Vulnerabilities in Application
            * Exploit Path Traversal Vulnerabilities in Application
            * Gain Unauthorized Access to Server File System
            * Exploit Default or Weak Configuration File Permissions
    * Abuse Log4j2 Appenders (OR)
        * *** High-Risk Path *** Redirect Logs to Attacker-Controlled Server (AND)
            * **CRITICAL NODE** Modify Configuration to Use SocketAppender/JDBCAppender with Malicious Destination
                * Modify Configuration to Use SocketAppender with Malicious Destination
                * Modify Configuration to Use JDBCAppender with Malicious Destination
            * Exploit Vulnerabilities in Custom Appenders
    * *** High-Risk Path *** Exploit Vulnerabilities in Custom Log4j2 Components (OR)
        * **CRITICAL NODE** Exploit Malicious Custom Appenders (AND)
            * Identify and Trigger Usage of Malicious Appender
```


## Attack Tree Path: [Exploit Message Formatting Vulnerabilities](./attack_tree_paths/exploit_message_formatting_vulnerabilities.md)

**Attack Vector:** Injecting specially crafted strings into log messages that leverage Log4j2's message formatting capabilities, specifically JNDI lookups.

* **CRITICAL NODE** Inject Malicious JNDI Lookup String (Log4Shell - CVE-2021-44228, etc.) (AND)
    * Inject via HTTP Headers (e.g., User-Agent, X-Forwarded-For)
        * **Attack Vector:**  Manipulating HTTP headers (e.g., User-Agent, X-Forwarded-For) with a malicious JNDI lookup string. If these headers are logged, Log4j2 will attempt the lookup.
    * Inject via HTTP Parameters (GET/POST)
        * **Attack Vector:**  Including a malicious JNDI lookup string in GET or POST parameters. If these parameters are logged, Log4j2 will attempt the lookup.
    * Inject via Other Input Fields (e.g., form data, API requests)
        * **Attack Vector:**  Submitting a malicious JNDI lookup string through form fields, API request bodies, or other user-provided input that is subsequently logged.
    * Inject via Data Logged from External Sources (e.g., database, other services)
        * **Attack Vector:**  Compromising an external data source (e.g., database, another service) to inject a malicious JNDI lookup string that is then logged by the application.

## Attack Tree Path: [Gain Access to Log4j2 Configuration File](./attack_tree_paths/gain_access_to_log4j2_configuration_file.md)

**Attack Vector:**

* Exploit File Inclusion Vulnerabilities in Application
    * **Attack Vector:** Leveraging vulnerabilities in the application that allow an attacker to include arbitrary files, potentially including the Log4j2 configuration file.
* Exploit Path Traversal Vulnerabilities in Application
    * **Attack Vector:** Using path traversal techniques (e.g., `../../log4j2.xml`) to access the Log4j2 configuration file if the application doesn't properly sanitize file paths.
* Gain Unauthorized Access to Server File System
    * **Attack Vector:**  Compromising the server through other means (e.g., SSH brute-force, exploiting other application vulnerabilities) to directly access the file system and the Log4j2 configuration file.
* Exploit Default or Weak Configuration File Permissions
    * **Attack Vector:**  Taking advantage of default or poorly configured file permissions that allow unauthorized users to read or modify the Log4j2 configuration file.

## Attack Tree Path: [Redirect Logs to Attacker-Controlled Server](./attack_tree_paths/redirect_logs_to_attacker-controlled_server.md)

* **CRITICAL NODE** Modify Configuration to Use SocketAppender/JDBCAppender with Malicious Destination
    * Modify Configuration to Use SocketAppender with Malicious Destination
        * **Attack Vector:** Changing the Log4j2 configuration (after gaining access) to use the `SocketAppender` and point it to an attacker-controlled server and port. This will cause the application to send log data to the attacker.
    * Modify Configuration to Use JDBCAppender with Malicious Destination
        * **Attack Vector:** Changing the Log4j2 configuration to use the `JDBCAppender` and configure it to write logs to a database controlled by the attacker. This allows the attacker to capture logged information.
* Exploit Vulnerabilities in Custom Appenders
    * **Attack Vector:** Exploit vulnerabilities in custom appenders that might allow for arbitrary log redirection or other malicious behavior.

## Attack Tree Path: [Exploit Malicious Custom Appenders](./attack_tree_paths/exploit_malicious_custom_appenders.md)

* **CRITICAL NODE** Exploit Malicious Custom Appenders (AND)
    * Identify and Trigger Usage of Malicious Appender
        * **Attack Vector:** If the application uses custom appenders, an attacker might try to identify if a malicious or vulnerable custom appender exists and then find ways to trigger its usage. This could involve manipulating the configuration (if possible) or exploiting application logic that leads to the instantiation and use of the malicious appender. The vulnerability within the custom appender itself could range from arbitrary code execution to data manipulation.

