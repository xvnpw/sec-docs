# Attack Tree Analysis for apache/logging-log4j2

Objective: Compromise application using Log4j2 vulnerabilities.

## Attack Tree Visualization

```
* Compromise Application Using Log4j2 **(Critical Node)**
    * Exploit Log4j2 Vulnerabilities
        * ***Achieve Remote Code Execution (RCE)*** **(High-Risk Path)**
            * ***Exploit JNDI Lookup Vulnerability (e.g., Log4Shell - CVE-2021-44228)*** **(Critical Node)**
                * ***Inject Malicious JNDI Lookup String into Logged Data*** **(Critical Node)**
                    * ***Inject via User-Controlled Input*** **(Critical Node)**
                        * ***HTTP Headers (e.g., User-Agent, X-Forwarded-For)***
                            * Likelihood: High
                            * Impact: Critical
                            * Effort: Low
                            * Skill Level: Low
                            * Detection Difficulty: Medium
                        * ***HTTP Request Parameters (GET/POST)***
                            * Likelihood: High
                            * Impact: Critical
                            * Effort: Low
                            * Skill Level: Low
                            * Detection Difficulty: Medium
                        * WebSocket Messages
                            * Likelihood: Medium
                            * Impact: Critical
                            * Effort: Medium
                            * Skill Level: Medium
                            * Detection Difficulty: Medium
                        * Other Input Fields Processed by the Application
                            * Likelihood: Medium
                            * Impact: Critical
                            * Effort: Medium
                            * Skill Level: Medium
                            * Detection Difficulty: Medium
                    * Inject via External Data Sources Logged by the Application
                        * Database Records
                            * Likelihood: Low
                            * Impact: Critical
                            * Effort: High
                            * Skill Level: High
                            * Detection Difficulty: High
                        * Message Queues (e.g., Kafka, RabbitMQ)
                            * Likelihood: Low to Medium
                            * Impact: Critical
                            * Effort: Medium to High
                            * Skill Level: Medium to High
                            * Detection Difficulty: Medium to High
                        * Other External Systems
                            * Likelihood: Low to Medium
                            * Impact: Critical
                            * Effort: Medium to High
                            * Skill Level: Medium to High
                            * Detection Difficulty: Medium to High
                * **Log4j2 Performs JNDI Lookup** **(Critical Node)**
                    * Configuration allows JNDI lookups (default in vulnerable versions)
                        * Likelihood: High
                        * Impact: N/A
                        * Effort: N/A
                        * Skill Level: N/A
                        * Detection Difficulty: N/A
                * Malicious Server Provides Payload
                    * LDAP Server hosting malicious Java object
                        * Likelihood: High
                        * Impact: Critical
                        * Effort: Low
                        * Skill Level: Low to Medium
                        * Detection Difficulty: Medium
                    * RMI Server hosting malicious Java object
                        * Likelihood: Medium
                        * Impact: Critical
                        * Effort: Medium
                        * Skill Level: Medium
                        * Detection Difficulty: Medium
                    * DNS Server with malicious response (less common for RCE)
                        * Likelihood: Low
                        * Impact: High
                        * Effort: Medium
                        * Skill Level: Medium
                        * Detection Difficulty: Medium to High
        * ***Achieve Denial of Service (DoS)*** **(High-Risk Path)**
            * ***Exploit Recursive Lookup Vulnerability (CVE-2021-45046, CVE-2021-45105)***
                * ***Inject a crafted lookup string that causes infinite recursion***
                    * Similar injection points as JNDI injection
                        * Likelihood: Similar to JNDI injection points
                        * Impact: High
                        * Effort: Low to Medium
                        * Skill Level: Medium
                        * Detection Difficulty: Medium
                * Log4j2 consumes excessive resources (CPU, memory)
                    * Likelihood: High
                    * Impact: High
                    * Effort: N/A
                    * Skill Level: N/A
                    * Detection Difficulty: High
```


## Attack Tree Path: [Achieve Remote Code Execution (RCE)](./attack_tree_paths/achieve_remote_code_execution__rce_.md)

**Attack Vector:** Exploits the JNDI Lookup vulnerability (e.g., Log4Shell - CVE-2021-44228) in Log4j2.
* **Sequence:**
    * The attacker injects a specially crafted string into data that will be logged by the application. This string leverages Log4j2's lookup functionality to perform a Java Naming and Directory Interface (JNDI) lookup.
    * Common injection points include HTTP headers (like User-Agent), HTTP request parameters (GET/POST), WebSocket messages, and other input fields processed by the application. Injection via external data sources is also possible but generally requires more control over those sources.
    * When Log4j2 processes the log message containing the malicious JNDI lookup string, it attempts to resolve the resource specified in the string.
    * This triggers a request to a malicious server controlled by the attacker (typically an LDAP or RMI server).
    * The malicious server responds with a payload containing a path to a malicious Java class.
    * The vulnerable version of Log4j2 then proceeds to download and execute this malicious Java class, resulting in arbitrary code execution on the server.
* **Critical Nodes within this path:**
    * **Compromise Application Using Log4j2:** The ultimate goal.
    * **Exploit JNDI Lookup Vulnerability (e.g., Log4Shell - CVE-2021-44228):** The specific vulnerability being targeted.
    * **Inject Malicious JNDI Lookup String into Logged Data:** The attacker's initial action to introduce the exploit.
    * **Inject via User-Controlled Input:** The most common and easily exploitable method for injecting the malicious string.
    * **Log4j2 Performs JNDI Lookup:** The vulnerable behavior of Log4j2 that enables the exploit.

## Attack Tree Path: [Achieve Denial of Service (DoS)](./attack_tree_paths/achieve_denial_of_service__dos_.md)

**Attack Vector:** Exploits the Recursive Lookup Vulnerability (CVE-2021-45046, CVE-2021-45105) in Log4j2.
* **Sequence:**
    * The attacker injects a carefully crafted lookup string into data that will be logged by the application. This string is designed to cause Log4j2 to enter an infinite recursion loop when attempting to resolve the lookups.
    * Similar injection points as the JNDI injection vulnerability can be used.
    * When Log4j2 processes the log message containing the malicious recursive lookup string, it repeatedly attempts to resolve the nested lookups, leading to excessive consumption of system resources (CPU and memory).
    * This resource exhaustion eventually leads to a Denial of Service, making the application unresponsive or crashing it entirely.
* **Critical Nodes within this path:**
    * **Compromise Application Using Log4j2:** The ultimate goal.
    * **Inject a crafted lookup string that causes infinite recursion:** The attacker's action to trigger the DoS.

## Attack Tree Path: [Compromise Application Using Log4j2](./attack_tree_paths/compromise_application_using_log4j2.md)

This represents the successful exploitation of Log4j2 to harm the application. It's the root of all attack paths.

## Attack Tree Path: [Exploit JNDI Lookup Vulnerability (e.g., Log4Shell - CVE-2021-44228)](./attack_tree_paths/exploit_jndi_lookup_vulnerability__e_g___log4shell_-_cve-2021-44228_.md)

This is a critical node because it represents the most severe and widely exploited vulnerability in Log4j2, leading to Remote Code Execution.

## Attack Tree Path: [Inject Malicious JNDI Lookup String into Logged Data](./attack_tree_paths/inject_malicious_jndi_lookup_string_into_logged_data.md)

This is a critical node because it's the necessary first step for exploiting the JNDI lookup vulnerability. Without successful injection, the RCE attack cannot proceed.

## Attack Tree Path: [Inject via User-Controlled Input](./attack_tree_paths/inject_via_user-controlled_input.md)

This is a critical node because it represents the most accessible and frequently targeted attack surface for injecting malicious payloads into log messages.

## Attack Tree Path: [Log4j2 Performs JNDI Lookup](./attack_tree_paths/log4j2_performs_jndi_lookup.md)

This is a critical node because it highlights the vulnerable behavior within Log4j2 that allows the JNDI injection attack to succeed. Disabling or mitigating this behavior is key to preventing RCE.

