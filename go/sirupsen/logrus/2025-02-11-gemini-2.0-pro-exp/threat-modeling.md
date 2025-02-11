# Threat Model Analysis for sirupsen/logrus

## Threat: [Sensitive Data Leakage](./threats/sensitive_data_leakage.md)

*   **Threat:** Sensitive Data Leakage

    *   **Description:** An attacker gains access to sensitive information (PII, credentials, API keys, internal application state) that is inadvertently logged. This occurs because developers directly log sensitive data without proper sanitization or redaction *within the logging calls themselves*. The attacker exploits the fact that `logrus`, by default, doesn't automatically protect against this. The attacker might gain access to log files through various means, but the root cause is the insecure use of `logrus`.
    *   **Impact:**
        *   Exposure of confidential data: privacy breaches, financial loss, identity theft, reputational damage, legal consequences.
        *   Compromise of application security: unauthorized access, privilege escalation.
    *   **Logrus Component Affected:**
        *   `logrus.Logger` instance (the main logging object).
        *   `logrus.Entry` (individual log entries).
        *   Formatters (e.g., `logrus.TextFormatter`, `logrus.JSONFormatter`) – *critically*, the lack of *custom* formatters to handle sensitive data is the direct `logrus` issue.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Custom Formatters:** Implement custom `logrus` formatters that *explicitly* redact or mask sensitive fields. This is the *primary* and most direct mitigation, addressing the core `logrus` usage issue.
        *   **Structured Logging:** Use structured logging (JSON) with a predefined schema, making it easier to identify and manage sensitive fields *within the formatter*.
        *   **Log Level Discipline:** Use appropriate log levels. Avoid logging sensitive data at `Info`, `Warn`, or `Error` levels. Scrutinize `Debug` level logs. This is a supporting mitigation, but custom formatters are the key.
        *   **Code Reviews:** Mandatory code reviews focusing on logging statements *to ensure the correct use of custom formatters and avoidance of direct logging of sensitive data*.
        *   **Avoid `fmt.Sprintf` with Untrusted Data:** Prevent format string vulnerabilities when constructing log messages *that are then passed to `logrus`*.

## Threat: [Log Injection](./threats/log_injection.md)

*   **Threat:** Log Injection

    *   **Description:** An attacker injects malicious content into log messages by providing crafted input that includes control characters or other special sequences.  This is possible because `logrus`, by default, doesn't automatically escape all potentially harmful characters in all output formats. The attacker exploits the lack of *built-in, comprehensive* escaping within `logrus` itself.
    *   **Impact:**
        *   Disruption of log analysis and monitoring.
        *   Corruption of log files.
        *   Potential exploitation of vulnerabilities in log parsers or viewers (though this is *indirectly* related to `logrus`).
        *   Insertion of misleading information.
    *   **Logrus Component Affected:**
        *   `logrus.Logger` instance.
        *   `logrus.Entry`.
        *   Formatters – the *lack of robust, built-in escaping for all special characters* in the default formatters is the direct `logrus` issue.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Custom Formatters (Escaping):** Use custom `logrus` formatters to *explicitly* escape special characters (newlines, carriage returns, control characters, and potentially others depending on the output format and log consumer). This is the *primary* mitigation, directly addressing the `logrus` behavior.
        *   **Structured Logging (JSON):** JSON formatters *generally* handle escaping within values, but this is not a complete solution.  Custom formatters provide more control and are recommended for robust protection.  Ensure that *keys* in structured logs are also not attacker-controlled.

