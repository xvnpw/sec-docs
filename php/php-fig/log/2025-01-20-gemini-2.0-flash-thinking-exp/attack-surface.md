# Attack Surface Analysis for php-fig/log

## Attack Surface: [Log Injection](./attack_surfaces/log_injection.md)

* **Description:** Malicious actors inject crafted input into log messages, which can be interpreted as commands or code by log viewers or analysis tools.
    * **How Log Contributes to the Attack Surface:** The `php-fig/log` library provides the mechanism for writing data into log files. If user-supplied data is included in log messages without proper sanitization, it becomes a direct vector for injection.
    * **Example:** A user provides the input `"; $(reboot)"` in a form field, and this is logged directly. A vulnerable log analysis tool might interpret `$(reboot)` as a shell command.
    * **Impact:** Code execution on the logging server or administrator's machine, manipulation of log data, denial of service of log analysis tools.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * Implement robust input validation and sanitization for all data included in log messages.
        * Avoid directly logging user-supplied input without processing.
        * Use parameterized logging or structured logging formats that separate data from the log message template.
        * Ensure log analysis tools are secure and do not execute commands embedded in log messages.

## Attack Surface: [Information Disclosure through Logs](./attack_surfaces/information_disclosure_through_logs.md)

* **Description:** Sensitive information, such as API keys, passwords, personal data, or internal system details, is unintentionally included in log messages.
    * **How Log Contributes to the Attack Surface:** The `php-fig/log` library facilitates the recording of application state and data. If developers are not careful about what they log, the library becomes the direct conduit for exposing sensitive information.
    * **Example:** Logging the entire request object containing authentication tokens, or logging database connection strings during debugging.
    * **Impact:** Exposure of confidential data, leading to account compromise, data breaches, or further attacks.
    * **Risk Severity:** Critical
    * **Mitigation Strategies:**
        * Implement strict policies regarding what data is logged, especially in production environments.
        * Regularly review log configurations and code to identify and remove instances of sensitive data logging.
        * Utilize log masking or redaction techniques to remove sensitive information before logging.
        * Avoid logging credentials or secrets directly. Use secure secret management solutions.

## Attack Surface: [Vulnerabilities in Log Handlers](./attack_surfaces/vulnerabilities_in_log_handlers.md)

* **Description:**  Security flaws exist in the specific log handlers used with the `php-fig/log` library, leading to potential exploits.
    * **How Log Contributes to the Attack Surface:** The `php-fig/log` library relies on handlers to output log messages to various destinations. The library's choice of handler and the way it integrates with it directly influences the attack surface if the handler is vulnerable.
    * **Example:** A custom file handler has a path traversal vulnerability, allowing an attacker to write log messages to arbitrary files on the system. A database handler might be vulnerable to SQL injection if log messages are not properly sanitized before insertion.
    * **Impact:** Code execution, data breaches, or other vulnerabilities depending on the specific handler and its flaw.
    * **Risk Severity:** High (can be Critical depending on the handler vulnerability)
    * **Mitigation Strategies:**
        * Use well-vetted and maintained log handlers.
        * Regularly update log handler libraries to patch known vulnerabilities.
        * If using custom handlers, conduct thorough security reviews and penetration testing.
        * Ensure handlers are configured securely, following the principle of least privilege. For example, database handlers should use parameterized queries.

