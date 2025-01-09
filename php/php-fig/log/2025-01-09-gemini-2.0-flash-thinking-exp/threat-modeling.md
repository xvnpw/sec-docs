# Threat Model Analysis for php-fig/log

## Threat: [Accidental Logging of Sensitive Data](./threats/accidental_logging_of_sensitive_data.md)

**Threat:** Accidental Logging of Sensitive Data

**Description:** Developers using the `php-fig/log` interface might inadvertently pass sensitive information (e.g., passwords, API keys, personal data) as part of the log message or context. This occurs at the point where the `LoggerInterface` methods (like `info`, `error`, etc.) are called within the application code. The attacker could then access these logs through compromised servers or exposed log files.

**Impact:** Information disclosure, potential data breach, violation of privacy regulations, reputational damage.

**Affected Component:**

*   Application Code Using Logger (`Psr\Log\LoggerInterface` method calls) - This is where the data being logged is determined.

**Risk Severity:** High

**Mitigation Strategies:**

*   Implement strict filtering and sanitization of data *before* passing it to the `LoggerInterface` methods.
*   Avoid directly logging raw request and response bodies. Implement mechanisms to redact sensitive information before logging.
*   Educate developers on secure logging practices and the risks of logging sensitive data.
*   Regularly review the code where `LoggerInterface` methods are used to identify potential sensitive data leaks.

## Threat: [Log Injection via Unsanitized Input in Log Messages](./threats/log_injection_via_unsanitized_input_in_log_messages.md)

**Threat:** Log Injection via Unsanitized Input in Log Messages

**Description:** If user-controlled input is directly included in log messages passed to the `LoggerInterface` methods without proper sanitization, attackers can inject arbitrary content into the logs. This happens when the application code constructs log messages using user input and then passes this unsanitized string to the logger. This injected content can be used to obfuscate malicious activity or potentially exploit vulnerabilities in log analysis tools.

**Impact:** Compromised log integrity, potential exploitation of log analysis tools, difficulty in incident investigation.

**Affected Component:**

*   Application Code Using Logger (`Psr\Log\LoggerInterface` method calls) - Specifically, the construction of the log message string.

**Risk Severity:** High

**Mitigation Strategies:**

*   Sanitize or encode user input *before* including it in log messages passed to the `LoggerInterface`.
*   Utilize parameterized logging (the `context` array in `LoggerInterface` methods) where data is treated separately from the message template, preventing direct injection.
*   Avoid directly concatenating user input into log message strings.

