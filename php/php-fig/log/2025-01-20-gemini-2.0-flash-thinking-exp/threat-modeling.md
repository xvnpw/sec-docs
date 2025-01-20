# Threat Model Analysis for php-fig/log

## Threat: [Logging Sensitive Data](./threats/logging_sensitive_data.md)

**Description:** Developers using the `LoggerInterface::log()` method might directly pass sensitive information as part of the log message. While the interface itself doesn't enforce security, its usage directly leads to the risk of logging sensitive data if developers are not careful. An attacker gaining access to these logs can then access this sensitive information.

**Impact:** Data breach, identity theft, financial loss, reputational damage, compliance violations.

**Affected Component:** `LoggerInterface::log()` method.

**Risk Severity:** Critical

**Mitigation Strategies:**

*   Implement strict guidelines on what data should be logged when using the `LoggerInterface`.
*   Educate developers on the risks of logging sensitive information directly through the interface.
*   Promote the use of placeholders or anonymization techniques *before* passing data to the `log()` method.
*   Implement code reviews to identify and prevent the logging of sensitive data.

## Threat: [Log Injection](./threats/log_injection.md)

**Description:** If user-supplied data is directly passed to the `LoggerInterface::log()` method without proper sanitization, an attacker can inject malicious content into the logs. The `php-fig/log` interface itself doesn't provide sanitization, making it the developer's responsibility when using the interface. This can lead to log poisoning and potential exploitation depending on how logs are processed.

**Impact:** Log analysis disruption, potential for remote code execution (depending on log processing), misleading security investigations.

**Affected Component:** `LoggerInterface::log()` method.

**Risk Severity:** High

**Mitigation Strategies:**

*   Sanitize or encode user-supplied data *before* passing it to the `LoggerInterface::log()` method.
*   Use parameterized logging or prepared statements where the log message format is defined separately from the data being logged.
*   Implement input validation to prevent malicious characters from being logged via the interface.

