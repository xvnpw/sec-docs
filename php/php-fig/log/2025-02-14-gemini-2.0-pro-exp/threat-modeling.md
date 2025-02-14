# Threat Model Analysis for php-fig/log

## Threat: [Threat 1: Log Injection (Newline Injection/CRLF Injection/Log Forging)](./threats/threat_1_log_injection__newline_injectioncrlf_injectionlog_forging_.md)

*   **Description:** An attacker inserts malicious content, primarily newline characters (`\n`, `\r`, or `\r\n`) and potentially other control characters or formatting strings, *directly into the data being passed to the logging functions*. This is not about a general input validation failure; it's specifically about manipulating the *log output* itself. The attacker aims to create fake log entries, obscure real ones, or disrupt log analysis by injecting data that is interpreted as part of the log structure.
    *   **Impact:**
        *   Spoofed log entries, making it difficult to track the attacker's actions and potentially framing others.
        *   Masking of other attacks by burying real log entries within a flood of injected ones.
        *   Disruption of log analysis tools that rely on consistent log formatting or parsing.
        *   Potential for code injection (e.g., XSS) if the log *viewer* (which is directly processing the log output) is vulnerable.
    *   **Component Affected:**
        *   Any code that directly logs user-supplied data without sanitization *immediately before* passing it to the PSR-3 `LoggerInterface` methods (`log()`, `debug()`, `info()`, etc.). The `$message` or the `$context` array are the direct attack vectors.
        *   Custom formatters or handlers that process the `$message` or `$context` without proper escaping *before writing to the log destination*.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Immediate Sanitization Before Logging:**  *Always* sanitize *any* data from untrusted sources *immediately before* it is included in log messages, even within the `$context` array. This is the most critical step.
        *   **Context-Aware Encoding (in Formatters):**  The logging implementation (or custom formatters) *must* be aware of the intended output format (file, database, web UI) and encode the `$message` and `$context` data accordingly *before writing to the log*.
        *   **Parameterized Logging (if supported):** Use a logging library that supports parameterized logging, where placeholders in the message are replaced with values, *provided the library handles this securely*.
        *   **Secure Log Viewers:** Use log analysis tools that are known to be secure and resistant to injection attacks, and keep them updated. This mitigates the *impact* of injection, even if it occurs.

## Threat: [Threat 2: Sensitive Data Exposure (in Logs)](./threats/threat_2_sensitive_data_exposure__in_logs_.md)

*   **Description:** The application *directly logs* sensitive information, such as passwords, API keys, session tokens, PII, or internal system details, *into the log files or other log destinations*. This is not about a general data leak; it's specifically about the logging mechanism being the source of the exposure.
    *   **Impact:**
        *   Compromise of user accounts due to exposed credentials.
        *   Unauthorized access to APIs and services via leaked keys.
        *   Identity theft and fraud due to exposed PII.
        *   Exposure of internal system architecture, facilitating further attacks.
        *   Violation of privacy regulations (GDPR, CCPA, etc.), leading to legal and financial penalties.
    *   **Component Affected:**
        *   Any code that calls the PSR-3 `LoggerInterface` methods with sensitive data *directly* included in the `$message` or `$context` array. This is a *direct* misuse of the logging functionality.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Data Minimization (in Logging):**  Log only the *absolute minimum* information necessary.  *Never* log sensitive data directly. This is the primary defense.
        *   **Data Masking/Redaction (Pre-Logging):**  Implement a pre-logging step that *always* masks or redacts sensitive data *before* it reaches the logging functions. Replace sensitive values with placeholders or hashes.
        *   **Tokenization (Pre-Logging):**  Use tokens instead of actual sensitive values in log messages.
        *   **Code Review (Focused on Logging):**  Regularly review code *specifically* to identify and remove any instances of sensitive data being passed to logging functions.
        *   **Secure Configuration (and Avoid Logging It):** Store sensitive configuration data securely (environment variables, secrets management) and *never* log the configuration itself.

## Threat: [Threat 3: Improper Context Handling Leading to Injection (Directly in Logs)](./threats/threat_3_improper_context_handling_leading_to_injection__directly_in_logs_.md)

* **Description:** The application passes unsanitized data within the `$context` array of a PSR-3 log call, and this data is *directly used* by the logging implementation or a custom formatter without proper escaping. This is a *direct* threat to the logging process because the vulnerability lies in how the logging library or its components handle the provided context. The attacker can inject malicious content that affects the log output itself.
    * **Impact:**
        *   XSS vulnerabilities in log viewers that render the context data without escaping.
        *   Log forging if the context data is used to construct log entries (e.g., inserted into the log message).
        *   Potential for other injection attacks depending on how the context data is *directly used* in the logging pipeline.
    * **Component Affected:**
        *   Any code that passes unsanitized data in the `$context` array to PSR-3 `LoggerInterface` methods.
        *   Custom formatters or handlers that process the `$context` array without proper escaping *before writing to the log destination*. This is where the direct vulnerability lies.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        *   **Sanitize Context Data (Immediately Before Logging):** Treat the `$context` array with the *same* level of scrutiny as the `$message`. Sanitize *all* data within the context array *immediately before* passing it to the logging functions.
        *   **Context-Aware Escaping (in Formatters):** If you create custom formatters, they *must* be aware of the output format and escape the context data appropriately *before writing to the log*. Use `htmlspecialchars()` for HTML, `json_encode()` for JSON, etc. This is crucial for preventing injection.
        *   **Avoid Unnecessary Context Data:** Only include essential data in the context array. Less data means a smaller attack surface.
        * **Use Structured Logging:** Prefer structured logging formats (like JSON) where the context data is clearly separated from the message. This makes it easier to parse and escape correctly *within the logging pipeline*.

