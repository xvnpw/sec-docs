# Attack Surface Analysis for php-fig/log

## Attack Surface: [Log Injection / Forging](./attack_surfaces/log_injection__forging.md)

*   **Description:** Attackers inject malicious content into log messages, potentially disrupting log analysis, causing misinterpretation, or even executing code within log viewing tools.
*   **How Log Contributes:** PSR-3's `$message` (string) and `$context` (array) parameters are direct injection points if user-supplied or untrusted data is included without sanitization.  This is a *direct* misuse of the logging interface.
*   **Example:**
    *   An attacker submits a form field containing `<script>alert('XSS')</script>`. If this is directly logged via `$logger->info($_POST['field'])`, a web-based log viewer might execute the script.
    *   An attacker provides input containing newline characters (`\n`) to break up log entries and confuse parsing tools:  `$logger->warning("User input: " . $_POST['input'])`.  
    *   An attacker injects SQL code into a log message, hoping it might be executed by a log analysis tool: `$logger->error("Failed query: " . $userInput)`.  
*   **Impact:**
    *   Log analysis disruption.
    *   False positives/negatives in security monitoring.
    *   Cross-site scripting (XSS) in log viewers.
    *   Potential command injection in log analysis tools.
*   **Risk Severity:** High (Potentially Critical if command injection is possible)
*   **Mitigation Strategies:**
    *   **Input Validation:**  Strictly validate *all* data included in log messages and the `$context` array. Use whitelists.
    *   **Output Encoding/Escaping:**  Encode or escape log data *before* writing or displaying it. Use context-aware escaping (HTML encoding for web UIs, etc.).
    *   **Contextual Logging:**  Favor using the `$context` array for structured data, rather than concatenating untrusted data into the `$message`.  This is a key PSR-3 best practice.
    *   **Avoid Direct User Input:**  Use static log messages where possible, placing dynamic data in the `$context`.
    *   **Secure Log Viewers:** Ensure log viewers properly escape output to prevent XSS.  This is crucial if the `$context` is rendered.
    *   **Sanitize Log Analysis Inputs:** If log data is used as input to other tools, sanitize it first.

## Attack Surface: [Log File Access / Disclosure](./attack_surfaces/log_file_access__disclosure.md)

*   **Description:** Unauthorized access to log files, revealing sensitive information contained within.
*   **How Log Contributes:** While PSR-3 doesn't *dictate* storage, the application's use of a PSR-3 logger *creates* the log files that are then vulnerable.  The act of logging itself is the direct contributor.
*   **Example:**
    *   Log files created by a PSR-3 logger are stored in a web-accessible directory.
    *   Log files have overly permissive file permissions, allowing unauthorized access.
*   **Impact:**
    *   Exposure of sensitive data (credentials, API keys, session tokens, internal IPs, etc.).  This is a direct consequence of logging sensitive information.
    *   Privacy violations (PII disclosure).
*   **Risk Severity:** High (Potentially Critical if credentials are leaked)
*   **Mitigation Strategies:**
    *   **Secure File Permissions:**  Use restrictive file permissions (e.g., `640` or `600`).
    *   **Store Outside Web Root:**  Place log files *outside* the web server's document root.
    *   **Dedicated Log Server:**  Use a separate, secure log server.
    *   **Log Rotation & Archiving:**  Rotate logs regularly and archive securely.
    *   **Avoid Sensitive Data:**  *Never* log passwords, API keys, or other sensitive credentials directly.  Redact or use placeholders. This is the most important mitigation.

## Attack Surface: [Log Tampering](./attack_surfaces/log_tampering.md)

*   **Description:** Attackers modify or delete log entries to cover their tracks or mislead investigations.
*   **How Log Contributes:** The existence of log files, created by the PSR-3 logger, is what the attacker targets. The logging process itself creates the target.
*   **Example:**
    *   An attacker gains access to the log files created by the PSR-3 logger and deletes entries.
    *   An attacker modifies log entries to alter the record of events.
*   **Impact:**
    *   Loss of audit trail, hindering incident response.
    *   Misleading investigations.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Secure Log Storage:** Store logs on a separate, secure server.
    *   **Log Integrity Monitoring:** Use File Integrity Monitoring (FIM) tools.
    *   **Digital Signatures:** If supported, use digital signatures for log entries.
    *   **Append-Only Logs:** Configure for append-only operation.
    *   **Centralized Logging:** Use a centralized logging system with audit trails.
    *   **Principle of Least Privilege:** Restrict access to log files.

