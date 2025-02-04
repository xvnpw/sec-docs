# Attack Surface Analysis for php-fig/log

## Attack Surface: [Information Disclosure through Excessive Logging](./attack_surfaces/information_disclosure_through_excessive_logging.md)

Description: Sensitive information is unintentionally logged, making it accessible to attackers if logs are compromised. This directly exposes confidential data due to logging practices.
*   **How Log Contributes:** Logging mechanisms are designed to record application activity. If developers log too much detail or sensitive data without proper care, it becomes part of the log data, creating a direct pathway for information leakage if logs are accessed by unauthorized parties. `php-fig/log` implementations will record whatever data is passed to them, making it crucial to control what is logged.
*   **Example:** A developer logs full HTTP request and response bodies, including sensitive data like user credentials, API keys, or personal information within request parameters or headers. If these logs are accessed by an attacker, it leads to direct exposure of this sensitive data.
*   **Impact:** **Critical**.  Direct confidentiality breach, identity theft, account takeover, financial loss, severe reputational damage, legal and regulatory penalties due to exposure of sensitive data.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Strict Data Minimization:** Implement a policy of logging only absolutely necessary information. Prohibit logging of sensitive data like passwords, API keys, secrets, credit card numbers, and Personally Identifiable Information (PII) unless under exceptional, justified circumstances with robust security controls.
    *   **Aggressive Data Masking/Redaction:** Implement mandatory and robust masking or redaction of sensitive data in logs. This should be automated and applied consistently to all log entries. For example, redact password fields, mask credit card numbers, and anonymize user IDs where possible.
    *   **Automated Log Analysis for Sensitive Data:** Implement automated tools to scan logs for patterns of sensitive data and flag or remove them.
    *   **Strong Access Control and Encryption for Logs:** Enforce strict access controls (Principle of Least Privilege) to log storage. Encrypt logs at rest and in transit to protect confidentiality even if storage is breached.

## Attack Surface: [Log Injection Vulnerabilities leading to Cross-Site Scripting (XSS) in Log Viewers](./attack_surfaces/log_injection_vulnerabilities_leading_to_cross-site_scripting__xss__in_log_viewers.md)

Description: Attackers inject malicious content into log files by manipulating input that is subsequently logged without proper sanitization. This injected content, when viewed through a log viewer, can execute as code, specifically leading to XSS if the viewer is web-based. This is a direct consequence of logging unsanitized input.
*   **How Log Contributes:** Logging functions directly write provided strings into log files. If these strings originate from user input or external sources and are not sanitized, they can contain malicious payloads. When these logs are displayed in a web-based viewer without proper output encoding, the injected malicious scripts can execute in the browser of the log viewer user. `php-fig/log` implementations will log whatever string is provided, making input sanitization before logging essential.
*   **Example:** An attacker injects a malicious payload like `<img src=x onerror=alert('XSS')>` into a username field. If failed login attempts are logged including the username without proper HTML encoding, and a system administrator views these logs through a web-based log viewer, the JavaScript `alert('XSS')` will execute in their browser. If the log viewer has access to sensitive administrative functionalities, this XSS can be leveraged for account takeover or further attacks.
*   **Impact:** **High**. Cross-Site Scripting (XSS) in log viewers can lead to session hijacking, account takeover of log viewers (potentially administrators), information theft from the log viewer interface, and further compromise of systems accessible through the log viewer.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Mandatory Output Encoding for Log Viewers:** Ensure all log viewers, especially web-based ones, implement strict output encoding (e.g., HTML entity encoding) for all log data before displaying it. This prevents browsers from interpreting injected code as executable.
    *   **Input Sanitization Before Logging:** Sanitize or encode data from external sources, especially user input, before logging it.  For web-related logs, HTML encode user input before logging to prevent potential XSS issues later in log viewers.
    *   **Content Security Policy (CSP) for Log Viewers:** Implement a strong Content Security Policy for web-based log viewers to further mitigate the impact of XSS vulnerabilities by restricting the sources from which scripts can be loaded and other browser behaviors.
    *   **Regular Security Audits of Log Viewers:** Conduct regular security audits and penetration testing of log viewers to identify and fix any XSS or other vulnerabilities.

## Attack Surface: [Insecure Log File/Destination Security leading to Information Disclosure](./attack_surfaces/insecure_log_filedestination_security_leading_to_information_disclosure.md)

Description: Log files or the systems where logs are stored are not adequately secured, allowing unauthorized access and leading to information disclosure. This directly exposes logged data due to insufficient security measures on log storage.
*   **How Log Contributes:** Logging systems create and manage log files. If the configuration or environment is insecure, these files become vulnerable to unauthorized access. `php-fig/log` implementations write logs to configured destinations, and if these destinations are not properly secured, the logged information becomes exposed.
*   **Example:** Log files are stored on a shared network drive with overly permissive access controls, allowing employees outside of the security or operations team to read them. These logs contain sensitive customer data or internal system details, leading to unauthorized information access. Alternatively, logs are stored in cloud storage with misconfigured permissions, making them publicly accessible over the internet.
*   **Impact:** **High**. Information disclosure of potentially sensitive data contained within logs. This can lead to reputational damage, legal repercussions, loss of customer trust, and further security breaches if exposed information is used to facilitate other attacks.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Implement Principle of Least Privilege for Log Access:** Restrict access to log files and log storage systems to only authorized personnel and systems that absolutely require it. Use role-based access control (RBAC) to manage permissions.
    *   **Secure Log Storage Locations:** Store logs in secure, dedicated storage locations that are not publicly accessible and are protected by strong access controls. Avoid storing logs in default or easily guessable locations.
    *   **Encryption at Rest for Logs:** Encrypt log files at rest to protect the confidentiality of data even if the storage medium is compromised.
    *   **Regular Security Audits of Log Storage:** Regularly audit log storage configurations, access controls, and encryption settings to identify and remediate any security weaknesses.
    *   **Secure Log Shipping and Aggregation:** If using remote logging or log aggregation systems, ensure secure communication channels (e.g., TLS encryption) are used to transmit logs and that the aggregation system itself is securely configured and managed.

