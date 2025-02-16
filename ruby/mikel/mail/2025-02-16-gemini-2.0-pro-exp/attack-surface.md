# Attack Surface Analysis for mikel/mail

## Attack Surface: [Header Injection (Email Injection)](./attack_surfaces/header_injection__email_injection_.md)

*   **Description:** Attackers manipulate email headers by injecting malicious data into user-supplied fields that are used to construct email headers. This remains the most significant and direct attack vector.
    *   **How `mail` Contributes:** The `mail` gem provides the core functionality for setting email headers.  Improper use of these methods, without sufficient input validation and sanitization, directly enables header injection.
    *   **Example:**
        *   An attacker enters `user@example.com\r\nBcc: attacker@evil.com` into a "Contact Us" form's email field.  If the application uses this input directly in `mail.to =`, the attacker receives a BCC.
        *   `innocent@example.com\r\nFrom: ceo@yourcompany.com` to spoof the sender.
    *   **Impact:**
        *   Email spoofing (impersonation).
        *   Unauthorized disclosure of email content (BCC injection).
        *   Reputation damage.
        *   Phishing attacks.
        *   Potential legal and compliance issues.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Strict Input Validation:** Validate *all* user-supplied data used in *any* email header.  Reject input containing CR (`\r`), LF (`\n`), or other unexpected characters. Use allow-lists.
        *   **Use `mail` Gem's Methods:** *Always* use `mail.to =`, `mail.subject =`, `mail.bcc =`, etc.  *Never* manually construct header strings.
        *   **Explicit Encoding:** Consider using `Mail::Encodings.q_value_encode` even with the gem's methods.
        *   **Avoid Direct User Input:** Use pre-defined, application-controlled values in sensitive headers like `From:` whenever possible.
        *   **Sanitize User Input:** Sanitize all user input before using it in headers.

## Attack Surface: [Body Content Injection (XSS & Phishing)](./attack_surfaces/body_content_injection__xss_&_phishing_.md)

*   **Description:** Attackers inject malicious content (JavaScript, phishing links) into the email body, primarily targeting HTML emails.
    *   **How `mail` Contributes:** The `mail` gem is directly responsible for constructing the email body (both plain text and HTML).  Lack of sanitization when using user input in the body creation process directly enables this attack.
    *   **Example:**
        *   `<script>alert('XSS');</script>` in a comment field included in an HTML email.
        *   A disguised phishing link in the email body.
    *   **Impact:**
        *   Cross-Site Scripting (XSS) in webmail clients.
        *   Successful phishing attacks.
        *   Malware distribution (via links).
        *   Reputation damage.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **HTML Sanitization:** *Always* use a robust HTML sanitizer (e.g., `sanitize` gem) for HTML emails. *Never* trust user-supplied HTML.
        *   **Prefer Plain Text:** Send plain text emails whenever possible to eliminate XSS.
        *   **Content Security Policy (CSP):** Consider CSP within the HTML body (advanced, limited support).
        *   **Encode User Input:** Encode user input before including it, even in plain text.
        *   **URL Validation and Rewriting:** Validate and potentially rewrite user-supplied URLs.

## Attack Surface: [Attachment-Based Attacks](./attack_surfaces/attachment-based_attacks.md)

*   **Description:** Attackers use attachments to deliver malware or exploit vulnerabilities.
    *   **How `mail` Contributes:** The `mail` gem provides the direct functionality for adding attachments to emails.
    *   **Example:**
        *   A malicious `.exe` disguised as a `.pdf`.
        *   An oversized file to cause a DoS.
    *   **Impact:**
        *   Malware infection.
        *   Denial-of-service (DoS).
        *   Data breaches.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Strict File Type Validation:** Validate using file extension *and* MIME type detection.
        *   **File Size Limits:** Enforce strict limits.
        *   **Malware Scanning:** Scan *all* attachments before sending.
        *   **Secure Storage:** Store attachments securely.
        *   **Avoid Executables:** Prohibit executable attachments.
        * **Content Disarm and Reconstruction:** If possible, use CDR to process attachments.

## Attack Surface: [SMTP Relay and Sendmail Exploitation (Focus on `sendmail` Command Injection)](./attack_surfaces/smtp_relay_and_sendmail_exploitation__focus_on__sendmail__command_injection_.md)

*   **Description:** This entry is narrowed to focus on the *direct* and most critical risk associated with `mail`'s interaction with delivery methods: `sendmail` command injection. While SMTP relay abuse is a concern, it's less directly tied to the `mail` gem's *code* itself.
    *   **How `mail` Contributes:** If the application is configured to use the `sendmail` delivery method *and* user-supplied data is passed to the `sendmail` command without proper sanitization, the `mail` gem's interaction with `sendmail` becomes the direct attack vector.
    *   **Example:**
        *   User input containing shell metacharacters (e.g., `;`, `|`, `` ` ``) is passed to the `sendmail` command, allowing the attacker to execute arbitrary commands on the server.
    *   **Impact:**
        *   Complete server compromise (Remote Code Execution).
        *   Data breaches.
        *   System destruction.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Avoid `sendmail`:** *Strongly* prefer SMTP over `sendmail`.
        *   **`sendmail` Sanitization (if unavoidable):** If `sendmail` is *absolutely required*, ensure *no* user-supplied data reaches the command without *extreme* sanitization and escaping. Use a dedicated library for secure `sendmail` interaction if possible. This is a very high-risk configuration and should be avoided if at all possible.  Consider this a last resort.
        * **Use API based delivery method:** If possible, use API based delivery method (like SendGrid, Mailgun, etc.).

