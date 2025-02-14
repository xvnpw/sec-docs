# Attack Surface Analysis for phpmailer/phpmailer

## Attack Surface: [Email Header Injection (Including BCC/CC Injection)](./attack_surfaces/email_header_injection__including_bcccc_injection_.md)

*   **Description:** Attackers inject malicious email headers (e.g., `Bcc`, `Cc`, `From`, `Subject`, `Reply-To`) into the email being sent. This is *directly* related to how PHPMailer handles header creation.
*   **How PHPMailer Contributes:** PHPMailer provides functions to set email headers. If these functions are used with unsanitized user input, the vulnerability is exposed *through PHPMailer's API*.
*   **Example:**
    *   User input field for "Your Name": `John Doe\nBcc: spamtarget1@example.com, spamtarget2@example.net`
    *   If the application directly uses this input in PHPMailer's `$mail->setFrom()` or a custom header without sanitization, the attacker adds hidden BCC recipients *via PHPMailer*.
*   **Impact:**
    *   Spam/Phishing: The application becomes a spam relay. Attackers can forge the sender and send malicious emails.
    *   Information Disclosure: Leaking email addresses of other users.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strict Input Validation:** Use whitelisting (preferred) or blacklisting to allow only expected characters in header fields.  Reject any input containing newline characters (`\r`, `\n`). This is crucial *before* passing data to PHPMailer.
    *   **Use PHPMailer's API *Correctly*:** *Always* use PHPMailer's dedicated methods (e.g., `$mail->addAddress()`, `$mail->addReplyTo()`, `$mail->setFrom()`, `$mail->Subject = ...`) to set headers.  These methods are designed to perform escaping, *but only if used as intended*.  *Never* directly concatenate user input into header strings that are then passed to PHPMailer.
    *   **Encoding:** Ensure consistent and correct character encoding (e.g., UTF-8) is used within PHPMailer.
    *   **Avoid `addCustomHeader()` with user input:** If absolutely necessary, sanitize *extremely* thoroughly *before* passing data to this PHPMailer function.

## Attack Surface: [Remote Code Execution (RCE) - (Directly related to PHPMailer's internal handling, especially in older versions)](./attack_surfaces/remote_code_execution__rce__-__directly_related_to_phpmailer's_internal_handling__especially_in_olde_ade1777e.md)

*   **Description:** Exploiting vulnerabilities within PHPMailer itself (particularly older versions) to execute arbitrary code on the server. This is a vulnerability *within* PHPMailer's code, not just how it's used.
*   **How PHPMailer Contributes:** Older versions had vulnerabilities in how they handled parameters, especially when using the `mail()` transport, leading to potential command injection *within PHPMailer's internal logic*.
*   **Example:** (Illustrative, specific exploits are patched)
    *   Malicious input crafted to be interpreted as command-line arguments to `sendmail` *due to flaws in PHPMailer's parameter handling*.
*   **Impact:** Complete server compromise.
*   **Risk Severity:** Critical (for unpatched, very old versions); High (for slightly outdated versions, even with SMTP, due to potential undiscovered vulnerabilities).
*   **Mitigation Strategies:**
    *   **Update PHPMailer:** *Crucially*, use the *latest* stable version of PHPMailer. This is the *primary* and most effective mitigation, addressing known vulnerabilities *within the library itself*.
    *   **Prefer SMTP (Reduces, Doesn't Eliminate Risk):** If possible, use the `SMTP` transport instead of the `mail()` transport. While SMTP is generally less susceptible, *it doesn't eliminate the risk of RCE if a vulnerability exists within PHPMailer itself*.
    *   **Input Sanitization (Defense in Depth):** Even with SMTP and updated versions, *always* sanitize user input as described for header injection. This is a defense-in-depth measure.
    *   **Least Privilege (Mitigation, Not Prevention):** Run the web server process with minimal necessary permissions. This limits the *impact* of a successful RCE, but doesn't prevent it.

## Attack Surface: [File Inclusion / Path Traversal (via `addAttachment()` with flawed application logic)](./attack_surfaces/file_inclusion__path_traversal__via__addattachment____with_flawed_application_logic_.md)

*   **Description:**  While the *vulnerability* is primarily in the application's handling of file paths, PHPMailer's `addAttachment()` function is the *direct mechanism* by which the attacker's malicious file path is used.
*   **How PHPMailer Contributes:** PHPMailer's `addAttachment()` function takes a file path as an argument. If the application passes an unsanitized, attacker-controlled path to this function, PHPMailer *executes* the inclusion.
*   **Example:**
    *   User input for attachment: `../../etc/passwd`
    *   If the application doesn't validate this path, and passes it *directly* to `$mail->addAttachment()`, PHPMailer attempts to attach and send the server's password file.
*   **Impact:** Information disclosure (reading arbitrary files).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **No User-Supplied Paths to `addAttachment()`:** *Never* directly use user-supplied input as a file path argument to PHPMailer's `addAttachment()` function. This is the core issue.
    *   **Controlled Uploads (Application-Level, but Essential):** Implement a secure file upload mechanism:
        *   Store uploads in a dedicated, non-web-accessible directory.
        *   Generate unique, random filenames for uploaded files.
        *   Validate file types and sizes.
        *   *Then*, pass the *safe, application-controlled* path to `addAttachment()`.
    *   **Whitelist (If Paths are Necessary, but Risky):** If user-provided paths are *absolutely* unavoidable, use a strict whitelist of allowed directories/files *before* passing the path to PHPMailer.
    *   **Sanitize (Last Resort, Least Secure):** If whitelisting is impossible, sanitize the path to remove `..`, `/`, `\`, and other dangerous characters *before* passing it to PHPMailer. This is *much less secure* than the other methods.

## Attack Surface: [SMTP Connection Security (If Using SMTP)](./attack_surfaces/smtp_connection_security__if_using_smtp_.md)

*   **Description:**  Vulnerabilities related to insecure connections to the SMTP server, *directly managed by PHPMailer's configuration*.
*   **How PHPMailer Contributes:** PHPMailer handles the connection to the SMTP server, including encryption and authentication. Incorrect PHPMailer configuration leads directly to the vulnerability.
*   **Example:**
    *   Using an unencrypted connection (no TLS/SSL) by not setting `$mail->SMTPSecure`.
    *   Using weak or default SMTP credentials, configured within PHPMailer.
    *   Not verifying the SMTP server's certificate by disabling `$mail->SMTPAuth`.
*   **Impact:**
    *   Email interception (eavesdropping).
    *   Unauthorized email sending.
    *   Potential compromise of the SMTP account.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Mandatory TLS/SSL:** *Always* use TLS/SSL encryption for the SMTP connection.  Configure PHPMailer correctly (e.g., `$mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;` or `$mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;`). This is a *direct PHPMailer configuration* issue.
    *   **Strong Credentials:** Use strong, unique passwords for the SMTP account, and configure these *within PHPMailer*.
    *   **Certificate Verification:** Ensure PHPMailer is configured to verify the SMTP server's certificate (usually enabled by default, but check `$mail->SMTPAutoTLS` and related settings). This is a *direct PHPMailer configuration* issue.
    *   **Appropriate Authentication:** Use secure authentication mechanisms supported by the SMTP server, configured *within PHPMailer*.

