# Threat Model Analysis for phpmailer/phpmailer

## Threat: [Header Injection](./threats/header_injection.md)

**Description:** An attacker manipulates user-supplied input fields used to construct email headers. By injecting newline characters (`\r\n`) and additional headers, they can add arbitrary headers to emails sent via PHPMailer. This allows for actions like spoofing sender addresses, adding BCC recipients for spamming, and potentially injecting malicious content.

**Impact:**
- Spoofing sender identity, enabling phishing attacks and damaging sender reputation.
- Sending spam or unwanted emails, leading to blacklisting and deliverability issues.
- Information disclosure by adding unintended recipients to BCC or CC fields.

**Affected PHPMailer Component:**
- `PHPMailer` class, specifically methods handling header construction such as `addAddress()`, `setFrom()`, `Subject`, `addCC()`, `addBCC()`, and custom header setting logic.

**Risk Severity:** High

**Mitigation Strategies:**
- **Input Sanitization and Validation:**  Strictly validate and sanitize all user-provided input before using it in email headers. Remove or escape newline characters and other potentially harmful characters.
- **Use PHPMailer's Built-in Functions:** Utilize PHPMailer's methods for setting headers and recipients, as they often provide some level of built-in protection. Avoid directly concatenating user input into header strings.

## Threat: [Command Injection](./threats/command_injection.md)

**Description:** In older PHPMailer versions or specific configurations (especially when using `sendmail` transport), if user input is used to construct commands executed by the system, an attacker can inject malicious commands. By crafting input, they can execute arbitrary system commands on the server hosting the application through PHPMailer's `sendmail` functionality.

**Impact:**
- Full server compromise, granting the attacker complete control over the server.
- Data breach and exfiltration of sensitive information stored on the server.
- Denial of Service by crashing the server or disrupting critical services.
- Website defacement or other malicious actions on the compromised server.

**Affected PHPMailer Component:**
- `PHPMailer` class, specifically the `sendmailSend()` method and related functions when `sendmail` transport is used.

**Risk Severity:** Critical

**Mitigation Strategies:**
- **Use Modern PHPMailer Version:** Upgrade to the latest stable version of PHPMailer, which has addressed known command injection vulnerabilities.
- **Avoid `sendmail` Transport:**  Prefer using SMTP transport directly instead of relying on the `sendmail` binary, as SMTP is generally safer in this context.
- **Strict Input Sanitization and Escaping (if `sendmail` is unavoidable):** If `sendmail` transport must be used, meticulously sanitize and escape all user-provided input used in command construction, using functions like `escapeshellarg()`. However, parameterization and avoiding direct command construction is always preferred.
- **Principle of Least Privilege:** Run the web server and PHP processes with minimal necessary privileges to limit the impact of command injection.

## Threat: [Path Traversal](./threats/path_traversal.md)

**Description:** If the application allows users to specify file paths for attachments or email templates (directly or indirectly), and these paths are not properly validated, an attacker can use path traversal techniques (e.g., using `../` sequences) to access files outside the intended directories through PHPMailer's file handling features. This can lead to reading sensitive files or including malicious files in emails.

**Impact:**
- Information disclosure by reading sensitive files on the server's file system.
- Remote code execution if an attacker can upload a malicious file and then include it as an attachment or template, potentially executing code when the email is processed or viewed in certain contexts.
- Denial of Service by accessing large files or system files, potentially overloading the server.

**Affected PHPMailer Component:**
- `PHPMailer` class, specifically methods like `addAttachment()`, `msgHTML()`, `AltBody`, and any custom template loading mechanisms used in conjunction with PHPMailer.

**Risk Severity:** High

**Mitigation Strategies:**
- **Whitelist Allowed Paths:**  Restrict the paths from which attachments and templates can be loaded to a predefined whitelist of directories.
- **Input Validation and Sanitization:**  Strictly validate and sanitize any user-provided input related to file paths. Avoid directly using user input to construct file paths.
- **Use Secure File Handling Functions:** Utilize secure file handling functions provided by PHP and PHPMailer, and avoid functions known to be vulnerable to path traversal.

