# Attack Surface Analysis for lettre/lettre

## Attack Surface: [Header Injection](./attack_surfaces/header_injection.md)

*   **Description:** Attackers inject malicious data into email headers, potentially leading to SMTP command injection, email spoofing, or redirection.
*   **How Lettre Contributes:** Lettre provides the mechanisms for constructing email headers. If user-supplied data is used in headers without proper sanitization, Lettre becomes the conduit for the attack.
*   **Example:**
    *   An attacker provides the following input for a "name" field that's used in the `From` header: `Evil Hacker\r\nBcc: victim@example.com`.
    *   If Lettre doesn't sanitize this (due to developer misuse), the resulting `From` header might become: `From: "Evil Hacker\r\nBcc: victim@example.com" <legit@example.com>`.
    *   This adds a `Bcc` header, sending a copy of the email to the attacker's chosen address.
*   **Impact:**
    *   **SMTP Smuggling:** Sending unauthorized emails, bypassing recipient restrictions.
    *   **Email Spoofing:** Impersonating other users.
    *   **Redirection:** Redirecting replies to an attacker-controlled address.
    *   **Application Logic Bypass:** Disrupting application logic that relies on header values.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Strict Input Validation:** Validate *all* user-supplied data used in *any* header against a strict whitelist.  Reject any input containing `\r` or `\n` characters.  For example, a name field should only allow alphanumeric characters, spaces, and a limited set of punctuation (e.g., `.`, `,`, `'`).
    *   **Use Lettre's Structured API:**  *Always* use `lettre::message::Mailbox`, `lettre::message::Mailboxes`, and related types to construct headers.  *Never* manually concatenate strings to build headers.  For example:
        ```rust
        // GOOD: Using Mailbox
        let from_mailbox = Mailbox::new(
            Some("User Name".to_string()), // Validate "User Name"
            "user@example.com".parse().unwrap(),
        );
        let email = Message::builder()
            .from(from_mailbox)
            // ... other parts of the email ...
            .build()?;
        ```
        ```rust
        // BAD: Manual string concatenation (VULNERABLE)
        let user_input_name = get_user_input(); // UNSAFE: Could contain \r\n
        let from_header = format!("From: \"{}\" <user@example.com>", user_input_name);
        // ... use from_header in the email ...
        ```
    *   **Encode Header Values (Lettre Handles This):**  When using Lettre's structured API, it automatically handles the necessary encoding (e.g., quoted-printable) for header values.  This is a key reason to use the structured API.
    *   **Principle of Least Privilege:** Only include necessary headers. Don't add custom headers unless absolutely required.

## Attack Surface: [SMTP Command Injection (via Header Injection)](./attack_surfaces/smtp_command_injection__via_header_injection_.md)

*   **Description:** A specialized form of header injection where the attacker injects complete SMTP commands, allowing them to take greater control of the email sending process.
*   **How Lettre Contributes:** Lettre handles the communication with the SMTP server.  If header injection is successful, the injected commands are passed to the server via Lettre.
*   **Example:**
    *   Attacker input for a "subject" field: `Normal Subject\r\nDATA\r\nFrom: attacker@evil.com\r\nTo: victim@example.com\r\nSubject: Malicious Subject\r\n\r\nMalicious Body.\r\n.\r\nQUIT\r\n`.
    *   This injects a complete second email into the SMTP transaction.
*   **Impact:** Sending arbitrary emails, bypassing all intended restrictions, potentially even executing commands on a vulnerable SMTP server.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**  Same as Header Injection (the root cause).  Preventing header injection prevents SMTP command injection.

## Attack Surface: [STARTTLS Downgrade Attack](./attack_surfaces/starttls_downgrade_attack.md)

*   **Description:** A man-in-the-middle attacker prevents the connection from upgrading to TLS, forcing communication over plain text.
*   **How Lettre Contributes:** Lettre handles the TLS negotiation with the SMTP server.
*   **Example:** An attacker intercepts the initial connection to the SMTP server and modifies the server's response to remove the `STARTTLS` capability.
*   **Impact:** Interception of email content and SMTP credentials.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Enforce TLS:** *Always* use `Tls::Required` in your `SmtpTransport` configuration:
        ```rust
        let transport = SmtpTransport::relay("smtp.example.com")?
            .credentials(credentials)
            .tls(Tls::Required) // ENFORCE TLS
            .build();
        ```
    *   **Do Not Disable Certificate Validation:** Lettre validates certificates by default. Do *not* disable this unless you have a very specific and well-justified reason (e.g., testing with self-signed certificates in a *controlled* environment). If you *must* disable validation, use `dangerous_accept_invalid_certs(true)` and `dangerous_accept_invalid_hostnames(true)` with extreme caution, and *only* in testing.

