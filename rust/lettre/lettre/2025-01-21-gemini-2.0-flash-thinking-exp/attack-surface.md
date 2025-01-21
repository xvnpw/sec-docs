# Attack Surface Analysis for lettre/lettre

## Attack Surface: [Email Header Injection](./attack_surfaces/email_header_injection.md)

*   **Description:** Attackers inject malicious headers into emails by manipulating user-provided input that is directly used when setting email headers through `lettre`'s API.
    *   **Lettre's Direct Contribution to Attack Surface:** `lettre` provides functions and methods to programmatically set email headers (e.g., `message.headers_mut().insert()`, `builder.header()`). If your application directly uses these `lettre` APIs to insert unsanitized user input into headers, it creates a direct vulnerability. `lettre` itself does not sanitize or validate header values by default, relying on the application to provide safe inputs.
    *   **Example:** Your application takes a "Subject" line from user input and directly uses `message_builder.subject(user_input)` with `lettre`. If an attacker inputs `Subject: My Subject\nBcc: attacker@example.com`, and this is passed directly to `lettre`, the injected `Bcc` header will be included in the email sent by `lettre`.
    *   **Impact:**
        *   Spam and phishing campaigns originating from your application.
        *   Exposure of sensitive information to unintended recipients via injected `Bcc` or `Cc` headers.
        *   Email spoofing by manipulating `From` or `Reply-To` headers, leading to reputational damage and potential legal issues.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Strictly Sanitize User Input Before Header Insertion:** Before using any user-provided input with `lettre`'s header setting functions, rigorously sanitize and validate it. Escape special characters that could be interpreted as header delimiters or commands.
        *   **Use `lettre`'s Header Building Mechanisms Carefully:** Understand how `lettre` handles header values. Ensure that when using functions like `header()` or `headers_mut().insert()`, the input is safe and does not contain malicious header injection sequences.
        *   **Prefer Predefined Header Structures:** Where possible, use predefined header structures or builder patterns provided by `lettre` or your application to minimize direct string manipulation and reduce the chance of injection.
        *   **Avoid Direct User Input in Critical Headers:** For sensitive headers like `From`, `Sender`, or `Return-Path`, avoid directly using user input. Set these programmatically within your application's trusted logic.

## Attack Surface: [Email Body Manipulation/Injection (HTML Emails)](./attack_surfaces/email_body_manipulationinjection__html_emails_.md)

*   **Description:** Attackers inject malicious content, particularly scripts or harmful HTML, into the email body when constructing HTML emails using `lettre`, by manipulating user-provided input that forms part of the HTML body.
    *   **Lettre's Direct Contribution to Attack Surface:** `lettre` allows constructing email bodies, including HTML bodies, using string manipulation or templating. If your application directly embeds unsanitized user input into the HTML body string that is then passed to `lettre` for email sending, it becomes vulnerable to HTML injection. `lettre` itself treats the provided body as content and does not perform HTML sanitization.
    *   **Example:** Your application allows users to personalize an email greeting. If you construct an HTML email body by directly concatenating user input into an HTML string like `format!("<h1>Hello, {}!</h1>", user_input)` and then use this with `lettre` to send an HTML email, an attacker could input `<img src="x" onerror="alert('XSS')">` as `user_input`. When the email is rendered by a vulnerable email client, the JavaScript will execute.
    *   **Impact:**
        *   Cross-Site Scripting (XSS) attacks within recipient email clients, potentially leading to session hijacking, information theft, or further malicious actions if the email client is vulnerable.
        *   Phishing attacks by embedding deceptive links or content within the HTML email body.
        *   Distribution of misleading or harmful information through manipulated email content.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Strict Output Encoding/Escaping for HTML Bodies:** When constructing HTML email bodies with `lettre`, *always* encode or escape user-provided input before embedding it into the HTML. Use HTML-specific escaping functions to prevent injection of HTML tags or JavaScript.
        *   **Utilize Secure Templating Engines:** Employ secure HTML templating engines that provide automatic output escaping by default. These engines are designed to prevent injection vulnerabilities by properly handling user input within templates.
        *   **Content Security Policy (CSP) for HTML Emails (Consideration):** While email client CSP support is limited and inconsistent, consider adding CSP headers to your HTML emails if your target audience uses email clients that support it. This can provide an additional layer of defense against XSS by restricting the capabilities of the HTML content.
        *   **Prefer Plain Text Emails When Possible:** If HTML formatting is not strictly necessary, send emails in plain text format. This completely eliminates the risk of HTML injection vulnerabilities in the email body. If HTML is required, minimize the complexity of the HTML and carefully control all dynamic content.

