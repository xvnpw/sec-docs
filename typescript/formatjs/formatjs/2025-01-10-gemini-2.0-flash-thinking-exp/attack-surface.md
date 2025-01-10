# Attack Surface Analysis for formatjs/formatjs

## Attack Surface: [Message Formatting Injection (Client-Side)](./attack_surfaces/message_formatting_injection__client-side_.md)

*   **Description:**  Occurs when user-provided data is directly embedded into message strings used with `formatjs` formatting functions without proper sanitization. This allows attackers to inject malicious content.
    *   **How formatjs contributes to the attack surface:** `formatjs` provides the mechanism to format messages, and if used carelessly with direct string interpolation, it facilitates the injection point.
    *   **Example:**
        ```javascript
        // Vulnerable code
        const userName = getUserInput(); // e.g., "<script>alert('XSS')</script>"
        const message = formatMessage({ id: 'greeting' }, { name: userName });
        // Message definition: 'Hello {name}'
        ```
    *   **Impact:** Cross-Site Scripting (XSS) attacks, leading to potential session hijacking, data theft, or redirection to malicious sites.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Always use placeholder syntax:**  Define messages with placeholders (e.g., `{name}`) and pass user data as arguments to the formatting function. This ensures that the data is treated as data, not code.
        *   **Sanitize output:** If direct string interpolation is unavoidable (highly discouraged), ensure the output is properly sanitized before rendering it in the DOM to prevent XSS. However, relying on output sanitization as the primary defense is less secure than using placeholders.

