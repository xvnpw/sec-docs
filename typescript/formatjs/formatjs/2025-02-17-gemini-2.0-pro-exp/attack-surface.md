# Attack Surface Analysis for formatjs/formatjs

## Attack Surface: [Untrusted Message Keys](./attack_surfaces/untrusted_message_keys.md)

*   **Description:** Using user-supplied data directly as message keys within FormatJS's `formatMessage` (or similar functions). This allows attackers to control which localized string is retrieved, potentially leading to the execution of malicious content if the corresponding message is vulnerable.
*   **How FormatJS Contributes:** FormatJS uses message keys as identifiers to look up localized strings. Attacker-controlled keys directly dictate which message is retrieved and processed.
*   **Example:**
    ```javascript
    // Vulnerable code:
    const userSuppliedKey = req.query.messageKey; // Directly from user input
    const message = intl.formatMessage({ id: userSuppliedKey }, values);

    // Attacker provides: ?messageKey=malicious.key
    // 'malicious.key' points to a crafted message string containing, e.g., XSS payload.
    ```
*   **Impact:** Code injection (XSS, potentially others depending on message usage), information disclosure, denial of service.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Whitelist Message Keys:** Enforce a strict whitelist of allowed message keys.  *Never* dynamically construct message keys from user input. Treat message keys as code.
    *   **Static Keys:** Use only hardcoded, static message keys defined within the application's codebase.
    *   **Input Validation:** If keys *must* originate externally (e.g., database), rigorously validate them against the whitelist *before* use with FormatJS.

## Attack Surface: [Untrusted Message Format Strings](./attack_surfaces/untrusted_message_format_strings.md)

*   **Description:** Allowing users to provide the entire message format string (the value associated with the `id` in the message descriptor) used by FormatJS. This grants attackers complete control over the message's structure and content, enabling injection attacks.
*   **How FormatJS Contributes:** FormatJS uses the provided format string to construct the final output. Attacker-controlled strings mean attacker-controlled output.
*   **Example:**
    ```javascript
    // Vulnerable code:
    const userSuppliedFormat = req.body.messageFormat; // Directly from user input
    const message = intl.formatMessage({ id: 'some.key', defaultMessage: userSuppliedFormat }, values);

    // Attacker provides:  {messageFormat: "Hello, {user}! <img src=x onerror=alert(1)>"}
    ```
*   **Impact:** Code injection (primarily XSS), denial of service.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Predefined Formats:** *Never* allow users to define message format strings. Formats should be predefined and static within the codebase or controlled translation files.
    *   **Secure Translation Management:** Treat translation files as code. Implement code signing, integrity checks, and secure storage to prevent tampering.

## Attack Surface: [Untrusted Values within Formatted Messages](./attack_surfaces/untrusted_values_within_formatted_messages.md)

*   **Description:** Using user-supplied data as *values* within a formatted message without proper sanitization or escaping.  Even with safe message keys and formats, the interpolated values can introduce vulnerabilities.
*   **How FormatJS Contributes:** FormatJS interpolates provided values into the message format string. Unescaped values become part of the rendered output, potentially introducing vulnerabilities.
*   **Example:**
    ```javascript
    // Vulnerable code:
    const userName = req.query.userName; // Directly from user input
    const message = intl.formatMessage({ id: 'welcome.message' }, { user: userName });

    // Attacker provides: ?userName=<script>alert(1)</script>
    // 'welcome.message' might be: "Welcome, {user}!"
    ```
*   **Impact:** Code injection (primarily XSS), other injection attacks depending on context.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Context-Aware Escaping:** Use appropriate escaping based on where the message is displayed (e.g., HTML escaping for HTML). Utilize FormatJS's `formatHTMLMessage` *correctly* for HTML, but always verify.
    *   **Input Validation:** Validate user data against expected types and formats *before* using them as values.
    *   **Content Security Policy (CSP):** Mitigate XSS impact with CSP.

