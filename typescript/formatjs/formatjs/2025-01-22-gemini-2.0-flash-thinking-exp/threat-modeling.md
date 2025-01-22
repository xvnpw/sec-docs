# Threat Model Analysis for formatjs/formatjs

## Threat: [Format String Injection](./threats/format_string_injection.md)

*   **Description:** An attacker crafts malicious input that is processed as a format string by `formatjs` functions (like `format`, `formatMessage`). By injecting specific format specifiers, the attacker can potentially extract sensitive information from the application's environment or cause significant disruptions. This is achieved by using user-controlled input directly within the format string without proper sanitization or parameterization.
*   **Impact:**
    *   **Information Disclosure (High):** Attackers might be able to extract sensitive data from the application's context, such as internal configurations, environment variables, or potentially even data intended for other users if the application context is not properly isolated.
    *   **Denial of Service (High to Critical):**  Malicious format strings could be designed to cause excessive resource consumption, leading to application slowdowns or crashes, effectively denying service to legitimate users. In critical systems, this can have severe consequences.
*   **Affected Component:**
    *   `@formatjs/intl` core formatting functions (e.g., `format`, `formatMessage`, `defineMessages` when used with direct string interpolation).
*   **Risk Severity:** High to Critical (depending on the potential for information disclosure of highly sensitive data and the ease of triggering a critical Denial of Service).
*   **Mitigation Strategies:**
    *   **Mandatory Parameterization:**  **Critically important:**  Always use parameterized formatting. Ensure user-provided data is *never* directly embedded into format strings. Pass user inputs exclusively as arguments to the formatting functions.
    *   **Strictly Control Format Strings:** Store format strings in code or dedicated configuration files. Avoid any dynamic generation of format strings based on user input. Treat format strings as code, not data.
    *   **Security Audits of Formatting Logic:** Regularly audit code that uses `formatjs` to ensure parameterized formatting is consistently applied and no user input reaches format string positions.

## Threat: [Client-Side Cross-Site Scripting (XSS) via Format String Injection (in browser context)](./threats/client-side_cross-site_scripting__xss__via_format_string_injection__in_browser_context_.md)

*   **Description:** When `formatjs` is used in client-side JavaScript applications, improper handling of user input within format strings can lead to Cross-Site Scripting (XSS) vulnerabilities. An attacker injects malicious format strings that, when processed and rendered by the application in the user's browser, execute arbitrary JavaScript code.
*   **Impact:**
    *   **Cross-Site Scripting (XSS) (Critical):** Successful XSS allows attackers to execute arbitrary JavaScript code in the victim's browser. This can lead to account hijacking, session theft, data theft, website defacement, and redirection to malicious sites. In modern web applications, XSS is often considered a critical vulnerability.
*   **Affected Component:**
    *   `@formatjs/intl` core formatting functions used in client-side JavaScript.
    *   Application's client-side rendering logic that displays formatted messages in the browser (especially if using `dangerouslySetInnerHTML` or similar approaches without proper escaping).
*   **Risk Severity:** Critical (due to the direct and severe impact of XSS on user security and application integrity in a browser environment).
*   **Mitigation Strategies:**
    *   **Parameterization (Client-Side):**  Apply the same strict parameterization principles as for server-side format string injection. User input must *never* be directly placed into format strings in client-side code.
    *   **Context-Aware Output Encoding:** When displaying formatted messages in HTML within the browser, ensure rigorous context-aware output encoding (e.g., HTML escaping). Use browser APIs or templating engines that automatically handle output encoding correctly to prevent XSS.
    *   **Content Security Policy (CSP):** Implement a strict Content Security Policy to significantly reduce the impact of XSS attacks. CSP can restrict the sources from which scripts can be loaded and limit other browser capabilities, making XSS exploitation much harder.
    *   **Regular Security Scans (Client-Side):** Use client-side security scanning tools to detect potential XSS vulnerabilities in the application's JavaScript code, particularly around `formatjs` usage and message rendering.

## Threat: [Locale Injection leading to Client-Side Cross-Site Scripting (XSS)](./threats/locale_injection_leading_to_client-side_cross-site_scripting__xss_.md)

*   **Description:** If the application dynamically loads locale data based on user-controlled input without strict validation, attackers might inject malicious locale data. If this malicious locale data is then processed and rendered by the client-side application in a way that is vulnerable to XSS (e.g., by directly embedding locale strings into HTML without proper escaping), it can lead to client-side XSS.
*   **Impact:**
    *   **Cross-Site Scripting (XSS) (High to Critical):** Similar to the previous XSS threat, successful exploitation allows arbitrary JavaScript execution in the user's browser, with the same critical consequences. The severity depends on how easily malicious locale data can be injected and how vulnerable the rendering logic is.
*   **Affected Component:**
    *   `@formatjs/intl-utils` locale loading mechanisms (if used for dynamic loading based on user input).
    *   Application's locale loading logic and client-side rendering of locale-dependent content.
*   **Risk Severity:** High to Critical (if XSS is achievable through locale injection and depending on the sensitivity of the application and user data).
*   **Mitigation Strategies:**
    *   **Strict Locale Whitelisting:**  **Critical:**  Only load locales from a predefined and tightly controlled whitelist. Never dynamically load locales based directly on unvalidated user input.
    *   **Robust Locale Data Validation:** If there's a legitimate need to load locales from external sources (which should be carefully considered), implement extremely robust validation of the locale data structure and content before it is processed by `formatjs` or rendered by the application.
    *   **Secure Locale Data Delivery:** Ensure locale data is delivered over HTTPS to prevent Man-in-the-Middle attacks that could inject malicious locale data during transit.
    *   **Context-Aware Output Encoding (Locale Data):** When rendering any data derived from locale files in HTML, apply rigorous context-aware output encoding to prevent XSS.

