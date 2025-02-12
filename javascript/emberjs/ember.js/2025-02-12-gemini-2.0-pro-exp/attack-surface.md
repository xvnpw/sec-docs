# Attack Surface Analysis for emberjs/ember.js

## Attack Surface: [Raw HTML Injection (Triple Curlies)](./attack_surfaces/raw_html_injection__triple_curlies_.md)

*   **Description:**  Injection of arbitrary HTML and JavaScript into the application through the use of triple curly braces (`{{{ }}}`) in Ember templates. This bypasses Ember's built-in escaping mechanisms.
*   **How Ember.js Contributes:** Ember's templating engine provides the triple curly brace syntax for rendering unescaped HTML. This is a deliberate feature, and it's the most direct and Ember-specific path to XSS if misused.
*   **Example:**
    ```javascript
    // In a component or controller:
    this.userInput = "<script>alert('XSS!');</script>";

    // In the template:
    {{{this.userInput}}}
    ```
    This would execute the injected JavaScript.
*   **Impact:**  Complete client-side compromise.  An attacker can steal user data, hijack sessions, deface the website, and perform any action the user could.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Avoid Triple Curlies:**  The primary mitigation is to *never* use triple curlies with untrusted data.  Use double curlies (`{{ }}`) for escaped output.
    *   **HTML Sanitization:** If raw HTML rendering is *absolutely unavoidable*, use a robust, well-maintained HTML sanitizer library like `DOMPurify` *before* passing the data to the template.  *Never* attempt to write custom sanitization logic.  Example:
        ```javascript
        import DOMPurify from 'dompurify';

        // ...
        this.safeHtml = DOMPurify.sanitize(this.userInput);

        // In the template:
        {{{this.safeHtml}}} // Still use triple curlies, but with sanitized input
        ```
    *   **Content Security Policy (CSP):**  A strong CSP, particularly one that disallows `unsafe-inline` scripts, provides a crucial defense-in-depth layer.  Even if an XSS vulnerability exists, the CSP can prevent the injected script from executing.
    *   **Input Validation:** Validate all user input on the *server-side* to ensure it conforms to expected formats and lengths. This is a general best practice, but it helps prevent malicious data from reaching the template.

## Attack Surface: [Unsafe `htmlSafe` Usage](./attack_surfaces/unsafe__htmlsafe__usage.md)

*   **Description:**  Marking untrusted strings as "safe" for HTML rendering using the `htmlSafe` helper (or implicitly through `SafeString`), bypassing Ember's escaping.
*   **How Ember.js Contributes:** Ember provides the `htmlSafe` helper and the `SafeString` type to allow developers to indicate that a string is safe to render without escaping.  This is intended for trusted HTML, but can be misused, leading directly to XSS.
*   **Example:**
    ```javascript
    import { htmlSafe } from '@ember/template';

    // ...
    this.userInput = "<img src=x onerror=alert('XSS')>";
    this.safeButDangerous = htmlSafe(this.userInput);

    // In the template:
    {{this.safeButDangerous}} // Double curlies, but the content is already marked as "safe"
    ```
*   **Impact:**  Similar to triple curlies, this leads to XSS and client-side compromise.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Extreme Caution with `htmlSafe`:**  Only use `htmlSafe` on strings that are *provably* safe, such as hardcoded HTML fragments or data that has been *rigorously* sanitized using a library like `DOMPurify`.
    *   **Prefer Escaping:**  Favor using double curlies (`{{ }}`) and Ember's built-in escaping whenever possible.
    *   **Code Audits:**  Regularly audit code for uses of `htmlSafe` and ensure that the input is genuinely safe.
    *   **Linters/Static Analysis:**  Use tools that can flag potentially unsafe uses of `htmlSafe`.
    *   **CSP:**  A strong CSP is essential as a defense-in-depth measure.

## Attack Surface: [Insecure Component Attribute Bindings](./attack_surfaces/insecure_component_attribute_bindings.md)

*   **Description:**  Using untrusted data to construct component attribute names or values, potentially leading to XSS or other injection attacks.
*   **How Ember.js Contributes:** Ember's component attribute binding system allows dynamic attribute creation. While powerful, this can be dangerous if not handled carefully, and is a direct feature of Ember.
*   **Example:**
    ```javascript
    // In a component:
    this.attributeName = 'onmouseover'; // From user input
    this.attributeValue = "alert('XSS')"; // From user input

    // In the template:
    <div {{this.attributeName}}={{this.attributeValue}}>Hover me</div>
    ```
    This could create a `<div>` with a malicious `onmouseover` event.
*   **Impact:**  XSS, potentially leading to client-side compromise.  Other injection attacks are possible depending on the attribute being manipulated.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Avoid Dynamic Attribute Names:**  Do not use user-supplied data directly in attribute names.
    *   **Sanitize Attribute Values:**  Sanitize attribute values, especially if they are derived from user input or external sources. Use `DOMPurify` if the attribute value might contain HTML.
    *   **Whitelist Allowed Attributes:**  If possible, maintain a whitelist of allowed attribute names and values.
    *   **Careful with `...attributes`:**  Be particularly cautious with the `...attributes` spread syntax, as it can make it harder to track the source of all attributes.
    *   **CSP:** A strong CSP can help mitigate the impact of XSS.

