# Threat Model Analysis for formatjs/formatjs

## Threat: [Malicious Message Catalog Injection](./threats/malicious_message_catalog_injection.md)

*   **Threat:** Malicious Message Catalog Injection

    *   **Description:** An attacker gains unauthorized write access to the application's message catalog files (e.g., JSON, YAML) and inserts malicious code, typically JavaScript, into the translated strings. The attacker leverages the fact that `formatjs` will render these strings, potentially executing the injected code.
    *   **Impact:** Cross-Site Scripting (XSS), leading to session hijacking, data theft, defacement, phishing, or other client-side attacks. The attacker's code executes in the context of the victim's browser when the malicious translation is displayed via `formatjs`.
    *   **Affected Component:** Primarily `FormattedMessage` (from `react-intl` or similar components in other frameworks), but potentially any component that renders translated text from the message catalog (e.g., `FormattedHTMLMessage` if used incorrectly). The core issue is that `formatjs` components are used to render the attacker-controlled content.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Strict Access Control:** Implement robust access controls to the message catalog files. Only authorized personnel should have write access. Use a secure deployment process.
        *   **Version Control:** Use version control (e.g., Git) to track changes to message catalogs.
        *   **Input Validation (of Message Catalogs):** Treat message catalogs as *untrusted input*. Validate the *content* of the catalogs before loading them. This is crucial:
            *   **Schema Validation:** Define a schema for the message catalog format and validate files against it.
            *   **Content Sanitization:** Sanitize the message catalog content. Whitelist allowed HTML tags (if any) and use regular expressions to detect and reject dangerous patterns.
        *   **Content Security Policy (CSP):** Implement a strong CSP to mitigate the impact of XSS.
        *   **Subresource Integrity (SRI):** If message catalogs are loaded as separate files, use SRI.

## Threat: [Unescaped User Input in `values`](./threats/unescaped_user_input_in__values_.md)

*   **Threat:** Unescaped User Input in `values`

    *   **Description:** The application passes user-supplied data directly into the `values` object of `FormattedMessage` (or similar components) without proper escaping. `formatjs` itself does *not* automatically escape these values, so the attacker-provided malicious JavaScript is interpolated into the translated message and executed.
    *   **Impact:** Cross-Site Scripting (XSS).
    *   **Affected Component:** `FormattedMessage` (and other formatting components that accept a `values` object, such as `FormattedNumber`, `FormattedDate`, etc.). The vulnerability is directly tied to how the application *uses* these `formatjs` components with untrusted input.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Escape User Input:** *Always* escape user-supplied data before passing it to the `values` object. Use a robust escaping library (e.g., `escape-html`) or the escaping functions provided by your templating engine.
        *   **Type Checking:** Enforce strict type checking for the `values` object.
        *   **Input Validation:** Validate user input *before* escaping it.

## Threat: [Unsafe Rich Text Formatting](./threats/unsafe_rich_text_formatting.md)

*   **Threat:** Unsafe Rich Text Formatting

    *   **Description:** The application uses `FormattedMessage`'s rich text formatting capabilities, but fails to properly sanitize user-supplied data that is used *within* the React components provided as values for rich text placeholders. The attacker's input, intended for a formatted section (e.g., a bolded username), contains malicious code that `formatjs` renders as part of the rich text, leading to XSS.
    *   **Impact:** Cross-Site Scripting (XSS).
    *   **Affected Component:** `FormattedMessage` (specifically when used with its rich text formatting feature). The vulnerability stems from the interaction between `formatjs`'s rich text handling and unsanitized user input within the custom React components.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Sanitize User Input (Before Component Creation):** *Never* pass raw user input directly into the React components used for rich text formatting. Sanitize the user input *before* creating the React components. Use a strict HTML sanitizer (e.g., DOMPurify).
        *   **Avoid Rich Text Formatting Where Possible:** If not strictly necessary, use plain text formatting.
        *   **Careful Component Design:** Design the React components used for rich text formatting to be as simple and secure as possible.

