# Threat Model Analysis for tapadoo/alerter

## Threat: [Malicious Content Injection (XSS/UI Redressing)](./threats/malicious_content_injection__xssui_redressing_.md)

*   **Description:** An attacker injects malicious code (e.g., JavaScript in a web context, or specially crafted text/markup) into the content displayed by `Alerter`.  This is achieved by exploiting an input validation flaw *where the application passes unsanitized user-supplied data directly to Alerter's display functions*. The attacker crafts a message that, when displayed, executes arbitrary code in the user's browser (XSS) or mimics legitimate UI elements to deceive the user (UI redressing).
    *   **Impact:**
        *   **XSS:** Theft of user cookies, session hijacking, redirection to malicious websites, defacement, execution of arbitrary code in the user's context.
        *   **UI Redressing:** Tricking the user into clicking malicious links, entering credentials on a fake form, or performing unintended actions.
    *   **Affected Alerter Component:**
        *   `Alerter.show(...)` (and related functions that accept text/attributed string input as parameters)
        *   `Alerter.title` (if it accepts and displays unsanitized input)
        *   `Alerter.text` (if it accepts and displays unsanitized input)
        *   Any custom views within an `Alerter` that display user-provided data *without* proper sanitization.
    *   **Risk Severity:** Critical (if user input is directly displayed) / High (if indirect user input or data from external sources is displayed, and not properly sanitized).
    *   **Mitigation Strategies:**
        *   **Strict Input Validation & Sanitization:**  Rigorously validate and sanitize *all* input passed to `Alerter`. Use appropriate escaping (HTML encoding for web, attributed string sanitization for native).  This is the *primary* defense.
        *   **Content Security Policy (CSP):** (Web context) Implement a strict CSP to limit executable content, preventing injected scripts.
        *   **Output Encoding:** Ensure all data displayed by `Alerter` is correctly encoded for the target context.
        *   **Template-Based Messages:** Prefer pre-defined message templates with placeholders for dynamic data, *never* constructing messages directly from raw user input.
        *   **Avoid Rich Text/HTML:** If possible, avoid allowing rich text or HTML in alerts. Use plain text.

## Threat: [Sensitive Information Disclosure](./threats/sensitive_information_disclosure.md)

*   **Description:** The application *directly* displays sensitive information (API keys, session tokens, PII, internal error details) within `Alerter` messages due to a coding error or oversight. This is a direct misuse of the `Alerter` component.
    *   **Impact:** Exposure of sensitive information to unauthorized individuals, leading to account compromise, identity theft, privacy violations, or other breaches.
    *   **Affected Alerter Component:**
        *   `Alerter.show(...)` (and related functions)
        *   `Alerter.title` (if used to display sensitive data)
        *   `Alerter.text` (if used to display sensitive data)
        *   Custom views within an `Alerter` displaying sensitive data.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Code Review:** Thoroughly review all code using `Alerter` to ensure sensitive information is *never* passed to it. This is the most critical mitigation.
        *   **Data Masking/Redaction:** If sensitive data *must* be displayed (e.g., for debugging), mask or redact it *before* passing it to `Alerter`.
        *   **Alert Context Awareness:** Consider where alerts are displayed. Avoid sensitive information in alerts visible to unauthorized users.
        *   **Conditional Alert Display:** Implement logic to show detailed error messages only to authorized users (e.g., admins) and generic messages to regular users.  *Never* expose internal error details to end-users via `Alerter`.

