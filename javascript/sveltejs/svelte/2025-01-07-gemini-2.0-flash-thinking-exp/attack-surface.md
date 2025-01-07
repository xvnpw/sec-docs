# Attack Surface Analysis for sveltejs/svelte

## Attack Surface: [Client-Side Template Injection (via JavaScript Expressions)](./attack_surfaces/client-side_template_injection__via_javascript_expressions_.md)

*   **Attack Surface:** Client-Side Template Injection (via JavaScript Expressions)
    *   **Description:**  Malicious JavaScript code can be injected and executed within the user's browser by manipulating data that is directly rendered in Svelte templates using JavaScript expressions (e.g., `<h1>{user.name}</h1>`).
    *   **How Svelte Contributes:** Svelte's template syntax allows embedding JavaScript expressions directly within the markup, which, if not handled carefully with user-provided data, becomes a direct injection point.
    *   **Example:** A Svelte component renders `<h1>{userInput}</h1>`, where `userInput` is taken directly from a URL parameter like `?name=<script>alert('XSS')</script>`.
    *   **Impact:** Cross-Site Scripting (XSS), leading to session hijacking, cookie theft, redirection to malicious sites, or defacement.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developers:** Sanitize all user-provided data before rendering it in Svelte templates. Avoid directly embedding unsanitized user input within JavaScript expressions. Utilize browser APIs or libraries for proper escaping of HTML entities. Consider using Svelte's built-in escaping mechanisms where applicable, though manual sanitization is often necessary for complex scenarios.

## Attack Surface: [`{@html}` Tag Vulnerabilities](./attack_surfaces/_{@html}__tag_vulnerabilities.md)

*   **Attack Surface:** `{@html}` Tag Vulnerabilities
    *   **Description:** The `{@html}` tag in Svelte allows rendering raw HTML strings directly into the DOM. If user-controlled data is passed to this tag without proper sanitization, it creates a direct path for XSS attacks.
    *   **How Svelte Contributes:** Svelte provides the `{@html}` tag as a feature, which, while useful for certain scenarios, introduces a significant security risk if misused with untrusted data.
    *   **Example:** A Svelte component renders `{@html untrustedHTML}`, where `untrustedHTML` comes from user input like a comment field. An attacker can inject malicious scripts within the comment.
    *   **Impact:** Cross-Site Scripting (XSS).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Developers:** **Absolutely avoid** using `{@html}` with any data that originates from user input or any untrusted source. If you must render dynamic HTML, use a trusted sanitization library (e.g., DOMPurify) to clean the HTML before passing it to `{@html}`.

