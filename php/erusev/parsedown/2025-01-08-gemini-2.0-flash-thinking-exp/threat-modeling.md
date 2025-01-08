# Threat Model Analysis for erusev/parsedown

## Threat: [Cross-Site Scripting (XSS) via Malicious HTML Tags](./threats/cross-site_scripting__xss__via_malicious_html_tags.md)

*   **Description:** An attacker crafts malicious Markdown input containing HTML tags (e.g., `<script>`, `<iframe>`, `<object>`) that Parsedown renders without proper sanitization or escaping. This allows the attacker to inject arbitrary HTML and potentially JavaScript into the application's pages.
    *   **Impact:** An attacker can execute arbitrary JavaScript in the user's browser. This can lead to session hijacking (stealing cookies), redirecting the user to malicious websites, defacing the page, or performing actions on behalf of the user without their consent.
    *   **Affected Parsedown Component:** The core parsing logic responsible for converting Markdown syntax into HTML elements. Specifically, the handling of inline HTML or fenced code blocks with language specifiers that might be misinterpreted.
    *   **Risk Severity:** High

## Threat: [Cross-Site Scripting (XSS) via `javascript:` URLs in Links](./threats/cross-site_scripting__xss__via__javascript__urls_in_links.md)

*   **Description:** An attacker crafts Markdown input with links using the `javascript:` protocol (e.g., `[Click Me](javascript:alert('XSS'))`). If Parsedown renders this directly as an `<a>` tag without proper sanitization, clicking the link will execute the JavaScript code.
    *   **Impact:** Similar to the previous XSS threat, an attacker can execute arbitrary JavaScript in the user's browser, leading to various malicious actions.
    *   **Affected Parsedown Component:** The part of the parsing logic that handles link creation from Markdown syntax.
    *   **Risk Severity:** High

## Threat: [Bypass of Intended Sanitization Logic](./threats/bypass_of_intended_sanitization_logic.md)

*   **Description:** An attacker discovers a specific combination of Markdown syntax or a subtle flaw in Parsedown's logic that allows them to bypass intended sanitization or escaping mechanisms, enabling the injection of malicious HTML or scripts.
    *   **Impact:**  Can lead to XSS or HTML injection vulnerabilities.
    *   **Affected Parsedown Component:** The sanitization and escaping logic within Parsedown.
    *   **Risk Severity:** High

