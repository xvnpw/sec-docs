# Threat Model Analysis for adam-p/markdown-here

## Threat: [Cross-Site Scripting (XSS) via Malicious `<script>` Tag](./threats/cross-site_scripting__xss__via_malicious__script__tag.md)

*   **Description:** An attacker crafts Markdown input containing a `<script>` tag. `markdown-here`'s core functionality of converting Markdown to HTML fails to adequately sanitize this input, resulting in the direct rendering of the `<script>` tag in the final HTML output. When a user views this output, the malicious script executes within their browser context.
    *   **Impact:** Critical. Account compromise, session hijacking, sensitive data theft, redirection to malicious sites, and arbitrary actions performed on behalf of the user.
    *   **Risk Severity:** Critical.
    *   **Mitigation Strategies:**
        *   **Developers:** Implement strict and robust HTML sanitization *after* `markdown-here` performs the Markdown to HTML conversion. Utilize a well-established and actively maintained sanitization library (e.g., DOMPurify) to remove or neutralize potentially harmful tags, including `<script>`. Avoid relying solely on any built-in sanitization within `markdown-here`, as it might be insufficient or have bypasses.

## Threat: [Cross-Site Scripting (XSS) via HTML Event Handlers](./threats/cross-site_scripting__xss__via_html_event_handlers.md)

*   **Description:** An attacker crafts Markdown that, upon conversion by `markdown-here`, results in HTML tags containing malicious event handlers (e.g., `<img src="x" onerror="maliciousCode()">`). `markdown-here`'s HTML rendering process does not strip or neutralize these event handlers, allowing the attacker to execute arbitrary JavaScript when the associated event is triggered in the user's browser.
    *   **Impact:** Critical. Similar to the `<script>` tag XSS, this can lead to account compromise, data theft, and other malicious actions.
    *   **Risk Severity:** Critical.
    *   **Mitigation Strategies:**
        *   **Developers:**  Employ thorough HTML sanitization that specifically removes or neutralizes potentially dangerous HTML attributes, including all event handlers (e.g., `onload`, `onerror`, `onclick`, `onmouseover`). Ensure the sanitization library is configured to be aggressive in removing such attributes.

## Threat: [HTML Injection leading to Phishing Attacks](./threats/html_injection_leading_to_phishing_attacks.md)

*   **Description:** An attacker leverages `markdown-here`'s Markdown to HTML conversion to inject arbitrary HTML elements that mimic legitimate user interface components or forms. This injected HTML can be used to create fake login forms or other elements designed to trick users into submitting sensitive information directly to the attacker. The vulnerability lies in `markdown-here`'s insufficient filtering of HTML tags that can be used for visual deception.
    *   **Impact:** High. Credential theft, compromise of user accounts, and potential further exploitation of those accounts.
    *   **Risk Severity:** High.
    *   **Mitigation Strategies:**
        *   **Developers:** Implement a strong HTML sanitization policy that restricts the range of allowed HTML tags to a safe subset necessary for formatting. Specifically block tags like `<form>`, `<iframe>`, and any other tags that can be used to embed external content or create interactive elements for phishing. Consider a whitelist approach for allowed tags and attributes.

