* **Client-Side Cross-Site Scripting (XSS) via `dangerouslySetInnerHTML`:**
    * **Description:** Attackers inject malicious scripts into the application that are then executed in the user's browser.
    * **How Preact Contributes to the Attack Surface:** Preact provides the `dangerouslySetInnerHTML` prop, which allows rendering raw HTML directly. If this prop is used with unsanitized user-provided data, it creates a direct path for XSS attacks.
    * **Example:** A blog comment application uses `dangerouslySetInnerHTML` to render user comments. An attacker submits a comment containing `<script>alert('XSS')</script>`, which is then executed in other users' browsers when they view the comment.
    * **Impact:** Stealing user credentials (cookies, session tokens), redirecting users to malicious websites, performing actions on behalf of the user, defacing the website.
    * **Risk Severity:** Critical
    * **Mitigation Strategies:**
        * **Developers:** Avoid using `dangerouslySetInnerHTML` whenever possible.
        * **Developers:** If `dangerouslySetInnerHTML` is necessary, rigorously sanitize the input using a trusted library like DOMPurify before rendering.
        * **Developers:** Implement Content Security Policy (CSP) to further restrict the sources from which the browser can load resources.