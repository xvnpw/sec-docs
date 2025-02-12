# Attack Surface Analysis for hakimel/reveal.js

## Attack Surface: [Cross-Site Scripting (XSS) via Slide Content](./attack_surfaces/cross-site_scripting__xss__via_slide_content.md)

*   **Description:** Injection of malicious JavaScript into the presentation content, executing in the viewer's browser. This is the most direct and significant vulnerability.
*   **reveal.js Contribution:** reveal.js renders HTML within slides, providing the *direct* mechanism for injecting and executing malicious script if user-provided content is not sanitized. reveal.js's core functionality of displaying HTML is the attack vector.
*   **Example:**
    ```html
    <section data-markdown>
      <script type="text/template">
        ## Hello, {{username}}!  <!-- UNSAFE: User input here -->
      </script>
    </section>
    ```
    If `username` comes from an untrusted source (e.g., URL parameter) without sanitization, an attacker can inject `<script>` tags.
*   **Impact:**
    *   Stealing cookies/session tokens.
    *   Redirection to malicious sites.
    *   Presentation defacement.
    *   Keylogging.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Input Sanitization (Primary):** Use a robust HTML sanitizer (e.g., DOMPurify) *before* inserting *any* user-supplied data into the DOM, *regardless* of whether it's Markdown or direct HTML. This is non-negotiable.
    *   **Content Security Policy (CSP) (Strong Secondary):** A strict CSP, especially `script-src`, is crucial. Avoid `unsafe-inline` if at all possible. This limits the damage even if sanitization fails.
    *   **Context-Aware Encoding:** Ensure proper encoding (HTML, JavaScript) for the specific context.
    *   **Avoid `innerHTML` with Untrusted Data:** Prefer `textContent` or a secure templating engine.

## Attack Surface: [Denial of Service (DoS) via Resource Exhaustion (reveal.js-Specific)](./attack_surfaces/denial_of_service__dos__via_resource_exhaustion__reveal_js-specific_.md)

*   **Description:** Overloading the browser with excessive content or complex animations *specifically crafted to exploit reveal.js's rendering engine*.
*   **reveal.js Contribution:** reveal.js's features for creating complex presentations (nested slides, transitions, large numbers of slides) are the *direct* tools used for this attack.  It's not just *any* large content; it's content designed to stress reveal.js's specific rendering capabilities.
*   **Example:** An attacker creates a presentation with thousands of deeply nested slides, each with complex CSS transitions and animations, specifically targeting reveal.js's slide management and rendering logic.  This goes beyond simply "large content" and targets reveal.js's internal mechanisms.
*   **Impact:**
    *   Presentation becomes unusable.
    *   Browser crashes/freezes.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Limit Slide Count and Nesting Depth (reveal.js-Specific):** Impose limits *specifically* on the number of slides and the depth of nested slides allowed. This directly mitigates the attack vector within reveal.js.
    *   **Limit Complex Animations:** Restrict the use of computationally expensive CSS transitions and animations, particularly on deeply nested elements.
    *   **Lazy Loading (reveal.js Feature):** Utilize reveal.js's built-in lazy loading (`data-src`) for images and iframes to reduce initial load.
    *   **Server-Side Validation (reveal.js Structure):** Validate the *structure* of the presentation data on the server-side to prevent maliciously crafted reveal.js configurations.

## Attack Surface: [Unsecured `remote` Plugin (Built-in)](./attack_surfaces/unsecured__remote__plugin__built-in_.md)

*   **Description:** Unauthorized control of the presentation if the built-in `remote` plugin is enabled without proper security.
*   **reveal.js Contribution:** This is a *direct* vulnerability of a built-in reveal.js feature. The `remote` plugin itself is the attack vector.
*   **Example:** The `remote` plugin is enabled with a default or easily guessable password, allowing an attacker to take control.
*   **Impact:**
    *   Complete control of the presentation by an attacker.
    *   Disruption, data exfiltration.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Disable if Unnecessary:** Disable the `remote` plugin if it's not actively required. This is the best mitigation if it's not needed.
    *   **Strong, Unique Password:** Use a strong, unique password *specifically* for the `remote` plugin.
    *   **Network Security:** Ensure a secure network connection (HTTPS).
    *   **Authentication/Authorization (Beyond reveal.js):** If possible, implement additional authentication layers *outside* of reveal.js itself.

