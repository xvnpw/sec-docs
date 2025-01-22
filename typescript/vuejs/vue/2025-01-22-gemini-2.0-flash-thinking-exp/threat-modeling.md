# Threat Model Analysis for vuejs/vue

## Threat: [DOM-based XSS via `v-html`](./threats/dom-based_xss_via__v-html_.md)

*   **Description:** Attacker injects malicious JavaScript code into user-controlled data. If developers then use the `v-html` directive in a Vue template to render this unsanitized data, the injected script executes in the victim's browser. This is because `v-html` directly renders raw HTML, bypassing Vue's built-in XSS protection.
*   **Impact:** Account compromise, data theft, malware distribution, website defacement, redirection to malicious sites. Full control over the user's session and browser within the application's context.
*   **Vue Component Affected:** `v-html` directive within Vue Templates.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Absolutely Avoid `v-html` with User Input:**  Never, under any circumstances, use `v-html` to render content that originates from user input or any untrusted source.
    *   **Server-Side Sanitization (If absolutely necessary to render HTML):** If you must render HTML from user input, perform rigorous sanitization on the server-side using a robust and well-vetted HTML sanitization library *before* sending it to the client and rendering it with `v-html`. Client-side sanitization is generally less reliable.
    *   **Content Security Policy (CSP):** Implement a strong Content Security Policy to significantly reduce the impact of XSS vulnerabilities, even if `v-html` is misused.
    *   **Prefer Text Interpolation (`{{ }}`):**  Use text interpolation (`{{ }}`) for displaying user-provided text content. Vue's text interpolation automatically escapes HTML entities, preventing XSS in the vast majority of cases.

## Threat: [DOM-based XSS via Dynamic Template Compilation with User Input](./threats/dom-based_xss_via_dynamic_template_compilation_with_user_input.md)

*   **Description:** Attacker manipulates user input that is subsequently used to dynamically construct and compile Vue templates. This can occur if developers use functions like `Vue.compile()` or render functions that are built dynamically based on user-provided strings. If malicious code is injected into this user-controlled template string, it will be compiled and executed as JavaScript in the browser, leading to XSS.
*   **Impact:** Account compromise, data theft, malware distribution, website defacement, redirection to malicious sites. Full control over the user's session and browser within the application's context.
*   **Vue Component Affected:** `Vue.compile()` function, render functions dynamically constructed from strings, potentially dynamic component creation if based on user input that influences template structure.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Avoid Dynamic Template Compilation with User Input:**  Refrain from dynamically compiling Vue templates based on user-provided data. This practice is generally discouraged for security and performance reasons.
    *   **Template Whitelisting and Strict Control (If absolutely necessary):** If dynamic templates are unavoidable, implement extremely strict whitelisting and validation of user input to ensure it cannot influence the template structure or inject malicious code. This is complex and error-prone, so avoidance is strongly preferred.
    *   **Use Pre-compiled Templates and Components:**  Favor pre-compiled templates defined in `.vue` files or render functions defined directly in JavaScript. Component-based architecture naturally reduces the need for dynamic template manipulation.
    *   **Content Security Policy (CSP):** Implement a strong CSP to mitigate the impact of XSS, even if dynamic template compilation is misused.

