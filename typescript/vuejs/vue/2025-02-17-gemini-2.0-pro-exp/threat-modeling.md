# Threat Model Analysis for vuejs/vue

## Threat: [Unsanitized `v-html` Injection](./threats/unsanitized__v-html__injection.md)

*   **Description:** An attacker injects malicious HTML and JavaScript code into a component that uses the `v-html` directive to render user-supplied or otherwise untrusted content. The attacker crafts input containing `<script>` tags or event handlers (e.g., `onload`, `onerror`) that execute arbitrary code when rendered.
*   **Impact:**  Cross-Site Scripting (XSS).  The attacker's code runs in the victim's browser, enabling cookie/token theft, redirection to phishing sites, page defacement, and other malicious actions.
*   **Affected Vue Component:** Any component using the `v-html` directive. The `v-html` directive *itself* is the direct point of vulnerability. Example: `<div v-html="userProvidedContent"></div>`.
*   **Risk Severity:** Critical.
*   **Mitigation Strategies:**
    *   **Avoid `v-html` whenever possible.** Use template interpolation (`{{ }}`) or `v-text` for dynamic text.
    *   **If `v-html` is *absolutely* necessary, use a robust client-side sanitization library like DOMPurify *before* binding the content.**
        ```javascript
        // Example using DOMPurify:
        import DOMPurify from 'dompurify';

        export default {
          computed: {
            sanitizedContent() {
              return DOMPurify.sanitize(this.untrustedContent);
            }
          }
        };
        ```
        ```html
        <div v-html="sanitizedContent"></div>
        ```
    *   **Never trust user input directly.**
    *   Implement a Content Security Policy (CSP).

## Threat: [Malicious Prop Injection](./threats/malicious_prop_injection.md)

*   **Description:** An attacker controls data passed as a prop to a child component. If the child component doesn't validate/sanitize this prop before using it (especially in `v-html`, template interpolation, or DOM manipulation), the attacker can inject malicious code or manipulate behavior.
*   **Impact:**  XSS, data corruption, unexpected component behavior.
*   **Affected Vue Component:** Any component receiving props. The vulnerability is in how the *receiving* component handles the prop. Affected methods depend on prop usage (e.g., `v-html`, `v-bind`, DOM manipulation in methods/computed properties).
*   **Risk Severity:** High.
*   **Mitigation Strategies:**
    *   **Prop Validation:** Use Vue's prop validation for type checking and custom validation.
        ```javascript
        // Example:
        props: {
          potentiallyDangerousProp: {
            type: String,
            required: true, // Or false, depending on the use case
            validator: (value) => { /* Robust validation logic here */ return true; }
          }
        }
        ```
    *   **Sanitization:** If a prop might contain HTML or is used in a way that could lead to XSS, sanitize it using DOMPurify *within the receiving component*.
    *   **Defensive Programming:** Treat *all* props as potentially untrusted.

## Threat: [Client-Side Security Bypass (using `v-if`/`v-show`)](./threats/client-side_security_bypass__using__v-if__v-show__.md)

*   **Description:** Developers incorrectly use `v-if` or `v-show` to hide elements based on user roles, believing this provides security. An attacker inspects the DOM or component state (using browser tools) to reveal hidden content.
*   **Impact:** Data leakage. Users access data they shouldn't see. *Does not* prevent unauthorized server actions if the server lacks authorization.
*   **Affected Vue Component:** Any component using `v-if` or `v-show` for conditional rendering based on roles/permissions. The directives themselves aren't vulnerable, but their *misuse* is.
*   **Risk Severity:** High.
*   **Mitigation Strategies:**
    *   **Server-Side Authorization:** Implement *all* authorization checks on the server. The server determines access and only sends authorized data.
    *   **Don't Send Sensitive Data:** Never send data the user isn't authorized to see, even if hidden with `v-if`/`v-show`.
    *   **Use `v-if`/`v-show` for UI:** Use these for UI enhancements *after* server-side authorization. They control *presentation*, not access.

## Threat: [Dynamic Component Injection with Untrusted Input](./threats/dynamic_component_injection_with_untrusted_input.md)

*   **Description:** The application uses `v-bind:is` (or `<component :is="...">`) to dynamically render components based on user input. An attacker provides a malicious component name, causing unexpected component rendering or code execution.
*   **Impact:** Similar to XSS, potentially more severe. Could allow instantiation of arbitrary components with their own logic.
*   **Affected Vue Component:** Any component using `v-bind:is` or `<component :is="...">` with dynamic values. The vulnerability is in the dynamic rendering mechanism with untrusted input.
*   **Risk Severity:** High.
*   **Mitigation Strategies:**
    *   **Whitelist Allowed Components:** Maintain a *strict* whitelist of allowed component names. *Do not* allow arbitrary names from user input.
        ```javascript
        // Example:
        const allowed = { 'safe-comp': SafeComponent, 'another-safe': AnotherSafe };
        export default {
          props: { compName: { type: String, required: true, validator: (v) => allowed.hasOwnProperty(v) } },
          computed: { dynComp() { return allowed[this.compName] || null; } }
        };
        ```
        ```html
        <component :is="dynComp"></component>
        ```
    *   **Lookup Table:** Map user input to a predefined set of safe component names.
    *   **Avoid if Possible:** Avoid dynamic component rendering with user input if possible.

## Threat: [SSR Data Exposure](./threats/ssr_data_exposure.md)

*   **Description:** (Server-Side Rendering specific) Sensitive data is inadvertently included in the server-rendered HTML, exposing it to anyone who views the page source.
*   **Impact:** Data leakage.
*   **Affected Vue Component:** Any component rendered on the server (using Vue SSR). The vulnerability is in the server-side rendering logic and data handling.
*   **Risk Severity:** High.
*   **Mitigation Strategies:**
    *   **Data Filtering:** Carefully control what data is passed to the Vue application during server-side rendering. Only include necessary and safe-to-expose data.
    *   **Separate API Endpoints:** Use separate API endpoints for server and client. The server-side endpoint can return minimal data for initial render; the client-side endpoint fetches additional data after hydration.
    *   **Don't Render Sensitive Data:** Avoid rendering sensitive data directly in the HTML. Fetch it client-side after the initial render, using secure API calls.

