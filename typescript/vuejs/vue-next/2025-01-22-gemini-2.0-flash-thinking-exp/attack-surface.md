# Attack Surface Analysis for vuejs/vue-next

## Attack Surface: [1. Template Injection and XSS via `v-html`](./attack_surfaces/1__template_injection_and_xss_via__v-html_.md)

*   **Description:**  Rendering unsanitized HTML using the `v-html` directive allows attackers to inject malicious scripts that execute in the user's browser.
*   **Vue-next Contribution:** Vue-next provides the `v-html` directive as a feature to render raw HTML. Misuse of this feature directly creates a pathway for XSS attacks.
*   **Example:**
    *   A Vue.js component dynamically renders user-provided content using `v-html`:
        ```vue
        <template>
          <div v-html="dynamicContent"></div>
        </template>
        <script>
        export default {
          data() {
            return {
              dynamicContent: '<img src="x" onerror="alert(\'XSS Vulnerability!\')">' // Malicious HTML from an untrusted source
            };
          }
        };
        </script>
        ```
    *   When this component renders, the `onerror` event handler in the injected `<img>` tag will execute the JavaScript `alert('XSS Vulnerability!')`, demonstrating the vulnerability.
*   **Impact:** Cross-Site Scripting (XSS), leading to:
    *   Session hijacking and account takeover
    *   Theft of sensitive user cookies and tokens
    *   Redirection of users to malicious websites
    *   Website defacement and manipulation of content
    *   Data theft and unauthorized access to user information
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Developers:**
        *   **Strictly avoid using `v-html` with any user-provided or untrusted content.** This is the most effective mitigation.
        *   **If `v-html` is absolutely necessary:**
            *   **Sanitize HTML input rigorously:** Use a robust and trusted HTML sanitization library (like DOMPurify) to clean user-provided HTML before rendering it with `v-html`. Sanitize on the server-side if possible, or as close to the source of untrusted data as feasible.
            *   **Implement Content Security Policy (CSP):** Deploy a strong CSP to limit the capabilities of injected scripts, even if XSS vulnerabilities exist. CSP can act as a secondary defense layer.
    *   **Users:**
        *   No direct mitigation for users. Users are reliant on developers to implement secure coding practices and avoid `v-html` misuse.

## Attack Surface: [2. Slot Injection and XSS via Slots](./attack_surfaces/2__slot_injection_and_xss_via_slots.md)

*   **Description:**  If a Vue.js component renders content passed into its slots without proper sanitization, and this slot content originates from an untrusted source, it can result in Cross-Site Scripting (XSS) vulnerabilities.
*   **Vue-next Contribution:** Vue-next's slot mechanism enables content projection into components. If components render slot content unsafely (e.g., using `v-html` within the component to render slot content), it creates an XSS risk.
*   **Example:**
    *   A child component is designed to render slot content using `v-html`:
        ```vue
        <template>
          <div>
            <slot v-html="slotContent"></slot>
          </div>
        </template>
        <script>
        export default {
          computed: {
            slotContent() {
              return this.$slots.default ? this.$slots.default() : ''; // Potentially unsafe rendering of default slot content
            }
          }
        };
        </script>
        ```
    *   A parent component passes malicious HTML into the slot:
        ```vue
        <template>
          <ChildComponent>
            <img src="x" onerror="alert(\'XSS via Slot!\')">  <!-- Malicious HTML injected into the slot -->
          </ChildComponent>
        </template>
        <script>
        import ChildComponent from './ChildComponent.vue';
        export default {
          components: { ChildComponent }
        };
        </script>
        ```
    *   When `ChildComponent` renders the slot content using `v-html`, the injected JavaScript will execute, demonstrating XSS.
*   **Impact:** Cross-Site Scripting (XSS), with the same severe consequences as described in the `v-html` attack surface.
*   **Risk Severity:** **High** to **Critical** (similar to `v-html` XSS)
*   **Mitigation Strategies:**
    *   **Developers:**
        *   **Avoid `v-html` for rendering slot content.**  Never use `v-html` to render content that is passed into slots, especially if the source of the slot content is not fully trusted or dynamically generated.
        *   **Prefer text interpolation for slots:**  Use text interpolation (`{{ }}`) to render text-based slot content safely.
        *   **Sanitize slot content if raw HTML rendering is absolutely necessary:** If you must render HTML from slots, sanitize the HTML content using a trusted HTML sanitization library *before* rendering it within the component. Ensure sanitization happens within the component that renders the slot, not just where the slot content is provided.
        *   **Design components to minimize raw HTML slot rendering:** Re-evaluate component design to reduce or eliminate the need to render raw HTML from slots. Consider passing data as props and letting the child component handle safe rendering.
    *   **Users:**
        *   No direct mitigation for users. Users depend on developers to handle slot content securely and avoid unsafe rendering practices.

