# Attack Surface Analysis for vuejs/vue

## Attack Surface: [Client-Side Template Injection (XSS)](./attack_surfaces/client-side_template_injection__xss_.md)

*   **Attack Surface:** Client-Side Template Injection (XSS)

    *   **Description:** Exploitation of Vue.js's template rendering mechanism to inject malicious JavaScript code. This occurs when user-supplied data is rendered directly into Vue templates *without proper sanitization*.
    *   **How Vue Contributes:** Vue's core functionality relies on dynamically rendering data into the DOM using templates and directives (e.g., `{{ }}`, `v-html`, `v-bind`). This is the *direct* mechanism of the attack. The vulnerability exists *because* of how Vue handles dynamic content.
    *   **Example:**
        ```vue
        <template>
          <div v-html="userInput"></div>
        </template>

        <script>
        export default {
          data() {
            return {
              userInput: '<img src=x onerror=alert(1)>' // User-provided input
            };
          }
        };
        </script>
        ```
        The use of `v-html` with unsanitized `userInput` is a *direct* use of a Vue feature that creates the vulnerability.
    *   **Impact:**
        *   Theft of user cookies and session tokens.
        *   Redirection to malicious websites.
        *   Modification of page content (defacement).
        *   Keylogging and capturing user input.
        *   Execution of arbitrary code in the user's browser.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Prefer `v-text`:** Use `v-text` instead of `v-html` whenever possible. `v-text` is a *Vue-specific* directive that prevents this attack.
        *   **Sanitize User Input (Mandatory for `v-html`):** If `v-html` is absolutely necessary, *always* sanitize user input using a robust, well-vetted HTML sanitization library like DOMPurify *before* passing it to Vue.
        *   **Content Security Policy (CSP):** Implement a strong CSP. While CSP is a general web security feature, its interaction with Vue's inline event handlers (`@click`) is relevant.
        *   **Avoid Dynamic Component Names from User Input:** If using dynamic components (`<component :is="...">`), strictly validate and whitelist allowed component names if they are derived from user input. This is a *Vue-specific* feature that can be misused.
        * **Avoid using `eval` or Function constructor:** Vue.js internally uses Function constructor for template compilation. If attacker can control part of template, it can lead to RCE.

## Attack Surface: [Prototype Pollution](./attack_surfaces/prototype_pollution.md)

*   **Attack Surface:** Prototype Pollution

    *   **Description:** Manipulation of the prototype of JavaScript objects used by Vue's reactivity system to inject properties or methods, leading to unexpected behavior or vulnerabilities.
    *   **How Vue Contributes:** Vue's reactivity system *depends* on observing changes to JavaScript objects. This dependency creates the vulnerability. The attack targets the *mechanism* Vue uses for reactivity.
    *   **Example:**
        ```javascript
        // Attacker's code (e.g., via a vulnerable third-party library)
        Object.prototype.pollutedProperty = '<img src=x onerror=alert(1)>';

        // Vue component
        export default {
          data() {
            return {
              someData: {} // Initially an empty object
            };
          },
          mounted() {
            // If someData doesn't explicitly define 'pollutedProperty',
            // it will inherit it from the prototype, and Vue's reactivity
            // system will track it.
            console.log(this.someData.pollutedProperty); // Outputs malicious code
            // If this is then rendered with v-html, it's XSS.
          }
        };
        ```
        The attack exploits how Vue *tracks* changes to objects.
    *   **Impact:**
        *   XSS vulnerabilities (if the polluted property is rendered in the template).
        *   Denial-of-service (by causing unexpected behavior or crashes).
        *   Data corruption or manipulation.
        *   Potentially arbitrary code execution (in more complex scenarios).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **`Object.freeze()`:** Use `Object.freeze()` on data objects that should be immutable. This directly prevents modification of the object, mitigating the attack on Vue's reactivity.
        *   **Schema Validation:** Validate data structures before using them in Vue components. This helps prevent unexpected properties from entering Vue's reactivity system.
        *   **Avoid Deeply Nested Objects from Untrusted Sources:** Flatten data structures to reduce the attack surface that Vue's reactivity system has to manage.
        *   **Use `Map` Objects:** Consider using `Map` objects instead of plain JavaScript objects. `Map` objects are less susceptible to prototype pollution, and Vue 3 has specific support for reactivity with `Map` and `Set`.
        *   **Careful Dependency Management:** While a general best practice, it's crucial for preventing the introduction of code that could pollute prototypes used by Vue.

