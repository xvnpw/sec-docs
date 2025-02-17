# Attack Surface Analysis for vuejs/vue-next

## Attack Surface: [Unsanitized Component Input (Props) Leading to XSS](./attack_surfaces/unsanitized_component_input__props__leading_to_xss.md)

*   **Description:**  Malicious code (JavaScript, HTML) injected through component props, which are then rendered without sanitization, leading to Cross-Site Scripting (XSS).
*   **How Vue-next Contributes:** Vue's component-based architecture relies heavily on props for data transfer.  Vue *does not* automatically sanitize prop data; it's the developer's responsibility.
*   **Example:**
    ```vue
    // Parent Component
    <template>
      <MyComponent :message="userInput" />
    </template>
    <script>
    export default {
      data() {
        return {
          userInput: '<img src=x onerror=alert(1)>' // Malicious
        }
      }
    }
    </script>

    // MyComponent (Vulnerable)
    <template>
      <div>{{ message }}</div>  // Or: <div v-html="message"></div>
    </template>
    <script>
    export default {
      props: ['message']
    }
    </script>
    ```
*   **Impact:**  Execution of arbitrary JavaScript in the user's browser, leading to session hijacking, data theft, etc.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strict Prop Type Validation:** Use Vue's prop validation (e.g., `type: String, validator: (value) => { /* custom validation */ }`).
    *   **Input Sanitization:** Use a library like DOMPurify to sanitize *all* prop data before rendering, especially if using `v-html`.
    *   **Prefer `v-text` or Template Interpolation:** Avoid `v-html` whenever possible. Use `v-text` or `{{ }}`.
    *   **Content Security Policy (CSP):** Implement a strict CSP.

## Attack Surface: [Dynamic Component Injection via `is` Attribute](./attack_surfaces/dynamic_component_injection_via__is__attribute.md)

*   **Description:**  Using user-controlled input to determine which component to render via the `is` attribute, allowing an attacker to load arbitrary components.
*   **How Vue-next Contributes:** The `is` attribute is a core Vue feature for dynamic component rendering.  Its misuse is a direct Vue-specific vulnerability.
*   **Example:**
    ```vue
    <template>
      <component :is="userInput"></component>
    </template>
    <script>
    export default {
      data() {
        return {
          userInput: 'MaliciousComponent' // Attacker-controlled
        }
      }
    }
    </script>
    ```
*   **Impact:**  Execution of arbitrary code within the application.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Whitelist Allowed Components:**  Maintain a strict whitelist of allowed component names.  Reject any input not on the whitelist.
    *   **Component Name Validation:** If a whitelist is impractical, implement rigorous validation of the component name.

## Attack Surface: [`v-html` with Untrusted Data](./attack_surfaces/_v-html__with_untrusted_data.md)

*   **Description:**  Using the `v-html` directive to render raw HTML from an untrusted source, leading to XSS.
*   **How Vue-next Contributes:** `v-html` is a built-in Vue directive.  It's a *direct* XSS vector if misused.  Vue provides this directive, and it's the developer's responsibility to use it safely (or, ideally, not at all).
*   **Example:**
    ```vue
    <template>
      <div v-html="userInput"></div>
    </template>
    <script>
    export default {
      data() {
        return {
          userInput: '<img src=x onerror=alert(1)>' // Malicious
        }
      }
    }
    </script>
    ```
*   **Impact:**  Classic XSS, allowing execution of arbitrary JavaScript.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Avoid `v-html`:**  This is the primary mitigation. Use `v-text` or template interpolation (`{{ }}`).
    *   **Sanitize with DOMPurify:** If `v-html` is *absolutely* necessary, sanitize the input with DOMPurify *before* rendering.

## Attack Surface: [Unvalidated Route Parameters](./attack_surfaces/unvalidated_route_parameters.md)

*   **Description:** Using route parameters to fetch data or control logic without validation, allowing access to unauthorized data or triggering unintended behavior.
*   **How Vue-next Contributes:** While routing itself isn't *exclusive* to Vue, Vue Router is the officially recommended routing solution and is tightly integrated with Vue. The way Vue Router handles parameters and integrates with components makes this a relevant Vue-specific concern.
*   **Example:**
    ```javascript
    // Route: /users/:id
    // Component (vulnerable):
    async fetchUserData() {
      const userId = this.$route.params.id; // Directly using
      const response = await fetch(`/api/users/${userId}`); // No validation
      // ...
    }
    ```
*   **Impact:** Data breaches, unauthorized access, application instability.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Validate Route Parameters:** Use route guards or component lifecycle hooks to validate parameters (type, range, etc.).
    *   **Server-Side Authorization:** *Always* perform authorization checks on the server-side.

## Attack Surface: [SSR-Specific XSS (Server-Side Rendering)](./attack_surfaces/ssr-specific_xss__server-side_rendering_.md)

*   **Description:**  Injecting malicious data into the server-rendered HTML during SSR, leading to XSS that bypasses client-side sanitization.
*   **How Vue-next Contributes:** Vue's built-in SSR capabilities create this specific attack surface. The way Vue handles server-side rendering and data hydration makes this a Vue-specific concern.
*   **Example:**
    ```javascript
    // Server-side (vulnerable)
    const app = createSSRApp(App);
    const appContent = await renderToString(app, { userData: '<img src=x onerror=alert(1)>' }); // Unescaped
    const html = `<div id="app">${appContent}</div>`;
    ```
*   **Impact:**  XSS executed before client-side JavaScript runs.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Serialize and Escape Data:** Use `serialize-javascript` (or similar) to escape data before injecting it into the server-rendered HTML.
    *   **Context-Aware Escaping:** Ensure escaping is appropriate for the HTML context.

