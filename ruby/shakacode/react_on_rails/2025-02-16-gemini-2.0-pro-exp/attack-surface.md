# Attack Surface Analysis for shakacode/react_on_rails

## Attack Surface: [Server-Side Rendering (SSR) Node.js Exploits](./attack_surfaces/server-side_rendering__ssr__node_js_exploits.md)

*   **Description:** Exploitation of vulnerabilities in the Node.js environment *specifically used for `react_on_rails`'s server-side rendering*.
*   **`react_on_rails` Contribution:** `react_on_rails` *directly* introduces and manages the Node.js runtime for SSR, making this its responsibility.
*   **Example:** An outdated Node.js package, *required by `react_on_rails`'s SSR setup*, has a known RCE vulnerability. An attacker crafts a malicious React component to trigger it.
*   **Impact:** RCE on the server, complete server compromise, data breaches, denial of service.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Regularly Update Node.js (SSR Context):** Keep the Node.js runtime *used by `react_on_rails` for SSR* up-to-date. This might be separate from your main Rails application's runtime.
    *   **Dependency Auditing (SSR Context):** Use `npm audit`, `yarn audit`, etc., *specifically within the Node.js environment used for SSR*.  Focus on dependencies listed in the `package.json` used for SSR.
    *   **Least Privilege (SSR Process):** Run the `react_on_rails` SSR Node.js process with minimal privileges. Never as root.
    *   **Resource Limits (SSR Process):** Configure CPU and memory limits for the `react_on_rails` SSR process to prevent DoS.
    *   **Containerization (SSR):** Isolate the `react_on_rails` SSR environment using containers (e.g., Docker) to limit the blast radius.
    *   **WAF (Targeting SSR):** Configure your WAF to specifically filter requests that might target known SSR vulnerabilities or patterns.

## Attack Surface: [XSS via Props (Serialization/Deserialization)](./attack_surfaces/xss_via_props__serializationdeserialization_.md)

*   **Description:** XSS vulnerabilities arising from `react_on_rails`'s handling of prop serialization and deserialization between Rails and React.
*   **`react_on_rails` Contribution:** The gem *is the bridge* that handles the data transfer, making its serialization/deserialization logic a critical point for XSS prevention.
*   **Example:** Unsanitized user input in Rails is passed as a prop. `react_on_rails`'s default serialization doesn't sanitize it, and the React component renders it without escaping.
*   **Impact:** Execution of arbitrary JavaScript in the user's browser, session hijacking, data theft.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Strict Input Validation (Rails):** *Always* sanitize user input on the Rails side *before* passing it as props, regardless of `react_on_rails`'s behavior.
    *   **Output Encoding (Rails & React):** Use Rails' `h` helper (or similar) for HTML encoding on the Rails side. Rely on React's built-in escaping.
    *   **Avoid `dangerouslySetInnerHTML`:** Minimize or eliminate its use. If unavoidable, *double-check* sanitization on *both* Rails and React sides.
    *   **Content Security Policy (CSP):** Implement a strong CSP to limit the impact of any XSS that might slip through.
    *   **Review `react_on_rails` Serializer:** If using a *custom* serializer with `react_on_rails`, thoroughly audit it for proper escaping and security.  Prefer the built-in serializers unless absolutely necessary.

## Attack Surface: [CSRF Protection Bypass (Specific to `react_on_rails` Integration)](./attack_surfaces/csrf_protection_bypass__specific_to__react_on_rails__integration_.md)

*   **Description:** Bypassing CSRF protection *specifically* in the interactions managed by `react_on_rails` between React components and Rails controllers.
*   **`react_on_rails` Contribution:** The gem provides helpers for CSRF token management, and *incorrect usage of these helpers* is the direct cause of this vulnerability.
*   **Example:** A React component makes an AJAX request, but the developer forgets to use `react_on_rails`'s `authenticityToken()` helper, or uses it incorrectly.
*   **Impact:** Attackers can forge requests on behalf of users, leading to unauthorized actions.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Correctly Use `react_on_rails` Helpers:** *Always* use the provided `react_on_rails` helpers (e.g., `authenticityToken()`) for including CSRF tokens in requests from React components. Follow the official documentation precisely.
    *   **Server-Side Validation (Rails):** Ensure Rails controllers *always* rigorously validate the authenticity token, even if `react_on_rails` helpers are used. This is a defense-in-depth measure.
    *   **Test `react_on_rails` CSRF Integration:** Write specific tests to verify that CSRF protection is working correctly for all interactions between React components and Rails controllers *through `react_on_rails`*.

## Attack Surface: [Sensitive Data Exposure via SSR](./attack_surfaces/sensitive_data_exposure_via_ssr.md)

*   **Description:** Unintentional leakage of sensitive data included in the server-side rendered HTML generated by `react_on_rails`.
*   **`react_on_rails` Contribution:**  `react_on_rails`'s SSR process is *directly responsible* for generating the initial HTML, making it the point where this leakage can occur.
*   **Example:** An API key is accidentally passed as a prop during SSR and ends up in the HTML source code.
*   **Impact:** Exposure of sensitive data (API keys, tokens, internal URLs), leading to unauthorized access.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Strict Data Control for SSR:**  Be *extremely* careful about what data is passed to React components during `react_on_rails`'s SSR process.  Never pass sensitive data unless absolutely necessary for the initial render.
    *   **Data Transformation (Server-Side):** Before passing data to React components for SSR, transform it to remove or redact any sensitive information.
    *   **Client-Side Data Fetching:** For sensitive data that needs to be displayed, fetch it *after* the initial render on the client-side, using secure API calls.  Don't include it in the SSR payload.
    *   **Environment Variables:** Store sensitive configuration *outside* of the codebase, using environment variables.

