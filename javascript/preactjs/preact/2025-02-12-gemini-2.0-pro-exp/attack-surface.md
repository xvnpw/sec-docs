# Attack Surface Analysis for preactjs/preact

## Attack Surface: [Cross-Site Scripting (XSS) via `dangerouslySetInnerHTML`](./attack_surfaces/cross-site_scripting__xss__via__dangerouslysetinnerhtml_.md)

*   **Description:**  Injection of malicious JavaScript code through user-supplied data rendered without proper sanitization, bypassing Preact's escaping.
    *   **How Preact Contributes:** Preact provides the `dangerouslySetInnerHTML` prop, which *intentionally* disables escaping.  This is the *direct* cause of the vulnerability if misused.
    *   **Example:**
        ```javascript
        // Vulnerable:
        function MyComponent({ userInput }) {
          return <div dangerouslySetInnerHTML={{ __html: userInput }} />;
        }
        // Attacker input: <img src=x onerror=alert(1)>
        ```
    *   **Impact:**  Execution of arbitrary JavaScript in the user's browser, leading to session hijacking, data theft, defacement, etc.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Primary: Avoid `dangerouslySetInnerHTML` whenever possible.** This is the most effective mitigation.
        *   **If unavoidable: Always sanitize input with a robust library like DOMPurify *before* using `dangerouslySetInnerHTML`.**
            ```javascript
            import DOMPurify from 'dompurify';

            function MyComponent({ userInput }) {
              const sanitized = DOMPurify.sanitize(userInput);
              return <div dangerouslySetInnerHTML={{ __html: sanitized }} />;
            }
            ```
        *   **Defense-in-depth: Implement a strong Content Security Policy (CSP).**

## Attack Surface: [XSS via Unescaped Variables in JSX (Specific Cases)](./attack_surfaces/xss_via_unescaped_variables_in_jsx__specific_cases_.md)

*   **Description:**  Injection of malicious JavaScript through user input directly embedded within JSX *without* `dangerouslySetInnerHTML`, but in contexts where Preact's escaping is insufficient or bypassed.  This is *less* common than misuse of `dangerouslySetInnerHTML`, but still possible.
    *   **How Preact Contributes:** While Preact *generally* escapes, developers can make mistakes, particularly in event handlers or when dynamically constructing attribute values.  The JSX syntax itself is the vector.
    *   **Example:**
        ```javascript
        // Vulnerable:
        function MyComponent({ userInput }) {
          return <div onClick={() => alert(userInput)}>Click Me</div>;
        }
        // Attacker input: "); alert("XSS"); //
        ```
    *   **Impact:**  Execution of arbitrary JavaScript, leading to the same consequences as above.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Rely on Preact's built-in escaping for simple variable interpolation: `{myVariable}`.**
        *   **Avoid manual HTML string construction within JSX.**
        *   **Be extremely cautious with event handlers.** Validate and, if necessary, escape user input *within the context of the handler*.  Prefer functions to generate handler logic.
        *   **Use a linter with security rules** (e.g., ESLint with `eslint-plugin-react` and security-focused rules) to detect potential issues.

## Attack Surface: [Insecure use of `preact/compat` (Inherited Vulnerabilities)](./attack_surfaces/insecure_use_of__preactcompat___inherited_vulnerabilities_.md)

*   **Description:** Vulnerabilities present in React libraries become exploitable when those libraries are used with Preact via the `preact/compat` compatibility layer.
    *   **How Preact Contributes:** `preact/compat` *directly* enables the use of React libraries, thus inheriting their attack surface. This is a Preact-specific concern because it's a Preact-provided feature.
    *   **Example:** A React component used through `preact/compat` has a known XSS vulnerability that is now exploitable in the Preact application.
    *   **Impact:** Varies depending on the specific React library vulnerability; could range from XSS to more severe issues.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Keep `preact/compat` and *all* React-compatible libraries meticulously up-to-date.** This is the most important mitigation.
        *   **Thoroughly vet any React libraries used with `preact/compat`.** Check their security advisories *before* using them.
        *   **Minimize the use of `preact/compat` if possible.** If a Preact-native alternative exists, use it instead.
        *   **Regularly scan for vulnerabilities in *all* dependencies,** including those introduced by `preact/compat`.

