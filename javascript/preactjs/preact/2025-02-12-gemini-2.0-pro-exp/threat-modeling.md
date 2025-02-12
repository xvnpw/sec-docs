# Threat Model Analysis for preactjs/preact

## Threat: [XSS via Third-Party Component](./threats/xss_via_third-party_component.md)

*   **Threat:**  XSS via Third-Party Component

    *   **Description:** An attacker exploits a vulnerability in a third-party Preact component (e.g., a rich text editor, charting library) to inject malicious JavaScript code. The attacker might provide crafted input to the vulnerable component, which then renders it without proper sanitization, leading to XSS.  While not a *core* Preact vulnerability, the use of Preact components creates this attack surface.
    *   **Impact:**  Cross-Site Scripting (XSS), allowing the attacker to steal user cookies, redirect users to malicious websites, deface the application, or perform other actions in the context of the user's browser.
    *   **Affected Component:**  Any third-party Preact component that renders user-provided data without proper sanitization.
    *   **Risk Severity:** Critical (if the vulnerable component is widely used and handles sensitive data) to High (if the component is less critical).
    *   **Mitigation Strategies:**
        *   Thoroughly vet all third-party components before using them. Review the source code (if available), check for known vulnerabilities, and assess the maintainer's reputation.
        *   Use a dependency vulnerability scanner (e.g., `npm audit`, `yarn audit`, Snyk) to automatically identify known vulnerabilities.
        *   Keep all dependencies up-to-date.
        *   Consider sandboxing third-party components using iframes (with appropriate `sandbox` attribute values) to limit their access to the main application's context (this has UX implications).

## Threat: [XSS via `dangerouslySetInnerHTML` Misuse](./threats/xss_via__dangerouslysetinnerhtml__misuse.md)

*   **Threat:**  XSS via `dangerouslySetInnerHTML` Misuse

    *   **Description:** An attacker provides malicious HTML input that is directly rendered using `dangerouslySetInnerHTML` without proper sanitization. The attacker might find a way to inject this input through a form, URL parameter, or other data source that is ultimately used in the `dangerouslySetInnerHTML` call. This is a direct misuse of a Preact-provided feature.
    *   **Impact:**  Cross-Site Scripting (XSS).
    *   **Affected Component:**  `dangerouslySetInnerHTML` (a method available on Preact components).
    *   **Risk Severity:** Critical.
    *   **Mitigation Strategies:**
        *   **Avoid `dangerouslySetInnerHTML` whenever possible.** Prefer using Preact's JSX syntax to build the UI.
        *   If `dangerouslySetInnerHTML` is absolutely necessary, **always** sanitize the HTML string using a robust and well-maintained HTML sanitization library like DOMPurify *before* passing it to the function.
        *   Never directly insert user-provided data into `dangerouslySetInnerHTML` without sanitization.

## Threat: [State Manipulation via Stale Closures (High-Risk Cases)](./threats/state_manipulation_via_stale_closures__high-risk_cases_.md)

*   **Threat:**  State Manipulation via Stale Closures (High-Risk Cases)

    *   **Description:**  An attacker exploits race conditions or stale closures within asynchronous state updates to manipulate the application's state *in a way that directly impacts security*. This is most critical when the state controls access, authorization, or displays sensitive information. The attacker leverages the asynchronous nature of `setState` or `useReducer` to cause the application to enter an insecure state.
    *   **Impact:**  Privilege escalation (if state controls access), information disclosure (if the manipulated state reveals sensitive data), or data corruption due to inconsistent state.
    *   **Affected Component:**  `useState`, `useReducer`, any component using asynchronous operations within event handlers or lifecycle methods (e.g., `useEffect`) *where the state directly affects security-relevant logic*.
    *   **Risk Severity:** High (when state directly controls security-critical aspects).
    *   **Mitigation Strategies:**
        *   Use functional updates with `setState` (e.g., `setState(prevState => ...)` ) to ensure updates are based on the most recent state.
        *   Carefully manage asynchronous operations within components, using techniques like abort controllers or flags to prevent outdated updates from being applied.
        *   Implement proper debouncing or throttling for event handlers that trigger frequent state updates, especially those related to security.
        *   Thoroughly test components with asynchronous logic, simulating various user interaction patterns and focusing on security-critical state transitions.

## Threat: [SSR-Specific XSS](./threats/ssr-specific_xss.md)

* **Threat:** SSR-Specific XSS

    * **Description:** An attacker provides malicious input that is used *during* the server-side rendering process to construct the initial state or props of a Preact component. Even though Preact escapes output during rendering, if the input is not sanitized *before* being used to build the initial state/props, it can lead to XSS. The vulnerability exists *before* Preact's rendering process, but is directly tied to how Preact is used for SSR.
    * **Impact:** Cross-Site Scripting (XSS).
    * **Affected Component:** Any Preact component rendered on the server where user input influences the initial state or props.
    * **Risk Severity:** Critical.
    * **Mitigation Strategies:**
        * **Always sanitize user input on the server *before* it is used to generate the initial state or props for server-side rendered components.**
        * Use a robust server-side HTML sanitization library.
        * Be extremely cautious about any user-provided data that influences the server-rendered HTML, even indirectly.

