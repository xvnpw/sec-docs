# Threat Model Analysis for facebook/react

## Threat: [XSS via `dangerouslySetInnerHTML`](./threats/xss_via__dangerouslysetinnerhtml_.md)

*   **Description:** An attacker can inject malicious JavaScript code into data that is rendered using React's `dangerouslySetInnerHTML` prop. If this data originates from user input or an untrusted source and is not properly sanitized, the injected script will execute in the user's browser. This is a direct misuse of a React API that bypasses React's default XSS protection.
*   **Impact:** Cross-Site Scripting (XSS), leading to account takeover, data theft, malware distribution, website defacement, and other malicious actions.
*   **Affected React Component:** React components that utilize the `dangerouslySetInnerHTML` prop to render dynamic HTML content. Specifically, the component instance where this prop is used.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Absolutely avoid using `dangerouslySetInnerHTML` if possible.**  Rethink the component structure and data handling to use React's standard JSX rendering instead.
    *   If `dangerouslySetInnerHTML` is unavoidable, ensure that the HTML string is **thoroughly sanitized on the server-side** using a robust and actively maintained HTML sanitization library (like DOMPurify) **before** it is passed to the React component.
    *   Never use `dangerouslySetInnerHTML` with unsanitized user-provided input or data from untrusted sources. Treat all external data as potentially malicious.

## Threat: [XSS via Server-Side Rendering (SSR) Hydration Mismatches](./threats/xss_via_server-side_rendering__ssr__hydration_mismatches.md)

*   **Description:** In React applications using Server-Side Rendering (SSR), if the server-rendered HTML contains malicious code (due to compromised server-side data, templates, or insufficient sanitization) and there are inconsistencies between the server-rendered HTML and the client-side React component structure, React's hydration process might execute the malicious code during client-side rendering. This occurs because React attempts to reconcile the server-rendered DOM with the client-side React tree, and discrepancies can lead to unexpected code execution if the server-rendered HTML is attacker-controlled.
*   **Impact:** Cross-Site Scripting (XSS), similar to `dangerouslySetInnerHTML` XSS, leading to account takeover, data theft, malware distribution, website defacement, and other malicious actions. In SSR scenarios, these vulnerabilities can be more complex to detect and debug.
*   **Affected React Component:** React components in SSR applications, specifically during the hydration phase. The vulnerability can originate from server-side rendering logic and propagate to client-side components during hydration.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   Maintain strict consistency between server-side and client-side rendering logic to prevent hydration mismatches. Ensure the same version of React and related libraries are used on both server and client.
    *   **Sanitize all data on the server-side** before rendering HTML for SSR. Use context-aware sanitization techniques that understand HTML structure and prevent injection within attributes, tags, and script blocks.
    *   Implement a robust Content Security Policy (CSP) to mitigate the impact of potential XSS vulnerabilities, including those that might arise from hydration issues. CSP can restrict the sources from which scripts can be loaded and other browser behaviors.
    *   Thoroughly test SSR implementation for hydration vulnerabilities, especially when dealing with user-generated content, external data sources, or complex component structures. Use browser developer tools to inspect the DOM during hydration and look for unexpected changes or script execution.

