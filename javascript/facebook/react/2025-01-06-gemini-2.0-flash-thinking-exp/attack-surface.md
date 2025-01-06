# Attack Surface Analysis for facebook/react

## Attack Surface: [Cross-Site Scripting (XSS) via Unsafe Rendering](./attack_surfaces/cross-site_scripting__xss__via_unsafe_rendering.md)

*   **Description:** Attackers inject malicious scripts into web pages, which are then executed by other users' browsers.
    *   **How React Contributes:**  Directly using `dangerouslySetInnerHTML` to render user-supplied or untrusted data without sanitization bypasses React's built-in JSX escaping and allows the execution of arbitrary HTML, including malicious scripts.
    *   **Example:** A component renders user comments using `dangerouslySetInnerHTML` on the `comment.text` property, and a malicious user submits a comment containing `<img src="x" onerror="alert('XSS')">`.
    *   **Impact:** Account takeover, redirection to malicious sites, data theft, session hijacking.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Developers:**  **Strongly avoid using `dangerouslySetInnerHTML` whenever possible.** Rely on React's default JSX escaping for rendering dynamic content. If `dangerouslySetInnerHTML` is absolutely necessary, sanitize the input using a trusted and up-to-date library like DOMPurify *before* passing it to the prop. Implement Content Security Policy (CSP) headers to further mitigate XSS risks.

## Attack Surface: [Server-Side Rendering (SSR) Related Issues (if applicable)](./attack_surfaces/server-side_rendering__ssr__related_issues__if_applicable_.md)

*   **Description:** Security vulnerabilities introduced when using server-side rendering with React.
    *   **How React Contributes:** When using SSR, React components are rendered to HTML on the server. If user-provided data is not properly sanitized *before* being rendered on the server using React's rendering process, it can lead to server-side XSS vulnerabilities. This occurs because the unsanitized data is directly included in the HTML sent to the client.
    *   **Example:** A server-rendered React component displays a user's name fetched from a database. If the database contains a malicious name like `<script>stealCookies()</script>`, and this name is rendered without sanitization on the server, the script will execute in the user's browser.
    *   **Impact:** Server compromise (in severe cases), sensitive data exposure, manipulation of the initial HTML sent to the client, potentially leading to client-side XSS.
    *   **Risk Severity:** High to Critical
    *   **Mitigation Strategies:**
        *   **Developers:**  **Sanitize all user-provided data on the server-side before passing it to React components for rendering.** Utilize server-side sanitization libraries appropriate for the rendering context. Ensure consistency between server-rendered and client-rendered output to prevent rehydration issues that could be exploited. Keep server-side dependencies up-to-date.

