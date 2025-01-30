# Attack Surface Analysis for facebook/react

## Attack Surface: [1. DOM-Based Cross-Site Scripting (XSS) via `dangerouslySetInnerHTML`](./attack_surfaces/1__dom-based_cross-site_scripting__xss__via__dangerouslysetinnerhtml_.md)

*   **Description:**  Injecting malicious scripts into the Document Object Model (DOM) by using the `dangerouslySetInnerHTML` prop with unsanitized or user-controlled data. This allows attackers to execute arbitrary JavaScript code in the victim's browser within the context of the web application.
*   **React Contribution:** React provides the `dangerouslySetInnerHTML` prop as a mechanism to directly set the HTML content of an element. This feature bypasses React's built-in sanitization and escaping mechanisms, creating a direct pathway for DOM-based XSS if developers use it improperly with untrusted data. React's design emphasizes protection against XSS by default, but `dangerouslySetInnerHTML` is an explicit escape hatch that shifts the responsibility of sanitization to the developer.
*   **Example:**
    *   A React component is designed to display user-generated content, such as blog posts or comments.
    *   The component uses `dangerouslySetInnerHTML` to render the content retrieved from a backend API, assuming the data is already safe.
    *   An attacker crafts a malicious blog post or comment containing JavaScript code embedded within HTML tags (e.g., `<img src=x onerror=alert('XSS')>`).
    *   This malicious content is stored in the backend database and served to users.
    *   When the React component renders this content using `dangerouslySetInnerHTML`, the browser executes the embedded JavaScript code, leading to XSS. This could result in session hijacking, cookie theft, redirection to malicious sites, or defacement of the application for other users viewing the content.
*   **Impact:** Account takeover, session hijacking, sensitive data theft, malware distribution, website defacement, phishing attacks targeting users of the application.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Strongly avoid using `dangerouslySetInnerHTML` whenever possible.**  Favor React's standard JSX rendering and text interpolation. React automatically escapes values rendered using JSX, effectively preventing many common XSS vulnerabilities.
    *   **If `dangerouslySetInnerHTML` is absolutely necessary, rigorously sanitize all input data before using it.**  Perform sanitization on the server-side or client-side *before* passing data to `dangerouslySetInnerHTML`. Utilize a well-vetted and actively maintained HTML sanitization library (e.g., DOMPurify, sanitize-html) to remove or neutralize potentially harmful HTML and JavaScript code. Configure the sanitizer to be strict and appropriate for your application's context.
    *   **Implement Content Security Policy (CSP).**  Deploy a robust Content Security Policy to act as a secondary defense layer. CSP can significantly reduce the impact of XSS attacks, even if they occur, by controlling the resources the browser is allowed to load and execute. Configure CSP to restrict inline scripts (`'unsafe-inline'`) and script sources to trusted origins.
    *   **Regularly audit code that uses `dangerouslySetInnerHTML`.** Conduct thorough code reviews and security testing specifically focusing on areas where `dangerouslySetInnerHTML` is used to ensure proper sanitization is in place and effective.

