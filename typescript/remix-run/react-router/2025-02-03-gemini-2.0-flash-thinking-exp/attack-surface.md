# Attack Surface Analysis for remix-run/react-router

## Attack Surface: [Data Loading and Route Loaders/Actions Vulnerabilities](./attack_surfaces/data_loading_and_route_loadersactions_vulnerabilities.md)

*   **Description:** Security issues arising from insecure data fetching or mutation logic within React Router's `loaders` and `actions`, particularly when handling route parameters or user input. This can lead to backend vulnerabilities and data breaches.
*   **React Router Contribution:** `loaders` and `actions` are the recommended way to handle data fetching and mutations in React Router applications. Vulnerabilities in how these functions are implemented directly contribute to this attack surface by providing a structured way to interact with backend systems based on routes.
*   **Example:** An `action` function uses `params.productId` to update product details in a database. If the `action` directly constructs a SQL query using `params.productId` without sanitization, it could be critically vulnerable to SQL injection. Exploitation could lead to complete database compromise. Similarly, insufficient input validation in the API endpoint called by the `loader` can still lead to backend vulnerabilities.
*   **Impact:** Data breaches, data manipulation, server-side vulnerabilities exploitation (like SQL injection, Remote Code Execution if backend is compromised), unauthorized actions performed on behalf of users (CSRF leading to critical state changes).
*   **Risk Severity:** **Critical** (due to potential for severe backend compromise and data breaches).
*   **Mitigation Strategies:**
    *   **Parameterized Queries/ORMs:**  Mandatory use of parameterized queries or Object-Relational Mappers (ORMs) in backend APIs to prevent injection vulnerabilities when handling data from `loaders` and `actions`.
    *   **Strict Input Sanitization and Validation:** Implement rigorous input sanitization and validation within `loaders` and `actions` *and* on the backend API endpoints. Treat all data from route parameters and user input as untrusted.
    *   **Secure Error Handling:** Implement secure error handling in `loaders` and `actions`. Prevent leakage of sensitive information in error responses. Log errors securely for debugging.
    *   **CSRF Protection for Actions:**  Mandatory implementation of CSRF protection (e.g., using robust CSRF tokens, SameSite cookies with proper settings) for all `actions` that perform state-changing operations.
    *   **Regular Security Audits:** Conduct regular security audits and penetration testing specifically focusing on data handling within `loaders` and `actions` and the backend APIs they interact with.

## Attack Surface: [Client-Side Rendering and XSS Vulnerabilities](./attack_surfaces/client-side_rendering_and_xss_vulnerabilities.md)

*   **Description:** Cross-Site Scripting (XSS) vulnerabilities arising from rendering unsanitized data, especially route parameters or data fetched by loaders, within React components. This allows attackers to inject malicious scripts that execute in users' browsers.
*   **React Router Contribution:** React Router renders components based on routes and provides route parameters and loader data to these components. If developers directly render this data without proper escaping or sanitization, React Router becomes a direct conduit for XSS attacks by delivering attacker-controlled data into the rendering process.
*   **Example:** A route `/profile/:username` displays user profiles. If the component directly renders `params.username` in the UI (e.g., "Welcome, {params.username}") without proper escaping, an attacker could craft a URL like `/profile/<img src=x onerror=alert('XSS')>` to inject malicious JavaScript. This script will execute when the profile page is rendered in another user's browser. Similarly, if data fetched by a loader contains unsanitized user-generated content and is rendered, it can lead to Stored XSS.
*   **Impact:** Account compromise, session hijacking, malware distribution, website defacement, sensitive information theft, full control over the user's browser within the application's context.
*   **Risk Severity:** **High** (XSS is a highly prevalent and impactful vulnerability, allowing for a wide range of malicious actions).
*   **Mitigation Strategies:**
    *   **Default JSX Escaping:**  Rely on React's default JSX escaping for rendering dynamic content within curly braces `{}`. This is crucial for preventing basic XSS.
    *   **Sanitization for HTML Rendering:** If rendering HTML content is absolutely necessary (e.g., displaying formatted user posts), use a robust and actively maintained sanitization library like DOMPurify to sanitize the HTML *before* rendering it using `dangerouslySetInnerHTML`. Exercise extreme caution with `dangerouslySetInnerHTML` and only use it after rigorous sanitization.
    *   **Content Security Policy (CSP):** Implement a strict Content Security Policy (CSP) header. Configure CSP to restrict the sources from which the browser can load resources (scripts, styles, images, etc.). This acts as a strong defense-in-depth mechanism to mitigate the impact of XSS even if other defenses fail. Regularly review and refine CSP.
    *   **Regular Security Scanning:** Implement automated security scanning tools that can detect potential XSS vulnerabilities in the application code and during runtime.

