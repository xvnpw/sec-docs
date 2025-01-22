# Attack Surface Analysis for remix-run/react-router

## Attack Surface: [Server-Side Injection in Loaders/Actions](./attack_surfaces/server-side_injection_in_loadersactions.md)

*   **Description:** Vulnerabilities arising from using unsanitized route parameters or user input within server-side data fetching logic (loaders/actions).
*   **How React Router Contributes:** `react-router` provides loaders and actions that can directly access route parameters, making it easy to use these parameters in backend queries, but also creating a potential injection point if not handled carefully.
*   **Example:** A loader using `params.userId` directly in a database query: `SELECT * FROM users WHERE id = ${params.userId}`. If `userId` is not validated, an attacker could inject SQL code through the URL.
*   **Impact:** Server-side injection attacks (SQL injection, NoSQL injection, command injection), leading to data breaches, data manipulation, or server compromise.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Input Sanitization and Validation:**  Thoroughly sanitize and validate all route parameters and user inputs before using them in backend queries or commands within loaders and actions.
    *   **Parameterized Queries/Prepared Statements:** Use parameterized queries or prepared statements for database interactions within loaders and actions to prevent SQL injection.
    *   **Principle of Least Privilege:** Ensure backend services accessed by loaders/actions operate with the minimum necessary privileges to limit the impact of potential injection vulnerabilities.

## Attack Surface: [Client-Side Data Exposure via Route State/Location](./attack_surfaces/client-side_data_exposure_via_route_statelocation.md)

*   **Description:**  Accidental exposure of sensitive data by including it in the URL (query parameters) or route state during navigation.
*   **How React Router Contributes:** `react-router`'s navigation mechanisms, including `useNavigate` and `useLocation`, allow passing data through route state and query parameters, which can be easily visible and stored in browser history and server logs.
*   **Example:** Passing a user's session token or password reset token as a query parameter in a redirect URL using `useNavigate({ search: '?token=sensitive_token' })`.
*   **Impact:** Information disclosure, exposure of sensitive user data, potential session hijacking or account compromise.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Avoid Storing Sensitive Data in URL:** Do not include sensitive information in query parameters or route state when using `useNavigate` or other navigation methods.
    *   **Secure Storage Mechanisms:** Utilize secure cookies (with `HttpOnly` and `Secure` flags), local storage (with caution and encryption if necessary), or in-memory state management for sensitive data instead of URL-based storage.
    *   **Encryption:** If sensitive data *must* be passed through the URL (which is generally discouraged), encrypt it before including it and decrypt it securely on the client-side after accessing it via `useLocation`.

## Attack Surface: [Cross-Site Request Forgery (CSRF) in Actions](./attack_surfaces/cross-site_request_forgery__csrf__in_actions.md)

*   **Description:** Actions performing state-changing operations on the server are vulnerable to CSRF if not protected.
*   **How React Router Contributes:** `react-router` actions are designed for server-side data mutations triggered by client-side interactions. If these actions are not CSRF-protected, they become vulnerable to attacks initiated from other origins.
*   **Example:** A form submission action that updates user profile information without CSRF protection. An attacker could embed a malicious form on another website that, when submitted by a logged-in user, unknowingly triggers the `react-router` action to change their profile on the vulnerable application.
*   **Impact:** Unauthorized state changes on the server, data manipulation, potential account takeover.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **CSRF Tokens:** Implement CSRF protection for all `react-router` actions that modify server-side state. Generate a unique token on the server, include it in forms or requests handled by actions, and validate it on the server-side for each state-changing action.
    *   **SameSite Cookie Attribute:** Utilize the `SameSite` cookie attribute (set to `Strict` or `Lax`) for session cookies to mitigate CSRF attacks originating from cross-site requests, especially in conjunction with CSRF tokens.

## Attack Surface: [Client-Side Injection (XSS) via Route Parameters/Query Strings](./attack_surfaces/client-side_injection__xss__via_route_parametersquery_strings.md)

*   **Description:** Rendering unsanitized route parameters or query strings directly into the DOM, leading to XSS vulnerabilities.
*   **How React Router Contributes:** `react-router` provides hooks like `useParams` and `useSearchParams` to access route parameters and query strings. Directly rendering these values in React components without proper escaping can introduce XSS vulnerabilities.
*   **Example:**  `<h1>Welcome, {useParams().username}</h1>` where `username` is taken directly from the URL and rendered without escaping. An attacker could inject malicious JavaScript code into the `username` parameter in the URL.
*   **Impact:** Cross-site scripting (XSS) attacks, leading to session hijacking, cookie theft, website defacement, and malicious actions on behalf of the user.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Input Sanitization and Escaping:** Always sanitize and escape user inputs, including route parameters obtained via `useParams` and query strings obtained via `useSearchParams`, before rendering them in the DOM.
    *   **React's JSX Escaping:**  Rely on React's JSX automatic escaping for most cases. Be particularly cautious when using `dangerouslySetInnerHTML` and ensure proper sanitization if absolutely necessary.
    *   **Content Security Policy (CSP):** Implement a strong Content Security Policy to further mitigate the impact of XSS attacks by restricting the sources from which the browser can load resources and limiting inline script execution.

## Attack Surface: [Open Redirect Vulnerabilities via `useNavigate`](./attack_surfaces/open_redirect_vulnerabilities_via__usenavigate_.md)

*   **Description:**  Redirects based on user-controlled URL parameters without proper validation, leading to redirection to malicious external sites.
*   **How React Router Contributes:** The `useNavigate` hook in `react-router` can be misused if used to redirect based on user-provided URL parameters without validation, creating an open redirect vulnerability.
*   **Example:**  `const navigate = useNavigate(); navigate(useSearchParams().get('redirectTo'));` where `redirectTo` is taken directly from the URL query string and used in `navigate` without any validation. An attacker could craft a URL with a malicious `redirectTo` parameter to redirect users to a phishing site.
*   **Impact:** Phishing attacks, malware distribution, user redirection to attacker-controlled websites, potentially leading to credential theft or system compromise.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Whitelist Allowed Redirect Destinations:** Maintain a strict whitelist of allowed redirect URLs and validate the target URL against this whitelist before using it in `navigate`.
    *   **Avoid User-Controlled Redirects:**  Minimize or eliminate redirects based on user-provided URL parameters. If possible, control the redirect destination internally within the application logic.
    *   **Indirect Redirects:** If redirects are necessary based on user input, use an indirect approach where the application maps user input to a predefined set of safe redirect destinations instead of directly using the user-provided URL.

