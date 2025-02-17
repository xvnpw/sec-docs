# Attack Surface Analysis for remix-run/react-router

## Attack Surface: [I. Route Manipulation and Navigation Attacks](./attack_surfaces/i__route_manipulation_and_navigation_attacks.md)

*   **A. Unexpected Navigation / Route Traversal (Client-Side)**

    *   **Description:** Attackers manipulate URL parameters, path segments, or the browser's history to access routes they shouldn't, bypassing client-side authorization checks *provided by React Router*.
    *   **How React-Router Contributes:**  React Router is the mechanism that handles client-side routing and navigation, making it the direct target of this manipulation.
    *   **Example:**
        *   An application uses React Router's route definitions to *attempt* to restrict access to `/admin/users`.  An attacker manually enters the URL, and because the authorization logic is *only* within React Router's configuration (and not duplicated on the server), the attacker gains access.  This is *directly* exploiting a weakness in how React Router is being used.
        *   A route `/profile/:userId` relies on a React Router guard to check if `currentUser.id === userId`.  An attacker modifies `:userId` and, if the guard has a flaw or is bypassed, gains access to another user's profile *because the core routing mechanism allowed the navigation*.
    *   **Impact:** Unauthorized access to sensitive data or functionality; potential for privilege escalation.
    *   **Risk Severity:** High to Critical (depending on the sensitivity of the exposed data/functionality).
    *   **Mitigation Strategies:**
        1.  **Server-Side Authorization:** *Always* perform authorization checks on the server-side for *every* data fetch and mutation.  This is the primary defense and mitigates the *direct* reliance on React Router for security.
        2.  **Robust Client-Side Route Guards:** Implement route guards that check user permissions *before* rendering, but *do not rely solely on them*.  These guards should ideally call a server-side endpoint to verify authorization.  This makes the client-side checks a *defense in depth* measure, not the primary security control.
        3.  **Input Validation:** Strictly validate and sanitize all data extracted from the URL (path parameters and query parameters) using a schema validation library.  This prevents attackers from injecting malicious values that might bypass route matching logic.

*   **B. Open Redirects (via Navigation)**

    *   **Description:** The application uses user-provided input within React Router's navigation functions (e.g., `navigate`) to construct redirect URLs, allowing attackers to redirect users to malicious sites.
    *   **How React-Router Contributes:** React Router's `navigate` function (or the `<Navigate>` component) is the *direct* mechanism being abused to perform the redirect.
    *   **Example:**
        *   A component uses `navigate(userProvidedUrl)` where `userProvidedUrl` is taken directly from a query parameter without validation. An attacker provides a malicious URL, and React Router performs the redirect.
        *   A `<Link to={userProvidedUrl}>` is used, and `userProvidedUrl` comes from untrusted input.
    *   **Impact:** Phishing attacks; malware distribution; damage to reputation.
    *   **Risk Severity:** High.
    *   **Mitigation Strategies:**
        1.  **Whitelist Allowed Redirect URLs:** Maintain a strict whitelist of allowed redirect destinations and validate any user-provided URLs against it *before* passing them to React Router's navigation functions.
        2.  **Use Relative Paths:** Prefer relative paths for redirects (e.g., `/dashboard`) instead of absolute URLs within `navigate` or `<Link>`.
        3.  **Avoid User Input in Redirects:** If possible, avoid using user input to construct redirect URLs *passed to React Router*. Use predefined routes or server-side logic.

## Attack Surface: [II. Data Fetching and Loading Attacks (Remix Specific)](./attack_surfaces/ii__data_fetching_and_loading_attacks__remix_specific_.md)

*   **A. Data Exposure via Loaders/Actions (Remix)**

    *   **Description:** Insecure loaders/actions in Remix, which are *directly tied to routes managed by `@remix-run/router`*, expose sensitive data or allow unauthorized modifications.
    *   **How React-Router Contributes:** Remix uses `@remix-run/router` internally, and loaders/actions are *fundamentally linked* to the routing mechanism.  The vulnerability exists because of how data fetching is integrated with routing.
    *   **Example:**
        *   A loader for a route `/api/users/:id` fetches user data without checking if the requesting user has permission to view that specific user's data.  The route exists *because of* React Router (via Remix), and the loader is executed *because of* the route match.
        *   An action associated with a route `/api/posts/:id/delete` deletes a post without verifying user authorization. The action is triggered *directly* by a form submission on that route.
    *   **Impact:** Unauthorized data access; data breaches; data modification/deletion.
    *   **Risk Severity:** Critical.
    *   **Mitigation Strategies:**
        1.  **Server-Side Authorization:** *Always* perform authorization checks *within* loaders and actions on the server-side. This is the primary defense, and it addresses the inherent risk of tying data fetching to routes.
        2.  **Input Validation:** Strictly validate and sanitize all input to loaders and actions. This prevents attackers from manipulating the data used by the loader/action, which is directly associated with the route.
        3. **Principle of Least Privilege:** Ensure database queries and API calls within loaders/actions only retrieve the *minimum* necessary data.

## Attack Surface: [III. Configuration Issues](./attack_surfaces/iii__configuration_issues.md)

* **A. Misconfigured `basename`**
    * **Description:** Incorrect `basename` configuration in `<BrowserRouter>` or `<HashRouter>` can lead to routing hijacking.
    * **How React-Router Contributes:** The `basename` prop is a core configuration option *of React Router itself*.
    * **Example:**
        * An attacker manages to inject a malicious value into the `basename` (e.g., through a server-side misconfiguration), causing React Router to load resources from an attacker-controlled domain. This is a *direct* attack on React Router's configuration.
    * **Impact:** Potential for routing hijacking and XSS attacks.
    * **Risk Severity:** High.
    * **Mitigation Strategies:**
        1. **Double-Check `basename`:** Ensure the `basename` is correctly set to your application's base URL.
        2. **Avoid Dynamic `basename` (If Possible):** Hardcode the `basename` if possible.
        3. **Validate Dynamic `basename`:** If the `basename` *must* be dynamic, validate it rigorously against a whitelist *before* providing it to React Router.

