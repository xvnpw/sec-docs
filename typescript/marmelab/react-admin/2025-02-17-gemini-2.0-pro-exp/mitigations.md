# Mitigation Strategies Analysis for marmelab/react-admin

## Mitigation Strategy: [Secure `authProvider` Configuration and Usage](./mitigation_strategies/secure__authprovider__configuration_and_usage.md)

1.  **`login` Implementation:** Ensure the `login` function correctly handles the authentication process:
    *   Sends credentials securely (HTTPS) to the backend API.
    *   Upon successful authentication, stores the received token *securely*.  **Crucially, this means using HTTP-Only, Secure cookies, *not* `localStorage` or `sessionStorage`.**
    *   Handles errors gracefully (e.g., incorrect credentials).
2.  **`checkAuth` Implementation:** This function is called by `react-admin` to determine if the user is authenticated.  It should:
    *   Check for the presence of the authentication token (in the cookie).
    *   Perform a *basic* client-side validity check (e.g., check if the token has expired *based on the client's clock*).  This is *not* a security check, but a UX improvement to avoid unnecessary API calls.  The backend is the ultimate authority.
    *   Return a Promise that resolves if the user is considered authenticated (client-side) and rejects otherwise.
3.  **`checkError` Implementation:** This function handles API errors.  It should:
    *   Check for 401 (Unauthorized) and 403 (Forbidden) errors.
    *   If a 401 or 403 error is received, it should:
        *   Clear the authentication token (from the cookie).
        *   Redirect the user to the login page.
        *   Optionally, handle token refresh logic (if using refresh tokens).
4.  **`logout` Implementation:** This function handles user logout.  It should:
    *   Clear the authentication token from the cookie.
    *   Ideally, send a request to the backend to invalidate the token (e.g., revoke a refresh token).  This is a backend task, but the `logout` function should initiate it.
5.  **`getPermissions` Implementation:** This function fetches the user's permissions.  It can:
    *   Decode the JWT (if permissions are included in the token).
    *   Make a separate API call to the backend to fetch permissions.
    *   Return a Promise that resolves with the user's permissions (e.g., an array of roles or a permissions object).
6.  **Avoid Client-Side Authorization Enforcement:**  The `authProvider` should *not* be the sole source of authorization.  It's for managing the authentication *flow* and providing permissions for UI-level decisions.  The backend *must* enforce authorization.

    **Threats Mitigated:**
    *   **Session Hijacking (High Severity):**  HTTP-Only, Secure cookies prevent XSS-based token theft.
    *   **Unauthorized Access (High Severity):**  Correct `checkAuth` and `checkError` handling ensures that unauthenticated or unauthorized users are redirected to the login page.
    *   **Improper Logout (Medium Severity):**  Ensures that the user's session is properly terminated on the client-side.

    **Impact:**
    *   **Session Hijacking:** Risk significantly reduced (when combined with backend token validation).
    *   **Unauthorized Access:** Risk significantly reduced (when combined with backend authorization).
    *   **Improper Logout:** Risk reduced.

    **Currently Implemented:**
    *   Example: "Implemented using JWTs stored in HTTP-Only, Secure cookies.  The `authProvider` handles login, logout (clearing the cookie), and `checkAuth` (basic token presence check). `getPermissions` decodes the JWT to get the user's role."

    **Missing Implementation:**
    *   Example: "`checkError` does not currently handle 403 errors correctly. It only redirects on 401.  The `logout` function only clears the cookie; it doesn't invalidate the token on the backend."

## Mitigation Strategy: [Input Sanitization and Output Encoding in Custom Components (React-Admin Specific Aspects)](./mitigation_strategies/input_sanitization_and_output_encoding_in_custom_components__react-admin_specific_aspects_.md)

1.  **Identify Custom Components:** List all custom Inputs, Fields, Views, and other components you've created within your `react-admin` application.
2.  **Input Sanitization:** Within these custom components, if you are handling *any* user input that will be displayed or used in any way, sanitize it using a library like DOMPurify. This is *especially* important if you are:
    *   Creating custom input components that accept rich text or HTML.
    *   Building custom display components that render data from potentially untrusted sources.
3.  **`dangerouslySetInnerHTML`:** Avoid using `dangerouslySetInnerHTML` if at all possible. If you *must* use it, ensure the input is *thoroughly* sanitized *before* being passed to this prop.  This is a high-risk area for XSS.
4.  **React's Built-in Protection:** Leverage React's built-in XSS protection.  JSX generally handles output encoding correctly, *unless* you are using `dangerouslySetInnerHTML` or directly manipulating the DOM.
5.  **Review and Audit:** Regularly review your custom components to ensure sanitization is being applied correctly and consistently.

    **Threats Mitigated:**
    *   **Cross-Site Scripting (XSS) (High Severity):** Prevents attackers from injecting malicious scripts through custom components.

    **Impact:**
    *   **XSS:** Risk significantly reduced (if sanitization is implemented correctly).

    **Currently Implemented:**
    *   Example: "Implemented in the `CustomRichTextInput` component using DOMPurify. All user-provided HTML is sanitized before being stored or displayed. Standard React rendering is used in all other custom components."

    **Missing Implementation:**
    *   Example: "The `CustomCommentField` component directly renders user-provided comments without sanitization. This is a potential XSS vulnerability."

## Mitigation Strategy: [Client-Side Route Guards (Using `authProvider` Integration)](./mitigation_strategies/client-side_route_guards__using__authprovider__integration_.md)

1.  **Identify Protected Routes:** Determine which routes within your `react-admin` application should be restricted based on authentication or permissions.
2.  **Leverage `authProvider`:** Use the `authProvider`'s `checkAuth` and `getPermissions` functions within your route guards.
3.  **Create Route Guards:** Use React Router's capabilities (or a similar routing library) to create route guards. These are functions that execute *before* a route is rendered.
4.  **Check Authentication:** In the guard, call `authProvider.checkAuth()`. If it rejects (meaning the user is not authenticated), redirect to the login page.
5.  **Check Permissions (Optional but Recommended):** If the route requires specific permissions, call `authProvider.getPermissions()` to get the user's permissions. Compare these permissions to the required permissions for the route. If the user doesn't have the necessary permissions, redirect to an unauthorized access page or the login page.
6.  **Integration with React Router:** Integrate these guards with your routing configuration (e.g., using `PrivateRoute` components or similar).
7.  **Backend is Paramount:** Remember, these client-side guards are *supplementary*. The backend *must* still enforce authorization on every API request.

    **Threats Mitigated:**
    *   **UI Exposure (Low Severity):** Prevents unauthenticated or unauthorized users from seeing UI elements they shouldn't. This is primarily a UX improvement.
    *   **Application Structure Exposure (Low Severity):** Makes it slightly harder for attackers to map out the application's routes.

    **Impact:**
    *   **UI Exposure:** Risk reduced.
    *   **Application Structure Exposure:** Risk slightly reduced.

    **Currently Implemented:**
    *   Example: "We use a custom `PrivateRoute` component that wraps React Router's `Route`.  It calls `authProvider.checkAuth()` and redirects to the login page if the user is not authenticated."

    **Missing Implementation:**
    *   Example: "We don't currently check permissions within our route guards. We only check for authentication. We need to integrate `authProvider.getPermissions()` to restrict access based on user roles."

## Mitigation Strategy: [Careful use of Data Providers](./mitigation_strategies/careful_use_of_data_providers.md)

1.  **Audit Existing Data Providers:** Review all data providers in use, whether they are built-in or custom.
2.  **Minimize Data Fetched:** Ensure that data providers are only fetching the *minimum* necessary data. Avoid fetching entire resources if only a few fields are needed. Use query parameters to limit the fields returned by the API (this is primarily a backend task, but the data provider should be configured to request only what's needed).
3.  **Custom Data Providers:** If the built-in data providers don't offer sufficient control over data fetching, create *custom* data providers. This allows you to:
    *   Intercept and modify requests before they are sent to the backend.
    *   Add custom headers or authentication logic.
    *   Implement more granular control over data fetching.
4.  **Understand Data Provider Logic:** Be thoroughly familiar with how your data providers handle filtering, sorting, and pagination. Ensure they are not vulnerable to injection attacks or other manipulations.
5.  **Backend Validation is Key:** Remember that the data provider is just a client-side interface. The backend *must* validate all requests and enforce authorization, regardless of how the data provider structures the request.

    **Threats Mitigated:**
    *   **Over-Fetching (Medium Severity):** Reduces the risk of exposing more data than intended if the backend authorization is flawed. While the backend is the primary defense, a well-configured data provider adds a layer of defense in depth.
    *   **Data Provider Misconfiguration (Medium Severity):** Reduces the risk of errors in the data provider exposing sensitive data.

    **Impact:**
    *   **Over-Fetching:** Risk reduced (in conjunction with strong backend authorization).
    *   **Data Provider Misconfiguration:** Risk reduced.

    **Currently Implemented:**
    *   Example: "We are using the `ra-data-simple-rest` data provider. We have reviewed its configuration and ensured it's only fetching necessary fields for most resources. We have a custom data provider for the `/reports` resource to handle complex filtering logic."

    **Missing Implementation:**
    *   Example: "The data provider for the `/users` resource is fetching all user data, including sensitive fields, even when only the username and ID are needed. We need to modify the data provider to request only the necessary fields."

