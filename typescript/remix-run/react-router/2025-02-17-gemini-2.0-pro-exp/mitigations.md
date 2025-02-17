# Mitigation Strategies Analysis for remix-run/react-router

## Mitigation Strategy: [Strict Route Definition and Parameter Validation](./mitigation_strategies/strict_route_definition_and_parameter_validation.md)

*   **1. Mitigation Strategy: Strict Route Definition and Parameter Validation**

    *   **Description:**
        1.  **Define Precise Routes:**  In your route configuration (using `createBrowserRouter` or `<Routes>`), define routes with specific path patterns.  For example, instead of `/products/*`, use `/products/:productId`.  Avoid overly broad wildcards unless absolutely necessary, and validate the remaining path segments within your component.
        2.  **Implement Parameter Validation:** Within your component or `loader` function, use a validation library (Zod, Yup, etc.) in conjunction with `react-router`'s `useParams` hook.
            *   Import the validation library.
            *   Define a schema that specifies the expected type, format, and constraints for each parameter (e.g., `z.number().int().positive()` for a positive integer ID).
            *   Use the `useParams` hook to access the parameters.
            *   Use the schema's `parse` or `safeParse` method to validate the parameter.  `parse` throws an error on failure; `safeParse` returns a result object.
            *   Handle validation errors appropriately (e.g., return a 404 error, display an error message, redirect using `navigate`).
        3.  **Type Safety (TypeScript):** If using TypeScript, define types for your route parameters in your route configuration and component/loader function signatures. This provides compile-time checks, integrated with `react-router`.
        4.  **Avoid Sensitive Data in URLs:** Never place sensitive data directly in the URL path or query parameters.

    *   **Threats Mitigated:**
        *   **Parameter Tampering (High Severity):** Attackers modify URL parameters (accessed via `useParams`) to access unauthorized data or trigger unexpected behavior.
        *   **Information Disclosure (Medium to High Severity):** Poorly defined routes or lack of validation can expose internal application structure or data.
        *   **Code Injection (Critical Severity):**  Indirectly mitigated; validation reduces the risk of unvalidated parameters reaching server-side code.
        *   **Broken Access Control (High Severity):** If parameters control access, validation helps enforce rules.

    *   **Impact:**
        *   **Parameter Tampering:** Risk significantly reduced (near elimination if validation is comprehensive).
        *   **Information Disclosure:** Risk significantly reduced.
        *   **Code Injection:** Risk indirectly reduced (server-side sanitization is still essential).
        *   **Broken Access Control:** Risk reduced, but needs to be combined with authentication and authorization.

    *   **Currently Implemented:**
        *   Example: `ProductDetail` component validates `:productId` as a positive integer using Zod in its `loader`, using `useParams`.
        *   Example: TypeScript types are defined for all route parameters in `routes.ts`, used by `createBrowserRouter`.

    *   **Missing Implementation:**
        *   Example: The `UserList` component uses a broad route (`/users/*`) and does not validate the remaining path segments within the component.
        *   Example: The `Search` component does not validate the `:query` parameter obtained from `useParams`.

## Mitigation Strategy: [Navigation and Redirection Security (using `navigate`)](./mitigation_strategies/navigation_and_redirection_security__using__navigate__.md)

*   **2. Mitigation Strategy: Navigation and Redirection Security (using `navigate`)

    *   **Description:**
        1.  **Validate Redirect URLs:**
            *   If you need to redirect based on user input (e.g., after a form submission), *never* directly use the user-provided URL in `react-router`'s `navigate` function or `<Navigate>` component.
            *   Create a whitelist of allowed redirect destinations (e.g., an array of allowed paths).
            *   Before calling `navigate`, check if the user-provided URL is in the whitelist.
            *   If the URL is not in the whitelist, redirect to a safe default location (e.g., the home page) using `navigate`.
        2.  **Prefer Relative Paths:**
            *   Whenever possible, use relative paths for navigation with `navigate` (e.g., `/profile`, `../users`).  This avoids the risk of open redirects altogether.
        3.  **Sanitize `search` and `hash` (when constructing URLs for `navigate`):**
            *   If you construct URLs with the `search` (query parameters) or `hash` (fragment identifier) properties to be used with `navigate`, and these are based on user input, validate and sanitize them.
            *   Use a URL encoding function to ensure that special characters are properly encoded.

    *   **Threats Mitigated:**
        *   **Open Redirects (Medium Severity):** Attackers use `navigate` to redirect users to malicious sites. URL validation prevents this.
        *   **Cross-Site Scripting (XSS) (High Severity):**  Indirectly mitigated; unvalidated `search` or `hash` values used with `navigate` could be exploited. Sanitization prevents this.

    *   **Impact:**
        *   **Open Redirects:** Risk significantly reduced (near elimination with proper validation).
        *   **XSS:** Risk indirectly reduced (but requires careful sanitization).

    *   **Currently Implemented:**
        *   Example: The `LoginForm` component uses a whitelist to validate the `redirect` query parameter before calling `navigate` after successful login.
        *   Example: Most navigation within the application uses relative paths with `navigate`.

    *   **Missing Implementation:**
        *   Example: The `ForgotPassword` component redirects to a URL provided in the password reset email without validation, using `navigate`.
        *   Example: The `ShareButton` component constructs a URL with an unvalidated `title` parameter in the `search` property, passed to `navigate`.

## Mitigation Strategy: [Component-Level Access Control (with `Navigate`)](./mitigation_strategies/component-level_access_control__with__navigate__.md)

*   **3. Mitigation Strategy: Component-Level Access Control (with `Navigate`)

    *   **Description:**
        1.  **Route-Based Access Control:**
            *   Within your components, check if the user is authenticated and authorized to view the component's content.
            *   Use conditional rendering to show or hide content based on the user's role or permissions.
            *   If the user is not authorized, use `react-router`'s `<Navigate>` component or the `navigate` function to redirect them to a login page, an unauthorized page, or display an appropriate error message.
        2.  **Higher-Order Components (HOCs) or Custom Hooks:**
            *   Create reusable HOCs or custom hooks to encapsulate access control logic, incorporating `Navigate` for redirection.
            *   The HOC or hook should check the user's authentication and authorization status and either render the wrapped component or use `<Navigate>` to redirect.

    *   **Threats Mitigated:**
        *   **Broken Access Control (High Severity):** Attackers bypass client-side checks. Component-level checks with `Navigate` provide an additional layer of defense.
        *   **Information Disclosure (Medium Severity):** Sensitive information might be exposed if access control is not enforced at the component level, even if loaders are secure.

    *   **Impact:**
        *   **Broken Access Control:** Risk reduced (provides defense-in-depth, using `react-router` for redirection).
        *   **Information Disclosure:** Risk reduced.

    *   **Currently Implemented:**
        *   Example: The `AdminDashboard` component is wrapped in a `RequireAdmin` HOC that uses `<Navigate to="/login" replace />` for non-admin users.
        *   Example: A `useUserRole` hook is used in several components, conditionally rendering content and using `navigate` for unauthorized access.

    *   **Missing Implementation:**
        *   Example: The `UserProfile` component displays some sensitive user information without checking authorization and using `Navigate` for redirection if needed.

## Mitigation Strategy: [Careful usage of `useSearchParams`](./mitigation_strategies/careful_usage_of__usesearchparams_.md)

*   **4. Mitigation Strategy: Careful usage of `useSearchParams`

    *   **Description:**
        1.  **Sanitize and Validate:**
            *   When retrieving values from `react-router`'s `useSearchParams` hook, treat them as untrusted user input.
            *   Use a validation library (like Zod or Yup) to define schemas for expected query parameters and validate their types and formats.
            *   Use a sanitization library (like DOMPurify) if you need to render HTML based on query parameters obtained from `useSearchParams`.
        2.  **Avoid Direct Rendering:**
            *   Never directly render values from `useSearchParams` into the DOM without proper escaping or sanitization.
        3.  **Whitelist Allowed Parameters:**
            *   If possible, maintain a list of allowed query parameters for each route that uses `useSearchParams`.
            *   Ignore any query parameters that are not on the whitelist.
        4. **Encode URL components:**
            * When constructing URLs with query parameters (e.g., for navigation with `navigate`), use `URLSearchParams` or a similar utility to properly encode the values, especially if those values came from `useSearchParams`.

    *   **Threats Mitigated:**
        *   **Cross-Site Scripting (XSS) (High Severity):** Attackers inject malicious code through query parameters accessed via `useSearchParams`.
        *   **Open Redirects (Medium Severity):** Attackers use query parameters (obtained via `useSearchParams`) to redirect users.
        *   **Parameter Tampering (Medium Severity):** Attackers modify query parameters to trigger unexpected behavior.

    *   **Impact:**
        *   **XSS:** Risk significantly reduced (near elimination with proper sanitization).
        *   **Open Redirects:** Risk reduced (especially with whitelisting).
        *   **Parameter Tampering:** Risk reduced (with validation).

    *   **Currently Implemented:**
        *   Example: The `SearchResults` component uses Zod to validate the `q` parameter from `useSearchParams` and DOMPurify to sanitize HTML snippets.

    *   **Missing Implementation:**
        *   Example: The `ProductFilter` component directly renders values from `useSearchParams` into filter labels without sanitization.
        *   Example: No whitelist of allowed query parameters for the `/search` route, which uses `useSearchParams`.

