# Threat Model Analysis for remix-run/react-router

## Threat: [Client-Side Route Guard Bypass](./threats/client-side_route_guard_bypass.md)

*   **Description:** An attacker could use browser developer tools (e.g., modifying local storage, session storage, or application state) or intercept network requests to bypass client-side route guards implemented using React components or hooks. This allows access to protected routes without proper authentication or authorization.
    *   **Impact:** Unauthorized access to sensitive data, functionalities, or administrative panels.
    *   **Affected Component:** `Route` component, custom route guard components (often using `useNavigate`, `useLocation`), conditional rendering logic within components.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Implement server-side authorization checks for all protected resources and actions.
        *   Avoid relying solely on client-side checks for security.
        *   Treat client-side route guards as a user experience enhancement, not a primary security mechanism.
        *   Implement proper session management and validation on the server-side.

## Threat: [Reliance on Client-Side URL Rewriting for Security](./threats/reliance_on_client-side_url_rewriting_for_security.md)

*   **Description:** An attacker might understand that `react-router` primarily handles routing on the client-side. If the server doesn't enforce the same route restrictions, an attacker could directly access server-side endpoints bypassing the client-side routing logic and security measures.
    *   **Impact:**  Bypassing client-side security measures, potential access to unauthorized resources or actions on the server.
    *   **Affected Component:** All `react-router` components involved in defining and navigating routes (`Route`, `Link`, `useNavigate`, etc.).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Always enforce security and authorization on the server-side, regardless of the client-side URL.
        *   Treat client-side routing as a user interface and navigation mechanism, not a security boundary.
        *   Ensure that server-side routes and APIs are protected with appropriate authentication and authorization mechanisms.

