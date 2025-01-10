# Attack Surface Analysis for marmelab/react-admin

## Attack Surface: [API Injection via Data Provider](./attack_surfaces/api_injection_via_data_provider.md)

**Description:**  Malicious input is injected into API requests through the `dataProvider`, potentially leading to unintended actions or data breaches on the backend.

**How React-Admin Contributes:** React-Admin relies heavily on the `dataProvider` to interact with the backend API. If the `dataProvider` implementation doesn't properly sanitize or validate input received from React-Admin components (like filters, search terms, or data in forms), it can pass unsanitized data to the API.

**Example:** A user enters a malicious string containing special characters into a filter field. If the `dataProvider` directly uses this string in a database query without sanitization, it could lead to NoSQL injection or other API-specific injection attacks.

**Impact:** Data breaches, unauthorized data modification, denial of service on the backend.

**Risk Severity:** High

**Mitigation Strategies:**
*   **Developers:**
    *   Implement robust input validation and sanitization within the `dataProvider` before sending data to the backend API.
    *   Use parameterized queries or prepared statements on the backend to prevent injection attacks.
    *   Enforce strict input validation rules on the backend API.

## Attack Surface: [Cross-Site Scripting (XSS) via Custom Components](./attack_surfaces/cross-site_scripting__xss__via_custom_components.md)

**Description:**  Malicious scripts are injected into the application's UI through custom React components, allowing attackers to execute arbitrary JavaScript in the user's browser.

**How React-Admin Contributes:** React-Admin's extensibility allows developers to create custom input fields, display components, and layouts. If developers don't properly sanitize data when rendering it in these custom components, they can introduce XSS vulnerabilities.

**Example:** A custom field displays user-provided text without escaping HTML characters. An attacker could inject `<script>alert('XSS')</script>` which would then be executed in the browsers of other users viewing that data.

**Impact:** Session hijacking, cookie theft, redirection to malicious sites, defacement of the application.

**Risk Severity:** High

**Mitigation Strategies:**
*   **Developers:**
    *   Always sanitize user-provided data before rendering it in custom components. Use React's built-in mechanisms for escaping (JSX handles this by default for simple text, but be careful with `dangerouslySetInnerHTML`).
    *   Implement Content Security Policy (CSP) headers to restrict the sources from which the browser can load resources.
    *   Regularly review and audit custom components for potential XSS vulnerabilities.

