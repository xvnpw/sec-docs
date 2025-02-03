# Attack Surface Analysis for marmelab/react-admin

## Attack Surface: [1. Data Exposure through List and Show Views](./attack_surfaces/1__data_exposure_through_list_and_show_views.md)

*   **Description:** React-Admin's automatic view generation can inadvertently expose sensitive data fields in list and show views if not configured carefully.
*   **React-Admin Contribution:** React-Admin simplifies data presentation, but developers must explicitly control displayed fields. Default configurations can expose more data than intended, directly through the React-Admin UI.
*   **Example:** Displaying sensitive user details like social security numbers or financial information in a React-Admin list view accessible to unauthorized admin users.
*   **Impact:** Confidentiality breach, severe privacy violation, potential identity theft, significant reputational damage.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Explicitly define `list` and `show` fields:**  Meticulously select and limit the fields displayed in React-Admin's `List` and `Show` components. Avoid relying on default field inclusion.
    *   **Implement Backend Authorization (Crucial):**  Backend API MUST enforce strict authorization checks to return only data the user is *explicitly* authorized to see. React-Admin frontend configuration is insufficient for security.
    *   **Utilize `omit` or `filter` props with Backend Context:**  Dynamically use React-Admin's `omit` or `filter` props based on user roles and permissions retrieved from the backend to hide sensitive fields client-side *after* secure backend data retrieval.

## Attack Surface: [2. GraphQL/REST API Interaction Vulnerabilities (Authorization & Mass Assignment)](./attack_surfaces/2__graphqlrest_api_interaction_vulnerabilities__authorization_&_mass_assignment_.md)

*   **Description:** React-Admin's interaction with backend APIs can expose vulnerabilities, particularly related to broken object-level authorization and mass assignment, if APIs are not designed with React-Admin's usage patterns in mind.
*   **React-Admin Contribution:** React-Admin's data providers generate API requests based on user actions in the UI.  If backend APIs are overly permissive or lack proper input validation, React-Admin's interaction can trigger exploits.
*   **Example:**
    *   **Broken Object Level Authorization:** A standard admin user, through React-Admin's UI, can modify or delete resources belonging to a super-admin by manipulating API request parameters (e.g., resource IDs) even if the React-Admin UI *appears* to restrict such actions.
    *   **Mass Assignment:**  An attacker modifies the payload of an update request sent by React-Admin to include fields like `isAdmin: true` for a user, and the backend API blindly accepts and applies these changes, leading to privilege escalation.
*   **Impact:** Unauthorized data access, data modification, privilege escalation to administrator level, complete system compromise.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Robust Backend Authorization (Mandatory):** Implement and enforce *strict* object-level authorization at the API level. Verify user permissions for *every* data access and modification request, regardless of React-Admin's frontend behavior.
    *   **Backend Mass Assignment Protection (Essential):** Configure backend frameworks to explicitly define allowed fields for updates. Use allow-lists, not block-lists, and prevent mass assignment by default.
    *   **Secure API Design with React-Admin in Mind:** Design APIs with the understanding of how React-Admin will interact with them.  Anticipate potential misuse through UI interactions and implement preventative measures in the API.

## Attack Surface: [3. Authentication and Authorization Bypass in React-Admin Components (Client-Side Focus)](./attack_surfaces/3__authentication_and_authorization_bypass_in_react-admin_components__client-side_focus_.md)

*   **Description:** Relying solely on client-side authorization logic within React-Admin components is a critical vulnerability. Attackers can easily bypass these checks.
*   **React-Admin Contribution:** React-Admin allows for client-side role-based access control within components.  Developers might mistakenly rely *only* on these frontend checks for security.
*   **Example:**  React-Admin components conditionally render admin features based on a user role stored in the frontend. An attacker can modify the frontend code (e.g., in browser developer tools) to change their role and access admin functionalities, even if the backend API is correctly secured.
*   **Impact:** Unauthorized access to admin functionalities, bypassing intended access controls, potential data breaches and system compromise.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Server-Side Authorization (Absolute Requirement):**  *Never* rely on client-side authorization for security. All authorization decisions *must* be enforced on the backend API. React-Admin's frontend should only *reflect* the backend's authorization decisions for UI purposes.
    *   **Frontend as UI Only:** Treat the React-Admin frontend purely as a user interface.  All security logic must reside on the server-side API.
    *   **Use Frontend Authorization for UI/UX Only:**  Utilize React-Admin's frontend authorization features *only* for enhancing user experience (e.g., hiding UI elements based on roles) but *never* for actual security enforcement.

## Attack Surface: [4. Client-Side Rendering and Cross-Site Scripting (XSS) Vulnerabilities](./attack_surfaces/4__client-side_rendering_and_cross-site_scripting__xss__vulnerabilities.md)

*   **Description:** React-Admin's client-side rendering can be exploited by XSS attacks if data from the backend is not rigorously sanitized, leading to malicious script execution in admin users' browsers.
*   **React-Admin Contribution:** React-Admin directly renders data fetched from the backend. If this data contains unsanitized malicious scripts, React-Admin will execute them in the browser, affecting admin users.
*   **Example:**  A malicious actor injects JavaScript code into a database field (e.g., a user's "notes" field). When a React-Admin user views this user's details in a "Show" view, React-Admin renders the malicious script, leading to XSS and potentially session hijacking or further attacks against the admin user.
*   **Impact:** Account compromise of admin users, session hijacking, data theft, defacement of the admin interface, potential for wider system compromise if admin accounts are highly privileged.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Strict Backend Input Sanitization (Mandatory):** Sanitize *all* user-provided data on the backend *before* storing it in the database. Use context-aware output encoding on the backend as well.
    *   **Frontend Output Encoding (Defense in Depth):**  Utilize React-Admin's components and React's built-in mechanisms to ensure proper output encoding of data rendered in components. Escape HTML entities and JavaScript code.
    *   **Content Security Policy (CSP) (Recommended):** Implement a strict Content Security Policy to significantly reduce the impact of XSS attacks by controlling the sources from which the browser can load resources and restricting inline script execution.

## Attack Surface: [5. Custom Components and Extensions Introducing Security Flaws](./attack_surfaces/5__custom_components_and_extensions_introducing_security_flaws.md)

*   **Description:** Custom React-Admin components and extensions, if not developed with security in mind, can introduce vulnerabilities, especially injection flaws or authorization bypasses within the React-Admin context.
*   **React-Admin Contribution:** React-Admin's extensibility allows for custom code integration.  Poorly written custom components directly become part of the React-Admin application's attack surface.
*   **Example:** A custom form component that directly constructs and executes SQL queries based on user input without proper sanitization, leading to SQL injection vulnerabilities accessible through the React-Admin UI.
*   **Impact:** Data breaches, data manipulation, unauthorized access, potential for remote code execution depending on the nature of the vulnerability in the custom component.
*   **Risk Severity:** High to Critical (depending on the vulnerability type and impact)
*   **Mitigation Strategies:**
    *   **Secure Coding Practices for Custom Components (Essential):**  Adhere to secure coding principles during the development of *all* custom React-Admin components. Focus on input validation, output encoding, and secure API interactions.
    *   **Mandatory Code Reviews for Custom Code:**  Conduct thorough security-focused code reviews of *all* custom React-Admin components and extensions before deployment.
    *   **Security Testing of Custom Components (Required):**  Include custom components in security testing efforts, such as static analysis, dynamic analysis, and penetration testing, to identify and remediate vulnerabilities.
    *   **Principle of Least Privilege in Custom Components:** Ensure custom components operate with the minimum necessary privileges and do not introduce new avenues for privilege escalation.

## Attack Surface: [6. Cross-Site Request Forgery (CSRF) in Admin Actions (React-Admin Context)](./attack_surfaces/6__cross-site_request_forgery__csrf__in_admin_actions__react-admin_context_.md)

*   **Description:** Lack of CSRF protection for sensitive admin actions performed through React-Admin can allow attackers to execute unauthorized actions on behalf of authenticated admin users.
*   **React-Admin Contribution:** React-Admin facilitates admin actions via API calls. If CSRF protection is missing or improperly implemented in the backend API *and* not correctly handled by React-Admin's data provider, vulnerabilities arise.
*   **Example:** An attacker tricks a logged-in admin user into unknowingly deleting a critical database record by embedding a malicious image tag or link in an email. When the admin user's browser loads the email, it inadvertently sends a DELETE request to the React-Admin backend API without proper CSRF protection, triggered by the malicious image source.
*   **Impact:** Unauthorized data modification or deletion, system disruption, potential for data integrity compromise.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Backend CSRF Protection (Fundamental):** Implement robust CSRF protection mechanisms in the backend API for *all* state-changing endpoints used by React-Admin (e.g., using CSRF tokens - Synchronizer Token Pattern is recommended).
    *   **React-Admin Data Provider CSRF Handling (Verify):** Ensure the React-Admin data provider being used (e.g., `dataProvider-json-server`, `dataProvider-graphql`) is correctly configured to handle CSRF tokens provided by the backend API. Most standard data providers handle this automatically if the backend implements CSRF correctly.
    *   **Validate CSRF Implementation End-to-End:** Thoroughly test the CSRF protection implementation from the backend API through to React-Admin's data provider to ensure it is effective and prevents CSRF attacks.

