# Attack Surface Analysis for revel/revel

## Attack Surface: [Overly Permissive Routing](./attack_surfaces/overly_permissive_routing.md)

*   **Description:** Unintentionally exposing internal controller actions or functions due to broad or poorly defined routes in the `routes` file.
*   **How Revel Contributes:** Revel's flexible routing system, especially its use of wildcards and automatic route generation, can easily lead to unintended exposures if not carefully managed. The `routes` file is a central point of configuration that directly impacts this.
*   **Example:** A route defined as `/admin/*` without proper authorization checks *within* the `Admin` controller could allow unauthenticated access to all actions within that controller.
*   **Impact:** Unauthorized access to sensitive data or functionality, potential for privilege escalation, data modification or deletion.
*   **Risk Severity:** High to Critical (depending on the exposed functionality).
*   **Mitigation Strategies:**
    *   **Developers:**
        *   Define routes explicitly and narrowly, avoiding overly broad wildcards.
        *   Implement robust authentication and authorization *within* controller actions, *not* solely relying on routing for access control.
        *   Regularly review and audit the `routes` file for unintended exposures.
        *   Use Revel's interceptors to enforce consistent access control policies across all routes.

## Attack Surface: [Parameter Injection in Controller Actions (Due to Revel Routing)](./attack_surfaces/parameter_injection_in_controller_actions__due_to_revel_routing_.md)

*   **Description:** Exploiting vulnerabilities in how controller actions handle parameters received from routes, leading to various injection attacks.
*   **How Revel Contributes:** Revel's routing mechanism directly passes parameters to controller actions. This direct coupling between routing and action parameters necessitates careful handling within the action.
*   **Example:** A controller action that uses a URL parameter (provided by Revel's routing) directly in a SQL query without proper escaping is vulnerable to SQL injection.
*   **Impact:** SQL injection, command injection, path traversal, and other injection-based attacks.
*   **Risk Severity:** High to Critical (depending on the type of injection).
*   **Mitigation Strategies:**
    *   **Developers:**
        *   Treat *all* parameters received from Revel's routing as untrusted input.
        *   Use Revel's validation framework or custom validation logic to strictly validate and sanitize all parameters *within the controller action*.
        *   Use parameterized queries (prepared statements) for database interactions.
        *   Avoid using parameters directly in file system operations or command execution without proper escaping.

## Attack Surface: [Unprotected Public Controller Methods](./attack_surfaces/unprotected_public_controller_methods.md)

*   **Description:** Public methods in controllers are automatically exposed as potential endpoints. Methods intended for internal use can become accessible.
*   **How Revel Contributes:** Revel's design inherently makes all `public` methods of a controller accessible via routing. This is a core feature of how Revel maps requests to code.
*   **Example:** A developer creates a `public` helper function within a controller for internal use, forgetting that it will be exposed as a route by Revel.
*   **Impact:** Unintentional exposure of internal logic, potential for data leakage or unintended actions.
*   **Risk Severity:** High (depending on the exposed functionality).
*   **Mitigation Strategies:**
    *   **Developers:**
        *   Make internal helper functions `private` or `protected`.
        *   Use Revel's interceptor mechanism to enforce authentication and authorization checks before *any* controller action is executed.

## Attack Surface: [Weak Session Secret (`app.secret`)](./attack_surfaces/weak_session_secret___app_secret__.md)

*   **Description:** Using a weak, predictable, or exposed `app.secret` key, allowing attackers to forge session cookies.
*   **How Revel Contributes:** Revel *requires* the `app.secret` setting for its session management. The security of Revel's session handling is *directly* tied to the strength and secrecy of this key.
*   **Example:** Using a default or easily guessable `app.secret` (e.g., "changeme") or storing it in the source code repository.
*   **Impact:** Session hijacking, impersonation of users, unauthorized access to sensitive data.
*   **Risk Severity:** Critical.
*   **Mitigation Strategies:**
    *   **Developers:**
        *   Generate a strong, random `app.secret`.
        *   Store the `app.secret` securely, *outside* of the application's source code (e.g., environment variables).
        *   Rotate the `app.secret` periodically.

## Attack Surface: [Session Fixation (Lack of Regeneration in Revel)](./attack_surfaces/session_fixation__lack_of_regeneration_in_revel_.md)

*   **Description:** An attacker sets a user's session ID to a known value, then hijacks the session after the user logs in.
*   **How Revel Contributes:** While Revel provides the *mechanism* for session management (the `revel.Session` object), it does *not* automatically regenerate the session ID on authentication. This is a crucial step that developers must explicitly implement using Revel's provided functions.
*   **Example:** An attacker sends a link with a preset session ID. When the user logs in, the attacker uses the same ID.
*   **Impact:** Session hijacking, unauthorized access to user accounts.
*   **Risk Severity:** High.
*   **Mitigation Strategies:**
    *   **Developers:**
        *   Regenerate the session ID upon successful authentication using `revel.Session.Session.SetId()`. This is a *direct use* of Revel's API to mitigate the risk.

## Attack Surface: [Unrestricted File Uploads (Using `revel.Params.Files`)](./attack_surfaces/unrestricted_file_uploads__using__revel_params_files__.md)

*   **Description:** Allowing users to upload files without proper validation and restrictions, leading to potential execution of malicious code.
*   **How Revel Contributes:** Revel provides the `revel.Params.Files` structure to handle file uploads. This is the *direct interface* developers use, and its misuse creates the vulnerability.
*   **Example:** An application allows any file type upload without checking contents, using `revel.Params.Files` directly.
*   **Impact:** Remote code execution, server compromise.
*   **Risk Severity:** Critical.
*   **Mitigation Strategies:**
    *   **Developers:**
        *   Validate file types and sizes *before* saving, using information from `revel.Params.Files`.
        *   Store uploaded files outside the web root.
        *   Rename files to prevent path traversal.

## Attack Surface: [Sensitive Information in `app.conf`](./attack_surfaces/sensitive_information_in__app_conf_.md)

*   **Description:**  Storing sensitive data directly in Revel's `app.conf` file.
*   **How Revel Contributes:**  `app.conf` is Revel's primary configuration file, and the framework reads settings from it.  This makes it a tempting (but insecure) place to store secrets.
*   **Example:**  Storing database credentials in plain text in `app.conf`.
*   **Impact:**  Exposure of sensitive data.
*   **Risk Severity:** Critical.
*   **Mitigation Strategies:**
    *   **Developers:**
        *   Store sensitive values in environment variables, *not* in `app.conf`.
        *   Restrict access to `app.conf`.
        *   Avoid committing `app.conf` (with secrets) to version control.

