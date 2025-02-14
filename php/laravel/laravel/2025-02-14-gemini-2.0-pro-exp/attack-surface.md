# Attack Surface Analysis for laravel/laravel

## Attack Surface: [Mass Assignment](./attack_surfaces/mass_assignment.md)

*   **Description:** Attackers inject unexpected or malicious data into database models by manipulating form submissions or API requests, bypassing intended attribute restrictions.
*   **Laravel Contribution:** Eloquent ORM's convenience features (like `create()` and `update()`) make it easy to accidentally expose models to mass assignment if `$fillable` or `$guarded` are not properly configured. This is a *direct* consequence of Laravel's design.
*   **Example:** An attacker adds an `is_admin` field to a user registration form, setting it to `true` to gain administrative privileges.
*   **Impact:** Unauthorized data modification, privilege escalation, data integrity compromise.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strictly Define `$fillable` or `$guarded`:** In *every* Eloquent model, explicitly define either `$fillable` (whitelist) or `$guarded` (blacklist). Prefer `$fillable`. Never leave both undefined.
    *   **Use Form Requests:** Leverage Laravel's Form Requests for validation and input filtering. Use `$request->validated()` to get only validated data.
    *   **Avoid `$request->all()` with `create()`/`update()`:** Never directly pass `$request->all()` to these methods.
    *   **Input Sanitization:** Sanitize input data even within allowed fields.

## Attack Surface: [Route Parameter Manipulation (with Route Model Binding)](./attack_surfaces/route_parameter_manipulation__with_route_model_binding_.md)

*   **Description:** Attackers modify route parameters (e.g., IDs in URLs) to access unauthorized resources.
*   **Laravel Contribution:** Laravel's Route Model Binding *directly* retrieves model instances based on route parameters. Without proper scoping and authorization, this *directly* enables unauthorized access. This is a core Laravel feature.
*   **Example:** An attacker changes the ID in `/posts/123` to `/posts/456` to view a post they shouldn't have access to.
*   **Impact:** Unauthorized data access, information disclosure.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Route Model Binding with Scoping:** Use scoped bindings (e.g., `$user->posts()->findOrFail($id);`) to ensure relationships are respected.
    *   **Explicit Authorization Checks:** Implement authorization checks (Policies, Gates, middleware) *after* retrieving the model.
    *   **Input Validation:** Validate route parameters (e.g., `numeric`, `exists`).
    *   **Regular Expression Constraints:** Use `where()` clauses in route definitions to restrict parameter formats.

## Attack Surface: [Unintended Route Exposure](./attack_surfaces/unintended_route_exposure.md)

*   **Description:** Routes intended for internal use or specific environments are accidentally exposed.
*   **Laravel Contribution:** Laravel's routing system and the potential for cached routes to become out of sync with code changes *directly* contribute to this risk. The framework's flexibility requires careful management.
*   **Example:** A route like `/admin/debug/database` is left accessible in production.
*   **Impact:** Information disclosure, unauthorized access to administrative functions.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Regular Route Review:** Use `php artisan route:list` frequently in all environments.
    *   **Middleware Protection:** Apply authentication/authorization middleware to sensitive routes.
    *   **Environment-Specific Routes:** Use conditional logic (e.g., `if (app()->environment('local'))`) for environment-specific routes.
    *   **Route Caching (with Caution):** Clear the route cache (`php artisan route:clear`) after *any* route changes.

## Attack Surface: [Unrestricted File Uploads](./attack_surfaces/unrestricted_file_uploads.md)

*   **Description:** Attackers upload malicious files (e.g., PHP scripts) that can be executed on the server.
*   **Laravel Contribution:** While Laravel *provides* file storage features, it's the developer's responsibility to configure them securely.  The framework doesn't inherently prevent this, but its file handling features are the mechanism through which the attack occurs.  This is less *direct* than the others, but still relevant.
*   **Example:** An attacker uploads a `shell.php` file.
*   **Impact:** Remote code execution, server compromise.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strict File Type Validation:** Use Laravel's validation rules (`mimes`, `image`, etc.) to restrict allowed file types to a *very specific* whitelist.
    *   **File Extension Validation:** Validate the file extension *in addition to* the MIME type.
    *   **Store Files Outside Web Root:** Store uploaded files *outside* the `public` directory. Use Laravel's storage system.
    *   **Randomize File Names:** Generate random file names.
    *   **File Size Limits:** Enforce limits in `php.ini` and with Laravel validation.

## Attack Surface: [Debug Mode Enabled in Production (APP_DEBUG)](./attack_surfaces/debug_mode_enabled_in_production__app_debug_.md)

*   **Description:** Leaving `APP_DEBUG=true` in production exposes sensitive information.
*   **Laravel Contribution:** Laravel's detailed error pages, *directly* controlled by `APP_DEBUG`, are the source of this vulnerability. This is a *direct* and framework-specific issue.
*   **Example:** An error page reveals database credentials.
*   **Impact:** Information disclosure, facilitates further attacks.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Set `APP_DEBUG=false`:** Ensure `APP_DEBUG` is `false` in the `.env` file for production. This is the *only* necessary mitigation.
    *   **Custom Error Pages:** Configure custom error pages.

## Attack Surface: [Insecure Direct Object References (IDOR) via Eloquent Relationships](./attack_surfaces/insecure_direct_object_references__idor__via_eloquent_relationships.md)

*   **Description:** Attackers manipulate relationships between models to access or modify data they shouldn't have.
*   **Laravel Contribution:** Eloquent's relationship methods, if used without proper authorization *within the relationship logic*, *directly* facilitate this vulnerability. The ease of defining relationships increases the risk if not handled carefully.
*   **Example:** A user accesses comments on a blog post they don't own by manipulating the comment ID.
*   **Impact:** Unauthorized data access, data modification.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Authorization within Relationships:** Implement authorization checks *within* relationship logic. Use scoped queries.
    *   **Constrain Eager Loading:** Be mindful of eager loading (`with()`). Use constrained eager loading.
    *   **Policies for Related Models:** Consider Policies for related models (e.g., `CommentPolicy`).

## Attack Surface: [Misconfigured Authentication Guards](./attack_surfaces/misconfigured_authentication_guards.md)

* **Description:** Using the incorrect authentication guard for a route or API endpoint, leading to bypassed or incorrect authentication.
* **Laravel Contribution:** Laravel's multiple authentication guards (e.g., `web`, `api`) provide flexibility but require careful configuration. The framework *provides* the feature that, if misconfigured, leads to the vulnerability.
* **Example:** An API endpoint intended for token-based authentication accidentally uses the `web` guard.
* **Impact:** Authentication bypass, unauthorized access.
* **Risk Severity:** High
* **Mitigation Strategies:**
    * **Explicit Guard Specification:** Always specify the correct guard using middleware (e.g., `auth:api`, `auth:web`).
    * **Default Guard Review:** Review and configure the default guard in `config/auth.php`.
    * **Testing:** Thoroughly test authentication with different guards.

