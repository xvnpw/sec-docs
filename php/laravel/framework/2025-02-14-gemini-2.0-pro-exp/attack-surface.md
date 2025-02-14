# Attack Surface Analysis for laravel/framework

## Attack Surface: [Mass Assignment Vulnerability](./attack_surfaces/mass_assignment_vulnerability.md)

*   *Description:* Attackers can modify database fields they shouldn't have access to by manipulating input data, bypassing intended restrictions within Eloquent models.
*   *Framework Contribution:* Laravel's Eloquent ORM provides convenient methods (`create()`, `update()`) that, if misused, allow mass assignment of attributes. This is a *direct* framework feature.
*   *Example:* An attacker adds a `role` field to a user registration form, setting it to `admin`, exploiting a model lacking proper `$fillable` or `$guarded` definitions.
*   *Impact:* Unauthorized data modification, privilege escalation, complete data compromise.
*   *Risk Severity:* **Critical** (if sensitive data/roles are exposed) / **High** (otherwise).
*   *Mitigation Strategies:*
    *   **Strictly define `$fillable` or `$guarded`:** On *every* Eloquent model, explicitly list allowed attributes (`$fillable`) or protected attributes (`$guarded`). Prefer `$fillable` (whitelist).
    *   **Use Form Requests:** Validate and filter incoming data using Laravel's Form Request validation classes *before* interacting with Eloquent.
    *   **Avoid `request()->all()` directly:** Never pass `request()->all()` to `create()` or `update()` without prior validation and filtering. Use `request()->only([...])`.

## Attack Surface: [Route Parameter Manipulation (Specifically related to SQL Injection via Eloquent)](./attack_surfaces/route_parameter_manipulation__specifically_related_to_sql_injection_via_eloquent_.md)

*   *Description:* Attackers modify URL parameters to inject malicious SQL code through Eloquent queries if parameters are used directly without sanitization.
*   *Framework Contribution:* Laravel's routing and Eloquent ORM are directly involved. While Laravel *encourages* safe practices, the framework *allows* direct use of route parameters in queries, creating the potential for misuse. This is a framework-specific risk because it relates to how Laravel handles routing and database interaction.
*   *Example:* A route `/products/{id}` uses `$product = Product::find($request->id);` without validating `$request->id`. An attacker injects SQL via the `id` parameter.
*   *Impact:* SQL injection, data leakage, data modification, database compromise.
*   *Risk Severity:* **High** / **Critical** (depending on the database and data).
*   *Mitigation Strategies:*
    *   **Route Parameter Constraints:** Use regular expressions to constrain route parameters: `Route::get('/.../{id}', ...)->where('id', '[0-9]+');`
    *   **Input Validation:** *Always* validate and sanitize route parameters using Laravel's validation features (Form Requests are strongly recommended).
    *   **Route Model Binding (with Caution):** Use route model binding, but *still validate the input*.  RMB provides a 404 if not found, but validation *before* binding is crucial.
    *   **Avoid Raw SQL:** Never use route parameters directly in raw SQL. Use Eloquent or the query builder with parameterized queries.

## Attack Surface: [Unprotected Artisan Commands](./attack_surfaces/unprotected_artisan_commands.md)

*   *Description:* Custom Artisan commands performing sensitive operations are exposed and executable by unauthorized users.
*   *Framework Contribution:* Laravel's Artisan console is the *direct* source of this risk. The framework provides the command functionality, and the developer's responsibility is to secure it.
*   *Example:* A command `php artisan create:admin` exists and can be triggered remotely without authentication.
*   *Impact:* Privilege escalation, data modification, system compromise.
*   *Risk Severity:* **Critical**.
*   *Mitigation Strategies:*
    *   **Environment Restrictions:** Limit sensitive commands to specific environments (e.g., local development) using `.env` variables and conditional logic.
    *   **Authentication/Authorization:** Implement authentication and authorization checks *within the command itself* using Laravel's auth features if the command must be accessible in production.
    *   **Avoid Web Exposure:** *Never* create web routes that directly execute Artisan commands, especially sensitive ones.
    *   **Input Validation:** Validate all command input.

## Attack Surface: [Debug Mode Enabled in Production](./attack_surfaces/debug_mode_enabled_in_production.md)

*   *Description:* `APP_DEBUG=true` in production reveals sensitive information (stack traces, environment variables, database credentials).
*   *Framework Contribution:* Laravel uses the `APP_DEBUG` setting in the `.env` file. This is a framework-provided configuration option that, when misconfigured, creates a severe vulnerability.
*   *Example:* An application error displays a full stack trace, including database credentials, to the attacker.
*   *Impact:* Information disclosure, complete system compromise.
*   *Risk Severity:* **Critical**.
*   *Mitigation Strategies:*
    *   **Set `APP_DEBUG=false`:** Ensure `APP_DEBUG=false` in the `.env` file for *all* production environments. This is a non-negotiable security practice.

## Attack Surface: [Insecure `APP_KEY`](./attack_surfaces/insecure__app_key_.md)

*   *Description:* A weak, default, or compromised `APP_KEY` allows attackers to decrypt data, forge cookies, and potentially gain control.
*   *Framework Contribution:* Laravel *requires* and uses the `APP_KEY` for encryption and security. The framework's security model relies on the secrecy of this key.
*   *Example:* An attacker obtains the `APP_KEY` and decrypts user session data or forges cookies.
*   *Impact:* Data decryption, session hijacking, impersonation, potential code execution.
*   *Risk Severity:* **Critical**.
*   *Mitigation Strategies:*
    *   **Generate a Strong Key:** Use `php artisan key:generate` *immediately* after installation.
    *   **Secure Storage:** Store the `APP_KEY` *outside* of version control, using environment variables. *Never* commit `.env` to Git.
    *   **Regular Key Rotation:** Periodically rotate the `APP_KEY` (with careful planning).

## Attack Surface: [Unsafe Query Scopes (leading to SQL Injection)](./attack_surfaces/unsafe_query_scopes__leading_to_sql_injection_.md)

*   *Description:* Eloquent query scopes that use user-supplied data without proper sanitization or parameterized queries can lead to SQL injection.
*   *Framework Contribution:* Laravel's Eloquent ORM provides the query scope feature. The framework *allows* the creation of potentially unsafe scopes; it's the developer's responsibility to write them securely. This is a direct framework feature.
*   *Example:* A scope `scopeSearch($query, $term)` uses `$term` directly in a `whereRaw` clause.
*   *Impact:* SQL injection, data leakage, data modification, database compromise.
*   *Risk Severity:* **High** / **Critical**.
*   *Mitigation Strategies:*
    *   **Parameterized Queries:** *Always* use parameterized queries or the query builder's methods (e.g., `where()`, `orWhere()`) within scopes.
    *   **Input Validation:** Validate and sanitize any user-supplied data *before* it's used in a scope.
    *   **Avoid Raw SQL:** Minimize the use of `whereRaw` and similar methods.

