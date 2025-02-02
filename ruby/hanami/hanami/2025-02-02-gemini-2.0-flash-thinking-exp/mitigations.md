# Mitigation Strategies Analysis for hanami/hanami

## Mitigation Strategy: [Explicitly Define Allowed Parameters in Actions](./mitigation_strategies/explicitly_define_allowed_parameters_in_actions.md)

### 1. Explicitly Define Allowed Parameters in Actions

*   **Mitigation Strategy:** Explicitly Define Allowed Parameters in Actions
*   **Description:**
    1.  **Identify Action Parameters:** In each Hanami action (`app/actions/your_action.rb`), identify all parameters expected from the request.
    2.  **Use `params.permit`:** Within the action's `handle` method, use `params.permit(:param1, :param2, ...)` to explicitly list allowed parameters.
    3.  **Validate Parameter Types (Optional but Recommended):** Use Hanami's parameter types within `params.permit` for stronger validation, e.g., `params.permit(id: Integer, name: String)`.
    4.  **Reject Unpermitted Parameters:** Hanami automatically rejects parameters not in `params.permit`.
    5.  **Test Parameter Filtering:** Write unit tests to verify parameter filtering.

*   **Threats Mitigated:**
    *   **Mass Assignment (High Severity):** Prevents unauthorized modification of database attributes.
    *   **Information Disclosure (Medium Severity):** Reduces risk of unintended parameter processing and logging.

*   **Impact:**
    *   **Mass Assignment:** High Risk Reduction
    *   **Information Disclosure:** Medium Risk Reduction

*   **Currently Implemented:** Partially Implemented
    *   Implemented in `app/actions/users/create.rb` and `app/actions/posts/update.rb`.

*   **Missing Implementation:**
    *   Missing in actions in `app/actions/comments/*`, `app/actions/sessions/*`, and some in `app/actions/admin/*`.

## Mitigation Strategy: [Implement Route-Level Authorization](./mitigation_strategies/implement_route-level_authorization.md)

### 2. Implement Route-Level Authorization

*   **Mitigation Strategy:** Implement Route-Level Authorization
*   **Description:**
    1.  **Identify Protected Routes:** Determine routes in `config/routes.rb` requiring authorization.
    2.  **Use `authorize:` Option:** In `config/routes.rb`, add `authorize: :policy_name` to protected routes.
    3.  **Create Policy Classes:** Create policy classes (e.g., `app/policies/policy_name.rb`) inheriting from `Hanami::Action::Policy`.
    4.  **Implement `authorized?` Method:** In policy classes, implement `authorized?` to define authorization logic using `context[:current_user]`.
    5.  **Ensure `current_user` in Context:** Set `current_user` in action context (e.g., `before` hook).
    6.  **Test Route Authorization:** Write integration tests to verify authorization.

*   **Threats Mitigated:**
    *   **Unauthorized Access (High Severity):** Prevents access to sensitive areas by unauthorized users.
    *   **Privilege Escalation (High Severity):** Reduces risk of gaining elevated privileges.

*   **Impact:**
    *   **Unauthorized Access:** High Risk Reduction
    *   **Privilege Escalation:** High Risk Reduction

*   **Currently Implemented:** Partially Implemented
    *   Implemented for admin routes under `/admin` using `authorize: :admin_required`.

*   **Missing Implementation:**
    *   Missing for user-specific routes like profile editing and settings. Need to implement policies like `UserAuthenticatedPolicy`.

## Mitigation Strategy: [Automatic Output Escaping in Templates](./mitigation_strategies/automatic_output_escaping_in_templates.md)

### 3. Automatic Output Escaping in Templates

*   **Mitigation Strategy:** Automatic Output Escaping in Templates
*   **Description:**
    1.  **Verify Template Engine Configuration:** Check template engine config (e.g., `config/app.rb`) for default automatic escaping.
    2.  **Use Template Helpers for Raw Output (Sparingly):** Use helpers for raw HTML output only for trusted content.
    3.  **Review Template Code:** Audit templates (`app/views/**/*.html.erb`) for manual disabling of escaping or raw output.
    4.  **Test XSS Prevention:** Write integration tests to verify script escaping.

*   **Threats Mitigated:**
    *   **Cross-Site Scripting (XSS) - Reflected (High Severity):** Prevents reflected XSS attacks.
    *   **Cross-Site Scripting (XSS) - Stored (Medium Severity):** Reduces impact of stored XSS.

*   **Impact:**
    *   **XSS - Reflected:** High Risk Reduction
    *   **XSS - Stored:** Medium Risk Reduction

*   **Currently Implemented:** Implemented
    *   Automatic output escaping is enabled by default with ERB templates.

*   **Missing Implementation:**
    *   No missing implementation of automatic escaping itself, but ongoing vigilance and template reviews are needed.

