# Threat Model Analysis for varvet/pundit

## Threat: [Policy Resolution Bypass (Policy Not Found)](./threats/policy_resolution_bypass__policy_not_found_.md)

*   **Description:** An attacker attempts to access a resource where the corresponding Pundit policy class cannot be found.  They might manipulate URLs or parameters to target a non-existent resource name, or a resource whose policy is deliberately misconfigured (e.g., renamed or moved). The attacker knows that if the policy isn't found, and the application doesn't handle `nil` policy results correctly, Pundit might default to allowing access.
    *   **Impact:** Unauthorized access to resources. The attacker gains access to data or functionality they should not be able to reach.
    *   **Pundit Component Affected:** Policy resolution mechanism (`Pundit.policy`, `authorize`, `policy_scope` methods, and the underlying class naming and lookup logic).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Implement a custom `pundit_policy_missing` handler in the ApplicationController (or base controller) to *always* deny access or raise a specific error when a policy is not found.  Never allow access by default.
        *   Enforce strict naming conventions for policy classes and files.
        *   Use explicit policy class specification in critical areas (e.g., `authorize @record, policy_class: MyPolicy`).
        *   Include comprehensive tests that specifically check for policy resolution failures, including cases where policies should *not* be found.

## Threat: [Missing Policy Method Exploitation](./threats/missing_policy_method_exploitation.md)

*   **Description:** An attacker targets a controller action where the corresponding policy method (e.g., `update?`) is missing. They craft a request to trigger this action, knowing that if the method is absent, and the application doesn't handle the resulting error, it might lead to unintended behavior, potentially granting access.
    *   **Impact:** Unauthorized action execution. The attacker can perform actions (create, update, delete) they are not authorized for.
    *   **Pundit Component Affected:** Individual policy methods (e.g., `show?`, `create?`, `update?`, `destroy?`) within policy classes.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Ensure every controller action requiring authorization has a corresponding method in the relevant policy class.
        *   Policy methods should default to `false` (deny access) and only return `true` if all authorization conditions are met.
        *   Write unit tests for *each* policy method, covering all authorization scenarios.
        *   Use `verify_authorized` to ensure that `authorize` is called in every action.

## Threat: [Scope Bypass (Information Disclosure)](./threats/scope_bypass__information_disclosure_.md)

*   **Description:** An attacker attempts to view a list of resources (e.g., an index page) where the `policy_scope` is either missing, misconfigured, or contains flawed logic. They might try different parameters or user roles to see if they can access records they shouldn't. The attacker aims to enumerate or access data beyond their authorized scope.
    *   **Impact:** Information disclosure. The attacker can view records they are not authorized to see, potentially revealing sensitive data.
    *   **Pundit Component Affected:** `policy_scope` and the `resolve` method within scope classes.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Define a scope class for each resource requiring scoped authorization.
        *   The `resolve` method should accurately filter records based on the user's permissions, using secure and efficient database queries.
        *   Test scope resolution with users having different roles and permissions.
        *   Use `verify_policy_scoped` to ensure that `policy_scope` is used in index actions.

## Threat: [`authorize` Call Omission](./threats/_authorize__call_omission.md)

*   **Description:** An attacker targets a controller action where the developer has forgotten to include the `authorize` call. The attacker crafts a request to this action, knowing that no authorization check will be performed.
    *   **Impact:** Complete authorization bypass. The attacker can perform the action without any restrictions.
    *   **Pundit Component Affected:** The `authorize` method and its presence (or absence) within controller actions.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Use Pundit's `verify_authorized` method in the ApplicationController to enforce that `authorize` is called in every action (unless explicitly skipped with justification).
        *   Implement code reviews to ensure all controller actions have `authorize` calls.
        *   Use static analysis tools to detect missing `authorize` calls.

## Threat: [Incorrect `user` or `record` Handling](./threats/incorrect__user__or__record__handling.md)

* **Description:** An attacker provides malicious input that is then used *within* a Pundit policy to make authorization decisions.  For example, the attacker might manipulate a `user.role` attribute (if it's directly accessible and trusted) or inject data into the `record` being authorized. The attacker aims to trick the policy into granting access based on false information.
    * **Impact:** Authorization bypass. The attacker gains access by manipulating the data used in the authorization decision.
    * **Pundit Component Affected:** The logic within policy methods that uses the `user` and `record` arguments.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        *   Treat the `user` object as potentially compromised.  Do not rely on user-provided attributes without verifying them against a trusted source (e.g., the database).
        *   Ensure policy logic is context-specific and avoids relying on easily manipulated data.
        *   Validate all data used within policy methods, even if it appears to come from a trusted source.

