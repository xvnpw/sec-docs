# Attack Surface Analysis for yiisoft/yii2

## Attack Surface: [Mass Assignment Vulnerability](./attack_surfaces/mass_assignment_vulnerability.md)

*   **Description:** Attackers manipulate model attributes they shouldn't have access to by submitting crafted form data.
*   **Yii2 Contribution:** Yii2's ActiveRecord models use mass assignment for convenience, which, if misconfigured, opens this vulnerability. This is a *direct* consequence of Yii2's design.
*   **Example:** An attacker adds `&User[is_admin]=1` to a registration form's POST data, potentially gaining administrative privileges if the `is_admin` attribute isn't explicitly protected.
*   **Impact:** Unauthorized data modification, privilege escalation.
*   **Risk Severity:** High to Critical (depending on the affected attributes).
*   **Mitigation Strategies:**
    *   **Strict `rules()` Definition:**  Explicitly define `safe` attributes in model `rules()`.  Use scenarios to control which attributes are mass-assignable in different contexts.
    *   **Explicit Assignment:**  Prefer explicit attribute assignment (e.g., `$model->username = $data['username'];`) over mass assignment for sensitive fields.
    *   **Input Validation:**  Thoroughly validate all input data, even for attributes considered "safe," to prevent unexpected values.
    *   **Use `load()` with Caution:** When using `load()`, ensure the data source is trusted and the scenario is correctly set.

## Attack Surface: [SQL Injection (via ActiveRecord)](./attack_surfaces/sql_injection__via_activerecord_.md)

*   **Description:** Attackers inject malicious SQL code through user input that is used in database queries.
*   **Yii2 Contribution:** While ActiveRecord *generally* protects against SQL injection, improper use of query building methods (especially `findBySql()`, or bypassing parameter binding) can create vulnerabilities.  This is a direct risk stemming from how developers *use* Yii2's features.
*   **Example:**  Using `$query->where("username = '" . $_GET['username'] . "'")` instead of `$query->where(['username' => $_GET['username']])`.
*   **Impact:** Data breach, data modification, data deletion, server compromise.
*   **Risk Severity:** Critical.
*   **Mitigation Strategies:**
    *   **Parameterized Queries:** Always use ActiveRecord's built-in parameter binding (prepared statements).  Avoid direct string concatenation with user input in query conditions.
    *   **Input Validation:** Sanitize and validate all user input used in queries, even if it's not directly part of the SQL string (e.g., column names, sort order).
    *   **Least Privilege:**  Ensure the database user account used by the application has only the necessary privileges.

## Attack Surface: [Gii/Debug Module Enabled in Production](./attack_surfaces/giidebug_module_enabled_in_production.md)

*   **Description:** The Gii code generator and Debug module expose sensitive information about the application if left enabled in production.
*   **Yii2 Contribution:** These are powerful development tools *provided by Yii2*, but they are not intended for production use.  Their presence in production is a direct Yii2-related risk.
*   **Example:** Accessing `/gii` or `/debug` on a production server reveals database schema, code structure, and other sensitive information.
*   **Impact:** Information disclosure, facilitating targeted attacks.
*   **Risk Severity:** Critical.
*   **Mitigation Strategies:**
    *   **Disable in Production:** Ensure that both Gii and the Debug module are *completely disabled* in production environments by removing or commenting out the relevant configuration sections in the application's configuration file.  This is a *critical* configuration step.

## Attack Surface: [Improper RBAC Configuration](./attack_surfaces/improper_rbac_configuration.md)

* **Description:** Incorrectly configured Role-Based Access Control (RBAC) can lead to authorization bypass.
    * **Yii2 Contribution:** Yii2 *provides* a robust RBAC system, but it requires careful configuration. The vulnerability arises directly from how this Yii2 feature is (mis)used.
    * **Example:** A misconfigured rule allows users with the "editor" role to access actions intended only for "administrators."
    * **Impact:** Unauthorized access to data and functionality.
    * **Risk Severity:** High to Critical.
    * **Mitigation Strategies:**
        * **Careful Design:** Carefully design and implement RBAC rules, ensuring that all actions and resources are protected by appropriate access checks.
        * **Regular Audits:** Regularly audit RBAC configurations to ensure they are up-to-date and effective.
        * **Testing:** Thoroughly test RBAC implementation to ensure it works as expected.
        * **Least Privilege:** Grant users only the minimum necessary permissions.
        * **Use `can()`:** Always use the `can()` method to check user permissions before granting access to resources or actions.

