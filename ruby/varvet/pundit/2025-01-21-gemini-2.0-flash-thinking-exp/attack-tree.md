# Attack Tree Analysis for varvet/pundit

Objective: Compromise application authorization by exploiting weaknesses in Pundit.

## Attack Tree Visualization

```
* Compromise Application Authorization (Pundit Focused)
    * OR: *** Bypass Authorization Checks [CRITICAL] ***
        * AND: *** Missing Authorization Checks [CRITICAL] ***
            * - Forgetting `authorize` Call: Developers fail to include `authorize` in controller actions.
            * - Missing `policy_scope` Application: Failing to apply scopes when listing resources, exposing unauthorized items.
        * AND: *** Bypassing Controller Logic [CRITICAL] ***
            * - Direct Model Manipulation: Attacker finds ways to modify data directly without going through controller actions with authorization.
            * - Mass Assignment Vulnerabilities (related to Pundit context):  Exploiting mass assignment to modify attributes that influence policy evaluation without proper authorization.
    * OR: Exploit Scope Logic Flaws
        * AND: *** Inconsistent Scope Application [CRITICAL] ***
            * - Using Unscoped Queries: Developers directly query the database without applying the appropriate scope.
```


## Attack Tree Path: [Bypass Authorization Checks [CRITICAL]](./attack_tree_paths/bypass_authorization_checks__critical_.md)

This represents the overarching goal of bypassing Pundit's intended authorization mechanisms. Success here grants unauthorized access or the ability to perform forbidden actions.

* **Missing Authorization Checks [CRITICAL]**

    * **Forgetting `authorize` Call:**
        * **Attack Vector:** Developers simply omit the `authorize` call within a controller action that should be protected. This leaves the action completely open, allowing any authenticated user (or even unauthenticated users if authentication is also missing) to execute it.
        * **Example:** A developer forgets to call `authorize @post` in the `PostsController#edit` action, allowing any logged-in user to edit any post, regardless of the defined policy.

    * **Missing `policy_scope` Application:**
        * **Attack Vector:** When displaying lists of resources, developers fail to use `policy_scope`. This results in all records being returned, regardless of the user's authorization to view them.
        * **Example:**  In `UsersController#index`, if `User.all` is used instead of `policy_scope(User)`, a user might see a list of all users, including those they shouldn't have access to view.

* **Bypassing Controller Logic [CRITICAL]**

    * **Direct Model Manipulation:**
        * **Attack Vector:** Attackers find ways to interact with the application's data models directly, bypassing the controller layer where Pundit authorization checks are typically performed. This could involve exploiting vulnerabilities in the ORM or database access layer.
        * **Example:**  An attacker might craft a request that directly updates a database record, bypassing the controller action that would normally enforce authorization rules before the update.

    * **Mass Assignment Vulnerabilities (related to Pundit context):**
        * **Attack Vector:** Attackers exploit mass assignment vulnerabilities to modify model attributes that directly influence Pundit's policy evaluation. By manipulating these attributes, they can trick Pundit into granting unauthorized access.
        * **Example:** A `Post` model has an `is_published` attribute. The policy only allows admins to publish. If the `Post` model is vulnerable to mass assignment, an attacker might send a request setting `is_published` to `true`, bypassing the intended authorization flow in the `publish` action.

## Attack Tree Path: [Inconsistent Scope Application [CRITICAL]](./attack_tree_paths/inconsistent_scope_application__critical_.md)

This focuses on the risk of developers not consistently applying Pundit's scoping mechanisms, leading to unauthorized data access.

* **Using Unscoped Queries:**
    * **Attack Vector:** Developers directly query the database (e.g., using `Model.all`, `Model.where(...)`) without applying the `policy_scope`. This bypasses the intended filtering logic defined in Pundit policies, potentially exposing sensitive data.
    * **Example:** In a `DocumentsController`, a developer might use `Document.where(user_id: params[:user_id])` instead of `policy_scope(Document).where(user_id: params[:user_id])`. This could allow a user to see documents belonging to another user if they know their ID, even if the Pundit policy should restrict this access.

