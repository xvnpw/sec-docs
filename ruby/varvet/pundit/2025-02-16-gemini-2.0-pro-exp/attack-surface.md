# Attack Surface Analysis for varvet/pundit

## Attack Surface: [1. Incorrectly Implemented Policy Methods (Logic Errors)](./attack_surfaces/1__incorrectly_implemented_policy_methods__logic_errors_.md)

*   **Description:** Flaws in the boolean logic, attribute comparisons, or edge case handling within Pundit policy methods, leading to incorrect authorization decisions.  This is the *core* area where Pundit-specific vulnerabilities arise.
    *   **How Pundit Contributes:** Pundit provides the framework, but the developer defines the authorization rules within the policy methods.  Errors *here* are directly attributable to how Pundit is used.
    *   **Example:**
        ```ruby
        # Policy for deleting a Comment
        class CommentPolicy < ApplicationPolicy
          def destroy?
            user.admin? || user.id == @record.post.user_id # Incorrect! Should be @record.user_id
          end
        end
        ```
        This allows any user who owns the *post* to delete *any* comment on that post, even if they didn't write the comment.
    *   **Impact:** Unauthorized access to data (read, create, update, delete), potentially leading to data breaches, data corruption, or privilege escalation.  The impact is directly tied to the flawed logic.
    *   **Risk Severity:** **Critical** to **High** (depending on the specific logic flaw and the sensitivity of the data/actions).
    *   **Mitigation Strategies:**
        *   **Rigorous Code Reviews:**  Multiple reviewers, focusing intensely on the boolean logic, attribute comparisons, and all potential edge cases within *each* policy method.
        *   **Comprehensive Unit Testing:**  Write unit tests for *every* policy method, covering *all* possible user roles, object states, and edge cases.  Use `pundit-matchers` to simplify and standardize testing.  Consider property-based testing.
        *   **Consistent Naming and Structure:**  Adopt a clear and consistent naming convention for policy methods and attributes to minimize confusion and errors.
        *   **Static Analysis (where applicable):**  Explore linters or static analysis tools that *might* detect some logic errors or inconsistencies in policy code (though this is less reliable than thorough testing and review).

## Attack Surface: [2. Missing `authorize` Call or Incorrect Policy Method Invocation](./attack_surfaces/2__missing__authorize__call_or_incorrect_policy_method_invocation.md)

*   **Description:**  Forgetting to call `authorize` in a controller action, or calling it with the wrong arguments (e.g., missing the policy method name or using incorrect syntax), leading to *completely bypassed* authorization checks.
    *   **How Pundit Contributes:** Pundit *requires* explicit `authorize` calls to enforce authorization.  Missing or incorrect calls directly circumvent Pundit's intended functionality.
    *   **Example:**
        ```ruby
        # Controller action
        def destroy
          @post = Post.find(params[:id])
          # authorize @post, :destroy?  <-- MISSING!  Authorization is bypassed.
          @post.destroy
          redirect_to posts_path
        end
        ```
        Or:
        ```ruby
        authorize @post  # Incorrect - should be authorize @post, :destroy?
        ```
    *   **Impact:**  Completely unauthorized access to actions and data.  This is a *critical* bypass of the authorization system.
    *   **Risk Severity:** **Critical**
    *   **Mitigation Strategies:**
        *   **Mandatory `after_action :verify_authorized`:**  Use this callback in `ApplicationController` (or relevant base controllers) to *force* a check that `authorize` has been called in every action.  This is a crucial preventative measure.
        *   **Code Reviews:**  Carefully review *all* controller actions to ensure that `authorize` is called correctly, with the appropriate policy method.
        *   **Automated Testing:**  Write integration tests that specifically check for unauthorized access when `authorize` is missing or incorrect.  These tests should attempt to access actions without proper authorization.
        *   **Linters/Static Analysis:**  Use tools that can reliably detect missing or incorrect `authorize` calls.

## Attack Surface: [3. Incorrect Scope Resolution (Information Disclosure)](./attack_surfaces/3__incorrect_scope_resolution__information_disclosure_.md)

*   **Description:** Errors in `Policy::Scope` classes that result in users seeing more data than they should, leading to information disclosure. This is a direct misuse of Pundit's scoping mechanism.
    *   **How Pundit Contributes:** Pundit's `Policy::Scope` classes are *specifically designed* to filter collections of records based on user authorization. Incorrect filtering logic within these classes is a direct Pundit-related vulnerability.
    *   **Example:**
        ```ruby
        # Policy scope for Posts
        class PostPolicy < ApplicationPolicy
          class Scope < Scope
            def resolve
              scope.all # Incorrect!  Returns ALL posts, regardless of user permissions.
            end
          end
        end
        ```
    *   **Impact:** Information disclosure, potentially revealing sensitive data to unauthorized users. The severity depends on the data exposed.
    *   **Risk Severity:** **High**
    *   **Mitigation Strategies:**
        *   **Thorough Testing:** Write specific tests for *each* `Policy::Scope` class, verifying that *only* the expected records are returned for *different* user roles and contexts.  This is crucial.
        *   **Code Reviews:** Carefully review the `resolve` method in *each* scope class, focusing intensely on the filtering logic and ensuring it correctly restricts access based on user permissions and relationships.
        *   **Database Query Analysis:** Examine the generated SQL queries (e.g., using database logging or profiling tools) to ensure they are efficient and, more importantly, do *not* inadvertently expose data.

## Attack Surface: [4. Overly Permissive Default Policy](./attack_surfaces/4__overly_permissive_default_policy.md)

*   **Description:** If a specific policy method is not defined, Pundit may fall back to a default policy (e.g., `ApplicationPolicy`). If this default policy is too permissive (e.g., allows access by default), it can lead to unauthorized access.
    *   **How Pundit Contributes:** Pundit's policy resolution mechanism can fall back to default policies if specific methods are not found. This fallback behavior, if misconfigured, is a direct source of vulnerability.
    *   **Example:**
        ```ruby
        # ApplicationPolicy (default)
        class ApplicationPolicy
          def create?
            true # Allows access by default - TOO PERMISSIVE!
          end
        end
        ```
        If a specific policy (e.g., `ProductPolicy`) does *not* define a `create?` method, this overly permissive default would be used, allowing any user to create products.
    *   **Impact:** Unauthorized access to actions and data, particularly if developers forget to define specific policy methods.
    *   **Risk Severity:** **High**
    *   **Mitigation Strategies:**
        *   **Restrictive Default Policies:** Ensure that default policies (e.g., `ApplicationPolicy`) are as restrictive as possible, ideally denying access by default for *all* actions. This is a crucial preventative measure.
            ```ruby
            class ApplicationPolicy
              def index?; false; end
              def show?; false; end
              def create?; false; end
              def update?; false; end
              def destroy?; false; end
              # ... deny access by default for all other actions
            end
            ```
        *   **Explicit Policy Methods:** Define *all* required policy methods explicitly in *each* policy class, rather than relying on defaults. This eliminates the risk of the fallback mechanism.

