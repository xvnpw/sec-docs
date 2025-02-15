# Attack Surface Analysis for drapergem/draper

## Attack Surface: [1. Unintended Method Exposure](./attack_surfaces/1__unintended_method_exposure.md)

*   **Description:** Decorator methods intended for internal use or presentation logic are inadvertently exposed and can be called directly by an attacker.
*   **How Draper Contributes:** Draper's core functionality is to add methods to objects via decorators. The access control of these methods is the primary concern.
*   **Example:** A decorator has a `publish_draft` method that bypasses normal workflow checks if called directly. An attacker crafts a request that triggers this method.
*   **Impact:** Unauthorized actions, data modification, data leakage, bypass of business logic.
*   **Risk Severity:** High to Critical (depending on the exposed method's functionality).
*   **Mitigation Strategies:**
    *   **Strict Method Visibility:** Use `private` or `protected` for *any* decorator methods that are *not* intended to be called directly from the view or externally. Only make public the methods absolutely required for presentation.
    *   **Code Review:** Mandatory code reviews focusing on decorator method visibility and potential side effects. Ensure reviewers understand the intended use of each method.
    *   **Input Validation (Secondary):** While not the primary defense, validating input *within* the decorator method can provide an additional layer of protection. This is defense-in-depth.
    *   **Testing:** Thoroughly test all decorator methods, including negative testing with invalid and unexpected inputs.

## Attack Surface: [2. Object Masquerading / Type Confusion](./attack_surfaces/2__object_masquerading__type_confusion.md)

*   **Description:** The application logic incorrectly handles the decorated object as if it were the underlying model, leading to unexpected behavior or security bypasses.
*   **How Draper Contributes:** Draper wraps model objects, creating a distinct object type. Incorrect handling of this distinction is the root cause.
*   **Example:** An authorization check uses `decorated_user.admin?` instead of `user.admin?`. The decorator might not have an `admin?` method, or it might return a different value, leading to incorrect authorization.
*   **Impact:** Authorization bypasses, incorrect data access, unexpected application behavior.
*   **Risk Severity:** High to Critical (depending on the context where the type confusion occurs).
*   **Mitigation Strategies:**
    *   **Explicit Model Access:** When interacting with security-sensitive attributes or methods, *always* access the underlying model explicitly using `.object` or `.model`. For example: `decorated_user.object.admin?`.
    *   **Code Review:** Ensure code reviewers are aware of the distinction between decorated objects and models and check for correct usage in security-critical areas.

## Attack Surface: [3. `delegate` Misuse (Overly Permissive Delegation)](./attack_surfaces/3___delegate__misuse__overly_permissive_delegation_.md)

*   **Description:** The `delegate` method is used too broadly, exposing model methods through the decorator that should not be accessible.
*   **How Draper Contributes:** Draper's `delegate` feature provides a convenient way to forward method calls, but it can easily be misused to expose unintended functionality.
*   **Example:** `delegate :all` in a decorator exposes *all* methods of the underlying model, including potentially sensitive ones like `update_password` or `delete`.
*   **Impact:** Unauthorized access to model methods, data modification, data leakage, bypass of business logic.
*   **Risk Severity:** High to Critical (depending on the delegated methods).
*   **Mitigation Strategies:**
    *   **Explicit Delegation:** *Never* use `delegate :all`. Explicitly list the *specific* methods you want to delegate, and *only* if they are safe for public exposure. Example: `delegate :name, :email, to: :user`.
    *   **Code Review:** Scrutinize all uses of `delegate` during code reviews. Ensure that only safe and necessary methods are being delegated.
    *   **Consider Alternatives:** If possible, define methods directly in the decorator instead of delegating.

