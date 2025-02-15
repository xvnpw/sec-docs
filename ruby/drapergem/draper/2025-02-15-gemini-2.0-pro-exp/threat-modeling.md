# Threat Model Analysis for drapergem/draper

## Threat: [Unauthorized Data Exposure via Decorator Method](./threats/unauthorized_data_exposure_via_decorator_method.md)

*   **Description:** An attacker, authenticated or unauthenticated, accesses a view or API endpoint that uses a Draper decorator. The decorator method (e.g., `full_address`, `admin_notes`) exposes sensitive information (e.g., PII, internal IDs, financial data) that the attacker should not have access to, based on their role or permissions. The attacker might inspect the HTML source, API response, or JavaScript variables to obtain this data.
*   **Impact:** Information disclosure, leading to potential privacy violations, data breaches, financial loss, reputational damage, or legal consequences.
*   **Affected Draper Component:** Decorator methods (instance methods defined within the decorator class). Specifically, any method that returns data derived from the decorated object or its associations.
*   **Risk Severity:** Critical (if exposing highly sensitive data) or High (if exposing less sensitive but still confidential data).
*   **Mitigation Strategies:**
    *   **Implement granular authorization checks *inside* the decorator method:** Use `current_user` (or equivalent) and a policy object (Pundit, CanCanCan) to verify access *before* returning sensitive data.  Example:
        ```ruby
        def admin_notes
          return unless context[:current_user]&.admin?
          object.internal_notes
        end
        ```
    *   **Use conditional logic:** Return different values based on user roles.
        ```ruby
        def display_name
          if context[:current_user]&.admin?
            "#{object.first_name} #{object.last_name} (ID: #{object.id})"
          else
            object.first_name
          end
        ```
    *   **Create separate decorator methods for different contexts:** Instead of one `full_address` method, have `public_address` and `private_address`.
    *   **Never expose raw model attributes directly:** Always use dedicated methods to control what is returned.
    *   **Sanitize and escape output:** Even if data is authorized, ensure it's properly escaped to prevent XSS vulnerabilities (though this is a general web security concern, it's relevant here and reinforces the importance of defense in depth).
    *   **Review all decorator methods regularly:** Conduct code reviews focusing on data exposure.

## Threat: [Indirect Privilege Escalation via Decorator Logic](./threats/indirect_privilege_escalation_via_decorator_logic.md)

*   **Description:**  A low-privileged user accesses a view or API endpoint that uses a Draper decorator.  The decorator method, *incorrectly*, performs an action that requires higher privileges (e.g., updating a record without proper authorization checks, accessing a restricted resource). The attacker gains access to functionality or data they should not have.  This is often due to a developer mistakenly assuming controller-level authorization is sufficient.
*   **Impact:** Privilege escalation, allowing the attacker to perform unauthorized actions.
*   **Affected Draper Component:** Decorator methods (instance methods) that contain logic that modifies data or interacts with other services.
*   **Risk Severity:** Critical.
*   **Mitigation Strategies:**
    *   **Replicate Authorization Checks:**  Mirror *all* authorization checks from the controller and model *within* the decorator method.  Never assume that controller-level checks are enough.
    *   **Delegate to Authorized Services:** If a decorator needs to perform a privileged action, delegate that action to a separate service class or model method that *does* have the necessary authorization checks.  The decorator should *not* perform the action directly.
    *   **Avoid Modifying Data in Decorators:**  Ideally, decorators should *not* modify data at all.  If modification is absolutely necessary (strongly discouraged), it should be done through a properly authorized service or model method.
    *   **Code Reviews:**  Thoroughly review decorator code for any logic that could potentially bypass authorization.

## Threat: [Denial of Service via Expensive Decorator Calculation](./threats/denial_of_service_via_expensive_decorator_calculation.md)

*   **Description:** An attacker repeatedly requests a page or API endpoint that uses a Draper decorator. The decorator contains a method that performs a computationally expensive operation, such as a complex database query, a large number of calculations, or an external API call *without caching*. The attacker's repeated requests overwhelm the server, causing it to become unresponsive to legitimate users.
*   **Impact:** Denial of service, making the application unavailable to users.
*   **Affected Draper Component:** Decorator methods (instance methods) that perform computationally expensive operations.
*   **Risk Severity:** High.
*   **Mitigation Strategies:**
    *   **Caching:** Use Rails' built-in caching mechanisms (e.g., `Rails.cache.fetch`) to store the results of expensive calculations.
        ```ruby
        def complex_calculation
          Rails.cache.fetch("complex_calc_#{object.id}", expires_in: 1.hour) do
            # ... expensive operation ...
          end
        end
        ```
    *   **Background Jobs:** Offload expensive operations to a background job queue (e.g., Sidekiq, Resque). The decorator method would then return a placeholder or a status indicator.
    *   **Eager Loading:** If the decorator accesses associated models, use eager loading (`includes`, `preload`, `eager_load`) in the controller to avoid N+1 query problems.
    *   **Rate Limiting:** Implement rate limiting at the controller or application level (e.g., using the `rack-attack` gem) to prevent attackers from making too many requests. This is a general mitigation, but it's *crucial* in this context.
    *   **Optimize Code:** Profile the decorator method and identify performance bottlenecks. Refactor the code to be more efficient.
    *   **Avoid Unnecessary Operations:** Ensure the decorator method only performs the calculations that are absolutely necessary for the current view or context.

