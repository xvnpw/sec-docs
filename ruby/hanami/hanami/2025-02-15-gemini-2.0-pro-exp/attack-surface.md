# Attack Surface Analysis for hanami/hanami

## Attack Surface: [Overly Permissive Routes](./attack_surfaces/overly_permissive_routes.md)

*   **Description:** Unintentionally exposing actions due to misconfigured routes, allowing unauthorized access to functionality.
*   **How Hanami Contributes:** Hanami's flexible routing system requires careful configuration. The framework's expressiveness allows for broad matching patterns, which, if misused, can lead to unintended exposure. This is a direct consequence of Hanami's routing design.
*   **Example:**
    ```ruby
    # config/routes.rb
    get "/admin/:anything", to: "admin#show"  # Too broad!
    ```
    This route would match *any* path starting with `/admin/`, potentially exposing sensitive actions.
*   **Impact:** Unauthorized access to sensitive data or functionality, potential data breaches, privilege escalation.
*   **Risk Severity:** High to Critical (depending on the exposed functionality).
*   **Mitigation Strategies:**
    *   **Developer:** Define routes with *precise* constraints (e.g., `get "/admin/users/:id", to: "admin#show", constraints: { id: /\d+/ }`).  Use regular expressions to restrict parameter values.
    *   **Developer:** Use named routes and helpers to avoid hardcoding and reduce errors.
    *   **Developer:** Thoroughly test routes, including *negative tests* (testing invalid inputs and unexpected paths).
    *   **Developer:** Regularly review the routing table using `hanami routes` to verify the exposed endpoints.
    *   **Developer:** Implement robust authorization checks *within* actions, *even if* routes appear correct.  Do *not* rely solely on routing for access control. This is crucial.

## Attack Surface: [Action Input Validation Bypass (Hanami-Specific)](./attack_surfaces/action_input_validation_bypass__hanami-specific_.md)

*   **Description:** Circumventing Hanami's input validation within actions, leading to processing of malicious or unexpected data.
*   **How Hanami Contributes:** Hanami *provides* validation mechanisms, but it's the developer's responsibility to use them correctly.  Directly accessing `request.params` *bypasses* Hanami's validation, which is a key Hanami-specific risk.
*   **Example:**
    ```ruby
    # app/actions/users/create.rb
    class Create < Hanami::Action
      def call(request)
        # BAD: Accessing raw params, bypassing validation
        user = User.new(request.params)
        user.save
        # ...
      end
    end
    ```
    This completely bypasses any validation schema defined for the `Create` action, a direct misuse of Hanami's action structure.
*   **Impact:**  Various vulnerabilities depending on the unvalidated input, including XSS, SQL injection, command injection, etc.
*   **Risk Severity:** High to Critical (depending on the nature of the unvalidated input).
*   **Mitigation Strategies:**
    *   **Developer:** *Always* use Hanami's validation schemas to define expected input for *every* action.
    *   **Developer:** Access parameters *exclusively* through the validated `params` object provided by Hanami *after* validation. This is the core mitigation.
    *   **Developer:** Handle validation errors appropriately (e.g., return 422 Unprocessable Entity with error messages).
    *   **Developer:** Never trust client-side validation alone; server-side validation within the Hanami action is mandatory.

## Attack Surface: [Secret Exposure in Configuration (Hanami Context)](./attack_surfaces/secret_exposure_in_configuration__hanami_context_.md)

*   **Description:**  Improperly storing or handling sensitive information within Hanami's configuration system.
*   **How Hanami Contributes:** Hanami applications rely on configuration files (often `.env` and environment variables). While not unique to Hanami, the *way* Hanami applications are structured and deployed makes this a relevant concern. Misconfiguration within the Hanami context is the risk.
*   **Example:**
    *   Storing a database password directly in `config/app.rb` (a Hanami configuration file).
    *   Committing a `.env` file containing secrets to version control (affecting the Hanami application's deployment).
*   **Impact:**  Compromise of sensitive data, unauthorized access to external services, complete system compromise.
*   **Risk Severity:** Critical.
*   **Mitigation Strategies:**
    *   **Developer:** *Never* store secrets directly in the codebase (especially within Hanami configuration files).
    *   **Developer/User:** Use environment variables to store secrets.
    *   **Developer/User:** Ensure `.env` files are *explicitly excluded* from version control (e.g., using `.gitignore`) and are properly secured on the server (correct file permissions, restricted access).
    *   **User (Production):** Use a dedicated secrets management solution (e.g., HashiCorp Vault, AWS Secrets Manager, etc.) for production deployments of the Hanami application.

## Attack Surface: [Unsafe Operations within Interactors (Hanami-Specific)](./attack_surfaces/unsafe_operations_within_interactors__hanami-specific_.md)

*   **Description:** Interactors performing unsafe operations without proper validation or sanitization, leading to various vulnerabilities.
*   **How Hanami Contributes:** Hanami *encourages* the use of interactors to encapsulate business logic.  However, the framework itself does *not* enforce security *within* interactors; it's entirely the developer's responsibility to write secure interactor code. This is a Hanami-specific architectural concern.
*   **Example:** An interactor directly executing SQL queries based on user input without parameterization, *bypassing* any repository-level protections.
    ```ruby
        # app/interactors/find_user.rb
        class FindUser
          include Hanami::Interactor

          expose :user

          def call(id:)
            # DANGEROUS: Unsafe SQL query, bypassing any repository
            @user = DB.execute("SELECT * FROM users WHERE id = #{id}")
          end
        end
    ```
*   **Impact:** SQL injection, path traversal, SSRF, and other injection vulnerabilities, depending on the unsafe operation.  This can bypass security measures in other layers.
*   **Risk Severity:** High to Critical.
*   **Mitigation Strategies:**
    *   **Developer:** Apply the *same* security best practices within interactors as in actions: rigorous input validation, sanitization, parameterized queries, etc.
    *   **Developer:** Prefer using Hanami's provided abstractions (e.g., repositories) for data access rather than directly interacting with low-level APIs (database, file system) within interactors.
    *   **Developer:** Thoroughly review and test *all* interactors for security vulnerabilities, treating them as potential entry points for attacks. Code reviews are essential.

