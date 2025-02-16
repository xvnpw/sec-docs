# Mitigation Strategies Analysis for rails-api/active_model_serializers

## Mitigation Strategy: [Explicit Attribute Definition (Whitelist)](./mitigation_strategies/explicit_attribute_definition__whitelist_.md)

*   **Description:**
    1.  **Identify Sensitive Data:** Review each model and identify attributes that should *not* be exposed via the API.
    2.  **Create/Modify Serializers:** For each model, create or modify the corresponding serializer (`app/serializers`).
    3.  **Use `attributes` Method:** Within each serializer, use the `attributes` method to *explicitly* list *only* the attributes that *should* be included.
    4.  **Example:**
        ```ruby
        class UserSerializer < ActiveModelSerializer
          attributes :id, :username, :email # Only these!
        end
        ```
    5.  **Repeat:** Do this consistently for *all* serializers.
    6.  **Review:** Regularly review serializers.

*   **List of Threats Mitigated:**
    *   **Over-Exposure of Attributes (Data Leakage):** (Severity: **High**) Prevents unintended exposure of sensitive data.
    *   **Indirect Mass Assignment (via `include`):** (Severity: **Medium**) Reduces the attack surface, though strong parameters are the primary defense.

*   **Impact:**
    *   **Over-Exposure of Attributes:** Risk reduction: **High**. This is the *primary* defense.
    *   **Indirect Mass Assignment:** Risk reduction: **Medium**. Secondary defense.

*   **Currently Implemented:**
    *   `app/serializers/user_serializer.rb` (partially - only `id`, `username`, `email`).
    *   `app/serializers/product_serializer.rb` (fully - all exposed attributes defined).

*   **Missing Implementation:**
    *   `app/serializers/order_serializer.rb` (missing - exposes all attributes).
    *   `app/serializers/admin_user_serializer.rb` (missing - exposes all, highly dangerous).

## Mitigation Strategy: [Explicit Serializers for Associations](./mitigation_strategies/explicit_serializers_for_associations.md)

*   **Description:**
    1.  **Identify Associations:** In each serializer, identify all associations.
    2.  **Create Dedicated Serializers:** For *each* associated model, create a dedicated serializer.
    3.  **Specify Serializer:** Use the `serializer:` option to explicitly specify the serializer.
    4.  **Define Attributes:** Within the associated serializer, whitelist attributes.
    5.  **Example:**
        ```ruby
        class PostSerializer < ActiveModel::Serializer
          attributes :id, :title, :body
          belongs_to :author, serializer: AuthorSerializer # Explicit
        end

        class AuthorSerializer < ActiveModel::Serializer
          attributes :id, :name # Only name and ID
        end
        ```
    6.  **Avoid Default Serializers:** Do *not* rely on defaults.

*   **List of Threats Mitigated:**
    *   **Nested Association Over-Exposure:** (Severity: **High**) Prevents exposure of all attributes of associated models.
    *   **Indirect Mass Assignment (via `include`):** (Severity: **Medium**) Reduces risk.

*   **Impact:**
    *   **Nested Association Over-Exposure:** Risk reduction: **High**. Direct prevention.
    *   **Indirect Mass Assignment:** Risk reduction: **Medium**. Secondary defense.

*   **Currently Implemented:**
    *   `app/serializers/post_serializer.rb` (partially - uses `AuthorSerializer`, but review `AuthorSerializer`).

*   **Missing Implementation:**
    *   `app/serializers/comment_serializer.rb` (missing - includes `user` without serializer).
    *   `app/serializers/product_serializer.rb` (missing - includes `reviews` without serializer).

## Mitigation Strategy: [Conditional Attributes](./mitigation_strategies/conditional_attributes.md)

*   **Description:**
    1.  **Identify Context-Dependent Attributes:** Determine attributes exposed only under conditions.
    2.  **Use `:if` or `:unless`:** Use these options with `attribute`.
    3.  **Define Predicate Methods:** Create methods (e.g., `current_user_is_admin?`) returning `true/false`. Access `scope`.
    4.  **Example:**
        ```ruby
        class UserSerializer < ActiveModel::Serializer
          attributes :id, :username, :email
          attribute :admin_notes, if: :current_user_is_admin?

          def current_user_is_admin?
            scope.try(:current_user)&.admin? # Access from scope
          end
        end
        ```
    5. **Ensure Scope is Available:** Ensure context (e.g., `current_user`) is in `scope`.

*   **List of Threats Mitigated:**
    *   **Over-Exposure of Attributes (Data Leakage):** (Severity: **Medium**) Prevents exposure based on context.

*   **Impact:**
    *   **Over-Exposure of Attributes:** Risk reduction: **Medium**. Granular control.

*   **Currently Implemented:**
    *   None (no conditional attributes used).

*   **Missing Implementation:**
    *   `app/serializers/user_serializer.rb` (expose `email` conditionally).
    *   `app/serializers/order_serializer.rb` (expose `shipping_address` conditionally).

## Mitigation Strategy: [Limit Nesting Depth](./mitigation_strategies/limit_nesting_depth.md)

*   **Description:**
    1.  **Review Serializer Structure:** Identify deeply nested associations.
    2.  **Refactor if Necessary:** Reduce nesting:
        *   Separate API endpoints.
        *   Flatter structures.
        *   Links instead of embedding.
    3.  **Justify Deep Nesting:** If unavoidable, justify and ensure explicit attributes.

*   **List of Threats Mitigated:**
    *   **Nested Association Over-Exposure:** (Severity: **Medium**) Reduces complexity.
    *   **Performance Issues:** (Severity: **Low**) Deep nesting can be slow.

*   **Impact:**
    *   **Nested Association Over-Exposure:** Risk reduction: **Medium**. Easier control.
    *   **Performance Issues:** Risk reduction: **Low to Medium**.

*   **Currently Implemented:**
    *   Generally good - limited nesting (1-2 levels).

*   **Missing Implementation:**
    *   `app/serializers/project_serializer.rb` (nested `tasks` -> `comments` - refactor).

## Mitigation Strategy: [Read-Only Serializers (Defense in Depth)](./mitigation_strategies/read-only_serializers__defense_in_depth_.md)

*   **Description:**
    1.  **Identify Read-Only Use Cases:** Determine serializers *only* for display.
    2.  **Restrict Attributes:** Include *only* necessary attributes. Avoid updatable ones.
    3.  **Consider Naming Conventions:**  e.g., `PostReadSerializer`.

*   **List of Threats Mitigated:**
    *   **Indirect Mass Assignment (via `include`):** (Severity: **Low**) Additional defense.

*   **Impact:**
    *   **Indirect Mass Assignment:** Risk reduction: **Low**. Defense-in-depth.

*   **Currently Implemented:**
    *   None (no explicit read-only serializers).

*   **Missing Implementation:**
    *   Create `PostReadSerializer` (only `id`, `title`, `body`, limited `AuthorReadSerializer`).

## Mitigation Strategy: [Proper Context in Background Jobs](./mitigation_strategies/proper_context_in_background_jobs.md)

*   **Description:**
    1. **Identify Background Serializations:** Find serializers used outside controllers (e.g., Sidekiq, Active Job).
    2. **Pass Context Explicitly:** Pass context (e.g., current user) via `scope`.
    3. **Example:**
        ```ruby
        # app/jobs/send_email_job.rb
        class SendEmailJob < ApplicationJob
          def perform(user_id)
            user = User.find(user_id)
            serializer = UserSerializer.new(user, scope: { current_user: user }) # Pass context
            serialized_user = serializer.as_json
            # ...
          end
        end
        ```
    4. **Consider Alternative Serializers:** If needed, create simpler serializers for background use.

*   **List of Threats Mitigated:**
    *   **Over-Exposure of Attributes (Data Leakage) due to Missing Context:** (Severity: **Medium**) Prevents issues with missing context.

*   **Impact:**
    *   **Over-Exposure of Attributes:** Risk reduction: **Medium**. Correct behavior outside controllers.

*   **Currently Implemented:**
    *   Partially - some jobs pass context, not consistently.

*   **Missing Implementation:**
    *   `app/jobs/generate_report_job.rb` (missing context).
    *   Review all background jobs using serializers.

