# Attack Surface Analysis for thoughtbot/factory_bot

## Attack Surface: [Overly Permissive Object Creation](./attack_surfaces/overly_permissive_object_creation.md)

*   **Description:** Factories create objects with attributes or permissions that exceed the minimum required, bypassing intended security controls.
*   **How `factory_bot` Contributes:** `factory_bot` provides the mechanism to easily create these overly permissive objects, often through default attribute values or easily misused traits.
*   **Example:** A `User` factory defaults to `admin: true`, or a `Post` factory bypasses content validation, allowing creation of posts with malicious scripts.
    ```ruby
    # Vulnerable Factory
    FactoryBot.define do
      factory :user do
        admin { true } # Defaulting to admin is dangerous
        password { "password" } # Weak password
      end
    end
    ```
*   **Impact:** Unauthorized access to sensitive data or functionality, privilege escalation, data corruption, XSS (if bypassing content validation).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Least Privilege Defaults:** Factories should default to the *least* privileged state.  Explicitly set attributes to restrictive values (e.g., `admin: false`).
    *   **Trait-Based Privileges:** Use traits for elevated privileges (e.g., `trait :admin do; admin true; end`).  Require explicit use of these traits.
    *   **Enforce Model Validations:** Ensure factories *do not* bypass model validations. Use `build` or `build_stubbed` and manually validate if necessary.
    *   **Code Reviews:** Mandatory code reviews for all factory definitions, focusing on defaults and attribute assignments.
    *   **Linting:** Implement custom linters to flag potentially dangerous factory defaults.

## Attack Surface: [Unintended Data Relationships](./attack_surfaces/unintended_data_relationships.md)

*   **Description:** Factories create associated objects in ways that bypass authorization checks or create unexpected data dependencies.
*   **How `factory_bot` Contributes:** `factory_bot`'s association features can be misused to automatically create associated objects without proper security considerations.
*   **Example:** A `Comment` factory automatically creates an associated `User` with `admin: true`, or a `Project` factory creates associated `Task` objects that bypass project-level access controls.
    ```ruby
    # Vulnerable Factory
    FactoryBot.define do
      factory :comment do
        association :user, factory: :admin_user # Automatically creates an admin user
        body { "Some comment" }
      end
    end
    ```
*   **Impact:** Unauthorized access to data, data leakage, violation of data integrity constraints.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Explicit Associations:** Avoid automatic creation of associated objects unless strictly necessary and thoroughly reviewed.
    *   **Controlled Association Factories:** Use separate, well-defined factories for associated objects, ensuring *those* factories adhere to least privilege.
    *   **Review Association Logic:** Carefully review how associations are handled within factories.

## Attack Surface: [Predictable Sequence Misuse](./attack_surfaces/predictable_sequence_misuse.md)

*   **Description:** Using predictable sequences for sensitive fields, allowing attackers to guess valid values.
*   **How `factory_bot` Contributes:** `factory_bot`'s `sequence` feature can be misused to generate predictable values for fields that should be unpredictable.
*   **Example:** Using a sequence for an API key, a password reset token, or a user ID (in some contexts).
    ```ruby
    # Vulnerable Factory
    FactoryBot.define do
      factory :api_key do
        sequence(:token) { |n| "API-KEY-#{n}" } # Predictable token
      end
    end
    ```
*   **Impact:** Unauthorized access, impersonation, data breaches.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Avoid Sequences for Sensitive Data:** Use secure random number generators (e.g., `SecureRandom.hex`) for sensitive fields.
    *   **Complex Sequences (Non-Sensitive Data):** If sequences *must* be used, use complex, non-linear progressions.
    *   **Audit Sequence Usage:** Review all uses of `sequence`.

## Attack Surface: [Factory Code Exposure in Production](./attack_surfaces/factory_code_exposure_in_production.md)

*   **Description:** Factory definitions are accessible or executable in the production environment.
*   **How `factory_bot` Contributes:** This is a configuration and deployment issue, but `factory_bot` is the tool that would be exploited if exposed.
*   **Example:** An attacker discovers a route or endpoint that allows them to invoke factory methods, creating users or manipulating data.
*   **Impact:** Complete system compromise, data breaches, data corruption, denial of service.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strict Environment Separation:** Ensure `factory_bot` is *only* loaded in `test` and `development` environments (Gemfile, Rails configuration).
    *   **Deployment Verification:** Verify that factory files are *not* included in the production build.
    *   **Secure Test Endpoints:** Secure any test-related endpoints, even in development.

## Attack Surface: [Seed Data Vulnerabilities](./attack_surfaces/seed_data_vulnerabilities.md)

*   **Description:** Factories used to generate seed data introduce vulnerabilities into the application.
*   **How `factory_bot` Contributes:** `factory_bot` is used as the mechanism to create the potentially vulnerable seed data.
*   **Example:** A factory creates a seed user with a weak password or an administrator account with default credentials.
*   **Impact:**  Compromised seed accounts, potential for privilege escalation or data breaches.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Review Seed Data Generation:** Carefully review scripts using factories for seed data.
    *   **Production Security Standards:** Apply the same security standards to seed data generation as to production code.  Use strong, randomly generated passwords and avoid default credentials.
    * **Avoid Seeding Sensitive Data:** Do not seed production databases with sensitive data. If necessary, use placeholder data or anonymization techniques.

