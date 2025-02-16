# Mitigation Strategies Analysis for thoughtbot/factory_bot

## Mitigation Strategy: [Overly Permissive Factories](./mitigation_strategies/overly_permissive_factories.md)

**Mitigation Strategy:** Enforce the principle of least privilege in factory definitions and test usage.

**Description:**
1.  **Minimal Defaults:** Within factory definitions (`FactoryBot.define do ... end`), set only the *absolutely necessary* attributes to their default values. Avoid setting attributes like `is_admin` to `true` by default. Focus on creating the most basic, unprivileged object possible.
2.  **Explicit Overrides:** In tests, *always* explicitly set the values of attributes that are relevant to the test scenario using the `create` or `build` method's hash arguments. Do *not* rely on factory defaults for anything security-sensitive or that influences the test's outcome.
    ```ruby
    # Good
    user = create(:user, is_admin: false, email: "test@example.com")

    # Bad
    user = create(:user) # What are the defaults? Potentially dangerous.
    ```
3.  **Transient Attributes:** Use `transient` blocks within factory definitions for values that are needed during the factory's internal logic (e.g., to calculate a derived attribute) but should *not* be persisted to the database. This is crucial for things like raw passwords or temporary tokens.
    ```ruby
    FactoryBot.define do
      factory :user do
        transient do
          raw_password { "P@$$wOrd" } # This won't be saved to the DB
        end
        password { BCrypt::Password.create(raw_password) }
      end
    end
    ```
4.  **Code Reviews:** Mandatory code reviews for *all* factory definitions. Reviewers should specifically look for overly permissive defaults, missing explicit overrides in tests, and proper use of transient attributes. The review should focus on the security implications of the factory's design.

**Threats Mitigated:**
*   **Privilege Escalation (High):** Prevents accidental creation of overly privileged objects (e.g., admin users) that could be exploited.
*   **Data Exposure (Medium):** Reduces the risk of sensitive data (like default passwords) being inadvertently exposed or persisted.
*   **Data Integrity Issues (Medium):** Helps ensure test data is created with appropriate and expected values.

**Impact:**
*   **Privilege Escalation:** Risk significantly reduced (relies on developer diligence and code review effectiveness).
*   **Data Exposure:** Risk reduced, especially with consistent use of transient attributes.
*   **Data Integrity Issues:** Risk reduced.

**Currently Implemented:**
*   Minimal Defaults: Partially, some factories follow this, others don't.
*   Explicit Overrides: Inconsistently followed in tests.
*   Transient Attributes: Used in some factories, but not consistently.
*   Code Reviews: Implemented, but not always focused on factory security.

**Missing Implementation:**
*   Minimal Defaults: Needs a comprehensive review and refactoring of all factories.
*   Explicit Overrides: Needs enforcement through code style guidelines, linter rules, and developer training.
*   Transient Attributes: Needs consistent application across all factories where appropriate.
*   Code Reviews: Needs to explicitly include factory security checks as a mandatory part of the review process.

## Mitigation Strategy: [Sequence Misuse](./mitigation_strategies/sequence_misuse.md)

**Mitigation Strategy:** Introduce randomness into sequences to avoid predictable data generation, and avoid sequences for sensitive data.

**Description:**
1.  **Combine with Randomness:** When using `sequence` within a factory definition, incorporate random elements to make the generated values less predictable. This is especially important for attributes that might be used as identifiers or in security-related contexts.
    ```ruby
    FactoryBot.define do
      factory :user do
        sequence(:email) { |n| "user#{n}-#{SecureRandom.hex(8)}@example.com" }
        sequence(:username) { |n| "user_#{n}_#{rand(1000..9999)}" }
      end
    end
    ```
2.  **Avoid Sequences for Sensitive Data:** For attributes like API keys, tokens, or passwords, *do not* use `sequence`. Instead, generate these values *within the factory* using secure random number generators (e.g., `SecureRandom.hex`, `SecureRandom.uuid`). Do *not* store these directly as defaults; generate them each time.
    ```ruby
    FactoryBot.define do
      factory :api_key do
        token { SecureRandom.hex(32) } # Generate a new token each time
      end
    end
    ```
3.  **Consider Alternatives:** For identifiers, consider alternatives to sequences, such as using UUIDs (`SecureRandom.uuid`) which are inherently less predictable.

**Threats Mitigated:**
*   **Predictable Data (Low/Medium):** Reduces the risk of attackers predicting generated values.
*   **Enumeration Attacks (Low):** Makes it slightly harder to enumerate resources by guessing sequential IDs.

**Impact:**
*   **Predictable Data:** Risk reduced, especially with secure random generation for sensitive fields.
*   **Enumeration Attacks:** Provides a small degree of additional protection.

**Currently Implemented:**
*   Combine with Randomness: Partially implemented in some factories.
*   Avoid Sequences for Sensitive Data: Partially implemented; some sensitive fields still use sequences.
*   Consider Alternatives: Not consistently considered.

**Missing Implementation:**
*   Combine with Randomness: Needs a comprehensive review and refactoring of all factories using sequences.
*   Avoid Sequences for Sensitive Data: Needs a thorough audit and refactoring to use secure random generation for *all* sensitive fields within factories.
*   Consider Alternatives: Needs to be part of the design process for new factories and when refactoring existing ones.

## Mitigation Strategy: [Association Mismanagement](./mitigation_strategies/association_mismanagement.md)

**Mitigation Strategy:** Carefully define associations and use traits for variations within factory definitions.

**Description:**
1.  **Explicit Association Definitions:** Within factory definitions, be explicit about how associated objects are created. Avoid ambiguous or implicit associations that could lead to unexpected data relationships. Use clear and concise association declarations.
2.  **Use Traits:** If you need different variations of an associated object, use `trait` blocks within the factory definition. This avoids complex conditional logic within the main factory body and makes the factory's behavior more predictable and easier to understand.
    ```ruby
    FactoryBot.define do
      factory :post do
        title { "My Post" }

        trait :published do
          published_at { Time.current }
        end

        trait :with_comments do
          after(:create) do |post|
            create_list(:comment, 3, post: post) # Explicitly create associated comments
          end
        end
      end
    end
    ```
3.  **Code Reviews:** Code reviews should specifically check the correctness, consistency, and clarity of factory associations. Reviewers should ensure that associations are defined logically and that traits are used appropriately.

**Threats Mitigated:**
*   **Data Inconsistency (Medium):** Prevents the creation of invalid or inconsistent data due to poorly defined associations.
*   **Logic Errors (Medium):** Reduces the risk of logic errors in tests due to unexpected data relationships.
*   **Masking Vulnerabilities (Low):** Ensures tests use valid data, helping to uncover real vulnerabilities.

**Impact:**
*   **Data Inconsistency:** Risk significantly reduced with careful association definitions.
*   **Logic Errors:** Risk reduced.
*   **Masking Vulnerabilities:** Risk reduced.

**Currently Implemented:**
*   Explicit Association Definitions: Generally good, but could be improved in some areas.
*   Use Traits: Used in some factories, but not consistently.
*   Code Reviews: Implemented, but not always focused on factory association correctness.

**Missing Implementation:**
*   Explicit Association Definitions: Needs review of specific factories for potential ambiguities.
*   Use Traits: Needs more consistent application across factories.
*   Code Reviews: Needs to explicitly include factory association checks as a mandatory part of the review.

## Mitigation Strategy: [Code Injection via Factory Definitions](./mitigation_strategies/code_injection_via_factory_definitions.md)

**Mitigation Strategy:** Never construct factories from user input. This is a fundamental design principle.

**Description:**
1.  **Static Factory Definitions:** Factory definitions (`FactoryBot.define do ... end`) should *always* be static code within the codebase. They should *never* be dynamically generated from user input, configuration files parsed unsafely, or any external source that could be tampered with.
2.  **Avoid `eval` and Similar:** Absolutely avoid using `eval`, `instance_eval`, `class_eval`, `send`, or any other Ruby metaprogramming mechanism that could execute arbitrary code based on user input or external data within the context of factory definitions.

**Threats Mitigated:**
*   **Code Injection (Critical):** Prevents attackers from injecting arbitrary code into the application.

**Impact:**
*   **Code Injection:** Risk reduced to near zero (assuming the fundamental principle is followed).

**Currently Implemented:**
*   Static Factory Definitions: Yes.
*   Avoid `eval` and Similar: Yes.

**Missing Implementation:**
*   None (current implementation is secure). This is a core design principle that is already being followed.

