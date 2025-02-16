# Mitigation Strategies Analysis for norman/friendly_id

## Mitigation Strategy: [Enforce Uniqueness within `friendly_id` Configuration](./mitigation_strategies/enforce_uniqueness_within__friendly_id__configuration.md)

**Description:** This strategy leverages `friendly_id`'s built-in features to manage slug uniqueness, including scopes and conflict resolution.

1.  **Application-Level Validation (using `friendly_id`):**
    *   **Step 1 (Developer):** In your ActiveRecord model, use the `validates` clause *in conjunction with* `friendly_id`.
        ```ruby
        class YourModel < ApplicationRecord
          extend FriendlyId
          friendly_id :name, use: :slugged # Or your configuration

          validates :slug, presence: true, uniqueness: { scope: :your_scope, case_sensitive: false }
        end
        ```
    *   **Step 2 (Developer):**  If you have a custom scope, replace `:your_scope` with the actual scope (e.g., `:user_id`, `[:category_id, :year]`).  If you don't have a scope, remove the `scope` option.  This is *crucial* for preventing collisions within the intended scope.
    *   **Step 3 (Developer):** Ensure `case_sensitive: false` is set unless you *specifically* need case-sensitive slugs (which is rare and generally discouraged).
2.  **Handle Uniqueness Failures Gracefully (within `friendly_id`):**
    *   **Step 1 (Developer):**  Understand `friendly_id`'s default conflict resolution behavior.  It typically appends a sequence number or UUID to make the slug unique.  Read the `friendly_id` documentation on conflict resolution.
    *   **Step 2 (Developer):**  If you need *custom* retry logic, override the `should_generate_new_friendly_id?` method in your model.  This allows you to control *when* a new slug is generated.
        ```ruby
        def should_generate_new_friendly_id?
          name_changed? || super # Regenerate if name changes, or if friendly_id decides it's needed
        end
        ```
    *   **Step 3 (Developer):** You can also customize the `normalize_friendly_id` method to control *how* the slug is generated, including how conflicts are resolved.  This is more advanced and rarely needed.

*   **Threats Mitigated:**
    *   **Slug Uniqueness Violations (within `friendly_id`'s scope):** (Severity: High) - Prevents data corruption, incorrect record retrieval, and application errors caused by duplicate slugs *within the defined scope*.
    *   **Incorrect Record Retrieval (within scope):** (Severity: High) - Ensures that users are directed to the correct record when using a slug, *considering the defined scope*.

*   **Impact:**
    *   **Slug Uniqueness Violations (within scope):** Risk significantly reduced (effectiveness depends on correct scope definition).
    *   **Incorrect Record Retrieval (within scope):** Risk significantly reduced.

*   **Currently Implemented:**
    *   Application-Level Validation: Yes, in `app/models/post.rb`
    *   Handle Uniqueness Failures Gracefully: Partially, relying on `friendly_id`'s default behavior.

*   **Missing Implementation:**
    *   Custom retry logic (overriding `should_generate_new_friendly_id?`) is missing.  We should evaluate if the default behavior is sufficient.

## Mitigation Strategy: [Strengthen Slug Generation with `friendly_id`](./mitigation_strategies/strengthen_slug_generation_with__friendly_id_.md)

**Description:** This strategy uses `friendly_id`'s features to create less predictable slugs, making them harder to guess.

1.  **Use `SecureRandom` (within `slug_candidates`):**
    *   **Step 1 (Developer):**  Modify your `slug_candidates` method in your model to include a `SecureRandom` component.  This is *essential* if your slug isn't solely based on a user-provided, unpredictable attribute.
        ```ruby
        # app/models/your_model.rb
        friendly_id :slug_candidates, use: :slugged

        def slug_candidates
          [
            :name,
            [:name, SecureRandom.hex(8)],  # Append 8 random hex characters
            [:name, SecureRandom.uuid]     # Or, append a UUID
          ]
        end
        ```
    *   **Step 2 (Developer):**  Choose an appropriate level of randomness (e.g., `hex(8)`, `uuid`).  Longer is generally better for security.  This makes the slug less predictable even if the `name` is guessable.
2.  **Avoid Predictable Patterns (in `slug_candidates`):**
    *   **Step 1 (Developer):**  *Never* use sequential IDs or timestamps alone as the *sole* basis for slugs within the `slug_candidates` array.
    *   **Step 2 (Developer):**  If using timestamps, *always* combine them with a random component (e.g., `SecureRandom.hex`) within the `slug_candidates` array.

*   **Threats Mitigated:**
    *   **Slug Generation Predictability:** (Severity: Medium) - Makes it harder for attackers to guess valid slugs.
    *   **Resource Enumeration:** (Severity: Medium) - Prevents attackers from systematically trying different slugs to discover all resources.

*   **Impact:**
    *   **Slug Generation Predictability:** Risk significantly reduced.
    *   **Resource Enumeration:** Risk significantly reduced.

*   **Currently Implemented:**
    *   Using `slug_candidates` with `:name` in `app/models/post.rb`.  This is *partially* implemented.

*   **Missing Implementation:**
    *   We are *not* currently appending a `SecureRandom` component to the `slug_candidates`.  This is a **critical missing piece** and should be implemented immediately.  We need to modify the `slug_candidates` method in `app/models/post.rb`.

## Mitigation Strategy: [Utilize `friendly_id`'s History Module](./mitigation_strategies/utilize__friendly_id_'s_history_module.md)

**Description:** This strategy uses `friendly_id`'s `:history` module to handle slug changes gracefully and prevent broken links.

1.  **Enable the History Module:**
    *   **Step 1 (Developer):**  Include the `:history` module in your `friendly_id` configuration.
        ```ruby
        # app/models/your_model.rb
        friendly_id :name, use: [:slugged, :history]
        ```
    *   **Step 2 (Developer):**  Run the `friendly_id` generator to create the necessary migration: `rails generate friendly_id`
    *   **Step 3 (Developer):**  Run the migration: `rails db:migrate`
2.  **Understand Redirect Behavior:**
    *   **Step 1 (Developer):**  `friendly_id` will automatically create records in the `friendly_id_slugs` table when a slug changes.
    *   **Step 2 (Developer):**  When you use `YourModel.friendly.find(old_slug)`, `friendly_id` will automatically find the correct record, even if the slug has changed.  It handles the redirection internally.

*   **Threats Mitigated:**
    *   **Broken Links After Slug Changes:** (Severity: Medium) - Prevents broken links if a slug is updated.
    *   **SEO Issues After Slug Changes:** (Severity: Medium) - Maintains SEO by allowing search engines to find the content even after a slug change.

*   **Impact:**
    *   **Broken Links:** Risk significantly reduced.
    *   **SEO Issues:** Risk significantly reduced.

*   **Currently Implemented:**
    *   We are using the `:history` module in `app/models/post.rb`.  The migration has been run.

*   **Missing Implementation:**
    *   None. This strategy is fully implemented.

## Mitigation Strategy: [Customize Slug Generation with `normalize_friendly_id` (Advanced)](./mitigation_strategies/customize_slug_generation_with__normalize_friendly_id___advanced_.md)

**Description:**  This strategy involves overriding the `normalize_friendly_id` method to have fine-grained control over how slugs are generated, including sanitization and conflict resolution.  This is generally *not* needed if you're using `slug_candidates` and basic sanitization appropriately.

1.  **Override `normalize_friendly_id`:**
    *   **Step 1 (Developer):**  Define the `normalize_friendly_id` method in your model.
        ```ruby
        # app/models/your_model.rb
        def normalize_friendly_id(input)
          # Custom sanitization and normalization logic here
          # Example:
          input.to_s.downcase.gsub(/[^a-z0-9\-_]+/, '-')
        end
        ```
    *   **Step 2 (Developer):**  Implement your custom logic.  This could include:
        *   More aggressive sanitization.
        *   Custom character replacements.
        *   Alternative conflict resolution strategies (though `slug_candidates` is usually preferred).
2.  **Thorough Testing:**
    *   **Step 1 (Developer):**  Test *extensively* to ensure your custom logic works as expected and doesn't introduce any regressions.

*   **Threats Mitigated:**
    *   **Slug Manipulation/Injection (Fine-grained Control):** (Severity: High) - Allows for very specific sanitization rules.
    *   **Slug Uniqueness Violations (Custom Conflict Resolution):** (Severity: High) - Provides an alternative way to handle conflicts (but `slug_candidates` is generally better).

*   **Impact:**
    *   **Slug Manipulation/Injection:** Risk can be further reduced (but proper sanitization *before* calling `friendly_id` is still crucial).
    *   **Slug Uniqueness Violations:** Risk can be managed differently (but `slug_candidates` and database constraints are the primary defenses).

*   **Currently Implemented:**
    *   Not implemented. We are relying on `friendly_id`'s default normalization.

*   **Missing Implementation:**
    *   Not currently needed, as we should focus on proper sanitization *before* passing data to `friendly_id`.  This is an advanced technique to be used only if absolutely necessary.

