# Threat Model Analysis for norman/friendly_id

## Threat: [Slug Collision (Spoofing)](./threats/slug_collision__spoofing_.md)

*   **Description:** An attacker crafts a specific input to exploit weaknesses in a *custom* slug generation method provided to `friendly_id`, causing a collision with an existing slug. This assumes the attacker cannot directly modify the database.
*   **Impact:** The attacker could gain unauthorized access to resources associated with the existing record, impersonate another user, or cause data corruption if authorization logic relies heavily on the slug.
*   **Affected Component:** `FriendlyId::Slugged` module – specifically, the developer-provided custom slug candidate methods or sequence generators. The core `friendly_id` slug generation (using `parameterize`) is *not* directly vulnerable unless misused.
*   **Risk Severity:** High (if authorization relies significantly on the slug and custom generation is flawed).
*   **Mitigation Strategies:**
    *   **Database Constraint:** Enforce uniqueness at the database level with a unique index on the `slug` column (and `scope` column, if applicable). This is the *primary* defense, even against flawed custom generators.
    *   **Robust Custom Slug Generation:** If using custom candidates, *thoroughly* test them to ensure they are well-tested, handle edge cases, and don't introduce predictability or collisions. Avoid complex logic or external dependencies within the custom generator. Use `parameterize` as a base and add randomness if needed.
    *   **ID-Based Authorization:** *Always* perform authorization checks based on the underlying record ID, *never* solely on the slug. This mitigates the impact of a collision.
    *   **Input Validation (Secondary):** Validate user input *before* it's used in the custom slug generation to prevent characters or patterns that might increase collision likelihood. This is a defense-in-depth measure.

## Threat: [Direct Slug Modification Through Mass Assignment (Tampering) - *Conditional High*](./threats/direct_slug_modification_through_mass_assignment__tampering__-_conditional_high.md)

*   **Description:** If the application has a mass-assignment vulnerability *and* the `slug` attribute is not properly protected, an attacker could directly modify the slug of a record, bypassing `friendly_id`'s generation logic. This is a combination of a general Rails vulnerability and `friendly_id`'s data.
*   **Impact:** Similar to slug collision: unauthorized access, data corruption, impersonation, if authorization relies on the slug.
*   **Affected Component:** While the vulnerability is in the application's mass-assignment handling, the *impacted data* is the slug managed by `FriendlyId::Slugged`.
*   **Risk Severity:** High (conditional on the presence of a mass-assignment vulnerability *and* insufficient authorization checks).
*   **Mitigation Strategies:**
    *   **Strong Parameters (or `attr_protected`/`attr_accessible`):**  *Strictly* control which attributes can be mass-assigned.  The `slug` attribute should *not* be directly mass-assignable unless absolutely necessary and carefully controlled. This is the *primary* defense.
    *   **ID-Based Authorization:** As always, perform authorization checks based on the record ID, not the slug.
    *   **Database Constraint (Defense-in-Depth):** A unique index on the `slug` column will prevent some (but not all) forms of this attack, as it will prevent direct duplication.

