# Threat Model Analysis for norman/friendly_id

## Threat: [Non-Unique Slugs Leading to Data Corruption or Access Issues](./threats/non-unique_slugs_leading_to_data_corruption_or_access_issues.md)

*   **Description:** An attacker might exploit a race condition or a flaw within `friendly_id`'s slug generation process to create two or more records with the same slug. This could involve rapidly creating new records, relying on weaknesses in `friendly_id`'s uniqueness checks.
*   **Impact:** When the application uses `friendly_id`'s `find` method with the non-unique slug, it might retrieve the wrong record. This can lead to incorrect data being displayed or manipulated, and updates or deletions could affect the unintended record, causing data corruption or loss.
*   **Affected Component:** `friendly_id`'s slug generation module, specifically the `should_generate_new_friendly_id?` method and the underlying uniqueness validation logic.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Ensure robust database-level unique constraints on the slug column, which acts as a secondary safety net.
    *   Investigate and potentially override `friendly_id`'s slug generation and uniqueness checking if the default behavior is insufficient under high concurrency.
    *   Thoroughly test record creation and slug generation under concurrent load to identify potential race conditions within `friendly_id`.

## Threat: [Slug Collisions During Updates Leading to Data Loss or Corruption](./threats/slug_collisions_during_updates_leading_to_data_loss_or_corruption.md)

*   **Description:** An attacker might attempt to update a record's slug to a value that already exists for another record, exploiting potential weaknesses in `friendly_id`'s update process or concurrent update handling.
*   **Impact:** If `friendly_id` doesn't properly prevent slug collisions during updates, one record's slug might overwrite another's, leading to data loss or the inability to access the original record using its intended slug.
*   **Affected Component:** `friendly_id`'s handling of slug updates, specifically the logic within the `set_slug` method and the interaction with database uniqueness constraints during updates.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Rely on database-level unique constraints on the slug column to enforce uniqueness during updates.
    *   Investigate and potentially customize `friendly_id`'s slug update logic if the default behavior is susceptible to race conditions.
    *   Implement optimistic or pessimistic locking at the application level when updating records with friendly IDs to prevent concurrent modifications that could lead to collisions.

## Threat: [Vulnerabilities in Custom Slug Generation Logic Leading to Critical Security Issues](./threats/vulnerabilities_in_custom_slug_generation_logic_leading_to_critical_security_issues.md)

*   **Description:** If developers implement custom logic for slug generation using `friendly_id`'s extension points (e.g., `slug_generator_class`), vulnerabilities in this custom code could lead to critical security flaws. This could involve generating predictable slugs, failing to enforce uniqueness, or introducing other exploitable weaknesses.
*   **Impact:**  Depending on the vulnerability, attackers could enumerate resources, cause data corruption due to non-unique slugs, or potentially gain unauthorized access if slugs are predictable and tied to sensitive resources.
*   **Affected Component:** Custom slug generator classes or methods implemented by the developer, interacting directly with `friendly_id`'s configuration and slug generation lifecycle.
*   **Risk Severity:** Varies depending on the vulnerability, can be Critical
*   **Mitigation Strategies:**
    *   Thoroughly review and security audit any custom slug generation code.
    *   Follow secure coding practices and avoid introducing predictable patterns or relying on insecure random number generators in custom slug generators.
    *   Consider using the well-tested default `friendly_id` slug generation mechanisms whenever possible.
    *   Implement comprehensive unit and integration tests for custom slug generation logic, including testing for uniqueness and predictability.

