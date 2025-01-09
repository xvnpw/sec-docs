# Threat Model Analysis for norman/friendly_id

## Threat: [Predictable Slug Generation leading to Resource Enumeration](./threats/predictable_slug_generation_leading_to_resource_enumeration.md)

**Description:** An attacker might attempt to guess or sequentially generate friendly IDs (slugs) to discover and access resources without authorization. They could iterate through possible slug patterns based on observed slugs or known generation logic. This directly exploits the predictability of `friendly_id`'s slug generation.

**Impact:** Unauthorized access to resources, information disclosure, potential for scraping data, and denial of service by repeatedly requesting non-existent resources.

**Affected Component:** `friendly_id`'s `SlugGenerator` module and the configuration of the slug generation strategy.

**Risk Severity:** High

**Mitigation Strategies:**
* Use a sufficiently random and non-sequential slug generation strategy provided by `friendly_id` (e.g., using UUIDs or random strings as the basis for slugs).
* Avoid predictable patterns in slug generation.

## Threat: [Slug Collision Leading to Data Integrity Issues or Denial of Service](./threats/slug_collision_leading_to_data_integrity_issues_or_denial_of_service.md)

**Description:** An attacker might intentionally or unintentionally cause the generation of duplicate friendly IDs (slugs) for different resources. This could happen if the `friendly_id`'s slug generation logic is not robust enough or if the application doesn't properly configure `friendly_id`'s collision handling.

**Impact:** Users might access the wrong resource when using a slug, data corruption if updates are performed on the incorrect record due to slug ambiguity, or a denial of service if the application fails to handle the non-unique slugs gracefully.

**Affected Component:** `friendly_id`'s `SlugGenerator` module and the `finders` module used to retrieve records by slug.

**Risk Severity:** High

**Mitigation Strategies:**
* Configure `friendly_id` to handle slug collisions appropriately (e.g., by appending a unique suffix or using a more robust collision resolution strategy).
* Ensure the database schema includes a unique constraint on the slug column, complementing `friendly_id`'s collision handling.

