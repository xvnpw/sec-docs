# Threat Model Analysis for norman/friendly_id

## Threat: [Predictable Slug Generation leading to Unauthorized Resource Access](./threats/predictable_slug_generation_leading_to_unauthorized_resource_access.md)

*   **Description:** An attacker might analyze the slug generation pattern used by `friendly_id`. If slugs are based on sequential IDs or easily guessable patterns, the attacker can iterate through potential slugs in URLs to discover and access resources they are not authorized to view. For example, they might try `/posts/1`, `/posts/2`, `/posts/3` if slugs are based on incrementing IDs.
*   **Impact:** Unauthorized access to sensitive data, potential data breaches, exposure of unpublished or private content.
*   **Friendly_id Component Affected:** Slug Generation Module, `friendly_id` configuration.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Use non-sequential and unpredictable attributes for slug generation (e.g., titles, UUIDs).
    *   Implement slug history and redirection to invalidate old, potentially predictable slugs.
    *   Enforce robust authorization checks in application code when accessing resources via friendly IDs, regardless of slug predictability.
    *   Avoid using database IDs directly or predictably in slug generation.

