# Attack Surface Analysis for norman/friendly_id

## Attack Surface: [Slug Collision / Uniqueness Violation](./attack_surfaces/slug_collision__uniqueness_violation.md)

*   **Description:**  Two different records end up with the same slug, leading to data access or modification issues.
*   **How `friendly_id` Contributes:** `friendly_id` is responsible for generating and managing slugs. Misconfiguration or edge cases in its collision handling can lead to this.
*   **Example:**
    *   User A creates a post titled "My Awesome Post." `friendly_id` generates "my-awesome-post."
    *   User B creates "My. Awesome. Post!" `friendly_id`, due to a bug or misconfiguration, *also* generates "my-awesome-post."
    *   Without database-level uniqueness, User B's post *could* overwrite User A's.
*   **Impact:** Data loss, unauthorized data access, data corruption, potential denial of service.
*   **Risk Severity:** High (if database uniqueness is not enforced).
*   **Mitigation Strategies:**
    *   **Database-Level Uniqueness:** *Crucially*, enforce uniqueness on the slug column at the database level (unique index). This is the primary defense.
    *   **Strict Input Validation:** Validate user input that contributes to slug generation. Limit length, allowed characters, and prevent malicious patterns.
    *   **Robust Collision Handling:** Configure `friendly_id` to handle collisions (e.g., sequence numbers). Test thoroughly.
    *   **Avoid Direct Slug Input:** Don't allow users to directly specify the slug. Generate it automatically.
    *   **Concurrency Testing:** If high concurrency is expected, perform load testing.

## Attack Surface: [Redirection Manipulation (via Slug History)](./attack_surfaces/redirection_manipulation__via_slug_history_.md)

*   **Description:** Attackers exploit flaws in the redirection logic used with `friendly_id`'s slug history to cause unexpected redirects.  This is *directly* related to how the application uses `friendly_id`'s features.
*   **How `friendly_id` Contributes:** `friendly_id` provides the mechanism for redirecting from old slugs. The vulnerability arises from how the application *implements* this redirection.
*   **Example:**
    *   An application blindly redirects to `params[:old_slug]` after a slug change.
    *   An attacker crafts `/products/old-slug?old_slug=http://evil.com`.
    *   The application redirects to `evil.com` (phishing attack).
*   **Impact:** Open redirect vulnerability, phishing attacks, bypassing security controls.
*   **Risk Severity:** High.
*   **Mitigation Strategies:**
    *   **Validate Redirect Targets:** *Always* validate the target URL before redirecting. Ensure it's an internal URL and matches the expected pattern. Never redirect based solely on user input.
    *   **Use `friendly_id`'s Redirection Safely:** If using `friendly_id`'s built-in redirection, ensure it's configured correctly and the application doesn't introduce additional vulnerabilities.

## Attack Surface: [Scope Bypass](./attack_surfaces/scope_bypass.md)

*   **Description:**  Attackers circumvent `friendly_id`'s scoping mechanisms to create collisions across different scopes.
*   **How `friendly_id` Contributes:** `friendly_id` *provides* the scoping functionality. Misconfiguration or bugs in its implementation are the direct cause.
*   **Example:**
    *   `friendly_id` is scoped to `user_id`.
    *   A bug allows an attacker to create a post with a slug colliding with a post belonging to a *different* user.
*   **Impact:** Similar to general slug collisions: data loss, unauthorized access, data corruption.
*   **Risk Severity:** High (if database uniqueness is not enforced).
*   **Mitigation Strategies:**
    *   **Thorough Scope Configuration:** Carefully configure and test the scoping functionality.
    *   **Database-Level Uniqueness (Again):** Enforce uniqueness at the database level, even within scopes, as a fallback.

## Attack Surface: [Overriding of find method](./attack_surfaces/overriding_of_find_method.md)

*   **Description:** `friendly_id` overrides the `find` method, which can lead to unexpected behavior if the application is not expecting this override.
*   **How `friendly_id` Contributes:** `friendly_id` overrides the `find` method to allow finding records by slug.
*   **Example:**
    *   The application uses `Model.find(params[:id])` and expects `params[:id]` to be an integer. If `params[:id]` is a string (slug), `friendly_id` will try to find the record by slug, which might not be the intended behavior.
*   **Impact:** Unexpected behavior, potential security issues if the application relies on the `find` method behaving in a specific way.
*   **Risk Severity:** Medium.
*   **Mitigation Strategies:**
    *   **Be Aware of the Override:** Developers should be aware that `friendly_id` overrides the `find` method.
    *   **Use `find_by` for Explicit Slug Lookups:** Use `Model.find_by(slug: params[:id])` when explicitly searching by slug.
    *   **Use `to_i` for ID Lookups:** If you are sure that `params[:id]` should be an integer ID, use `Model.find(params[:id].to_i)` to ensure it's treated as an integer.
    *   **Thorough Testing:** Test the application thoroughly to ensure that the `find` method override doesn't cause any unexpected behavior.

