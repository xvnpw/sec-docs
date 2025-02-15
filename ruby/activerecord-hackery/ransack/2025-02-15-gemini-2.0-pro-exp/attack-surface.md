# Attack Surface Analysis for activerecord-hackery/ransack

## Attack Surface: [Unintended Data Exposure (Information Disclosure) - Directly via Ransack](./attack_surfaces/unintended_data_exposure__information_disclosure__-_directly_via_ransack.md)

*   **Description:** Attackers can access data they should not have authorization to view *through Ransack's query building capabilities*.
*   **How Ransack Contributes:** Ransack provides the mechanism for users to construct database queries, which, if not properly controlled, can bypass intended access restrictions. This is the *core* risk of using Ransack.
*   **Example:**
    *   An attacker uses a URL parameter `q[admin_only_field_eq]=true` to filter by a field intended only for administrators.
    *   A `ransacker` method exposes a sensitive field (e.g., `credit_card_number`) for filtering, even if the value itself isn't displayed.
    *   A `ransackable_association` allows traversing to a related table containing confidential data: `q[user_private_notes_content_cont]=secret`.
*   **Impact:** Leakage of sensitive data (PII, financial information, internal details), violating privacy and compliance.
*   **Risk Severity:** High to Critical (depending on the data exposed).
*   **Mitigation Strategies:**
    *   **Developers:**
        *   **Strict Whitelisting:** *Always* explicitly define `ransackable_attributes` and `ransackable_associations`. *Never* use the default "allow all" behavior. Only include attributes/associations *absolutely necessary* for user-facing search.
        *   **Secure `ransacker` Methods:** Implement *mandatory* authorization checks *inside* every `ransacker` method. Verify user permissions *before* constructing the query. Do *not* rely solely on controller-level authorization.
        *   **No Internal Details:** Never expose database column names or internal IDs directly in Ransack parameters. Use aliases or custom predicates.
        *   **Mandatory Code Reviews:** All Ransack-related code *must* undergo thorough security-focused code reviews.

## Attack Surface: [Denial of Service (DoS) - Exploiting Ransack Query Complexity](./attack_surfaces/denial_of_service__dos__-_exploiting_ransack_query_complexity.md)

*   **Description:** Attackers can craft overly complex Ransack queries that overwhelm the database or application, causing a denial of service.
*   **How Ransack Contributes:** Ransack's flexibility in combining predicates and associations allows for the creation of resource-intensive queries.
*   **Example:**
    *   An attacker submits a query with many nested `_or` and `_and` conditions, combined with `_cont` predicates on large, unindexed text fields: `q[field1_or_field2_or_field3_cont]=...` (repeated excessively).
    *   An attacker targets an unindexed column via a Ransack predicate: `q[unindexed_column_eq]=value`.
    *   An attacker triggers N+1 queries through a Ransack association search without proper eager loading: `q[posts_comments_body_cont]=keyword` (where `posts` have many `comments`).
*   **Impact:** Application downtime, loss of service, potential financial loss.
*   **Risk Severity:** High.
*   **Mitigation Strategies:**
    *   **Developers:**
        *   **Mandatory Predicate Limit:** *Strictly* limit the number of predicates allowed in a single Ransack search. Implement this in the controller or a service object.
        *   **Required Database Indexing:** *All* columns used in `ransackable_attributes` and within `ransacker` methods *must* have appropriate database indexes.
        *   **Mandatory Eager Loading:** *Always* use `includes`, `preload`, or `eager_load` when dealing with Ransack searches involving associations to prevent N+1 queries.
        *   **Query Timeouts:** Enforce query timeouts at the database level.
        *   **Rate Limiting:** Implement rate limiting specifically for Ransack search requests.

## Attack Surface: [SQL Injection (Indirect) - Through Custom Ransack Predicates](./attack_surfaces/sql_injection__indirect__-_through_custom_ransack_predicates.md)

*   **Description:** Attackers can inject malicious SQL code via improperly handled user input within custom `ransacker` methods.
*   **How Ransack Contributes:** Ransack's `ransacker` feature allows developers to define custom query logic, which, if not implemented securely, creates a direct SQL injection vulnerability.
*   **Example:**
    *   A `ransacker` directly interpolates user input:
        ```ruby
        ransacker :vulnerable_search do |parent|
          Arel.sql("column_name = '#{params[:q][:vulnerable_search_eq]}'") # CRITICAL VULNERABILITY
        end
        ```
        An attacker can inject SQL using a crafted `q[vulnerable_search_eq]` value.
*   **Impact:** Complete database compromise, data theft/modification, potential server compromise.
*   **Risk Severity:** Critical.
*   **Mitigation Strategies:**
    *   **Developers:**
        *   **Never Interpolate:** *Absolutely never* directly interpolate user input into SQL strings within `ransacker` methods.
        *   **Mandatory Parameterized Queries:** *Always* use parameterized queries or ActiveRecord's safe query methods (e.g., `where`, `select`) to construct SQL within `ransacker` methods.
        *   **Input Sanitization (Defense in Depth):** While parameterized queries are the primary defense, also sanitize and validate user input as a secondary measure.
        *   **Avoid `type: :string` Risks:** Be extremely cautious with `ransacker` methods that return strings.  Ensure proper sanitization *before* use in any query. Prefer returning `ActiveRecord::Relation` objects.
        * **Mandatory code review:** All custom ransackers must be reviewed by security expert.

