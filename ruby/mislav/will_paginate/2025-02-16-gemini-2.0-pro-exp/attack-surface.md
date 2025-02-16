# Attack Surface Analysis for mislav/will_paginate

## Attack Surface: [Denial of Service (DoS) via Excessive Pagination Parameters](./attack_surfaces/denial_of_service__dos__via_excessive_pagination_parameters.md)

*   **Description:** Attackers can manipulate `page` and `per_page` parameters to request extremely large datasets, overwhelming the server and database.
*   **`will_paginate` Contribution:** The gem provides the mechanism for pagination via URL parameters, which, without proper validation, are directly controllable by the attacker.  `will_paginate` directly processes these parameters to construct database queries.
*   **Example:**
    *   Normal Request: `/products?page=2&per_page=20`
    *   Attack Request: `/products?page=9999999&per_page=9999999`
*   **Impact:** Application unavailability, resource exhaustion (CPU, memory, database connections), potential financial loss.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Strict Input Validation:** Validate `page` and `per_page` as integers within a predefined, reasonable range. Reject non-numeric or out-of-range values.
    *   **Server-Side `per_page` Limit:** Enforce a hard-coded maximum `per_page` value in the controller *before* calling `will_paginate`, overriding any user-supplied value.
    *   **Rate Limiting:** Implement rate limiting to prevent repeated malicious requests.
    *   **Database Query Optimization:** Ensure efficient database queries to minimize the impact.
    *   **Resource Monitoring:** Monitor server resources to detect and respond to attacks.

## Attack Surface: [Indirect SQL Injection (via Custom `find` Options - *Uncommon but Critical*)](./attack_surfaces/indirect_sql_injection__via_custom__find__options_-_uncommon_but_critical_.md)

*   **Description:** If developers use custom `find` options within the `paginate` method *and* those options include unsanitized user input, it *could* lead to SQL injection.  While this is a misuse scenario, `will_paginate`'s flexibility allows for this vulnerability to be introduced.
*   **`will_paginate` Contribution:** The gem *allows* for custom `find` options to be passed to the `paginate` method.  It is the *use* of these custom options, combined with a lack of sanitization, that creates the vulnerability.  `will_paginate` executes the provided (potentially malicious) query.
*   **Example:**
    ```ruby
    # VULNERABLE CODE (DO NOT USE)
    Post.paginate(:page => params[:page], :per_page => 20,
                  :conditions => "title LIKE '%#{params[:search]}%'")
    ```
    If `params[:search]` contains malicious SQL, it will be injected.
*   **Impact:** Complete database compromise, data theft, data modification, data deletion.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Avoid Custom `find` with User Input:** Strongly prefer the standard `paginate` method and its built-in parameterization.
    *   **Parameterized Queries (Always):** If custom `find` options *must* be used, *always* use parameterized queries.  *Never* concatenate user input directly into the SQL query.
    *   **Input Validation & Sanitization:** Validate and sanitize *all* user input (defense-in-depth).

