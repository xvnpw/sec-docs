# Attack Surface Analysis for mislav/will_paginate

## Attack Surface: [Indirect SQL Injection (via Pagination Parameters)](./attack_surfaces/indirect_sql_injection__via_pagination_parameters_.md)

*   **Attack Surface:** Indirect SQL Injection (via Pagination Parameters)
    *   **Description:** While `will_paginate` doesn't directly execute SQL, if the application uses the pagination parameters (like `page` or a custom parameter influencing the offset) directly in raw SQL queries without proper sanitization, it can create an SQL injection vulnerability.
    *   **How `will_paginate` Contributes:** `will_paginate` provides the `offset` value based on the `page` and `per_page` parameters. If this calculated offset is directly inserted into a raw SQL query without proper escaping, it becomes a vulnerability.
    *   **Example:**  The application constructs a SQL query like `SELECT * FROM items LIMIT 10 OFFSET #{params[:page].to_i * 10}` without proper escaping. An attacker could set `page` to something like `0 UNION SELECT credit_card FROM users --`.
    *   **Impact:**  Full database compromise, including data breaches, data manipulation, and unauthorized access.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Never directly interpolate user-provided input (including pagination parameters) into raw SQL queries.**
        *   **Always use parameterized queries or ORM methods (like ActiveRecord in Rails) that handle proper escaping and prevent SQL injection.**
        *   Review all database interaction code to ensure pagination parameters are handled securely.

## Attack Surface: [Cross-Site Scripting (XSS) in Pagination Links](./attack_surfaces/cross-site_scripting__xss__in_pagination_links.md)

*   **Attack Surface:** Cross-Site Scripting (XSS) in Pagination Links
    *   **Description:** If the application incorporates user-controlled data into the model attributes being paginated and then renders those attributes directly within the pagination links (e.g., in query parameters for sorting or filtering), it could be vulnerable to XSS.
    *   **How `will_paginate` Contributes:** `will_paginate` generates links that often include parameters based on the current state, including potentially user-influenced data. If this data isn't properly escaped before being included in the link, it can lead to XSS.
    *   **Example:** An item's name contains malicious JavaScript like `<script>alert('XSS')</script>`. When `will_paginate` generates a link that includes this item's name in a query parameter, the script could execute.
    *   **Impact:**  Session hijacking, cookie theft, redirection to malicious sites, defacement of the application.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Always sanitize and escape user-provided data before rendering it in HTML, including within the pagination links.**
        *   Utilize Rails' built-in helpers like `h` or `sanitize` for escaping HTML.
        *   Implement Content Security Policy (CSP) to further mitigate XSS risks.

