# Attack Surface Analysis for android/sunflower

## Attack Surface: [Potential SQL Injection via Raw Queries](./attack_surfaces/potential_sql_injection_via_raw_queries.md)

*   **Description:**  Improper handling of user input when constructing database queries, particularly if using `SupportSQLiteQuery` or raw SQL queries directly, can allow attackers to inject malicious SQL code.
    *   **How Sunflower Contributes to the Attack Surface:** If Sunflower uses raw queries for features like searching plants by name or filtering data based on user-provided criteria without proper sanitization or parameterized queries, it becomes vulnerable.
    *   **Example:** A user enters a plant name like `"orchid' OR 1=1 --"` in a search field. If the application directly concatenates this into a raw SQL query, it could bypass intended filtering and potentially expose or modify data.
    *   **Impact:** Data breach (access to sensitive plant data, user notes), data manipulation (modifying plant information), or even potential denial of service.
    *   **Risk Severity:** High
    *   **Mitigation Strategies (Developers):**
        *   **Always use parameterized queries or prepared statements:** This prevents user input from being interpreted as SQL code.
        *   **Utilize Room's type-safe query mechanisms:** Rely on Room's annotations and generated code to build queries instead of raw SQL where possible.
        *   **Implement robust input validation and sanitization:**  Sanitize user input to remove or escape potentially harmful characters before using it in database queries.

## Attack Surface: [Insecure Communication if Interacting with a Backend (Hypothetical)](./attack_surfaces/insecure_communication_if_interacting_with_a_backend__hypothetical_.md)

*   **Description:** If Sunflower interacts with a backend server for features like fetching plant data or user accounts, using plain HTTP instead of HTTPS exposes data in transit.
    *   **How Sunflower Contributes to the Attack Surface:** If Sunflower's networking code doesn't enforce HTTPS for all communication with its backend, attackers can intercept and potentially modify data being exchanged.
    *   **Example:** An attacker on the same Wi-Fi network intercepts the request for plant data and sees the plant names and descriptions being transmitted in plain text.
    *   **Impact:** Information disclosure, data manipulation.
    *   **Risk Severity:** High
    *   **Mitigation Strategies (Developers):**
        *   **Enforce HTTPS for all backend communication:** Use `https://` URLs and configure networking libraries to only allow secure connections.
        *   **Implement Certificate Pinning:** For critical backend connections, pin the server's certificate to prevent man-in-the-middle attacks even if a rogue certificate is present.

