# Attack Surface Analysis for kaminari/kaminari

## Attack Surface: [Kaminari Key Attack Surface List (High/Critical, Direct Involvement Only)](./attack_surfaces/kaminari_key_attack_surface_list__highcritical__direct_involvement_only_.md)

*   **Attack:** Parameter Tampering - `per_page` Parameter (DoS)

    *   **Description:** Attackers manipulate the `per_page` parameter (if exposed) to request an excessive number of items per page, aiming to cause a denial-of-service (DoS) attack by overwhelming the database and application server.
    *   **Kaminari Contribution:** Kaminari directly uses the `per_page` parameter to determine the number of records to retrieve in a single database query.  A very large value can lead to resource exhaustion.
    *   **Example:** `?per_page=1000000000`
    *   **Impact:** Denial of service (DoS). The application becomes unresponsive due to excessive database load and memory consumption.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developer:**
            *   **Strict `per_page` Limits:** Enforce a *hard* maximum value for `per_page` (e.g., 100, 200, or a value determined through performance testing).  This limit should be enforced *regardless* of user input.
            *   **Default `per_page` Value:** Always have a sensible default value (e.g., 25) if the parameter is missing or invalid.  This prevents unexpected behavior if the parameter is omitted.
            *   **Input Validation:** Validate that `per_page` is a positive integer and within the allowed range. Reject or sanitize any other input.
            *   **Rate Limiting (Optional, but Recommended):** Consider implementing rate limiting at the application or infrastructure level (e.g., using a web application firewall or reverse proxy) to further mitigate DoS attacks, even if `per_page` is limited. This adds an extra layer of defense.
        *   **User:** (Limited direct mitigation) Avoid manually modifying URL parameters.

