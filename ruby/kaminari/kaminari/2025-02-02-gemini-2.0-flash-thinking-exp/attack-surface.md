# Attack Surface Analysis for kaminari/kaminari

## Attack Surface: [`per_page` Parameter Manipulation](./attack_surfaces/_per_page__parameter_manipulation.md)

*   **Description:** Attackers manipulate the `per_page` parameter in the URL to request an excessively large number of items per page. This directly leverages Kaminari's functionality to control the number of records fetched.
*   **Kaminari Contribution:** Kaminari uses the `per_page` parameter to determine the `LIMIT` clause in database queries, directly influencing the amount of data retrieved.  By design, Kaminari allows users to control this parameter, creating the attack surface.
*   **Example:** An attacker crafts a URL like `/items?per_page=50000` (or an even larger number) repeatedly.
*   **Impact:**
    *   **Performance Degradation:**  Significant increase in database load, query execution time, and data transfer, leading to slow response times for all users.
    *   **Denial of Service (DoS):**  Repeated requests with high `per_page` values can overwhelm database and application server resources, potentially causing service disruption or complete outage.
    *   **Memory Exhaustion:**  Attempting to retrieve and process a very large number of records can lead to memory exhaustion on the application server, causing crashes or instability.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Strictly Limit `per_page` Values:**  **Crucially, do not allow arbitrary user control over `per_page`.** Define a reasonable and **small** maximum value for `per_page` in your application's Kaminari configuration or controller logic.  Enforce this limit server-side.
    *   **Input Validation and Sanitization:** Validate the `per_page` parameter to ensure it is an integer within the pre-defined acceptable range. Sanitize the input to prevent any injection attempts (though less relevant for integer parameters, good practice).
    *   **Whitelist Allowed `per_page` Values:** Instead of just a maximum, consider whitelisting a small set of allowed `per_page` values (e.g., 10, 20, 50, 100) and reject any other values.
    *   **Rate Limiting:** Implement rate limiting to restrict the number of requests from a single IP address within a given timeframe. This can help mitigate DoS attempts that exploit `per_page` manipulation.
    *   **Resource Monitoring and Alerting:** Monitor server resources (CPU, memory, database load) and set up alerts to detect unusual spikes that might indicate a `per_page` manipulation attack.

