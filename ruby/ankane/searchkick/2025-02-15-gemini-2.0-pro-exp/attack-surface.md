# Attack Surface Analysis for ankane/searchkick

## Attack Surface: [Overly Permissive Search Queries (Data Exposure)](./attack_surfaces/overly_permissive_search_queries__data_exposure_.md)

*   **Description:** Attackers craft queries that retrieve more data than intended, bypassing access controls.
*   **Searchkick Contribution:** Searchkick provides a powerful, user-friendly query interface to Elasticsearch. This ease of use, *without proper application-level restrictions*, directly enables attackers to construct overly broad queries. The core issue is Searchkick's *capability* combined with insufficient application-level safeguards.
*   **Example:** An attacker uses `"*"` in a search field intended for usernames, and the application doesn't restrict this via Searchkick's `where` clause, leading to retrieval of all user records. Or, an attacker leverages complex `where` clause combinations (e.g., many `_or` conditions) that the application fails to validate, bypassing intended filters.
*   **Impact:** Unauthorized disclosure of sensitive data, violation of privacy, potential for further attacks.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strict Input Validation:** Implement a whitelist of allowed characters and patterns for search terms. Reject any input that doesn't conform. This is *essential* before the input even reaches Searchkick.
    *   **Pre-Filtering (Crucial):** Use Searchkick's `where` clause *before* applying the user's search term to restrict results based on user roles and permissions.  Example: `User.search(params[:q], where: { organization_id: current_user.organization_id })`. This is the *primary* defense, leveraging Searchkick's features for security.
    *   **Field Control:** Limit which fields are searchable and retrievable via Searchkick and Elasticsearch configuration. Don't index sensitive data that doesn't need to be searched. Use `_source` filtering.
    *   **Aggregation Control:** Restrict or disable aggregations, or carefully control the fields and parameters used via Searchkick's API.
    *   **Pagination and Rate Limiting:** Implement strict pagination limits and rate limiting (both in the application and potentially within Searchkick/Elasticsearch) to prevent exhaustive data retrieval.

## Attack Surface: [Resource Exhaustion (Denial of Service)](./attack_surfaces/resource_exhaustion__denial_of_service_.md)

*   **Description:** Attackers craft complex or computationally expensive queries to overload the Elasticsearch cluster, causing a denial of service.
*   **Searchkick Contribution:** Searchkick's simplified query building makes it easier to create (intentionally or unintentionally) resource-intensive queries *if the application doesn't impose limits*. The library itself doesn't inherently *cause* DoS, but its ease of use facilitates it without proper controls.
*   **Example:** An attacker submits a query with deeply nested `OR` conditions, excessive wildcards, or complex aggregations through Searchkick's interface, and the application doesn't limit the query's complexity. Or, a query using `User.search("*", fields: [:field1, :field2, ...], where: { ... })` with a large number of fields and complex `where` conditions, *not restricted by the application*.
*   **Impact:** Application downtime, loss of service availability, potential financial losses.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Query Timeouts:** Use Searchkick's `timeout` option to limit the execution time of individual queries. This is a *direct* use of Searchkick for mitigation. Set appropriate timeouts on the Elasticsearch cluster itself.
    *   **Resource Limits:** Configure resource limits (CPU, memory) on the Elasticsearch cluster (this is outside of Searchkick, but essential).
    *   **Query Monitoring:** Monitor Elasticsearch performance and identify slow or resource-intensive queries (partially related to Searchkick usage).
    *   **Rate Limiting:** Implement rate limiting on search requests to prevent abuse. Limit the frequency of searches per user or IP address (can be done in conjunction with Searchkick).
    *   **Disable Scripting:** Disable or severely restrict the use of scripting in queries accessible through Searchkick.
    *   **Input Validation (Again):** Limit the complexity of user-provided search terms *before* they reach Searchkick (e.g., restrict the number of wildcards, the length of the query, the number of `OR` conditions).

