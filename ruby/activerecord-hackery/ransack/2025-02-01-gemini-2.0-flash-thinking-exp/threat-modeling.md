# Threat Model Analysis for activerecord-hackery/ransack

## Threat: [SQL Injection via Malicious Predicates and Values](./threats/sql_injection_via_malicious_predicates_and_values.md)

*   **Description:** An attacker crafts a Ransack query with manipulated predicates or values that inject raw SQL into the database query. For example, an attacker might modify a search parameter to include SQL commands within a string value or predicate, bypassing intended query logic. This could be achieved by exploiting insufficient input sanitization when processing search parameters.
*   **Impact:**  Complete database compromise. Attackers could gain unauthorized access to sensitive data, modify or delete data, or even execute arbitrary code on the database server, leading to data breaches, data corruption, and system takeover.
*   **Ransack Component Affected:**  Query Builder, Predicate Handling, Value Processing
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Input Sanitization and Validation:**  Strictly sanitize and validate all user inputs used in Ransack search parameters. Use parameterized queries or ORM features that automatically handle escaping to prevent SQL injection.
    *   **Attribute Whitelisting:**  Explicitly define and whitelist allowed search attributes. Prevent users from searching on arbitrary database columns.
    *   **Predicate Whitelisting:**  Limit the allowed Ransack predicates to a safe subset. Avoid exposing potentially dangerous predicates like `Arel.sql` or raw SQL injection points.
    *   **Principle of Least Privilege:**  Grant the database user used by the application minimal necessary permissions to reduce the impact of a successful SQL injection.
    *   **Regular Security Audits:** Conduct regular security audits and penetration testing focusing on Ransack search functionality to identify and remediate potential SQL injection vulnerabilities.

## Threat: [Denial of Service (DoS) through Complex Query Construction](./threats/denial_of_service__dos__through_complex_query_construction.md)

*   **Description:** An attacker crafts extremely complex Ransack queries designed to consume excessive database and application server resources. This can be done by using a large number of search parameters, deeply nested conditions, computationally expensive predicates (e.g., `matches`, `cont` on large text fields), or requesting massive result sets without pagination. The attacker aims to overload the system, making it unresponsive to legitimate users.
*   **Impact:** Application unavailability or severe performance degradation. Legitimate users are unable to access or use the application, leading to business disruption and potential financial losses.
*   **Ransack Component Affected:** Query Builder, Predicate Handling, Search Parameter Parsing
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Query Complexity Limits:** Implement limits on the number of search parameters allowed in a single query.
    *   **Predicate Restrictions:** Restrict or disable the use of resource-intensive predicates like `matches` or `cont` if not absolutely necessary, or apply them cautiously with input length limitations.
    *   **Pagination and Result Limits:**  Always enforce pagination for search results and limit the maximum number of results returned per page.
    *   **Query Timeouts:** Set timeouts for database queries to prevent long-running queries from consuming resources indefinitely.
    *   **Rate Limiting:** Implement rate limiting on search requests to prevent attackers from sending a flood of complex queries.
    *   **Database Monitoring and Throttling:** Monitor database performance and identify and throttle or block requests generating excessively resource-intensive queries.

## Threat: [Information Disclosure via Unintended Attribute Exposure](./threats/information_disclosure_via_unintended_attribute_exposure.md)

*   **Description:**  An attacker exploits Ransack's search capabilities to access data they are not authorized to view. This occurs when Ransack is configured to allow searching on attributes that contain sensitive information without proper access control checks. Attackers can craft queries to retrieve data from these attributes, bypassing intended authorization mechanisms.
*   **Impact:** Confidentiality breach. Unauthorized access to sensitive data, such as personal information, financial records, or proprietary business data, leading to privacy violations, reputational damage, and regulatory non-compliance.
*   **Ransack Component Affected:**  Attribute Resolution, Search Parameter Handling, Query Builder
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Attribute Whitelisting and Authorization:**  Strictly whitelist searchable attributes and enforce authorization checks *before* executing Ransack queries. Ensure users can only search attributes they are authorized to access.
    *   **Scoped Searches:** Utilize Ransack's scoping features to automatically limit search results to data the current user is authorized to view based on their roles and permissions.
    *   **Data Masking/Redaction:**  Consider masking or redacting sensitive data in search results if full access is not required for all users.
    *   **Regular Access Control Reviews:** Regularly review and update access control policies related to searchable attributes to ensure they align with the principle of least privilege.

