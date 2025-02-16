# Threat Model Analysis for facebook/relay

## Threat: [Relay Store Cache Poisoning via Mutation Response](./threats/relay_store_cache_poisoning_via_mutation_response.md)

*   **Threat:**  Relay Store Cache Poisoning via Mutation Response

    *   **Description:** An attacker exploits a vulnerability in the server's mutation response handling (e.g., insufficient validation) to inject malicious data into the response.  When Relay processes this response, it updates the client-side Relay store with the poisoned data.  This could lead to incorrect data display, XSS (if the data is rendered without sanitization), or other client-side issues.  The *direct* Relay involvement is the processing and storage of the malicious response.
    *   **Impact:**  Data corruption in the client-side cache, potential XSS, incorrect application behavior, display of false information.
    *   **Affected Component:**  Relay `Store`, specifically the update logic triggered by mutation responses (`commitUpdate`, `commitLocalUpdate`).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Server-Side:**  Strictly validate *all* data returned in mutation responses.  Treat these as untrusted inputs.
        *   **Client-Side:**  Validate data *before* updating the Relay store, even if it comes from a mutation response.  Use type checking (TypeScript) and potentially custom validation logic.
        *   **Client-Side:**  Sanitize any data from the Relay store before rendering it in the UI, especially if using `dangerouslySetInnerHTML` or similar.

## Threat: [Over-Fetching Sensitive Data via Fragments](./threats/over-fetching_sensitive_data_via_fragments.md)

*   **Threat:**  Over-Fetching Sensitive Data via Fragments

    *   **Description:** A developer inadvertently includes fields in a Relay fragment that expose sensitive data not needed by the component.  While the UI might not *display* this data, it's present in the Relay store and network responses, making it accessible to an attacker.  The *direct* Relay involvement is the use of fragments to define data requirements, and the subsequent storage of this over-fetched data in the Relay `Store`.
    *   **Impact:**  Information disclosure, potential privacy violations.
    *   **Affected Component:**  Relay Fragments (`graphql` tagged template literals), Relay `Store`.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Client-Side:**  Carefully review all Relay fragments to ensure they only request the *minimum* necessary data.
        *   **Client-Side:** Use Relay's fragment masking features to enforce data access restrictions at the component level.
        *   **Server-Side:** Implement authorization checks *before* returning data. Don't rely solely on client-side filtering.
        *   **Code Review:**  Mandatory code reviews focusing on GraphQL query and fragment construction.
        *   **Linting:** Use a GraphQL linter with rules to detect potential over-fetching.

## Threat: [Unintended Mutation Execution](./threats/unintended_mutation_execution.md)

*   **Threat:**  Unintended Mutation Execution

    *   **Description:** A bug in the client-side code, or a compromised third-party component, triggers a Relay mutation that the user did not intend or authorize. This is *directly* related to Relay because it involves the `commitMutation` API.
    *   **Impact:**  Unauthorized data modification or deletion, potential data loss, violation of user trust.
    *   **Affected Component:**  Relay `commitMutation`, any component that triggers mutations.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Server-Side:**  Implement robust authorization checks for *every* mutation.
        *   **Client-Side:**  Implement input validation to prevent malformed mutation inputs.
        *   **Client-Side:**  For critical mutations, require explicit user confirmation.
        *   **Code Review:** Thoroughly review all code that triggers mutations.

## Threat: [Relay Environment Misconfiguration (Network Layer)](./threats/relay_environment_misconfiguration__network_layer_.md)

* **Threat:** Relay Environment Misconfiguration (Network Layer)

    * **Description:** The Relay `Network` layer is misconfigured, leading to insecure communication with the GraphQL server. Examples include using HTTP instead of HTTPS, using an incorrect endpoint URL, or failing to provide necessary authentication headers. This is a *direct* threat to the Relay configuration itself.
    * **Impact:** Data interception (man-in-the-middle attacks), unauthorized access to the GraphQL API.
    * **Affected Component:** Relay `Environment`, specifically the `Network` configuration.
    * **Risk Severity:** Critical
    * **Mitigation Strategies:**
        * **Client-Side:** Ensure the `Network` is configured to use HTTPS with a valid SSL/TLS certificate.
        * **Client-Side:** Validate the GraphQL endpoint URL.
        * **Client-Side:** Implement proper authentication mechanisms (e.g., providing authentication tokens in headers).
        * **Code Review:** Review the Relay `Environment` configuration.

## Threat: [GraphQL Query Complexity DoS (Relay Facilitated)](./threats/graphql_query_complexity_dos__relay_facilitated_.md)

*   **Threat:**  GraphQL Query Complexity DoS (Relay Facilitated)

    *   **Description:** While the core vulnerability is on the GraphQL server, Relay's fragment composition *facilitates* the creation of overly complex queries. An attacker crafts a deeply nested GraphQL query, potentially leveraging Relay fragments, to consume excessive server resources.
    *   **Impact:** Application unavailability, denial of service.
    *   **Affected Component:** Relay `Network` layer (transmitting the query), Relay Fragments (contributing to complexity). Although the server is the primary target, Relay's structure makes this attack easier to construct.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Server-Side:** Implement query complexity analysis and limits.
        *   **Server-Side:** Implement query depth limiting.
        *   **Server-Side:** Implement rate limiting and throttling.
        *   **Server-Side:** Consider using persisted queries.
        *   **Client-Side (Limited Help):** Developers should avoid unnecessarily complex queries and fragments.

