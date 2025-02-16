# Attack Surface Analysis for facebook/relay

## Attack Surface: [Unprotected GraphQL Introspection](./attack_surfaces/unprotected_graphql_introspection.md)

*   **Description:** Exposure of the GraphQL schema through introspection, revealing the entire data model, available queries, mutations, and types.
*   **Relay Contribution:** Relay *requires* introspection during development for query building and optimization. This reliance significantly increases the risk of developers accidentally leaving introspection enabled in production environments.  Relay's tooling and workflow make it easy to use introspection, so developers must be *explicitly* aware of the need to disable it.
*   **Example:** An attacker uses a tool like GraphiQL or Altair to query the `__schema` and `__type` fields, obtaining a complete map of the application's data and operations.  This is made easier because Relay likely used these tools during development.
*   **Impact:** Enables attackers to craft highly targeted attacks, understand data relationships, and identify potential vulnerabilities. Facilitates data exfiltration and unauthorized modifications.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Developers:** *Must* disable introspection in production environments via GraphQL server configuration (e.g., setting `introspection: false` in Apollo Server). Use schema-masking techniques or access control lists to limit schema visibility even if introspection is accidentally enabled.  This is a *critical* configuration step due to Relay's reliance on introspection.

## Attack Surface: [Query Complexity Attacks (DoS)](./attack_surfaces/query_complexity_attacks__dos_.md)

*   **Description:** Crafting excessively complex or deeply nested GraphQL queries that consume excessive server resources, leading to denial of service.
*   **Relay Contribution:** Relay's fragment composition and client-side query building *facilitate* the creation of complex, deeply nested queries.  While Relay aims for efficiency, the *ease* with which complex queries can be built increases the risk.  The client-side nature of query construction means the server has less *a priori* knowledge of the query's complexity.
*   **Example:** An attacker constructs a query with deeply nested relationships, requesting many fields at each level, causing the server to perform numerous database lookups and consume excessive CPU/memory.  Relay's fragment composition makes it easier to build such a query unintentionally.
*   **Impact:** Server becomes unresponsive, affecting all users. Potential for resource exhaustion and service outage.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developers:** Implement query complexity analysis and limitation on the GraphQL server (e.g., using `graphql-cost-analysis` or similar libraries). Set maximum query depth limits. Consider using persisted queries or query whitelisting to restrict allowed queries (this mitigates Relay's flexibility but increases security). Implement rate limiting and throttling.

## Attack Surface: [Over-Fetching Leading to Data Leakage](./attack_surfaces/over-fetching_leading_to_data_leakage.md)

*   **Description:** Server-side resolvers fetching more data than necessary, even if Relay only requests a subset of fields, creating a risk of unintended data exposure.
*   **Relay Contribution:** Relay's focus on *client-side* data requirements can *mask* inefficient server-side resolver implementations. Developers might *assume* that because Relay only *requests* specific fields, the server only *fetches* those fields, which is *not* guaranteed. This is a crucial misunderstanding that Relay's design can inadvertently encourage.
*   **Example:** A resolver for a `User` type fetches all user data (including `passwordHash`, `secretToken`, etc.) from the database, even if Relay only requests the `username` and `email`. An unrelated vulnerability in the resolver could then expose this extra data.  The developer might not realize this is happening because Relay only *shows* the requested fields.
*   **Impact:** Sensitive data leakage, even if the client doesn't directly receive it. Increased risk of data breaches.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developers:** Implement efficient resolvers that only fetch the required data from the underlying data sources. Use data loaders to optimize data fetching and avoid the N+1 problem. Implement field-level authorization checks within resolvers.  Developers must be *proactive* in ensuring resolvers are efficient, despite Relay's client-side optimizations.

## Attack Surface: [Client-Side Query Manipulation](./attack_surfaces/client-side_query_manipulation.md)

*   **Description:** Attackers modifying Relay-generated queries before they are sent to the server, potentially bypassing client-side validation or injecting malicious payloads.
*   **Relay Contribution:** Relay's *core functionality* of client-side query building means that the final query is assembled in the user's browser, making it a *direct* target for manipulation.  This is inherent to Relay's architecture.
*   **Example:** An attacker uses a browser extension or exploits an XSS vulnerability to intercept and modify a Relay query, adding arguments to fetch unauthorized data or trigger unintended mutations.  The attacker is directly manipulating the query that Relay built.
*   **Impact:** Unauthorized data access, data modification, or execution of unintended actions on the server.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developers:** Implement robust server-side input validation and sanitization for *all* GraphQL arguments. Never trust client-provided data, *even if it's generated by Relay*. Consider using persisted queries to prevent arbitrary client-side query construction (this directly limits Relay's core feature, but is a strong security measure).

