# Threat Model Analysis for apollographql/apollo-client

## Threat: [Client-Side Query Injection](./threats/client-side_query_injection.md)

**Description:** An attacker could manipulate dynamically constructed GraphQL queries on the client-side by injecting malicious GraphQL syntax or logic through user input. This could be achieved by exploiting vulnerabilities in how the application handles user input when building queries, allowing the attacker to craft queries that bypass intended access controls or execute unintended operations on the GraphQL server.
**Impact:** Unauthorized data access, data modification, denial of service on the GraphQL server.
**Apollo Client Component Affected:** `useQuery`, `useMutation`, manual query/mutation construction using `ApolloClient` instance. Specifically, the dynamic query building logic within the application code using these components.
**Risk Severity:** High
**Mitigation Strategies:**
* Avoid dynamic query construction based on raw user input.
* Use parameterized queries or GraphQL variables.
* Implement client-side input validation.
* Enforce strict server-side input validation and authorization.

## Threat: [Man-in-the-Middle (MitM) Attacks on GraphQL Requests](./threats/man-in-the-middle__mitm__attacks_on_graphql_requests.md)

**Description:** An attacker positioned between the client and the GraphQL server could intercept network traffic if HTTPS is not properly enforced. This allows the attacker to eavesdrop on GraphQL requests and responses, potentially stealing sensitive data transmitted in the queries or mutations. They could also modify requests or responses, leading to data manipulation or injection of malicious content.
**Impact:** Confidentiality breach, data integrity compromise, potential injection of malicious data.
**Apollo Client Component Affected:** `HttpLink`, `WebSocketLink` (for subscriptions), network communication layer of Apollo Client.
**Risk Severity:** High
**Mitigation Strategies:**
* Enforce HTTPS for all communication between Apollo Client and the GraphQL server in production.
* Ensure proper SSL/TLS certificate validation is enabled in Apollo Client's configuration.
* Implement HTTP Strict Transport Security (HSTS) on the server.

