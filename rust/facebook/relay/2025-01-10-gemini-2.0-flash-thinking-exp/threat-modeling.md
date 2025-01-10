# Threat Model Analysis for facebook/relay

## Threat: [Client-Side Query Manipulation Leading to GraphQL Injection](./threats/client-side_query_manipulation_leading_to_graphql_injection.md)

**Description:** An attacker intercepts or modifies the GraphQL query or variables sent from the Relay client before it reaches the server. They could inject malicious GraphQL code or alter variables to access unauthorized data or trigger unintended server-side actions. This is possible if the client-side logic dynamically constructs queries based on user input without proper sanitization or if network requests are intercepted and modified.
*   **Impact:** Unauthorized data access, data modification, potential server-side vulnerabilities exploitation (depending on server-side GraphQL implementation), and application logic bypass.
*   **Affected Relay Component:** `useQuery` hook, `useMutation` hook, `useSubscription` hook, potentially Relay Compiler if query transformations are predictable.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Avoid dynamic query construction on the client-side based on unsanitized user input.
    *   Implement robust server-side validation of all GraphQL queries and variables, regardless of the client.
    *   Use parameterized queries or prepared statements on the server-side to prevent injection.
    *   Implement proper authentication and authorization mechanisms on the server-side to restrict data access.
    *   Consider using query whitelisting on the server-side to only allow predefined, safe queries.

## Threat: [Subscription Data Leaks due to Inadequate Authorization](./threats/subscription_data_leaks_due_to_inadequate_authorization.md)

**Description:** Attackers subscribe to GraphQL subscriptions they are not authorized to access. If the server-side subscription implementation doesn't properly enforce authorization rules, attackers could receive real-time data updates intended for other users or components.
*   **Impact:** Unauthorized access to sensitive real-time data, potential privacy violations.
*   **Affected Relay Component:** `useSubscription` hook.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Implement robust authorization checks within the GraphQL subscription resolver on the server-side.
    *   Verify user permissions before pushing data through subscriptions.
    *   Avoid relying solely on client-side logic to filter subscription data.
    *   Use secure authentication mechanisms to identify and authorize users establishing subscriptions.

## Threat: [Vulnerabilities in Custom Resolvers Leading to Privilege Escalation](./threats/vulnerabilities_in_custom_resolvers_leading_to_privilege_escalation.md)

**Description:** Developers might implement custom resolvers in their GraphQL server to handle specific data fetching or mutation logic. If these resolvers contain vulnerabilities, such as insecure data access patterns or lack of proper authorization checks, attackers could exploit them to gain unauthorized access to data or perform actions they are not permitted to. While the resolver itself isn't Relay, Relay is the mechanism through which these vulnerable resolvers are often accessed.
*   **Impact:** Unauthorized data access, data modification, potential for complete system compromise depending on the resolver's functionality.
*   **Affected Relay Component:**  The Relay client (`useQuery`, `useMutation`, etc.) is the entry point to trigger these resolvers.
*   **Risk Severity:** High to Critical
*   **Mitigation Strategies:**
    *   Follow secure coding practices when implementing custom resolvers.
    *   Implement robust authorization checks within resolvers to verify user permissions.
    *   Avoid direct database access within resolvers if possible; use data access layers with proper security controls.
    *   Regularly review and audit custom resolver code for potential vulnerabilities.

