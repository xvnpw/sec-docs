# Attack Surface Analysis for graphql/graphql-js

## Attack Surface: [Query Complexity Attacks](./attack_surfaces/query_complexity_attacks.md)

*   **Description:** Attackers craft excessively complex or deeply nested GraphQL queries to consume server resources (CPU, memory, database), leading to Denial of Service (DoS).
*   **How graphql-js Contributes:** `graphql-js` doesn't inherently limit query complexity; it executes queries as provided.  This is the *core* of the issue.
*   **Example:**
    ```graphql
    query {
      users {
        posts {
          comments {
            author {
              friends {
                posts {
                  comments { # ... and so on, deeply nested ... }
                }
              }
            }
          }
        }
      }
    }
    ```
    (Repeated nesting to extreme depths).
*   **Impact:** Service unavailability, degraded performance for legitimate users, potential server crashes.
*   **Risk Severity:** High to Critical (depending on server resources and existing protections).
*   **Mitigation Strategies:**
    *   **Maximum Query Depth:** Implement a hard limit on the nesting depth of queries using libraries like `graphql-depth-limit`. (Developer)
    *   **Query Cost Analysis:** Assign costs to fields and limit the total cost of a query using libraries like `graphql-cost-analysis`. (Developer)
    *   **Rate Limiting (GraphQL-Specific):** Limit the rate of complex operations or specific fields, not just overall requests. (Developer/Operations)
    *   **Timeout Enforcement:** Set reasonable execution timeouts for GraphQL queries at the server and resolver levels. (Developer/Operations)
    *   **Pagination:** Enforce pagination on lists, using cursor-based pagination for efficiency. (Developer)

## Attack Surface: [Batching Attacks](./attack_surfaces/batching_attacks.md)

*   **Description:** Attackers send multiple GraphQL queries in a single request (batching) to amplify the impact of other attacks, like query complexity attacks.
*   **How graphql-js Contributes:** `graphql-js` supports batching by default, enabling this attack vector.
*   **Example:** An attacker sends a single request containing 100 moderately complex queries, or even many simple queries targeting a resource-intensive resolver.
*   **Impact:** Increased server load, potential DoS, exacerbates other vulnerabilities (especially query complexity).
*   **Risk Severity:** High (can easily escalate to critical if combined with other attacks).
*   **Mitigation Strategies:**
    *   **Limit Batch Size:** Restrict the number of operations allowed per batch request. (Developer/Operations)
    *   **Combined Cost Analysis:** Calculate the *total* cost of *all* queries in a batch and reject if it exceeds the limit.  This is crucial. (Developer)
    *   **Rate Limiting (per Batch):** Rate limit based on the number of batches or total operations within batches. (Developer/Operations)

## Attack Surface: [Resolver-Level Vulnerabilities (with GraphQL-Specific Considerations)](./attack_surfaces/resolver-level_vulnerabilities__with_graphql-specific_considerations_.md)

*   **Description:** While vulnerabilities *within* resolvers (SQLi, XSS, etc.) aren't directly caused by `graphql-js`, the way GraphQL structures data access can *increase the risk* if developers aren't careful.  Specifically, the potential for N+1 queries and the ease of accessing related data can lead to performance bottlenecks and, if combined with poor input validation, increased vulnerability.
*   **How graphql-js Contributes:** `graphql-js` executes the resolvers as provided.  The *structure* of GraphQL, where resolvers are called for each field, can lead to performance issues (N+1 problem) that attackers might exploit if resolvers are not optimized or if they contain vulnerabilities.  This is an *indirect* but important contribution.
*   **Example:** A resolver that constructs a SQL query using string concatenation with user-provided input, *and* is called repeatedly due to a nested query structure, amplifies the risk of SQL injection.
*   **Impact:** Varies greatly, but can be Critical (data breaches, system compromise).
*   **Risk Severity:** High to Critical.
*   **Mitigation Strategies:**
    *   **Input Validation:** Thoroughly validate *all* inputs to resolvers, *especially* those used in database queries or other sensitive operations. (Developer)
    *   **Parameterized Queries/ORM:** Use parameterized queries or an ORM to *prevent* injection vulnerabilities. This is non-negotiable. (Developer)
    *   **Data Loaders:** Use data loaders (e.g., `dataloader`) to mitigate the N+1 problem and improve resolver efficiency, reducing the potential for performance-related exploits. (Developer)
    *   **Sanitize Output:** Sanitize data returned from resolvers to prevent XSS. (Developer)
    *   **Least Privilege:** Grant minimal database privileges to resolvers. (Developer/Operations)

