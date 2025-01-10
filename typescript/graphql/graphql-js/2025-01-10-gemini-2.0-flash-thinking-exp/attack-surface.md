# Attack Surface Analysis for graphql/graphql-js

## Attack Surface: [Complex Queries Leading to Denial of Service (DoS)](./attack_surfaces/complex_queries_leading_to_denial_of_service__dos_.md)

*   **Description:** Malicious clients can craft deeply nested or computationally intensive queries that consume excessive server resources (CPU, memory), leading to service degradation or failure.
    *   **How graphql-js Contributes:** `graphql-js`'s execution engine will attempt to resolve any valid GraphQL query, regardless of its complexity, without inherent limitations on resource consumption per query.
    *   **Example:** A query with multiple nested levels and numerous fields at each level, especially with relationships that could trigger multiple database lookups, like:
        ```graphql
        query {
          users {
            posts {
              comments {
                author {
                  posts {
                    # ... and so on
                  }
                }
              }
            }
          }
        }
        ```
    *   **Impact:** Server overload, service unavailability, increased infrastructure costs.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Implement query complexity analysis and cost limiting to reject overly expensive queries before execution.
        *   Set query depth limits to prevent excessively nested queries.
        *   Implement request timeouts to prevent long-running queries from tying up resources indefinitely.
        *   Consider using persisted queries to have more control over the queries executed.
        *   Implement rate limiting to restrict the number of requests from a single client within a given time frame.

## Attack Surface: [Introspection Exposure](./attack_surfaces/introspection_exposure.md)

*   **Description:** When introspection is enabled, attackers can query the GraphQL schema, revealing all available types, fields, and relationships. This information can be used to understand the API structure and craft more targeted attacks.
    *   **How graphql-js Contributes:** `graphql-js` provides the built-in `__schema` field that allows clients to introspect the schema.
    *   **Example:** An attacker using a tool like `curl` or a GraphQL client to send an introspection query:
        ```graphql
        query IntrospectionQuery {
          __schema {
            queryType {
              name
            }
            mutationType {
              name
            }
            types {
              name
              fields {
                name
                args {
                  name
                  type {
                    name
                  }
                }
              }
            }
          }
        }
        ```
    *   **Impact:** Information disclosure, enabling more sophisticated attacks, potential exposure of sensitive data structures.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Disable introspection in production environments.
        *   Implement access controls for introspection queries, allowing it only for authorized users or internal systems.
        *   Consider using schema stitching or federation to expose only necessary parts of the schema.

