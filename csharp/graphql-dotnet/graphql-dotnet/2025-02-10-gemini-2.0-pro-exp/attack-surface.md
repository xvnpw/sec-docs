# Attack Surface Analysis for graphql-dotnet/graphql-dotnet

## Attack Surface: [Query Complexity/Depth Attacks (DoS)](./attack_surfaces/query_complexitydepth_attacks__dos_.md)

*   **Description:** Attackers craft excessively complex or deeply nested queries to overwhelm server resources.
*   **`graphql-dotnet` Contribution:** Provides the *mechanisms* for cost analysis and depth limiting (`MaxComplexity`, `MaxDepth`, etc.), but *doesn't enforce them by default*.  It is entirely up to the developer to implement and configure these protections using the library's provided features. The library *executes* the complex queries if no limits are set.
*   **Example:**
    ```graphql
    query {
      users {
        posts {
          comments {
            author {
              friends {
                posts {
                  comments { # ... and so on ...
                    author { name }
                  }
                }
              }
            }
          }
        }
      }
    }
    ```
    (A deeply nested query; `graphql-dotnet` will attempt to resolve this unless limits are configured.)
*   **Impact:** Denial of Service (DoS), server unresponsiveness, resource exhaustion (CPU, memory, database).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Implement Query Cost Analysis:** *Must* be implemented using `graphql-dotnet`'s features. Assign costs to fields and use `MaxComplexity` to reject overly expensive queries. This is a *direct use* of the library's API.
    *   **Set Maximum Query Depth:** Use `graphql-dotnet`'s `MaxDepth` to limit nesting. This is a *direct configuration* of the library.
    *   **Timeout Individual Resolvers:** While a general best practice, setting timeouts *within resolvers* (which are executed by `graphql-dotnet`) is crucial.
    *   **(Indirect) Rate Limiting:** While rate limiting is often handled at a higher level, it's relevant because `graphql-dotnet` is the engine processing the requests.

## Attack Surface: [Introspection Exposure](./attack_surfaces/introspection_exposure.md)

*   **Description:** Attackers use GraphQL's introspection feature to discover the entire schema.
*   **`graphql-dotnet` Contribution:** Provides the introspection feature and *defaults to enabling it* unless explicitly disabled. The library *serves* the introspection query results.
*   **Example:**
    ```graphql
    query {
      __schema { ... }
    }
    ```
    (`graphql-dotnet` will process this introspection query by default.)
*   **Impact:** Information disclosure, aiding attackers.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Disable Introspection in Production:** *Directly* use `graphql-dotnet`'s configuration to disable introspection. This is a configuration setting *within the library*.
    *   **Conditional Introspection:** If needed, use `graphql-dotnet`'s middleware and authorization features to control access to introspection. This involves using the library's extension points.

## Attack Surface: [Over-Fetching and Data Leakage (Authorization Bypass)](./attack_surfaces/over-fetching_and_data_leakage__authorization_bypass_.md)

*   **Description:** Attackers retrieve data they shouldn't have access to due to flaws in resolvers.
*   **`graphql-dotnet` Contribution:** `graphql-dotnet` *executes the resolvers*.  The library provides the context and arguments to the resolvers, but the *responsibility for authorization checks lies entirely within the resolver code*.  The library doesn't inherently enforce authorization.
*   **Example:** A resolver fetches all user data, including sensitive fields, and relies on flawed filtering *after* the fetch. `graphql-dotnet` executes this flawed resolver.
*   **Impact:** Data breach, unauthorized access.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Field-Level Authorization:** Implement checks *within each resolver* (which are executed by `graphql-dotnet`). This is crucial because the library is the execution engine for these resolvers.
    *   **Data Loader Authorization:** If using `graphql-dotnet`'s data loaders, authorization checks *must* be within the data loader logic, as the library manages the batching.
    *   **(Indirect) Principle of Least Privilege:** While a general principle, it's directly relevant because resolvers (executed by `graphql-dotnet`) should only fetch necessary data.

## Attack Surface: [Injection Attacks (within Resolvers)](./attack_surfaces/injection_attacks__within_resolvers_.md)

*   **Description:** Injection vulnerabilities within resolver code.
*   **`graphql-dotnet` Contribution:** `graphql-dotnet` *executes the resolvers* and passes arguments to them.  The library itself doesn't perform any sanitization or validation beyond basic GraphQL type checking. The vulnerability exists *because* the library executes the potentially flawed resolver code.
*   **Example:** A resolver uses a user-provided argument directly in a raw SQL query (as shown in previous examples). `graphql-dotnet` passes the malicious argument to the resolver.
*   **Impact:** Data breach, data modification/deletion, server compromise.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **(Indirect) Parameterized Queries/Input Sanitization:** While general best practices, they are critical *within resolvers*, which are executed by `graphql-dotnet`. The library is the pathway for the malicious input.

## Attack Surface: [Batching Attacks (DoS)](./attack_surfaces/batching_attacks__dos_.md)

*   **Description:** Attackers send a large number of queries in a single request.
*   **`graphql-dotnet` Contribution:** Supports batching and *does not limit the number of operations per batch by default*. The library *processes* the entire batch.
*   **Example:** A request with 1000 queries; `graphql-dotnet` will attempt to process them all unless a limit is configured.
*   **Impact:** Denial of Service (DoS).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Limit Batch Size:** Configure `graphql-dotnet` (or request handling logic) to limit operations per batch. This is a direct interaction with how the library handles requests.
    *   **Combined Complexity Limits:** Apply complexity limits to the *entire batch*, leveraging `graphql-dotnet`'s complexity analysis features.

