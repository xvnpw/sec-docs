# Attack Surface Analysis for apollographql/apollo-client

## Attack Surface: [GraphQL Query Complexity Attacks (DoS)](./attack_surfaces/graphql_query_complexity_attacks__dos_.md)

*   **Description:**  Attackers craft deeply nested or computationally expensive GraphQL queries to overload the server.  While the server is ultimately responsible for protection, Apollo Client is the *direct tool* used to send these malicious queries.
*   **Apollo Client Contribution:**  Provides the core functionality for constructing and sending GraphQL queries, making it easy for attackers to craft and transmit malicious payloads.  The client's flexibility in query building is a double-edged sword.
*   **Example:**  A query requesting deeply nested relationships across multiple entities:
    ```graphql
    query {
      users {
        posts {
          comments {
            author {
              friends {
                posts {
                  comments {
                    # ... and so on ...
                  }
                }
              }
            }
          }
        }
      }
    }
    ```
*   **Impact:**  Service unavailability, performance degradation, potential financial losses.
*   **Risk Severity:**  **Critical** (if the server lacks adequate protection).
*   **Mitigation Strategies:**
    *   **Server-Side:** (Primary Mitigation) Implement query cost analysis, depth limiting, and rate limiting.  These are *essential* server-side defenses.
    *   **Client-Side (Limited/Unreliable):**  Avoid *obviously* complex queries in client code.  This is *not* a reliable security measure, but good practice.

## Attack Surface: [GraphQL Introspection Abuse (Information Disclosure)](./attack_surfaces/graphql_introspection_abuse__information_disclosure_.md)

*   **Description:**  Attackers use introspection queries (`__schema`) to discover the GraphQL schema. Apollo Client, especially with its developer tools, makes accessing this information trivial if it's enabled on the server.
*   **Apollo Client Contribution:**  Apollo Client's DevTools often *rely* on introspection for features like autocompletion and schema exploration.  This highlights the ease of access and makes it a readily available tool for attackers if the server permits introspection.
*   **Example:**  Using Apollo Client DevTools or a direct query:
    ```graphql
    query IntrospectionQuery {
      __schema {
        # ... schema details ...
      }
    }
    ```
*   **Impact:**  Provides a roadmap for further attacks, exposing the structure and potentially sensitive details of the backend.
*   **Risk Severity:**  **High** (if introspection is enabled in production).
*   **Mitigation Strategies:**
    *   **Server-Side:** (Primary Mitigation) *Disable* introspection in production environments. This is the *critical* defense.
    *   **Client-Side:** Ensure Apollo Client DevTools are *not* accessible in production builds.

## Attack Surface: [Cache Poisoning (Client-Side)](./attack_surfaces/cache_poisoning__client-side_.md)

*   **Description:**  Attackers manipulate server responses to inject malicious data into Apollo Client's `InMemoryCache`.  This poisoned data can then trigger client-side vulnerabilities (e.g., XSS) if not handled carefully.
*   **Apollo Client Contribution:**  The `InMemoryCache` is the *direct target* of this attack.  Apollo Client's caching mechanism, while designed for performance, creates this vulnerability if data integrity is compromised.
*   **Example:**  An attacker modifies a GraphQL response to include a malicious script in a field that is later rendered unsafely:
    ```json
    // Modified Response (by attacker)
    { "data": { "user": { "bio": "<script>alert('XSS');</script>" } } }
    ```
*   **Impact:**  Client-side code execution (XSS), data manipulation, session hijacking.
*   **Risk Severity:**  **High** (dependent on the sensitivity of cached data and client-side rendering practices).
*   **Mitigation Strategies:**
    *   **Client-Side:**
        *   **Data Validation & Sanitization:**  *Always* validate and sanitize data *retrieved from the cache* before use, especially before rendering. This is *crucial*.
        *   **Strict Cache Policies:** Use `no-cache` or `network-only` for sensitive data, mitigating the risk of using stale or manipulated data.
        *   **Normalized Cache:** Leverage Apollo Client's normalized cache for improved data consistency.
        *   **HTTPS:** Enforce *strict* HTTPS to prevent man-in-the-middle attacks that could tamper with responses.
    * **Server-Side:** Ensure that server is not compromised.

