# Mitigation Strategies Analysis for apollographql/apollo-client

## Mitigation Strategy: [Cache Poisoning Prevention (Apollo Client Cache)](./mitigation_strategies/cache_poisoning_prevention__apollo_client_cache_.md)

1.  **Validate Data Before Caching:**
    *   *Before* writing *any* data to the Apollo Client cache (using `cache.writeQuery`, `cache.writeFragment`, or through normalized cache updates from mutations), validate the data within your React components or Apollo Client link chain.
    *   Use a schema validation library (e.g., Yup, Joi) or custom validation functions *within your client-side code*.
    *   Ensure the data conforms to the expected types and formats.  This is best done as close to the cache interaction as possible.
    *   Check for potentially malicious content (e.g., HTML tags, JavaScript code) in string fields, especially if those fields are rendered in the UI.  This is crucial for preventing XSS.
2.  **Use Cache Policies Wisely:**
    *   When defining your queries and mutations using `useQuery`, `useMutation`, or the lower-level Apollo Client APIs, configure the `fetchPolicy` appropriately.
    *   For data that is highly sensitive or frequently changes, use the `network-only` fetch policy. This ensures that the data is always fetched from the server and *never* read from or written to the cache.
    *   For data that is less sensitive and can be cached, use `cache-and-network`, `cache-first`, or `cache-only` as appropriate, but *always* combine this with data validation.
3.  **Type Policies:**
    *   When initializing your `ApolloClient` instance, define `typePolicies` in the `InMemoryCache` configuration.
    *   For specific types or fields that should *never* be cached, use the `fields` option within the `typePolicies` to define a `read` function that always returns `undefined`.  This prevents the field from being stored in the cache *at all*.
    *   Use the `merge` function within `typePolicies` to customize how incoming data is merged with existing data in the cache.  This is a powerful way to prevent malicious data from overwriting legitimate data, or to implement custom validation logic *during the merge process*.  This is a more advanced, but very effective, technique.
4.  **Sanitize User Input (Client-Side):**
    *   If user input is used to construct queries (e.g., search terms) or update the cache directly (rare, but possible), sanitize the input *on the client-side* before using it.  Use a dedicated sanitization library to remove any potentially harmful characters or code.

    **Threats Mitigated:**
    *   **Cross-Site Scripting (XSS) via Cache:** (Severity: High) - Prevents malicious code from being injected into the cache and executed in the client's browser.
    *   **Data Tampering:** (Severity: Medium) - Prevents unauthorized modification of cached data.
    *   **Client-Side Logic Manipulation:** (Severity: Medium) - Reduces the risk of attackers manipulating client-side behavior through the cache.

    **Impact:**
    *   **XSS:** Risk significantly reduced (High reduction) with thorough validation and type policies.
    *   **Data Tampering/Logic Manipulation:** Risk moderately reduced (Medium reduction).

    **Currently Implemented:**
    *   `network-only` fetch policy is used for a few specific queries related to user authentication.

    **Missing Implementation:**
    *   Consistent and comprehensive data validation before caching is missing in many parts of the application. This is a high-priority item and needs to be implemented within React components or Apollo Link middleware.
    *   Type Policies are not currently utilized. This is a powerful feature that should be explored.
    *   Systematic sanitization of user input before interacting with the cache is not implemented.

## Mitigation Strategy: [Client-Side State Manipulation Prevention](./mitigation_strategies/client-side_state_manipulation_prevention.md)

1.  **Input Validation (Client-Side):**
    *   Any time user input is used to update the Apollo Client's local state (using the `@client` directive or local resolvers), validate the input *within your React components or custom Apollo Link*.
    *   Use a validation library or custom functions to ensure the input conforms to expected types and constraints.
    *   Sanitize the input to remove any potentially malicious content *before* it interacts with the Apollo Client cache.
2.  **Avoid Sensitive Data in Local State:**
    *   Do *not* store sensitive data (e.g., API keys, authentication tokens, personal information) in the Apollo Client's local state (managed by `InMemoryCache`).
    *   Use more secure storage mechanisms. For authentication tokens, `HttpOnly` cookies are the recommended approach. For temporary, less sensitive data, consider the browser's `sessionStorage` (but be aware of its limitations and security implications). Never use `localStorage` for sensitive data.
3.  **Code Reviews (Focus on Client-Side Logic):**
    *   Conduct thorough code reviews of any code that interacts with the Apollo Client's local state, paying particular attention to how user input is handled and how the state is updated.
    *   Look for potential vulnerabilities that could allow attackers to manipulate the state. This is a crucial part of the development process.

    **Threats Mitigated:**
    *   **Client-Side Logic Manipulation:** (Severity: Medium) - Prevents attackers from altering the application's behavior by modifying the local state.
    *   **Data Tampering (Local State):** (Severity: Medium) - Prevents unauthorized modification of data stored in the local state.
    *   **Potential XSS (if combined with poor rendering practices):** (Severity: High) - If manipulated state is rendered without proper sanitization, it could lead to XSS.  This highlights the importance of output encoding in your React components.

    **Impact:**
    *   **Client-Side Logic Manipulation/Data Tampering:** Risk moderately reduced (Medium reduction).
    *   **XSS:** Risk can be significantly reduced (High reduction) if combined with proper output encoding and sanitization in your React components.

    **Currently Implemented:**
    *   Limited input validation is performed in some components that use local state.

    **Missing Implementation:**
    *   Consistent and comprehensive input validation for *all* local state updates is missing. This needs to be implemented within the React components or through a custom Apollo Link.
    *   A clear policy on what data can and cannot be stored in local state is not fully defined.
    *   Regular code reviews specifically focused on local state interactions are not consistently performed.

## Mitigation Strategy: [Using Persisted Queries (Client-Side)](./mitigation_strategies/using_persisted_queries__client-side_.md)

1.  **Enable Persisted Queries in Apollo Client:**
    *   Configure your `ApolloClient` instance to use persisted queries. This usually involves using a specific link (e.g., `apollo-link-persisted-queries`) in your link chain.
2.  **Build Process Integration:**
    *   Integrate a build process (e.g., using `apollo-cli` or a similar tool) that automatically extracts your GraphQL queries and mutations and generates a mapping of query IDs (hashes) to query strings. This mapping is typically stored in a JSON file.
3.  **Client-Side Query ID Usage:**
    *   Instead of sending the full GraphQL query string, your client-side code (in your React components) will send only the query ID. The Apollo Client link will handle this automatically, looking up the ID in the generated mapping.
4. **Automatic Persisted Queries (APQ):**
    * Consider using Automatic Persisted Queries. With APQ, Apollo Client will first attempt to send only the query ID. If the server doesn't recognize the ID (because it's the first time it's seen it), the client will automatically send the full query string along with the ID. The server can then store this association, and subsequent requests with the same ID will only need to send the ID.

    **Threats Mitigated:**
    *   **Denial of Service (DoS) via Complex Queries:** (Severity: High) - Prevents clients from sending arbitrary, potentially large and complex queries.
    *   **Information Gathering (if combined with Introspection control):** (Severity: Medium) - Makes it harder for attackers to probe the schema.
    * **Reduces request size:** (Severity: Low) - Improves performance by sending smaller requests.

    **Impact:**
    *   **DoS/Resource Exhaustion:** Risk significantly reduced (High reduction).
    *   **Information Gathering:** Risk moderately reduced (Medium reduction).
    * **Performance:** Improves performance.

   **Currently Implemented:**
    *   The server supports persisted queries, but the client-side build process is not fully integrated.

    **Missing Implementation:**
    *   Full integration of Persisted Queries on the client-side is missing, including the build process to generate the query ID mapping and the configuration of Apollo Client to use the persisted queries link. Automatic Persisted Queries is not implemented.

