# Mitigation Strategies Analysis for graphql/graphql-js

## Mitigation Strategy: [Query Complexity and Depth Limiting (using `graphql-js` validation rules)](./mitigation_strategies/query_complexity_and_depth_limiting__using__graphql-js__validation_rules_.md)

1.  **Leverage `graphql-js` Validation:** `graphql-js` provides a `validationRules` option in its execution functions (and middleware like `express-graphql`). This is the *core* mechanism for this mitigation.
2.  **Depth Limiting:** Use the `depthLimit` validation rule (often from the `graphql-depth-limit` package, but it interacts directly with `graphql-js`).  Import `depthLimit` and add it to the `validationRules` array.  This rule *rejects* the query *before* any resolvers are executed, based purely on the query's structure.
    ```javascript
    import depthLimit from 'graphql-depth-limit';
    import { graphqlHTTP } from 'express-graphql';

    app.use('/graphql', graphqlHTTP({
        schema: mySchema,
        validationRules: [ depthLimit(10) ] // Limit to 10 levels
    }));
    ```
3.  **Cost Analysis (Advanced):** Use `graphql-cost-analysis` (or a custom implementation) *in conjunction with* the `validationRules` option.  This also operates *before* resolver execution.  The cost analysis library examines the query AST and calculates a cost based on your schema's field costs.
    ```javascript
    // (Conceptual - using a hypothetical cost analysis library)
    import { costAnalysis } from 'my-graphql-cost-library';

    const costRules = { /* ... your cost rules ... */ };

    app.use('/graphql', graphqlHTTP({
        schema: mySchema,
        validationRules: [ costAnalysis({ costRules, maxCost: 100 }) ]
    }));
    ```
4.  **Custom Validation Rules:** You can create *your own* validation rules that are functions conforming to the `graphql-js` validation rule interface.  This allows for highly specific checks based on the query AST. This is the most direct `graphql-js` interaction.

*   **Threats Mitigated:**
    *   **Denial of Service (DoS) via Resource Exhaustion:** (Severity: High) - `graphql-js`'s validation prevents execution of overly complex queries.
    *   **Algorithmic Complexity Attacks:** (Severity: High) - Specifically targets GraphQL's query capabilities.

*   **Impact:**
    *   **DoS/Algorithmic Complexity:** Risk significantly reduced (High impact) because the validation happens *before* any potentially expensive resolver logic.

*   **Currently Implemented:**
    *   Depth limiting (using `graphql-depth-limit` within `validationRules`) is implemented in `server/index.js`.

*   **Missing Implementation:**
    *   Cost analysis (using `graphql-cost-analysis` or a custom rule within `validationRules`) is not implemented.
    *   Custom validation rules (beyond depth limiting) are not implemented.

## Mitigation Strategy: [Introspection Control (using `graphql-js` options)](./mitigation_strategies/introspection_control__using__graphql-js__options_.md)

1.  **`introspection` Option:** `graphql-js` (and middleware like `express-graphql`) provides an `introspection` option.  This *directly* controls whether the introspection query (`__schema`, `__type`, etc.) is allowed.
2.  **Disable in Production:** Set `introspection: false` in your production configuration. This is a *direct* configuration of `graphql-js`'s behavior.
    ```javascript
    app.use('/graphql', graphqlHTTP({
        schema: mySchema,
        introspection: process.env.NODE_ENV !== 'production'
    }));
    ```
3. **GraphiQL and Introspection:** The `graphiql` option (in `express-graphql`) often implicitly controls introspection, as GraphiQL relies on it. Disabling GraphiQL *usually* disables introspection as a side effect.

*   **Threats Mitigated:**
    *   **Information Disclosure (Schema Exposure):** (Severity: Medium) - Directly prevents `graphql-js` from responding to introspection queries.
    *   **Reconnaissance:** (Severity: Medium) - Makes it harder for attackers to map out your API.

*   **Impact:**
    *   **Information Disclosure/Reconnaissance:** Risk significantly reduced (High impact) in production by setting `introspection: false`.

*   **Currently Implemented:**
    *   Introspection is disabled in production using the `introspection` option in `server/index.js`.

*   **Missing Implementation:**
    *   None, as long as we don't need restricted introspection access.

## Mitigation Strategy: [Field Suggestion Control (via GraphiQL and `graphql-js`)](./mitigation_strategies/field_suggestion_control__via_graphiql_and__graphql-js__.md)

1.  **GraphiQL Dependency:** Field suggestions are primarily a feature of GraphiQL, the in-browser IDE.  `graphql-js` itself doesn't *directly* offer a "suggestions" option separate from GraphiQL.
2.  **`graphiql` Option:** The `graphiql` option in `express-graphql` (which wraps `graphql-js`) controls the availability of GraphiQL.  Disabling GraphiQL *effectively* disables field suggestions.
    ```javascript
    app.use('/graphql', graphqlHTTP({
        schema: mySchema,
        graphiql: false, // Disables GraphiQL and, thus, suggestions
    }));
    ```
3. **No Direct `graphql-js` Control:** There isn't a separate, fine-grained "disable suggestions" option *within* `graphql-js` itself, independent of GraphiQL.

*   **Threats Mitigated:**
    *   **Information Disclosure (Field Enumeration):** (Severity: Low) - Prevents attackers from using suggestions to guess field names.

*   **Impact:**
    *   **Information Disclosure:** Risk significantly reduced (High impact) in production by disabling GraphiQL (and thus suggestions).

*   **Currently Implemented:**
    *   Field suggestions are disabled in production because GraphiQL is disabled via the `graphiql` option in `server/index.js`.

*   **Missing Implementation:**
    *   None, given the dependency on GraphiQL.

## Mitigation Strategy: [Batching Attack Mitigation (Custom Middleware interacting with `graphql-js`)](./mitigation_strategies/batching_attack_mitigation__custom_middleware_interacting_with__graphql-js__.md)

1.  **No Built-in Batch Limiting:** `graphql-js` *does not* have built-in options to limit the number of queries in a batch. This is a crucial distinction.
2.  **Custom Middleware:** You *must* implement custom middleware *that interacts with* the incoming request *before* it reaches `graphql-js`'s execution functions. This middleware would:
    *   Parse the request body (usually JSON).
    *   Check if it's an array (indicating a batch).
    *   Count the number of operations in the array.
    *   Reject the request if the count exceeds a limit.
3. **Interaction with `graphql-js`:** The mitigation is *indirect*. The middleware prevents the batch from *ever reaching* `graphql-js` if it's too large.  It's not a configuration *of* `graphql-js`.

*   **Threats Mitigated:**
    *   **Amplified DoS Attacks:** (Severity: High) - Prevents `graphql-js` from processing excessively large batches.
    *   **Resource Exhaustion (via Batching):** (Severity: High)

*   **Impact:**
    *   **Amplified DoS/Resource Exhaustion:** Risk significantly reduced (High impact) by preventing large batches from reaching `graphql-js`.

*   **Currently Implemented:**
    *   Not implemented.

*   **Missing Implementation:**
    *   Batch limiting middleware is entirely missing. This requires custom code *outside* of `graphql-js`'s direct configuration.

