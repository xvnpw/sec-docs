# Mitigation Strategies Analysis for graphql-dotnet/graphql-dotnet

## Mitigation Strategy: [Query Depth Limiting with `MaxDepthRule`](./mitigation_strategies/query_depth_limiting_with__maxdepthrule_.md)

*   **Description:**
    1.  **Identify Maximum Depth:** Analyze your GraphQL schema and determine the maximum reasonable nesting depth. Start conservatively (e.g., 5-7).
    2.  **Implement `MaxDepthRule`:**  Use the `AddValidationRule` method within your `AddGraphQL` configuration to add the built-in `MaxDepthRule`.
        ```csharp
        services.AddGraphQL(b => b
            .AddSchema<MySchema>()
            .AddValidationRule(new MaxDepthRule(10)) // Example: Limit to 10
        );
        ```
    3.  **Test:** Create queries exceeding the limit and verify rejection. Test valid queries within the limit.
    4.  **Monitor and Adjust:** Monitor logs for rejected legitimate queries and adjust the limit if needed.

*   **List of Threats Mitigated:**
    *   **Denial of Service (DoS) via Deeply Nested Queries:** (Severity: High)
    *   **Resource Exhaustion:** (Severity: High)

*   **Impact:**
    *   **Denial of Service (DoS):** Risk significantly reduced.
    *   **Resource Exhaustion:** Risk significantly reduced.

*   **Currently Implemented:** Yes / Partially / No (Specify) - Provide details.

*   **Missing Implementation:** If "Partially" or "No" above, describe where it's missing.

## Mitigation Strategy: [Query Complexity Limiting with `MaxComplexityRule` or Custom Analyzer](./mitigation_strategies/query_complexity_limiting_with__maxcomplexityrule__or_custom_analyzer.md)

*   **Description:**
    1.  **Choose a Complexity Metric:** Decide on a metric (cost-per-field or custom logic).
    2.  **Assign Costs:** (If using `MaxComplexityRule`) Assign costs to fields, considering list fields, complex queries, external services, and impactful arguments.
    3.  **Implement the Rule:** Use `AddValidationRule` with `MaxComplexityRule` or a custom `IDocumentValidator`.
        ```csharp
        // Example using MaxComplexityRule
        services.AddGraphQL(b => b
            .AddSchema<MySchema>()
            .AddValidationRule(new MaxComplexityRule(1000, (context, node) => {
                if (node is Field field) {
                    return field.Definition.ResolvedType is ListGraphType ? 10 : 1;
                }
                return 0;
            }))
        );
        ```
    4.  **Set a Complexity Limit:** Determine a reasonable maximum complexity score.
    5.  **Test and Refine:** Test with varying complexity levels. Monitor and adjust costs/limit.

*   **List of Threats Mitigated:**
    *   **Denial of Service (DoS) via Complex Queries:** (Severity: High)
    *   **Resource Exhaustion:** (Severity: High)
    *   **Performance Degradation:** (Severity: Medium)

*   **Impact:**
    *   **Denial of Service (DoS):** Risk significantly reduced.
    *   **Resource Exhaustion:** Risk significantly reduced.
    *   **Performance Degradation:** Risk reduced.

*   **Currently Implemented:** Yes / Partially / No (Specify) - Provide details.

*   **Missing Implementation:** If "Partially" or "No" above, describe where it's missing.

## Mitigation Strategy: [Introspection Control](./mitigation_strategies/introspection_control.md)

*   **Description:**
    1.  **Assess Introspection Needs:** Determine if introspection is needed in production.
    2.  **Disable Introspection (if applicable):** Set `EnableSchemaPrinting` to `false` in `ExecutionOptions`.
        ```csharp
        services.AddGraphQL(options =>
        {
            if (Environment.IsProduction())
            {
                options.EnableSchemaPrinting = false;
            }
        });
        ```
    3.  **Implement `ISchemaFilter` (if partial introspection is needed):**
        *   Create a class implementing `ISchemaFilter`.
        *   In the `Filter` method, use `ISchemaFilterContext` to `Ignore` types/fields/arguments.
        *   Register the `ISchemaFilter` using `AddSchemaFilter`.
        ```csharp
        // Example ISchemaFilter
        public class MySchemaFilter : ISchemaFilter
        {
            public void Filter(ISchemaFilterContext context)
            {
                context.Ignore(context.Schema.AllTypes.FirstOrDefault(t => t.Name == "InternalType"));
            }
        }
        services.AddGraphQL(b => b.AddSchemaFilter<MySchemaFilter>());
        ```
    4.  **Test:** Verify introspection is disabled or partially restricted.

*   **List of Threats Mitigated:**
    *   **Information Disclosure:** (Severity: Medium)
    *   **Schema Enumeration:** (Severity: Medium)

*   **Impact:**
    *   **Information Disclosure:** Risk significantly reduced/eliminated.
    *   **Schema Enumeration:** Risk significantly reduced/eliminated.

*   **Currently Implemented:** Yes / Partially / No (Specify) - Provide details.

*   **Missing Implementation:** If "Partially" or "No" above, describe where it's missing.

## Mitigation Strategy: [Disable Field Suggestions](./mitigation_strategies/disable_field_suggestions.md)

*   **Description:**
    1.  **Locate Configuration:**  Find `ExecutionOptions` in your `AddGraphQL` configuration.
    2.  **Disable Suggestions:** Set `EnableSuggestions` to `false`.
        ```csharp
        services.AddGraphQL(b => b
            .ConfigureExecutionOptions(options =>
            {
                options.EnableSuggestions = false;
            })
        );
        ```
    3.  **Test:** Send a query with an invalid field and verify no suggestions are provided.

*   **List of Threats Mitigated:**
    *   **Information Disclosure (Minor):** (Severity: Low)

*   **Impact:**
    *   **Information Disclosure (Minor):** Risk eliminated.

*   **Currently Implemented:** Yes / Partially / No (Specify) - Provide details.

*   **Missing Implementation:** If "Partially" or "No" above, describe where it's missing.

## Mitigation Strategy: [Customized Error Handling](./mitigation_strategies/customized_error_handling.md)

*   **Description:**
    1.  **Identify Sensitive Information:** Determine what shouldn't be exposed in errors.
    2.  **Implement `UnhandledExceptionDelegate`:** Set `UnhandledExceptionDelegate` in `ExecutionOptions`.
        ```csharp
        services.AddGraphQL(b => b
            .ConfigureExecutionOptions(options =>
            {
                options.UnhandledExceptionDelegate = async context =>
                {
                    // Log internally
                    _logger.LogError(context.OriginalException, "GraphQL error");
                    context.ErrorMessage = "An unexpected error occurred."; // Generic message
                    await Task.CompletedTask;
                };
            })
        );
        ```
    3.  **Log Exceptions Internally:** Log full exception details internally, *not* to the client.
    4.  **Return Generic Error Messages:** Return generic messages to the client.
    5.  **Consider Error Codes:** Use standardized error codes for client handling.
    6. **Use `AddErrorInfoProvider`:** Use for more control over error formatting, set `ExposeExceptionStackTrace` to `false`.
        ```csharp
        services.AddGraphQL(b => b
            .AddErrorInfoProvider(opt => opt.ExposeExceptionStackTrace = false)
        );
        ```
    7.  **Test:** Trigger errors and verify non-revealing messages.

*   **List of Threats Mitigated:**
    *   **Information Disclosure via Error Messages:** (Severity: Medium)

*   **Impact:**
    *   **Information Disclosure via Error Messages:** Risk significantly reduced.

*   **Currently Implemented:** Yes / Partially / No (Specify) - Provide details.

*   **Missing Implementation:** If "Partially" or "No" above, describe where it's missing.

## Mitigation Strategy: [Apply Per-Operation Limits within Batches (if batching is enabled)](./mitigation_strategies/apply_per-operation_limits_within_batches__if_batching_is_enabled_.md)

*   **Description:**
    1. **Access Operations in Batch:** Within your `MaxComplexityRule`, `MaxDepthRule` or custom `IDocumentValidator`, access the individual operations within a batched query.  The `Document` property of the `IValidationContext` will contain a `Document` with multiple `OperationDefinition` nodes if it's a batch request.
    2. **Iterate and Validate:** Iterate through each `OperationDefinition` within the `Document`.  Apply your complexity and depth checks *to each operation individually*.
    3. **Aggregate Results (if needed):** If you need to track a total complexity across the entire batch (in addition to per-operation limits), you can accumulate the complexity scores within your validation rule.
    4. **Test:** Send batched queries with varying numbers and complexities of operations to ensure per-operation limits are enforced.

    ```csharp
    //Example within a custom IDocumentValidator
    public class MyCustomValidator : DocumentValidator
    {
        public override ValueTask<INodeVisitor> ValidateAsync(ValidationContext context)
        {
            return new ValueTask<INodeVisitor>(new MyVisitor(context));
        }
    }
    public class MyVisitor: INodeVisitor{
        private readonly ValidationContext _context;
        public MyVisitor(ValidationContext context){
            _context = context;
        }
        public void Enter(ASTNode node){
            if (node is Document doc)
            {
                foreach (var operation in doc.Definitions.OfType<OperationDefinition>())
                {
                    // Apply your per-operation complexity/depth checks here
                    int depth = CalculateDepth(operation); // Example: Custom depth calculation
                    if (depth > 10) // Example limit
                    {
                        _context.ReportError(new ValidationError(
                            _context.Document.Source,
                            "operation-depth",
                            $"Operation exceeds maximum depth of 10. Depth: {depth}",
                            operation
                        ));
                    }
                }
            }
        }
        public void Exit(ASTNode node){}
        private int CalculateDepth(ASTNode node)
        {
            // Implement your depth calculation logic here
            // ... (recursive function to traverse the AST) ...
            return 0; // Placeholder
        }
    }

    //Register in services
    services.AddGraphQL(b => b.AddValidator<MyCustomValidator>());
    ```

*   **List of Threats Mitigated:**
    *   **Denial of Service (DoS) via Batching:** (Severity: High)
    *   **Resource Exhaustion:** (Severity: High)

*   **Impact:**
    *   **Denial of Service (DoS) via Batching:** Risk significantly reduced.
    *   **Resource Exhaustion:** Risk significantly reduced.

*   **Currently Implemented:** Yes / Partially / No (Specify) - Provide details.

*   **Missing Implementation:** If "Partially" or "No" above, describe where it's missing.

## Mitigation Strategy: [Proper DataLoader Configuration (if used)](./mitigation_strategies/proper_dataloader_configuration__if_used_.md)

*   **Description:**
    1.  **Understand DataLoader:** Familiarize yourself with the `DataLoader` pattern and its use in `graphql-dotnet`.
    2.  **Identify N+1 Problems:** Analyze resolvers for potential N+1 query problems.
    3.  **Implement DataLoaders:** Create `DataLoader` instances for fields prone to N+1 problems, using batching to fetch data efficiently.
    4.  **Configure Batching:** Ensure correct `DataLoader` configuration for batching requests.
    5.  **Test:** Use a profiler/logging to verify reduced database queries.
    6. **Monitor:** Regularly monitor performance.

*   **List of Threats Mitigated:**
    *   **Performance Degradation (N+1 Problem):** (Severity: Medium)
    *   **Resource Exhaustion (Database):** (Severity: Medium)

*   **Impact:**
    *   **Performance Degradation (N+1 Problem):** Risk significantly reduced.
    *   **Resource Exhaustion (Database):** Risk significantly reduced.

*   **Currently Implemented:** Yes / Partially / No (Specify) - Provide details.

*   **Missing Implementation:** If "Partially" or "No" above, describe where it's missing.

