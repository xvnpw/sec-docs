- Vulnerability name: Code Injection in RBQL Query Execution

- Description:
    1. An attacker can craft a malicious RBQL query containing JavaScript code.
    2. The extension uses `eval()` in `rbql_core/rbql-js/rbql.js` to execute the generated JavaScript code based on the RBQL query.
    3. If the attacker-controlled RBQL query is executed, the attacker's JavaScript code will be executed within the extension's context.

- Impact:
    - **Critical**
    - Remote Code Execution (RCE). An attacker can execute arbitrary JavaScript code within the VSCode extension's context. This could lead to:
        - Stealing sensitive information from the user's workspace, including files, environment variables, and potentially credentials if stored in the workspace.
        - Modifying or deleting files in the user's workspace.
        - Installing malicious extensions or tools.
        - Using the VSCode extension as a stepping stone to further compromise the user's system.

- Vulnerability rank: critical

- Currently implemented mitigations:
    - None. The code directly uses `eval()` to execute dynamically generated JavaScript code from user-provided RBQL queries.

- Missing mitigations:
    - **Must sanitize or validate RBQL queries to prevent injection.** Ideally, use a safer alternative to `eval()`, such as a sandboxed JavaScript environment or a more secure code generation approach. If `eval()` is unavoidable, strictly control the input to ensure only safe RBQL language constructs are processed and user-provided JavaScript code cannot be injected.
    - Implement input validation and sanitization for all user-provided data that influences code execution, especially RBQL queries.

- Preconditions:
    - The user must execute an RBQL query provided or controlled by the attacker. This could be achieved through social engineering (e.g., tricking a user into running a malicious query) or if the attacker can somehow influence the query input (e.g., through a configuration setting or a file that the extension processes).

- Source code analysis:
    1. File: `/code/rbql_core/rbql-js/rbql.js`
    2. Function: `compile_and_run(query_context)`
    3. Line:
    ```javascript
    let main_loop_promise = eval(main_loop_body);
    ```
    4. The `eval(main_loop_body)` function directly executes the JavaScript code contained in the `main_loop_body` string.
    5. The `main_loop_body` is generated in `generate_main_loop_code(query_context)` function.
    6. The `generate_main_loop_code` function embeds various expressions and code snippets into template strings, including:
        - `query_context.user_init_code` - User-defined functions (less directly attacker-controlled, but still a risk if user is tricked into using a malicious init file).
        - `query_context.where_expression` - WHERE clause expression.
        - `query_context.select_expression` - SELECT clause expression.
        - `query_context.update_expressions` - UPDATE clause expressions.
        - `query_context.aggregation_key_expression` - GROUP BY clause expression.
        - `query_context.sort_key_expression` - ORDER BY clause expression.
        - `query_context.lhs_join_var_expression` - JOIN clause expression.
    7. These expressions are derived from the user-provided RBQL query text.
    8. If an attacker can inject malicious JavaScript code into any of these RBQL query components, it will be executed by `eval()`.

    Visualization:

    ```mermaid
    graph LR
        A[User Input: Malicious RBQL Query] --> B(Extension Code: rbql_client.js, extension.js);
        B --> C(RBQL Parser: rbql_core/rbql-js/rbql.js);
        C --> D{Code Generation: generate_main_loop_code};
        D --> E["eval(main_loop_body)"];
        E --> F[Code Execution in Extension Context];
        F --> G((Compromise: RCE));
    ```

- Security test case:
    1. Open VSCode with the Rainbow CSV extension installed.
    2. Create a new file or open an existing CSV file.
    3. Open the RBQL console by running the "RBQL" command.
    4. In the RBQL input, enter the following malicious query:
    ```rbql
    SELECT a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24, a25, a26, a27, a28, a29, a30, a31, a32, a33, a34, a35, a36, a37, a38, a39, a40, a41, a42, a43, a44, a45, a46, a47, a48, a49, a50, a51, a52, a53, a54, a55, a56, a57, a58, a59, a60, a61, a62, a63, a64, a65, a66, a67, a68, a69, a70, a71, a72, a73, a74, a75, a76, a77, a78, a79, a80, a81, a82, a83, a84, a85, a86, a87, a88, a89, a90, a91, a92, a93, a94, a95, a96, a97, a98, a99, a100, process.exit()
    ```
    5. Execute the query by pressing Enter or clicking the "Run" button.
    6. Observe that VSCode immediately closes or becomes unresponsive, indicating that the `process.exit()` command was successfully executed, confirming code injection.