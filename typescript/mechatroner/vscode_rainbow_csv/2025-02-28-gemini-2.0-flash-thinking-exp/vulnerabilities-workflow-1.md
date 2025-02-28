## Combined Vulnerability List: RBQL Code Injection Vulnerabilities

This document outlines code injection vulnerabilities found within the RBQL (Rainbow Query Language) functionality of the Rainbow CSV VSCode extension. These vulnerabilities stem from the unsafe use of `eval()` to execute dynamically generated JavaScript code based on user inputs, including RBQL queries, User Defined Functions (UDFs), and CSV column names. Exploiting these vulnerabilities can lead to arbitrary code execution on the user's machine.

### 1. Vulnerability Name: RBQL Query Code Injection via User Defined Functions (UDFs)

- Description:
    1. An attacker can create a malicious JavaScript file at `~/.rbql_init_source.js` (or `~/.rbql_init_source.py` for Python backend).
    2. This file can contain arbitrary JavaScript code, including malicious commands.
    3. When a user executes an RBQL query in the VSCode extension (using either JS or Python backend), the extension automatically loads and executes the code from this UDF file within the RBQL query execution context.
    4. The attacker's malicious code will be executed with the privileges of the VSCode extension, which in turn runs with the privileges of the VSCode user.

- Impact:
    - **High/Critical:** Arbitrary code execution on the user's machine. An attacker can potentially gain full control over the user's system, steal sensitive data, install malware, or perform other malicious actions. The impact is critical because it allows for complete compromise of the user's environment through the VSCode extension.

- Vulnerability Rank: Critical

- Currently implemented mitigations:
    - None. The extension explicitly loads and executes user-provided code from `~/.rbql_init_source.js` without any sandboxing or security checks as described in `/code/rbql_core/rbql.js`, `/code/rainbow_utils.js` and documentation `/code/rbql_core/README.md`, `/code/README.md`.

- Missing mitigations:
    - **Sandboxing UDF execution:** Implement a secure sandbox environment for executing UDF code to prevent access to sensitive system resources and APIs.
    - **Input sanitization and validation:** While this vulnerability is about UDF execution, general input sanitization and validation for RBQL queries could reduce the attack surface.
    - **User warning:** Display a clear warning to the user when UDFs are about to be loaded and executed, emphasizing the security risks involved and advising users to only use trusted UDF sources. Consider disabling UDFs by default and requiring explicit user opt-in.
    - **Path restriction:** Restrict UDF loading to a specific extension-controlled directory instead of user home directory to limit attacker's control over UDF source.

- Preconditions:
    1. The attacker must have write access to the user's home directory to create or modify the UDF file (`~/.rbql_init_source.js` or `~/.rbql_init_source.py`). This could be achieved through various means like exploiting other vulnerabilities on the user's system or social engineering.
    2. The user must execute an RBQL query using the Rainbow CSV extension after the malicious UDF file has been placed.

- Source code analysis:
    1. **`/code/rainbow_utils.js`**:
        - Functions `get_default_js_udf_content` and `get_default_python_udf_content` provide default content for UDF files, indicating the intended use of these files.
        - Functions `rbql_query_web` and `rbql_query_node` are responsible for executing RBQL queries. `rbql_query_node` specifically loads user init code:
            ```javascript
            async function rbql_query_node(vscode_global_state, query_text, input_path, input_delim, input_policy, output_path, output_delim, output_policy, csv_encoding, output_warnings, with_headers=false, comment_prefix=null, user_init_code='', options=null) {
                // ...
                let default_init_source_path = path.join(os.homedir(), '.rbql_init_source.js');
                if (user_init_code == '' && fs.existsSync(default_init_source_path)) {
                    user_init_code = rbql_csv.read_user_init_code(default_init_source_path);
                }
                // ...
                await rbql.query(query_text, input_iterator, output_writer, output_warnings, join_tables_registry, user_init_code);
                // ...
            }
            ```
    2. **`/code/rbql_core/rbql-js/rbql_csv.js`**:
        - Function `read_user_init_code` reads the content of the UDF file:
            ```javascript
            function read_user_init_code(rbql_init_source_path) {
                return fs.readFileSync(rbql_init_source_path, 'utf-8');
            }
            ```
    3. **`/code/rbql_core/rbql-js/rbql.js`**:
        - Function `query` takes `user_init_code` as input and executes it as part of the query processing:
            ```javascript
            async function query(query_text, input_iterator, output_writer, output_warnings, join_tables_registry=null, user_init_code='') {
                query_context = new RBQLContext(query_text, input_iterator, output_writer, user_init_code);
                await shallow_parse_input_query(query_text, input_iterator, join_tables_registry, query_context);
                await compile_and_run(query_context);
                await query_context.writer.finish();
                output_warnings.push(...input_iterator.get_warnings());
                if (query_context.join_map_impl)
                    output_warnings.push(...query_context.join_map_impl.get_warnings());
                output_warnings.push(...output_writer.get_warnings());
            }
            ```
        - Function `generate_main_loop_code` embeds the `user_init_code` into the main loop body, which is then evaluated using `eval()`:
            ```javascript
            const MAIN_LOOP_BODY = `
            __USER_INIT_CODE__

            let NU = 0;
            let NR = 0;

            let stop_flag = false;
            while (!stop_flag) {
                let record_a = await query_context.input_iterator.get_record();
                if (record_a === null)
                    break;
                NR += 1;
                let NF = record_a.length;
                query_context.unnest_list = null; // TODO optimize, don't need to set this every iteration
                try {
                    __CODE__
                } catch (e) {
                    if (e.constructor.name === 'InternalBadFieldError') {
                        throw new RbqlRuntimeError(\`No "a\${e.bad_idx + 1}" field at record \${NR}\`);
                    } else if (e.constructor.name === 'RbqlParsingError') {
                        throw(e);
                    } else {
                        throw new RbqlRuntimeError(\`At record \${NR}, Details: \${e.message}\`);
                    }
                }
            }
            `;
            function generate_main_loop_code(query_context) {
                // ...
                js_code = embed_code(MAIN_LOOP_BODY, '__USER_INIT_CODE__', query_context.user_init_code);
                // ...
                return "(async () => {" + js_code + "})()";
            }

            async function compile_and_run(query_context) {
                let main_loop_body = generate_main_loop_code(query_context);
                try {
                    let main_loop_promise = eval(main_loop_body); // Vulnerable line: User code is executed via eval()
                    await main_loop_promise;
                    // ...
                } catch (e) {
                    // ...
                }
            }
            ```
        - The code clearly shows that the content of `user_init_code` is directly embedded into the generated JavaScript code and then executed using `eval()`, which is a well-known code injection vulnerability if the `user_init_code` is not from a trusted source.

- Security test case:
    1. **Prerequisites:** Ensure you have the Rainbow CSV extension installed in VSCode.
    2. **Create Malicious UDF:** Create a file named `.rbql_init_source.js` in your home directory (`~/.rbql_init_source.js`) with the following content:
        ```javascript
        function malicious_udf() {
            const process = require('process');
            process.mainModule.require('child_process').execSync('touch /tmp/pwned_by_rainbow_csv');
            return "pwned";
        }
        ```
        This code will attempt to create a file `/tmp/pwned_by_rainbow_csv` when the UDF is executed.
    3. **Open a CSV file in VSCode.** Any CSV file will work.
    4. **Execute RBQL Query:** Open the RBQL console (e.g., by running the `Rainbow CSV: RBQL` command) and enter a query that uses the malicious UDF, for example: `SELECT malicious_udf(), a1`.
    5. **Run the query.**
    6. **Verify Code Execution:** Check if the file `/tmp/pwned_by_rainbow_csv` has been created. If it exists, the malicious code from the UDF has been successfully executed, confirming the vulnerability. On Windows, you can modify the command to create a file in the `TEMP` directory, e.g., `process.mainModule.require('child_process').execSync('echo pwned > %TEMP%\\pwned_by_rainbow_csv.txt');`.

### 2. Vulnerability Name: RBQL Query Injection

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

- Vulnerability Rank: critical

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

### 3. Vulnerability Name: RBQL Query Injection via Crafted Column Names

- Description:
  1. An attacker can craft a CSV file where column names contain JavaScript code.
  2. When a user executes an RBQL query on this CSV file, the crafted column names, when used in the RBQL query (e.g., using attribute access like `a.column_name`), can lead to arbitrary JavaScript code execution within the extension's context. This is because the extension dynamically generates JavaScript code based on the RBQL query and column names, and then executes it using `eval`.

- Impact:
  Critical. Arbitrary JavaScript code execution within the VSCode extension context. This could allow an attacker to:
    - Steal sensitive information from the user's VSCode workspace.
    - Modify files in the user's workspace.
    - Install malicious extensions or tools.
    - Potentially gain further access to the user's system depending on the VSCode extension's permissions and the user's environment.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
  - None. The code directly uses column names in dynamically generated JavaScript code without sufficient sanitization.

- Missing Mitigations:
  - Input sanitization for column names to prevent injection. Column names should be validated and sanitized to remove or escape any characters that could be interpreted as code.
  - Instead of using `eval`, consider using a safer approach for executing RBQL queries, such as a sandboxed environment or a more secure code generation and execution mechanism.
  - Implement Content Security Policy (CSP) for webview if applicable to further restrict the capabilities of potentially injected scripts.

- Preconditions:
  1. The user must open a CSV file crafted by the attacker in VSCode with the Rainbow CSV extension activated.
  2. The crafted CSV file must contain malicious JavaScript code within its column names.
  3. The user must execute an RBQL query that references these malicious column names using attribute access notation (e.g., `a.column_name`).

- Source Code Analysis:
  1. **`/code/rbql_core/rbql-js/rbql.js`**:
     - The `parse_attribute_variables` function in `/code/rbql_core/rbql-js/rbql.js` is responsible for parsing attribute-style column variables (e.g., `a.column_name`).
     - It directly uses the column names from the header to construct variable names without proper sanitization.
     - These unsanitized column names are then used in dynamically generated JavaScript code.

     ```javascript
     function parse_attribute_variables(query_text, prefix, column_names, column_names_source, dst_variables_map) {
         // ...
         for (let column_name of column_names_from_query) {
             let zero_based_idx = column_names.indexOf(column_name);
             if (zero_based_idx != -1) {
                 dst_variables_map[`${prefix}.${column_name}`] = {initialize: true, index: zero_based_idx};
             } else {
                 throw new RbqlParsingError(`Unable to find column "${column_name}" in ${prefix == 'a' ? 'input' : 'join'} ${column_names_source}`);
             }
         }
     }
     ```

  2. **`/code/rbql_core/rbql-js/rbql.js`**:
     - The `generate_init_statements` function creates JavaScript code to initialize variables based on column names.
     - It uses the potentially malicious column names directly within the generated code.

     ```javascript
     function generate_init_statements(query_text, variables_map, join_variables_map, indent) {
         // ...
         for (const [variable_name, var_info] of Object.entries(variables_map)) {
             if (var_info.initialize) {
                 let variable_declaration_keyword = simple_var_name_rgx.exec(variable_name) ? 'var ' : '';
                 code_lines.push(`${variable_declaration_keyword}${variable_name} = safe_get(record_a, ${var_info.index});`);
             }
         }
         // ...
     }
     ```

  3. **`/code/rbql_core/rbql-js/rbql.js`**:
     - The `compile_and_run` function uses `eval` to execute the dynamically generated JavaScript code, including the unsanitized column names.

     ```javascript
     async function compile_and_run(query_context) {
         let main_loop_body = generate_main_loop_code(query_context);
         try {
             let main_loop_promise = eval(main_loop_body); // Vulnerable eval call
             await main_loop_promise;
         } catch (e) {
         // ...
     }
     ```

- Security Test Case:
  1. Create a CSV file named `evil_csv.csv` with the following content:
     ```csv
     Column1,Column'); process.mainModule.require('child_process').execSync('touch /tmp/pwned'); //EvilColumn
     value1,value2
     ```
     This CSV contains a column named `Column'); process.mainModule.require('child_process').execSync('touch /tmp/pwned'); //EvilColumn` which includes JavaScript code.

  2. Open `evil_csv.csv` in VSCode with the Rainbow CSV extension activated. Ensure the file is recognized as a CSV format by the extension.

  3. Open the RBQL console by running the command `Rainbow CSV: RBQL`.

  4. In the RBQL console, enter the following query that references the malicious column name using attribute access:
     ```rbql
     SELECT a."Column'); process.mainModule.require('child_process').execSync('touch /tmp/pwned'); //EvilColumn" FROM input
     ```
     or
     ```rbql
     SELECT a.Column____process_mainModule_require_child_process_execSync_touch__tmp_pwned_____EvilColumn FROM input
     ```

  5. Execute the RBQL query by pressing Enter or clicking the "Run" button.

  6. **Verify the vulnerability:** Check if the file `/tmp/pwned` has been created on your system. If it has, this confirms that the JavaScript code embedded in the column name was executed, demonstrating arbitrary code execution.