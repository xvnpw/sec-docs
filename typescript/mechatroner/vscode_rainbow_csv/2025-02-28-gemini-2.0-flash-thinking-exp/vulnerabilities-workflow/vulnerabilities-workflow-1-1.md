## Vulnerability List

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

This test case will demonstrate arbitrary code execution through UDFs, confirming the critical vulnerability.