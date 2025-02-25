- **Vulnerability Name:** Arbitrary File Disclosure via Join Table Path Traversal  
  **Description:**  
  An attacker may supply an absolute file path as the “join table” identifier in an RBQL JOIN query. For example, by crafting a JOIN clause such as  
  ```
  ... INNER JOIN /etc/passwd ON a1 == b1
  ```  
  the function used to resolve the join table (i.e. `find_table_path` in *rbql_csv.py*) calls `os.path.expanduser()` on the supplied value without any sanitization or restrictions. If the supplied absolute path (e.g. `/etc/passwd` on Unix systems) exists, the code then opens and reads that file as if it were a CSV join table.  
  **Impact:**  
  Sensitive files outside the intended CSV data—such as system files or private documents—could be read and their contents injected into the query output. This may result in unauthorized disclosure of sensitive information.  
  **Vulnerability Rank:** High  
  **Currently Implemented Mitigations:**  
  There is no explicit check or validation on the join table identifier; the code simply uses `os.path.expanduser()` and then returns any candidate path that exists.  
  **Missing Mitigations:**  
  • Validate and sanitize join table paths by enforcing that only relative paths (or paths within a predetermined “safe” directory) are allowed.  
  • Implement a whitelist of allowed directories or restrict file access based on the application’s context.  
  **Preconditions:**  
  • The attacker must be able to supply a JOIN query (or another parameter that determines the join table file name) via the application’s interface.  
  • The underlying file system (especially on a publicly hosted instance) must be accessible and contain sensitive or system files.  
  **Source Code Analysis:**  
  • In *rbql_csv.py*, the function `find_table_path(main_table_dir, table_id)` takes the user‑supplied table identifier and calls:  
  ```python
  candidate_path = os.path.expanduser(table_id)
  if os.path.exists(candidate_path):
      return candidate_path
  ```  
  • The absence of any directory or file‐type checks means an absolute path (e.g. “/etc/passwd”) is accepted if it exists.  
  **Security Test Case:**  
  1. Prepare a query that uses a JOIN clause with an absolute file path (for example, `/etc/passwd`) as the join table identifier.  
  2. Run the query in an instance of the application that accepts external query input.  
  3. Verify that the output (or error messages) includes content from the sensitive file.  
  4. Confirm that restricting the join table filename (by implementing input validation) prevents the leak.

- **Vulnerability Name:** Detailed Error Message Information Disclosure  
  **Description:**  
  In several parts of the code—especially in the query execution routines (for example, in *vscode_rbql.py* and within the RBQL engine’s `exception_to_error_info(e)` routine)—if an error occurs (such as a SyntaxError or runtime exception), the code returns a JSON‐encoded error report that may include detailed error messages. These details can contain traceback information, file names, line numbers, and other internal diagnostic data. An attacker who can trigger an error by supplying a malformed or carefully crafted query might obtain internal configuration details that could be used in further attacks.  
  **Impact:**  
  Internal details (such as file paths, source code snippets, or even version information) may be leaked to an attacker. Such disclosures can ease reconnaissance by providing an attacker with insights into the application’s internals.  
  **Vulnerability Rank:** High  
  **Currently Implemented Mitigations:**  
  The code uses a helper function (`exception_to_error_info`) to reformat exception messages; however, it does not strip out or sufficiently sanitize detailed traceback information for errors such as SyntaxError.  
  **Missing Mitigations:**  
  • Sanitize error messages before sending them to the client, ensuring that sensitive details (e.g. internal file paths or traceback data) are removed or replaced with generic text.  
  • In a production/deployed setup, apply a “friendly error” policy that avoids dumping internal debug information.  
  **Preconditions:**  
  • The attacker must be able to supply query input (for example, via a publicly accessible web-based instance) and force an error (e.g. by supplying a malformed RBQL query).  
  **Source Code Analysis:**  
  • In *vscode_rbql.py*, the main function wraps `rbql.query_csv(...)` in a try/except block. If an exception occurs, it calls:  
  ```python
  error_type, error_msg = rbql.exception_to_error_info(e)
  sys.stdout.write(json.dumps({'error_type': error_type, 'error_msg': error_msg}))
  ```  
  • Inside *rbql_engine.py*, the function `exception_to_error_info(e)` uses Python’s traceback formatting (e.g. via `traceback.format_exception_only`) which may include file names and line numbers.  
  **Security Test Case:**  
  1. Submit a deliberately malformed or syntactically invalid RBQL query to the application.  
  2. Capture the JSON‑encoded error output.  
  3. Verify that the error output includes unsanitized internal details (e.g. absolute file paths, module names, or line numbers).  
  4. Confirm that after applying proper sanitization the detailed information is no longer disclosed.

- **Vulnerability Name:** CSV Injection via Unsanitized Cell Content in Output  
  **Description:**  
  When the application generates an output CSV file (for example, after running a transformation query), the CSV writer routines (in *rbql_csv.py* and *csv_utils.py*) may emit cell values without any additional sanitization in “simple” split mode. In particular, if a field’s content starts with characters such as “=”, “+”, “-”, or “@” (which many spreadsheet applications interpret as a formula), an attacker could embed a malicious formula. This is known as CSV injection or Formula Injection.  
  **Impact:**  
  When the output CSV file is subsequently opened in a vulnerable spreadsheet application (for example, Microsoft Excel), the injected formulas may be automatically executed. This can lead to arbitrary command execution or data exfiltration from the victim system.  
  **Vulnerability Rank:** High  
  **Currently Implemented Mitigations:**  
  • When using certain output policies like “quoted” or “quoted_rfc”, the fields are wrapped in double‑quotes. However, if the source CSV and the output are processed using a “simple” policy (or if the user chooses “input” as the out‑format), fields are written as‑is without sanitization against formula injection.  
  **Missing Mitigations:**  
  • Sanitize cell contents that begin with characters known to trigger formula interpretation. For example, prepend a single‑quote (or use another safe escape mechanism) to any cell that starts with “=”, “+”, “-”, or “@”.  
  **Preconditions:**  
  • The attacker must be able to control one or more cell values of the input CSV (or join file) used in the RBQL query.  
  • The output CSV must be generated using a policy that does not automatically quote/sanitize cell values (e.g. “simple” mode).  
  • A victim later opens the exported CSV in a spreadsheet application that executes formulas.  
  **Source Code Analysis:**  
  • In *rbql_csv.py*, the `CSVWriter.write()` method calls `normalize_fields(fields)`, which iterates over the output fields and converts non‑string values using `str()`. There is no check to see if a field starts with a dangerous character.  
  • In contrast, the quoting function (`quote_field`) only adds quotes if the field contains the delimiter or a double‑quote character; it does not check for a leading “=” (or similar) character.  
  **Security Test Case:**  
  1. Create an input CSV file (or join file) where one of the fields is set to a malicious formula (for example, `=CMD|' /C calc'!A0`).  
  2. Run an RBQL query in a configuration that uses a “simple” or “input” output policy (i.e. non‑quoted output).  
  3. Examine the output CSV file to verify that the malicious formula appears without added protection.  
  4. (Optionally) Open the output CSV in a testing spreadsheet environment to confirm that the formula is interpreted and executed.  
  5. Confirm that a proper fix (such as sanitizing fields that start with “=” by prefixing a safe character) would prevent the exploitation.