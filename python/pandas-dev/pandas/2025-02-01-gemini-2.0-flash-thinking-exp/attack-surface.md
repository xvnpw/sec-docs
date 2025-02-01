# Attack Surface Analysis for pandas-dev/pandas

## Attack Surface: [Deserialization Vulnerabilities via `read_pickle()`](./attack_surfaces/deserialization_vulnerabilities_via__read_pickle___.md)

**Description:** Using `pandas.read_pickle()` to deserialize data from untrusted sources can lead to arbitrary code execution. Malicious pickle files can execute code during deserialization.

**Pandas Contribution:** `pandas.read_pickle()` is the function that performs deserialization of pickle files, inherently executing code embedded within them.

**Example:** A web application processes user-uploaded `.pkl` files using `read_pickle()`. A malicious `.pkl` file is uploaded, containing code that executes on the server when processed by pandas, leading to server compromise.

**Impact:** Critical - Arbitrary code execution, full server compromise.

**Risk Severity:** Critical

**Mitigation Strategies:**
*   **Avoid `read_pickle()` for untrusted data:** Do not use `read_pickle()` to process data from untrusted sources.
*   **Use safer formats:** Prefer safer, text-based formats like JSON or CSV for untrusted data.
*   **Sandboxing:** If `read_pickle()` is unavoidable, execute it in a heavily sandboxed environment.

## Attack Surface: [Code Execution via `eval()` and `query()`](./attack_surfaces/code_execution_via__eval____and__query___.md)

**Description:**  Pandas functions utilizing `eval()` or similar dynamic code execution, especially with user-controlled input, can be exploited for code injection. This includes `DataFrame.query()` and potentially data input functions with specific engines.

**Pandas Contribution:** `DataFrame.query()` directly uses string-based expressions that can execute arbitrary code if crafted maliciously. Certain data reading engines in pandas might also use `eval()` internally.

**Example:** A web application uses user-provided input to construct a query string for `DataFrame.query()`. A malicious user injects code into the query string, which is then executed by pandas, leading to server compromise.

**Impact:** High - Arbitrary code execution, server compromise.

**Risk Severity:** High

**Mitigation Strategies:**
*   **Avoid `eval()` and `query()` with user input:** Do not use `DataFrame.query()` or functions relying on `eval()` with user-provided input.
*   **Parameterize queries:** Use safer filtering methods without string-based code execution.
*   **Input sanitization (complex and less reliable):**  Sanitize user input if dynamic queries are absolutely necessary, but this is error-prone for code injection.

## Attack Surface: [Path Traversal Vulnerabilities in File Path Handling](./attack_surfaces/path_traversal_vulnerabilities_in_file_path_handling.md)

**Description:**  Pandas file I/O functions (`read_csv`, `to_csv`, etc.) accepting file paths derived from user input without validation can lead to path traversal attacks, allowing access or manipulation of files outside intended directories.

**Pandas Contribution:** Pandas provides functions that take file paths as arguments for reading and writing data. If these paths are constructed from unsanitized user input, pandas becomes a vector for path traversal.

**Example:** A web application uses user-provided filenames with `pandas.to_csv()`. A malicious user provides a filename like `../../../../sensitive_data.csv`, potentially overwriting or accessing sensitive files due to insufficient path validation in the application using pandas.

**Impact:** High - Information disclosure (reading sensitive files), data manipulation (overwriting files).

**Risk Severity:** High

**Mitigation Strategies:**
*   **Strict input validation for file paths:** Thoroughly validate and sanitize user-provided file paths before using them with pandas functions.
*   **Allowlisting:** Use allowlists for permitted characters and directory paths.
*   **Avoid direct user input in path construction:** Do not directly concatenate user input into file paths. Use secure path construction methods.

