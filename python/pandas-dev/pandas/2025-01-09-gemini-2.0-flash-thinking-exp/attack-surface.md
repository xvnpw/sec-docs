# Attack Surface Analysis for pandas-dev/pandas

## Attack Surface: [Deserialization of Untrusted Data](./attack_surfaces/deserialization_of_untrusted_data.md)

*   **Description:**  Processing data from external sources without proper validation can lead to vulnerabilities if the data is maliciously crafted.
    *   **How Pandas Contributes:** Pandas provides numerous `read_*` functions (e.g., `read_csv`, `read_excel`, `read_json`, `read_pickle`) that parse data from various formats. These parsers can be susceptible to exploits if the input data is malicious.
    *   **Example:** A malicious CSV file with excessively long fields or deeply nested structures could cause a denial-of-service by consuming excessive memory during parsing with `read_csv`. A crafted Excel file with a malicious formula could lead to unintended calculations or information disclosure when read with `read_excel`. Deserializing a malicious pickle file with `read_pickle` can lead to arbitrary code execution.
    *   **Impact:** Denial of service, arbitrary code execution (especially with pickle), information disclosure, unexpected application behavior.
    *   **Risk Severity:** Critical (for pickle), High (for other formats depending on the exploit).
    *   **Mitigation Strategies:**
        *   **Input Validation:**  Thoroughly validate and sanitize all input data *before* passing it to pandas `read_*` functions.
        *   **Avoid `read_pickle` with Untrusted Sources:** Never deserialize pickle files from untrusted sources. Use safer data serialization formats like JSON or CSV when possible.
        *   **Resource Limits:** Implement resource limits (e.g., memory limits, processing time limits) to mitigate potential DoS attacks during parsing.
        *   **Use Specific Parsing Engines Carefully:**  Be aware of potential vulnerabilities in specific parsing engines used by pandas (e.g., the Python engine for CSV).

## Attack Surface: [Code Injection via `eval()` and `query()`](./attack_surfaces/code_injection_via__eval____and__query___.md)

*   **Description:**  Using the `eval()` or `query()` methods with user-controlled input allows for the execution of arbitrary Python code or pandas expressions.
    *   **How Pandas Contributes:** Pandas DataFrames have `eval()` and `query()` methods that take string arguments to perform operations. If these strings are constructed using untrusted input, attackers can inject malicious code.
    *   **Example:**  An application allows users to filter data using a string passed to `df.query()`. A malicious user could input `os.system('rm -rf /')` (or similar dangerous commands) which would be executed on the server.
    *   **Impact:** Arbitrary code execution, complete system compromise, data breaches.
    *   **Risk Severity:** Critical.
    *   **Mitigation Strategies:**
        *   **Avoid `eval()` and `query()` with Untrusted Input:**  Never use `eval()` or `query()` with strings that are directly or indirectly derived from user input or external sources.
        *   **Use Safe Alternatives:**  Implement filtering and data manipulation logic using safer pandas methods that do not involve string execution.
        *   **Input Sanitization (Insufficient):** While sanitization might seem like a solution, it's extremely difficult to reliably prevent code injection via string manipulation. Avoid this approach for critical security.

## Attack Surface: [SQL Injection via `read_sql` and Related Functions](./attack_surfaces/sql_injection_via__read_sql__and_related_functions.md)

*   **Description:**  Constructing SQL queries using unsanitized user input can lead to SQL injection vulnerabilities.
    *   **How Pandas Contributes:** Functions like `read_sql`, `read_sql_query`, and `read_sql_table` execute SQL queries against databases. If the SQL query or table name is built using user-provided strings without proper escaping or parameterization, it's vulnerable to SQL injection.
    *   **Example:** An application takes a table name as user input and uses it in `pd.read_sql_table(table_name, con=engine)`. A malicious user could input `users; DROP TABLE users;` leading to the deletion of the `users` table.
    *   **Impact:** Data breaches, data manipulation, unauthorized access to the database, potential remote code execution on the database server (depending on database permissions and features).
    *   **Risk Severity:** High to Critical (depending on the database permissions and the severity of the injection).
    *   **Mitigation Strategies:**
        *   **Use Parameterized Queries:**  Always use parameterized queries (also known as prepared statements) when interacting with databases. This prevents user input from being interpreted as SQL code. Pandas supports parameterized queries when using SQLAlchemy.
        *   **Input Validation and Sanitization (Defense in Depth):** While parameterized queries are the primary defense, validate and sanitize user input to further reduce the risk.
        *   **Principle of Least Privilege:** Ensure the database user used by the application has only the necessary permissions.

