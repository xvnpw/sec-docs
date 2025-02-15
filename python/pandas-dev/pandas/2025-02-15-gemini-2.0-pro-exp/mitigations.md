# Mitigation Strategies Analysis for pandas-dev/pandas

## Mitigation Strategy: [Safe `read_csv` and Input Handling](./mitigation_strategies/safe__read_csv__and_input_handling.md)

**1. Mitigation Strategy: Safe `read_csv` and Input Handling**

*   **Description:**
    1.  **`dtype` Parameter:**  When using `pd.read_csv()`, *always* use the `dtype` parameter to explicitly specify the data type of *each* column.  This prevents pandas from inferring types incorrectly, which could lead to vulnerabilities or unexpected behavior.  Example: `pd.read_csv(..., dtype={'col1': str, 'col2': int, 'col3': float})`
    2.  **`converters` Parameter:** Use the `converters` parameter to apply custom sanitization functions to specific columns *during* the read process. This is more efficient than reading the entire DataFrame and then cleaning it.  Example: `pd.read_csv(..., converters={'col1': sanitize_string})`, where `sanitize_string` is a custom function you define.
    3.  **`chunksize` Parameter:** For large CSV files, use the `chunksize` parameter to read the data in smaller chunks.  This prevents pandas from attempting to load the entire file into memory at once. Example: `for chunk in pd.read_csv('large_file.csv', chunksize=10000): process_chunk(chunk)`
    4.  **Avoid `read_clipboard()`:** Do not use `pd.read_clipboard()` with untrusted clipboard data, as this could introduce malicious content.
    5. **Limit Input Size (Pre-pandas, but relevant):** Before calling `read_csv`, check file size.

*   **Threats Mitigated:**
    *   **Untrusted Data Input (Severity: High):** Prevents malicious or malformed data from causing unexpected behavior or vulnerabilities within pandas.
    *   **Resource Exhaustion (Severity: Medium):**  `chunksize` prevents memory exhaustion from large files.
    *   **Data Corruption (Severity: Medium):** `dtype` and `converters` ensure data is interpreted correctly.

*   **Impact:**
    *   **Untrusted Data Input:** Risk reduced significantly (High impact).
    *   **Resource Exhaustion:** Risk reduced significantly with `chunksize` (High impact).
    *   **Data Corruption:** Risk reduced moderately (Medium impact).

*   **Currently Implemented:**
    *   Example: "`dtype` is used in all `read_csv` calls in `data_loading.py`. `chunksize` is used for files larger than 100MB."

*   **Missing Implementation:**
    *   Example: "We are not currently using `converters` for sanitization.  This should be added to `data_loading.py`."
    *   Example: "`read_clipboard` is used in a testing script. This should be removed."

## Mitigation Strategy: [Avoid Pickle with Untrusted Data](./mitigation_strategies/avoid_pickle_with_untrusted_data.md)

**2. Mitigation Strategy: Avoid Pickle with Untrusted Data**

*   **Description:**
    1.  **Prohibit `pd.read_pickle()` with Untrusted Data:** *Never* use `pd.read_pickle()` to load data from an untrusted source (e.g., user uploads, external APIs). Pickle can execute arbitrary code during deserialization.
    2.  **Safe Alternatives:** Use safer serialization formats like JSON (`pd.read_json()`, `pd.to_json()`), CSV (`pd.read_csv()`, `pd.to_csv()`), or Parquet (`pd.read_parquet()`, `pd.to_parquet()`) for data exchange.

*   **Threats Mitigated:**
    *   **Deserialization Vulnerabilities (Pickle) (Severity: Critical):** Eliminates the risk of arbitrary code execution.

*   **Impact:**
    *   **Deserialization Vulnerabilities (Pickle):** Risk eliminated completely if the rule is followed (High impact).

*   **Currently Implemented:**
    *   Example: "Code review policy prohibits `pd.read_pickle()` with external data. All external data exchange uses JSON."

*   **Missing Implementation:**
    *   Example: "Legacy code in `old_module.py` uses `pd.read_pickle()`. This needs to be refactored."

## Mitigation Strategy: [Safe `eval()`, `query()`, and Indexing](./mitigation_strategies/safe__eval______query_____and_indexing.md)

**3. Mitigation Strategy: Safe `eval()`, `query()`, and Indexing**

*   **Description:**
    1.  **Avoid Untrusted Input:** *Never* pass user-provided strings directly to `df.eval()`, `df.query()`, or use them to construct dynamic selections with `df.loc[]` or `df.iloc[]`. These can execute arbitrary code.
    2.  **Boolean Indexing:**  If filtering based on user input is needed, construct boolean indexing conditions *programmatically* based on validated and sanitized user input.  Do *not* embed user input directly into a string passed to `eval()` or `query()`.
    3. Sanitize any string that will be used within a query.

*   **Threats Mitigated:**
    *   **Code Injection via `eval()`/`query()` (Severity: Critical):** Prevents arbitrary code execution.

*   **Impact:**
    *   **Code Injection:** Risk eliminated completely if the rule is followed (High impact).

*   **Currently Implemented:**
    *   Example: "All filtering in `data_analysis.py` uses boolean indexing with validated input."

*   **Missing Implementation:**
    *   Example: "`report_generator.py` uses `df.query()` with user input. Refactor to use boolean indexing."

## Mitigation Strategy: [Post-Read Data Type Enforcement](./mitigation_strategies/post-read_data_type_enforcement.md)

**4. Mitigation Strategy: Post-Read Data Type Enforcement**

*   **Description:**
    1.  **`astype()`:** After reading data into a DataFrame (even after using `dtype` in `read_csv`), explicitly cast columns to their intended data types using the `.astype()` method.  Example: `df['col1'] = df['col1'].astype(str)`
    2.  **Categorical Data:** For columns with a limited set of known values, use the pandas categorical data type: `df['col2'] = df['col2'].astype('category')`.
    3.  **Downcasting:** For numerical columns, consider downcasting to smaller data types if the data range allows: `df['col3'] = pd.to_numeric(df['col3'], downcast='integer')`.

*   **Threats Mitigated:**
    *   **Untrusted Data Input (Severity: High):** Provides a second layer of defense against incorrect data types.
    *   **Data Corruption (Severity: Medium):** Ensures data is interpreted correctly.
    *   **Resource Exhaustion (Severity: Low):** Categorical types and downcasting can reduce memory usage.

*   **Impact:**
    *   **Untrusted Data Input:** Risk reduced moderately (Medium impact).
    *   **Data Corruption:** Risk reduced moderately (Medium impact).
    *   **Resource Exhaustion:** Risk reduced slightly (Low impact).

*   **Currently Implemented:**
    *   Example: "`.astype(str)` is used for text columns in `data_processing.py`."

*   **Missing Implementation:**
    *   Example: "Categorical types are not consistently used.  Implement for 'status' and 'category' columns."
    *   Example: "Downcasting is not implemented. Review numerical columns in `data_analysis.py`."

## Mitigation Strategy: [Chunked Processing with `read_sql`](./mitigation_strategies/chunked_processing_with__read_sql_.md)

**5. Mitigation Strategy: Chunked Processing with `read_sql`**

* **Description:**
    1. **`chunksize` with `read_sql`:** When using `pd.read_sql` to read data from a database, use the `chunksize` parameter to retrieve data in smaller batches. This is analogous to the `chunksize` parameter in `read_csv`.
    2. **Iterate and Process:** Iterate through the chunks and process each one individually, similar to how you would handle chunks from `read_csv`.

* **Threats Mitigated:**
    * **Resource Exhaustion (Severity: Medium):** Prevents pandas from attempting to load an entire, potentially very large, database result set into memory at once.

* **Impact:**
     * **Resource Exhaustion:** Risk reduced significantly (High impact).

* **Currently Implemented:**
    * Example: "Not currently implemented. All database reads use `pd.read_sql` without `chunksize`."

* **Missing Implementation:**
    * Example: "Implement `chunksize` in all `pd.read_sql` calls within the `database_connector.py` module. Determine an appropriate chunk size based on testing and expected data volumes."


