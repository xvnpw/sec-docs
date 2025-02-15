# Attack Surface Analysis for pandas-dev/pandas

## Attack Surface: [1. Arbitrary Code Execution via Deserialization](./attack_surfaces/1__arbitrary_code_execution_via_deserialization.md)

*   **Description:**  Loading data from untrusted sources using formats that support serialization of arbitrary Python objects (primarily Pickle, but also potentially Feather, HDF5) allows attackers to execute arbitrary code on the system.
*   **How Pandas Contributes:**  Pandas provides functions like `read_pickle`, `read_feather`, and `read_hdf` that deserialize data, potentially executing malicious code embedded within the file.
*   **Example:** An attacker uploads a crafted `.pkl` file that, when loaded with `pd.read_pickle()`, executes a shell command to open a reverse shell back to the attacker.
*   **Impact:**  Complete system compromise.  The attacker gains full control over the server or application.
*   **Risk Severity:**  Critical
*   **Mitigation Strategies:**
    *   **a. Avoid Untrusted Deserialization:**  *Never* use `read_pickle`, `read_feather`, or `read_hdf` with data from untrusted sources.  This is the most important mitigation.
    *   **b. Use Safer Formats:**  Prefer safer data formats like CSV, JSON, or Parquet (with appropriate validation) for data exchange.
    *   **c. Cryptographic Verification (If Unavoidable):** If deserialization of untrusted data is *absolutely* necessary (which should be extremely rare), implement robust cryptographic verification (e.g., digital signatures, HMAC) to ensure the data's integrity and authenticity *before* deserialization.  This requires a secure key management system.
    *   **d. Sandboxing:**  If deserialization is unavoidable, perform it within a highly restricted, isolated environment (e.g., a container with minimal privileges and network access) to limit the impact of a successful exploit.

## Attack Surface: [2. Denial of Service (DoS) via Resource Exhaustion](./attack_surfaces/2__denial_of_service__dos__via_resource_exhaustion.md)

*   **Description:**  Attackers can provide crafted input data that causes pandas to consume excessive memory or CPU, leading to a denial of service.
*   **How Pandas Contributes:**  Pandas' data structures and operations can be resource-intensive, especially with large or complex datasets.  Functions like `read_csv`, `read_json`, `read_excel`, joins, group-bys, and pivots can be exploited.
*   **Example:**
    *   **Memory Exhaustion:** An attacker uploads a CSV file with millions of rows and extremely long strings in each cell, causing `pd.read_csv()` to consume all available memory.
    *   **CPU Exhaustion:** An attacker provides a dataset that triggers a computationally expensive `groupby` operation with a very large number of unique groups.
*   **Impact:**  Application unavailability.  The server becomes unresponsive or crashes.
*   **Risk Severity:**  High
*   **Mitigation Strategies:**
    *   **a. Input Size Limits:**  Enforce strict limits on the size of input data (e.g., file size, number of rows, column width).  Reject any input that exceeds these limits.
    *   **b. Resource Quotas:**  Implement resource quotas (memory, CPU time) for processes handling pandas operations.  This can be done at the operating system level or using libraries like `resource` (on Unix-like systems).
    *   **c. Chunking:**  For large datasets, process data in chunks using the `chunksize` parameter in functions like `read_csv` and `read_json`.  This allows you to process data incrementally without loading the entire dataset into memory at once.
    *   **d. Data Type Optimization:**  Use efficient data types (e.g., `category` for columns with many repeated values, appropriate numeric types) to reduce memory usage.
    *   **e. Timeout Mechanisms:** Implement timeouts for pandas operations to prevent them from running indefinitely.
    *   **f. Input Validation:** Validate the structure and content of the input data *before* passing it to pandas.  For example, check for excessively long strings or deeply nested JSON objects.

## Attack Surface: [3. XML External Entity (XXE) and XML Injection](./attack_surfaces/3__xml_external_entity__xxe__and_xml_injection.md)

*   **Description:**  When parsing untrusted XML data, attackers can exploit vulnerabilities in the underlying XML parser (usually `lxml` or `etree`) to access local files, internal network resources, or cause a denial of service.
*   **How Pandas Contributes:**  Pandas' `read_xml` function uses `lxml` or `etree` for XML parsing, making it indirectly vulnerable to XXE attacks.
*   **Example:** An attacker uploads an XML file containing an external entity declaration that points to a sensitive local file (e.g., `/etc/passwd`).  When `pd.read_xml()` processes the file, the parser attempts to resolve the external entity, potentially exposing the file's contents.
*   **Impact:**  Information disclosure (sensitive files, internal network information), denial of service.
*   **Risk Severity:**  High
*   **Mitigation Strategies:**
    *   **a. Disable External Entities:**  Configure the underlying XML parser to disable the resolution of external entities.  With `lxml`, you can use a custom parser:
        ```python
        from lxml import etree
        parser = etree.XMLParser(resolve_entities=False)
        df = pd.read_xml(untrusted_xml_data, parser=parser)
        ```
    *   **b. Use a Safe XML Parser:**  Consider using a dedicated XML parsing library known for its security features, such as `defusedxml`.
    *   **c. Input Validation:**  Validate the XML data against a strict schema *before* parsing it with pandas.  This can help prevent many XXE attacks.
    *   **d. Least Privilege:** Run the application with minimal privileges to limit the impact of a successful XXE attack.

