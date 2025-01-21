# Attack Surface Analysis for pandas-dev/pandas

## Attack Surface: [Deserialization of Untrusted Data (Pickle)](./attack_surfaces/deserialization_of_untrusted_data__pickle_.md)

**Description:**  Loading data serialized using Python's `pickle` module from untrusted sources can lead to arbitrary code execution.
*   **How Pandas Contributes to the Attack Surface:** Pandas provides the `pd.read_pickle()` function, which directly deserializes data from pickle files. If an application uses this function to load data from an untrusted source, it becomes vulnerable.
*   **Example:** An attacker crafts a malicious pickle file containing code to execute a reverse shell. If the application uses `pd.read_pickle()` to load this file, the attacker's code will be executed on the server.
*   **Impact:**  Complete compromise of the application and potentially the underlying system. Attackers can gain full control, steal data, or disrupt operations.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   Avoid using `pd.read_pickle()` with data from untrusted sources.
    *   Use safer serialization formats like CSV or JSON for data exchange with external entities.
    *   If `pickle` is absolutely necessary, implement strong authentication and authorization to ensure the source of the data is trusted.
    *   Consider using cryptographic signing to verify the integrity and origin of pickle files.

## Attack Surface: [Reading Data from External Sources (URLs, Files)](./attack_surfaces/reading_data_from_external_sources__urls__files_.md)

**Description:** Pandas can read data directly from URLs and local file paths using functions like `pd.read_csv()`, `pd.read_json()`, etc. If the application allows users to specify these sources, it can be vulnerable to Server-Side Request Forgery (SSRF) or path traversal attacks.
*   **How Pandas Contributes to the Attack Surface:** Functions like `pd.read_csv(url)` or `pd.read_csv(filepath)` directly interact with the provided source. If the URL or filepath is controlled by a malicious user without proper validation, it can be exploited.
*   **Example (SSRF):** An attacker provides an internal URL (e.g., `http://localhost:8080/admin`) to `pd.read_csv()`. The server running the application will make a request to this internal resource.
*   **Example (Path Traversal):** An attacker provides a filepath like `../../../../etc/passwd` to `pd.read_csv()`. If not properly sanitized, Pandas might attempt to read this sensitive system file.
*   **Impact:**
    *   **SSRF:** Access to internal resources, potential data breaches, ability to interact with internal services.
    *   **Path Traversal:** Unauthorized access to files on the server, potentially exposing sensitive data or configuration files.
*   **Risk Severity:** **High** (SSRF)
*   **Mitigation Strategies:**
    *   Validate and sanitize user-provided URLs and file paths.
    *   Implement whitelisting of allowed domains or file locations.
    *   Avoid directly using user input to construct URLs or file paths for Pandas reading functions.
    *   For URL inputs, consider using a dedicated library for URL parsing and validation.
    *   Implement proper access controls and permissions on the server's file system.

