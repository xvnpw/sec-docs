# Threat Model Analysis for ccgus/fmdb

## Threat: [SQL Injection](./threats/sql_injection.md)

*   **Description:** An attacker injects malicious SQL code into input fields or parameters that are used to construct SQL queries executed by FMDB. This is done by crafting input strings that, when processed by the application and passed to FMDB, alter the intended SQL query structure. For example, an attacker might input `' OR '1'='1` into a username field if the application naively concatenates this input into a SQL query using FMDB's `executeQuery:` method. This would bypass intended query logic and potentially expose or modify data.
*   **Impact:**
    *   Unauthorized data access (data breach)
    *   Data modification or deletion
    *   Potential application compromise or control
*   **FMDB Component Affected:**
    *   FMDB methods used for query execution: `executeQuery:`, `executeUpdate:`, `executeStatements:`, and similar methods when used incorrectly with string concatenation for query building. The vulnerability is in the *application's usage* of these FMDB functions, not in FMDB itself.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Mandatory Use of Parameterized Queries:**  Exclusively use FMDB's parameterized query methods such as `executeQuery:withArgumentsInArray:` and `executeUpdate:withArgumentsInArray:`. This ensures that user-provided data is treated as data, not as executable SQL code, effectively preventing SQL injection.
    *   **Strict Code Reviews:** Implement rigorous code reviews focusing on database interaction code to ensure parameterized queries are consistently used and string concatenation for query building is avoided.

## Threat: [SQLite-Specific Vulnerabilities](./threats/sqlite-specific_vulnerabilities.md)

*   **Description:** Attackers exploit known security vulnerabilities present in the underlying SQLite library that FMDB wraps. These vulnerabilities could be in SQLite's parsing engine, query execution logic, or data storage mechanisms. Exploitation might involve crafting specific SQL queries or database files that trigger these vulnerabilities when processed by SQLite through FMDB.
*   **Impact:**
    *   Data corruption or integrity issues within the SQLite database managed by FMDB.
    *   Denial of Service (application crash or database unavailability) due to SQLite vulnerability exploitation.
    *   Information disclosure if SQLite vulnerability allows unauthorized data leakage.
    *   In rare and severe cases, potential for code execution if a critical SQLite vulnerability is exploited.
*   **FMDB Component Affected:**
    *   Indirectly, FMDB is affected because it relies on the underlying SQLite library. The vulnerability resides within the *linked SQLite library*, not directly in FMDB's wrapper code. Applications using FMDB are vulnerable if the linked SQLite version has vulnerabilities.
*   **Risk Severity:** High to Critical (depending on the specific SQLite vulnerability and its exploitability)
*   **Mitigation Strategies:**
    *   **Proactive SQLite Updates:**  Maintain an up-to-date SQLite library. Regularly update the SQLite version linked with FMDB to the latest stable and patched release. This is crucial to address known vulnerabilities.
    *   **Security Monitoring and Patch Management:**  Actively monitor security advisories and vulnerability disclosures related to SQLite from reputable sources. Establish a process for promptly patching or updating SQLite when security vulnerabilities are announced and fixes are available.
    *   **Dependency Management:**  Implement robust dependency management practices to ensure that the correct and patched version of SQLite is consistently used throughout the application development and deployment lifecycle.

