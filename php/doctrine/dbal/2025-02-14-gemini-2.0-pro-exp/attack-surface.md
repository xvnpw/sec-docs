# Attack Surface Analysis for doctrine/dbal

## Attack Surface: [SQL Injection (Primary Vector)](./attack_surfaces/sql_injection__primary_vector_.md)

*   **Description:**  Unauthorized execution of arbitrary SQL commands on the database due to improper use of DBAL's query building and execution methods.
*   **DBAL Contribution:** DBAL provides prepared statements and parameter binding as *core features* to prevent SQL injection.  The vulnerability arises when the application *fails to use these features correctly*, bypassing the intended protection. This is a direct misuse of DBAL's API.
*   **Example:**
    ```php
    // VULNERABLE: Direct string concatenation with DBAL
    $userInput = $_GET['username'];
    $sql = "SELECT * FROM users WHERE username = '" . $userInput . "'";
    $result = $connection->executeQuery($sql); // Using DBAL, but incorrectly!

    // VULNERABLE: executeQuery/executeStatement without parameters
    $userInput = $_GET['id'];
    $sql = "SELECT * FROM products WHERE id = ?";
    $result = $connection->executeQuery($sql); // Placeholder present, but no parameters!
    ```
*   **Impact:**  Complete database compromise.  Attackers can read, modify, or delete any data.  Potential for remote code execution on the database server in some scenarios.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **1.a.  Mandatory Prepared Statements:**  *Always* use DBAL's `executeQuery()` or `executeStatement()` with placeholders and the `$params` array for *all* user-supplied data.  This is the *primary* defense.
    *   **1.b.  Input Validation (Secondary Defense):**  Validate all user input *before* passing it to DBAL, even when using prepared statements.  This adds a layer of defense-in-depth.
    *   **1.c.  Strictly Avoid Dynamic Table/Column Names:**  Do not allow user input to dictate table or column names.  If absolutely necessary, use a very strict whitelist.
    *   **1.d.  Code Reviews Focused on DBAL Usage:**  Regularly review code, specifically looking for *any* instance where user input might be concatenated into a SQL string, even if DBAL is being used.
    *   **1.e. SAST Tools:** Employ static analysis tools to automatically detect potential SQL injection vulnerabilities related to DBAL usage.

## Attack Surface: [Data Exposure through DBAL Errors](./attack_surfaces/data_exposure_through_dbal_errors.md)

*   **Description:**  Sensitive database information (queries, table names, data) revealed through DBAL's exception messages or error output if not handled correctly by the application.
*   **DBAL Contribution:** DBAL *throws exceptions* that may contain sensitive information.  The application's error handling (or lack thereof) directly determines whether this information is exposed. This is a direct consequence of how the application interacts with DBAL's error reporting.
*   **Example:**  A `try-catch` block around a DBAL `executeQuery()` call that, in the `catch` block, echoes the exception message directly to the user.  This message might contain the full SQL query, including injected malicious code.
*   **Impact:**  Provides attackers with valuable information about the database structure and the queries being executed, significantly aiding in the development of further attacks.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **2.a.  Production Error Handling:**  *Never* display raw DBAL exception messages or stack traces to users in a production environment.
    *   **2.b.  Robust `try-catch` Blocks:**  Wrap *all* DBAL interactions in `try-catch` blocks.
    *   **2.c.  Secure Logging:**  Log detailed error information (including exception details) to a secure location (file, dedicated logging service) *not* accessible to users.
    *   **2.d.  Generic User-Facing Errors:**  Display only generic, non-descriptive error messages to users (e.g., "An unexpected error occurred.").

## Attack Surface: [Insecure Database Connection Management (Credentials)](./attack_surfaces/insecure_database_connection_management__credentials_.md)

*   **Description:** Exposure of database credentials due to improper configuration of DBAL connection parameters.
*   **DBAL Contribution:** DBAL *requires* connection parameters (username, password, host, etc.) to function. How the application *provides* these parameters to DBAL is the critical security factor. This is a direct consequence of how the application configures and uses DBAL.
*   **Example:** Hardcoding database credentials directly within the PHP code that uses DBAL, or storing them in an insecure configuration file that is accessible to unauthorized users.
*   **Impact:** Complete database compromise if the credentials are leaked. An attacker gains full access to the database.
*   **Risk Severity:** High (Critical if credentials are leaked and easily accessible)
*   **Mitigation Strategies:**
    *   **3.a. Secure Credential Storage:** *Never* hardcode credentials. Use environment variables, secure configuration files (outside the web root), or a dedicated secrets management service.
    *   **3.b. Principle of Least Privilege:** Ensure the database user configured in DBAL has only the absolute minimum necessary permissions.

