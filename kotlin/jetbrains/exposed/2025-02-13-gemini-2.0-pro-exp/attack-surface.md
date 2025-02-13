# Attack Surface Analysis for jetbrains/exposed

## Attack Surface: [SQL Injection (Via Bypassed Safeguards)](./attack_surfaces/sql_injection__via_bypassed_safeguards_.md)

*   **Description:**  Execution of malicious SQL code due to developers circumventing Exposed's built-in protection mechanisms.
*   **How Exposed Contributes:** Exposed provides safe ways to interact with the database (DAOs, `Entity` classes), but also offers "escape hatches" (raw SQL execution, dynamic `Op` building) that, if misused, *directly* lead to SQL injection.  The framework's flexibility is the direct contributor to this risk.
*   **Example:**
    ```kotlin
    // UNSAFE: User input directly concatenated into a WHERE clause using Exposed's functions
    val userInput = request.getParameter("username")
    Users.select { Users.name eq "admin' OR username = '$userInput" }.forEach { ... }

    // SAFE: Using Exposed's parameterized query
    val userInput = request.getParameter("username")
    Users.select { Users.name eq "admin" or (Users.username eq userInput) }.forEach { ... }
    ```
*   **Impact:**  Complete database compromise, data theft, data modification, data deletion, potential server compromise (depending on database privileges).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Mandatory Code Reviews:**  Every database interaction using Exposed, *especially* `Transaction.exec()`, dynamic `Op` building, or any string manipulation within queries, requires rigorous review.
    *   **Static Analysis:**  Use static analysis tools configured to detect SQL injection patterns *specifically within the context of Exposed usage*.
    *   **Developer Training:**  Comprehensive training on secure Exposed usage, emphasizing the dangers of raw SQL and dynamic query construction with user input *within Exposed's API*.  Focus on correct use of Exposed's features.
    *   **Principle of Least Privilege:** Database user account should have minimal permissions. (While a general best practice, it directly limits the impact of an Exposed-related SQL injection).

## Attack Surface: [Data Exposure (Over-Fetching with `exposed-dao`)](./attack_surfaces/data_exposure__over-fetching_with__exposed-dao__.md)

*   **Description:**  Unintentional retrieval and potential exposure of sensitive data due to fetching entire entities or more columns than necessary using `exposed-dao`.
*   **How Exposed Contributes:**  The ease of retrieving complete `Entity` objects with `exposed-dao` *directly* encourages developers to fetch all columns, even when only a subset is needed. This is a feature of Exposed that increases the risk.
*   **Example:**
    ```kotlin
    // Potentially exposes sensitive data if User entity has fields like "passwordHash"
    // Directly using exposed-dao's findById
    val user = User.findById(userId)
    return user // Returning the entire entity

    // Safer: Use a DTO and Exposed's select to get only necessary columns
    val user = Users.select { Users.id eq userId }.map {
        UserDto(it[Users.id].value, it[Users.username])
    }.singleOrNull()
    return user
    ```
*   **Impact:**  Leakage of sensitive data (PII, credentials, internal data) to unauthorized users or attackers.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Explicit Column Selection:**  *Always* use Exposed's `select` or `slice` to retrieve only the specific columns required.  Avoid fetching entire entities with `exposed-dao` unless absolutely necessary and justified.
    *   **Data Transfer Objects (DTOs):**  Use DTOs in conjunction with Exposed's query results to represent the data returned, ensuring only intended fields are exposed. Never directly return `Entity` objects.

## Attack Surface: [Denial of Service (Unbounded Queries via Exposed API)](./attack_surfaces/denial_of_service__unbounded_queries_via_exposed_api_.md)

*   **Description:** An attacker triggers a query through Exposed that returns a massive result set, consuming excessive resources.
*   **How Exposed Contributes:** Exposed's API does *not* inherently limit the number of rows returned by a query. Developers must explicitly use Exposed's features to implement safeguards. The lack of built-in limits within the Exposed API is the direct contributor.
*   **Example:**
    ```kotlin
    // Potentially returns ALL users, causing a DoS, directly using Exposed's selectAll
    val allUsers = Users.selectAll().toList()

    // Safer: Use Exposed's pagination features
    val page = request.getParameter("page")?.toIntOrNull() ?: 1
    val pageSize = 20
    val users = Users.selectAll().limit(pageSize, offset = (page - 1) * pageSize.toLong()).toList()
    ```
*   **Impact:** Application unavailability, resource exhaustion, potential database server crash.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Pagination (Using Exposed's `limit`):**  Mandatory pagination for *all* queries using Exposed that could potentially return many results. Use Exposed's `limit` and `offset` functions. Enforce a maximum page size.
    *   **Query Timeouts (Configured through Exposed's Transaction):** Set appropriate timeouts for database queries *within Exposed's transaction management* to prevent long-running queries.

## Attack Surface: [Insecure Logging of Sensitive Data (Exposed's Default Behavior)](./attack_surfaces/insecure_logging_of_sensitive_data__exposed's_default_behavior_.md)

*   **Description:** Exposed's logging, if not carefully configured, logs the *full SQL query*, including potentially sensitive parameter values.
*   **How Exposed Contributes:** This is a *direct* consequence of Exposed's default logging behavior. The framework provides the logging functionality that, without modification, creates this risk.
*   **Example:**
    *   Exposed's default logging might output: `SELECT * FROM Users WHERE username = 'admin' AND password = 'plaintext_password'`
*   **Impact:** Exposure of sensitive data (credentials, PII) in application logs.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Disable Sensitive Data Logging in Exposed:** *Specifically* configure Exposed's logging to *never* log raw query parameters. Use parameterized query logging (if available in Exposed) to show placeholders instead of values. This is a direct configuration change within Exposed.
    *   **Log Level Control (Within Exposed's Configuration):** Set Exposed's log level appropriately (e.g., `INFO`, `WARN`, `ERROR`) to minimize unnecessary logging. Avoid `DEBUG` in production. This is a direct configuration of Exposed.

