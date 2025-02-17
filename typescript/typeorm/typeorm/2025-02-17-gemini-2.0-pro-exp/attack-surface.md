# Attack Surface Analysis for typeorm/typeorm

## Attack Surface: [SQL Injection](./attack_surfaces/sql_injection.md)

*   **Description:**  Exploiting vulnerabilities in how TypeORM constructs SQL queries to execute arbitrary SQL commands on the database. This occurs when user-supplied data is incorporated into queries without proper sanitization or parameterization *within TypeORM's API*.
*   **How TypeORM Contributes:**  Improper use of `manager.query()`, `connection.query()`, `createQueryBuilder()`, or `FindOptionsWhere` with unsanitized user input directly embedded in the SQL string or query builder methods bypasses TypeORM's intended protections.
*   **Example:**
    ```typescript
    // Vulnerable:
    const userName = req.body.userName; // User-supplied input
    const user = await connection.getRepository(User).createQueryBuilder("user")
        .where("user.name = '" + userName + "'") // Direct concatenation - TypeORM is used incorrectly
        .getOne();

    // Safe:
    const userName = req.body.userName;
    const user = await connection.getRepository(User).createQueryBuilder("user")
        .where("user.name = :name", { name: userName }) // Parameterized query - TypeORM is used correctly
        .getOne();
    ```
*   **Impact:**  Complete database compromise, data theft, data modification, data deletion, denial of service.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Always Use Parameterized Queries:**  Employ placeholders (e.g., `:name`) in `createQueryBuilder()` and raw queries, allowing TypeORM to handle escaping.  This is the *primary* defense.
    *   **Prefer TypeORM's API:**  Favor `createQueryBuilder()` and entity methods (`find()`, `findOne()`, `save()`, etc.) over raw SQL whenever possible, and use them *correctly* with parameters.
    *   **Input Validation (Defense in Depth):**  Validate and sanitize user input *before* it reaches the ORM, but do not rely solely on this. Parameterization is crucial.
    *   **Regular Code Reviews:**  Conduct thorough code reviews, focusing on *all* database interactions involving TypeORM.
    *   **Update TypeORM:**  Keep TypeORM and database drivers updated to the latest versions to benefit from security patches.
    *   **Least Privilege:**  Grant the database user used by TypeORM only the necessary permissions.

## Attack Surface: [Data Exposure / Information Leakage (Through TypeORM)](./attack_surfaces/data_exposure__information_leakage__through_typeorm_.md)

*   **Description:**  Unintentional disclosure of sensitive data through TypeORM's logging or error handling mechanisms.
*   **How TypeORM Contributes:**  Overly verbose TypeORM logging (especially `logging: true` or detailed logging levels) can expose query parameters and data, including sensitive information, if not configured carefully. Uncaught TypeORM errors, if propagated directly to the client, might reveal details about the database schema, table names, or query structure.
*   **Example:**
    *   **Logging:**  Setting `logging: true` in TypeORM's configuration and then logging all queries, including those that handle user passwords or other PII.
    *   **Error Handling:**  Directly returning a TypeORM error object to the client, which might contain sensitive database schema information.
*   **Impact:**  Exposure of sensitive data (PII, credentials, internal system details), facilitating further attacks.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Configure Logging Appropriately:**  Use a low logging level (e.g., `warn` or `error`) in production.  *Never* log raw SQL queries containing sensitive data in production.  Consider a custom logger to filter sensitive data *before* it's logged.
    *   **Robust Error Handling:**  Catch *all* TypeORM errors and return generic error messages to the client.  Log detailed errors internally (and securely) for debugging.  Never expose TypeORM error details directly to the user.

## Attack Surface: [Denial of Service (DoS) (Through TypeORM Misuse)](./attack_surfaces/denial_of_service__dos___through_typeorm_misuse_.md)

*   **Description:**  Overwhelming the database or application server due to improper use of TypeORM's querying capabilities.
*   **How TypeORM Contributes:** Allowing users to directly control TypeORM query parameters like `limit` and `offset` without proper validation, or allowing users to influence the structure of complex TypeORM queries, can lead to resource exhaustion. Connection pool exhaustion can also occur due to TypeORM connection leaks (if connections aren't properly released).
*   **Example:**
    ```typescript
    // Vulnerable:
    const limit = req.query.limit; // User-controlled limit, directly passed to TypeORM
    const users = await connection.getRepository(User).find({ take: limit });

    // Safe:
    const limit = Math.min(parseInt(req.query.limit) || 10, 100); // Limit to a maximum of 100
    const users = await connection.getRepository(User).find({ take: limit });
    ```
*   **Impact:**  Application unavailability, disruption of service.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Validate and Limit Query Parameters:**  Strictly validate and limit *all* user-controlled parameters passed to TypeORM's query methods (e.g., `limit`, `offset`, filter criteria).  Implement pagination with reasonable, server-side enforced limits.
    *   **Restrict Query Complexity:**  Carefully control how user input affects the structure of TypeORM queries.  Avoid allowing users to construct arbitrary queries through TypeORM.
    *   **Proper Connection Pool Configuration:**  Configure TypeORM's connection pool with appropriate `poolSize`, `connectionTimeout`, etc.  Monitor for connection leaks (connections not being returned to the pool by TypeORM). Ensure proper error handling and resource cleanup in your code interacting with TypeORM.

