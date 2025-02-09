# Attack Surface Analysis for dotnet/efcore

## Attack Surface: [SQL Injection (via Raw SQL)](./attack_surfaces/sql_injection__via_raw_sql_.md)

*   **Attack Surface Area:** SQL Injection (via Raw SQL)

    *   **Description:**  Injection of malicious SQL code into database queries.
    *   **EF Core Contribution:**  Provides `FromSqlRaw` and `ExecuteSqlRaw` methods that allow developers to execute raw SQL queries, bypassing the built-in parameterization of LINQ-to-Entities. This is a *direct* EF Core feature that creates the vulnerability.
    *   **Example:**
        ```csharp
        // Vulnerable code:
        string userInput = Request.Query["username"]; // Untrusted input
        var users = context.Users.FromSqlRaw($"SELECT * FROM Users WHERE Username = '{userInput}'").ToList();
        ```
        An attacker could provide `'; DROP TABLE Users; --` as the `username`.
    *   **Impact:**  Complete database compromise, data loss, data modification, data exfiltration, denial of service.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Developer:** *Always* use parameterized queries, even with `FromSqlRaw` and `ExecuteSqlRaw`.  Use `FromSqlInterpolated` and string interpolation *only for values*, never for table or column names.  Implement strict input validation *before* passing data to any EF Core method.  Conduct thorough code reviews, specifically focusing on any use of raw SQL.
        *   **User/Administrator:** Ensure database user accounts have the least necessary privileges.  Regularly back up the database.

## Attack Surface: [SQL Injection (via Dynamic LINQ)](./attack_surfaces/sql_injection__via_dynamic_linq_.md)

*   **Attack Surface Area:** SQL Injection (via Dynamic LINQ)

    *   **Description:**  Injection of malicious code through dynamically constructed LINQ queries or expression trees.
    *   **EF Core Contribution:**  EF Core's LINQ provider translates LINQ expressions into SQL.  If the *structure* of the LINQ query is dynamically built based on untrusted input, it can create an injection vulnerability. This is a *direct* consequence of how EF Core processes LINQ.
    *   **Example:**  A scenario where a user can control the `OrderBy` clause, potentially injecting SQL.
        ```csharp
        //Potentially vulnerable if 'orderByField' comes directly from user input
        string orderByField = Request.Query["sort"];
        var users = context.Users.OrderBy(orderByField).ToList(); //Simplified
        ```
        If `orderByField` is `Username; WAITFOR DELAY '0:0:10'; --`.
    *   **Impact:**  Database compromise, data loss, data modification, data exfiltration, denial of service.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developer:** Avoid dynamic query construction based on untrusted input whenever possible.  If unavoidable, use a whitelist approach. Consider a safe query builder library. Thorough input validation is essential.
        *   **User/Administrator:**  Similar to raw SQL injection mitigation.

## Attack Surface: [Data Exposure (Sensitive Data in Exceptions)](./attack_surfaces/data_exposure__sensitive_data_in_exceptions_.md)

*   **Attack Surface Area:** Data Exposure (Sensitive Data in Exceptions)

    *   **Description:**  Exposure of sensitive information (connection strings, query fragments) in exception messages.
    *   **EF Core Contribution:**  EF Core exceptions can, by default, include details that might be considered sensitive. This is a *direct* behavior of EF Core's exception handling.
    *   **Example:**  A database connection error including the connection string in the exception message.
    *   **Impact:**  Exposure of sensitive database credentials or query details.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developer:**  Implement robust error handling and logging.  *Never* expose raw exception details to the user.  Sanitize exception messages.  Use `EnableSensitiveDataLogging(false)` in production (and ideally in development).
        *   **User/Administrator:**  Ensure proper logging configuration.

## Attack Surface: [Denial of Service (Unbounded Queries)](./attack_surfaces/denial_of_service__unbounded_queries_.md)

*   **Attack Surface Area:** Denial of Service (Unbounded Queries)

    *   **Description:**  Queries that return a large number of results, consuming excessive resources.
    *   **EF Core Contribution:**  EF Core doesn't automatically limit the number of results returned by a query. This is a *direct* consequence of how EF Core handles query execution.
    *   **Example:**
        ```csharp
        // Returns all users.
        var allUsers = context.Users.ToList();
        ```
    *   **Impact:**  Server resource exhaustion, denial of service.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developer:**  *Always* implement pagination (`Skip` and `Take`).  Set reasonable limits.
        *   **User/Administrator:**  Monitor server resource usage.

## Attack Surface: [Data Tampering (Lack of Model Validation)](./attack_surfaces/data_tampering__lack_of_model_validation_.md)

*   **Attack Surface Area:** Data Tampering (Lack of Model Validation) - *While EF Core doesn't *directly* cause this, it's highly relevant because EF Core is the data access layer.*

    *   **Description:**  Insertion of invalid or malicious data due to missing validation.
    *   **EF Core Contribution:** EF Core focuses on persistence; it doesn't inherently enforce business rules. *It's the developer's responsibility to validate data before using EF Core to save it.*
    *   **Example:**  Saving a `User` with an invalid email or negative age.
    *   **Impact:**  Data corruption, application instability, potential security vulnerabilities.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developer:** Implement comprehensive data validation *before* calling `SaveChanges`. Use data annotations, fluent validation, or custom logic.
        *   **User/Administrator:** No direct mitigation.

## Attack Surface: [Data Tampering (Mass Assignment)](./attack_surfaces/data_tampering__mass_assignment_.md)

*   **Attack Surface Area:** Data Tampering (Mass Assignment) - *Similar to above, EF Core's update mechanism makes this relevant.*

    *   **Description:**  Unauthorized modification of entity properties.
    *   **EF Core Contribution:** EF Core allows updating by modifying properties and calling `SaveChanges`. *If property access isn't controlled, this is a risk.*
    *   **Example:** An attacker modifying the `IsAdmin` property.
    *   **Impact:** Unauthorized data modification, privilege escalation.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developer:** Avoid directly binding user input to entity objects. Use DTOs or view models, and explicitly control which properties are updated. Use a whitelist approach.
        *   **User/Administrator:** No direct mitigation.

