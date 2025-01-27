# Attack Surface Analysis for dotnet/efcore

## Attack Surface: [SQL Injection Vulnerabilities](./attack_surfaces/sql_injection_vulnerabilities.md)

*   **Description:** Attackers inject malicious SQL code into database queries, potentially allowing them to bypass security measures, access unauthorized data, modify data, or even execute arbitrary commands on the database server. This occurs when EF Core is used in a way that allows unsanitized user input to be directly interpreted as SQL code.
*   **How EF Core Contributes:**
    *   **Directly embedding user input in Raw SQL:** Using `FromSqlRaw`, `ExecuteSqlRaw`, or similar methods without proper parameterization allows user-controlled strings to be directly interpreted as SQL commands by the database. EF Core provides these methods for advanced scenarios, but their misuse opens a direct SQL injection vector.
    *   **Potentially through Dynamic LINQ (less common but possible):** While EF Core parameterizes LINQ queries by default, complex scenarios involving dynamic construction of LINQ expressions based on user input, especially if string manipulation is involved in building predicates, *could* create injection points if not handled with extreme care. This is less frequent than raw SQL injection but still a potential risk when using dynamic query building techniques with EF Core.
*   **Example:**
    ```csharp
    // Vulnerable code: Directly embedding user input into FromSqlRaw
    string city = _userInput; // User-provided input
    var users = _context.Users.FromSqlRaw($"SELECT * FROM Users WHERE City = '{city}'").ToList();
    ```
    If `_userInput` is crafted as `' OR '1'='1`, the query becomes `SELECT * FROM Users WHERE City = '' OR '1'='1'`, bypassing the intended city filter and potentially exposing all user data. More sophisticated injections can lead to data manipulation or database takeover.
*   **Impact:** Data breach, data modification, data deletion, denial of service, potential database server compromise.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Strictly use Parameterized Queries with EF Core:**  **Always** utilize EF Core's built-in parameterization when working with `FromSql`, `ExecuteSql`, and standard LINQ queries.  Use placeholders and parameters instead of string interpolation or concatenation to include user input in SQL commands.
        ```csharp
        // Secure code: Using parameterized query with FromSql
        string city = _userInput;
        var users = _context.Users.FromSql($"SELECT * FROM Users WHERE City = {{0}}", city).ToList();
        ```
    *   **Avoid `FromSqlRaw` and `ExecuteSqlRaw` with User Input when Possible:**  Prefer using LINQ queries or parameterized `FromSql` and `ExecuteSql` methods whenever user input is involved. Reserve `FromSqlRaw` and `ExecuteSqlRaw` for static SQL or scenarios where input is strictly controlled and validated server-side, not directly from user input.
    *   **Careful Dynamic LINQ Construction:** If dynamic LINQ query building is necessary, use libraries or methods that explicitly handle parameterization and prevent SQL injection. Avoid string-based predicate construction directly from user input.
    *   **Input Validation and Sanitization (Defense in Depth):** While parameterization is the primary defense, implement input validation and sanitization as a secondary layer of defense. Validate data types, lengths, and formats to prevent unexpected input from reaching the database layer, even if parameterization is in place.
    *   **Code Review Focused on Raw SQL Usage:**  Specifically review code sections that utilize `FromSqlRaw` and `ExecuteSqlRaw` to ensure they are not vulnerable to SQL injection, especially when handling user-provided data.

