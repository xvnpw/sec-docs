# Attack Surface Analysis for aspnet/entityframeworkcore

## Attack Surface: [SQL Injection (via Raw SQL or Misused Interpolation)](./attack_surfaces/sql_injection__via_raw_sql_or_misused_interpolation_.md)

*   **Description:**  Execution of malicious SQL code through user-supplied data that is improperly handled within EF Core queries.  This is the most direct and severe EF Core-specific risk.
*   **How EF Core Contributes:**  Provides methods (`FromSqlRaw`, `ExecuteSqlRaw`, `FromSqlInterpolated`, `ExecuteSqlInterpolated`) that allow direct or interpolated SQL execution.  The vulnerability arises from *misusing* these methods by failing to properly parameterize user input.  EF Core *provides* the mechanism for safe parameterized queries; the vulnerability is in *not using them*.
*   **Example:**
    ```csharp
    // VULNERABLE: Direct concatenation
    string userInput = "'; DROP TABLE Users; --";
    var users = context.Users.FromSqlRaw("SELECT * FROM Users WHERE Name = '" + userInput + "'").ToList();

    // VULNERABLE: Misused interpolation (missing *proper* parameterization)
    string userInput2 = "'; DROP TABLE Products; --";
    var products = context.Products.FromSqlInterpolated($"SELECT * FROM Products WHERE Category = '{userInput2}'").ToList(); //Still vulnerable!

    // SAFE: Correctly parameterized
    string userInput3 = "'; DROP TABLE Orders; --"; // This input will be treated as a literal.
    var orders = context.Orders.FromSqlInterpolated($"SELECT * FROM Orders WHERE CustomerId = {userInput3}").ToList();
    ```
*   **Impact:**  Complete database compromise, data theft, data modification, data deletion, denial of service.
*   **Risk Severity:**  Critical
*   **Mitigation Strategies:**
    *   **Primary:**  *Strictly* adhere to parameterized queries.  With `FromSqlInterpolated` and `ExecuteSqlInterpolated`, *always* use the correct parameterization techniques (implicitly via `FormattableString` or explicitly with parameter objects).  *Never* directly concatenate user input into SQL strings, even within interpolated strings.
    *   **Secondary:**  Prefer LINQ expressions over raw SQL whenever possible.  LINQ expressions are inherently safer.
    *   **Code Review:**  Mandatory code reviews for *any* use of `FromSqlRaw`, `ExecuteSqlRaw`, `FromSqlInterpolated`, or `ExecuteSqlInterpolated`.
    *   **Static Analysis:** Employ static analysis tools to automatically detect potential SQL injection vulnerabilities related to these methods.

## Attack Surface: [Query Filter Bypass](./attack_surfaces/query_filter_bypass.md)

*   **Description:**  Circumventing intended data access restrictions implemented through EF Core's global query filters.
*   **How EF Core Contributes:**  Provides the `HasQueryFilter` method (for defining global filters) and the `IgnoreQueryFilters()` method (for bypassing them).  The vulnerability lies in misconfiguring filters or inappropriately using `IgnoreQueryFilters()`.  This is a direct feature of EF Core.
*   **Example:**
    ```csharp
    // Global filter (in OnModelCreating):
    modelBuilder.Entity<TenantData>().HasQueryFilter(td => td.TenantId == _currentUserService.TenantId);

    // VULNERABLE: Bypassing the filter without authorization
    var allData = context.TenantData.IgnoreQueryFilters().ToList(); // Retrieves data from ALL tenants.
    ```
*   **Impact:**  Unauthorized data access, data leakage, violation of data privacy regulations.
*   **Risk Severity:**  High
*   **Mitigation Strategies:**
    *   **Careful Filter Design:**  Thoroughly design and rigorously test global query filters to ensure they are robust and cannot be easily bypassed.  Consider all edge cases and potential attack vectors.
    *   **Restrict `IgnoreQueryFilters()`:**  Strictly limit the use of `IgnoreQueryFilters()` to highly privileged operations *with explicit and robust authorization checks*.  Thoroughly audit any usage of this method.
    *   **Authorization Checks (Pre-Query):** Implement strong authorization checks *before* executing any query, even with global filters in place.  These checks should verify the user's permissions to access the *specific data* being requested. This is a defense-in-depth measure.

## Attack Surface: [Insecure Connection String Management](./attack_surfaces/insecure_connection_string_management.md)

*   **Description:** Improper storage or handling of database connection strings, leading to credential exposure.
*   **How EF Core Contributes:** EF Core *requires* a connection string to connect to the database. While the vulnerability isn't *within* EF Core's code, the framework's *necessity* for a connection string makes this a directly related concern. The framework relies on external mechanisms for secure storage.
*   **Example:** Hardcoding the connection string directly in the `appsettings.json` file, which is then committed to source control. Or, storing it in an unencrypted environment variable that is easily accessible.
*   **Impact:** Database compromise, data theft, data modification, data deletion.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Secure Configuration Providers:** Use secure configuration providers (e.g., Azure Key Vault, AWS Secrets Manager, HashiCorp Vault, .NET User Secrets for development) to store and manage connection strings. *Never* store them in plain text.
    *   **Environment Variables (Securely):** If using environment variables, ensure they are set securely and are not exposed in logs or other insecure locations. Use appropriate operating system and deployment platform mechanisms for secure environment variable management.
    *   **Never Hardcode:** *Never* hardcode connection strings in the application code or in easily accessible configuration files.
    *   **Integrated Security:** Use integrated security (Windows Authentication) where possible to avoid storing credentials in the connection string altogether.
    *   **Least Privilege:** Ensure the database user account specified in the connection string has only the minimum necessary privileges (Principle of Least Privilege).

