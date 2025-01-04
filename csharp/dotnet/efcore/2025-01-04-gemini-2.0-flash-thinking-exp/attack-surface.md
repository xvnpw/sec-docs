# Attack Surface Analysis for dotnet/efcore

## Attack Surface: [SQL Injection via Raw SQL Methods](./attack_surfaces/sql_injection_via_raw_sql_methods.md)

* **SQL Injection via Raw SQL Methods**
    * **Description:** Executing raw SQL queries using methods like `FromSqlRaw`, `ExecuteSqlRaw`, or string interpolation within these methods without proper parameterization, allowing for injection of malicious SQL code.
    * **How EF Core Contributes:** EF Core provides these methods, and their misuse directly leads to the vulnerability by bypassing built-in parameterization.
    * **Example:**
    ```csharp
    // Vulnerable code:
    var userId = GetUserInput();
    var query = $"SELECT * FROM Users WHERE Id = {userId}";
    var users = context.Users.FromSqlRaw(query).ToList();
    ```
    * **Impact:** Full database compromise, including data exfiltration, modification, or deletion.
    * **Risk Severity:** Critical
    * **Mitigation Strategies:**
        * **Always use parameterized queries with `FromSqlInterpolated` or `FromSqlRaw` with parameters.**
        * **Avoid string concatenation or interpolation for constructing SQL queries with user input within these EF Core methods.**

## Attack Surface: [Dynamic LINQ and String-Based Predicates](./attack_surfaces/dynamic_linq_and_string-based_predicates.md)

* **Dynamic LINQ and String-Based Predicates**
    * **Description:** Constructing LINQ queries dynamically based on user input, especially using string-based predicates, allowing attackers to craft malicious query conditions.
    * **How EF Core Contributes:** EF Core executes the generated LINQ queries. If the LINQ expression is maliciously crafted (often through external libraries but executed by EF Core), it can lead to unintended data access or manipulation.
    * **Example:**
    ```csharp
    // Vulnerable code (using a hypothetical dynamic LINQ library):
    var filter = GetUserInput(); // e.g., "Name == 'Admin' || 1 == 1"
    var users = context.Users.Where(filter).ToList();
    ```
    * **Impact:** Unauthorized data access, data exfiltration, potential performance degradation, or even data modification.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **Avoid using string-based dynamic LINQ where possible.**
        * **If dynamic filtering is necessary, use strongly-typed filtering mechanisms or a safe subset of allowed expressions.**
        * **Implement strict input validation and sanitization on any user-provided input used in dynamic query construction that EF Core will execute.**

## Attack Surface: [Mass Assignment Vulnerabilities](./attack_surfaces/mass_assignment_vulnerabilities.md)

* **Mass Assignment Vulnerabilities**
    * **Description:** Directly binding user input to entity properties without explicit control, allowing attackers to modify properties they shouldn't have access to.
    * **How EF Core Contributes:** EF Core facilitates binding data from requests to entity instances. Lack of control over this binding exposes the vulnerability.
    * **Example:**
    ```csharp
    // Vulnerable code:
    public class User { public string Username { get; set; } public string Role { get; set; } }

    // In controller:
    var user = new User();
    UpdateModel(user); // Directly binds request data to User properties
    ```
    * **Impact:** Privilege escalation, unauthorized data modification, bypassing business logic.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **Use Data Transfer Objects (DTOs) or View Models to explicitly define the properties that can be bound from user input.**
        * **Use the `[Bind]` attribute or `Exclude` attribute sparingly and with caution.**
        * **Manually map properties from the request to the entity after performing authorization checks before interacting with EF Core.**

## Attack Surface: [Insecure Handling of Sensitive Data in Migrations](./attack_surfaces/insecure_handling_of_sensitive_data_in_migrations.md)

* **Insecure Handling of Sensitive Data in Migrations**
    * **Description:** Including sensitive data (e.g., default passwords, API keys) directly within EF Core migration scripts.
    * **How EF Core Contributes:** EF Core generates and applies these migration scripts. If sensitive data is included, it becomes part of the application's deployment process via EF Core.
    * **Example:**
    ```csharp
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.InsertData(
            table: "Users",
            columns: new[] { "Id", "Username", "PasswordHash" },
            values: new object[] { 1, "admin", "P@$$wOrd" }); // Insecure!
    }
    ```
    * **Impact:** Exposure of sensitive credentials or other confidential information.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **Avoid including sensitive data directly in migration scripts.**
        * **Use secure methods for seeding initial data, such as configuration settings or separate scripts executed after deployment, not directly managed by EF Core migrations.**
        * **Ensure migration scripts are stored and managed securely.**

