# Attack Surface Analysis for aspnet/entityframeworkcore

## Attack Surface: [SQL Injection through Raw SQL and Interpolated Strings](./attack_surfaces/sql_injection_through_raw_sql_and_interpolated_strings.md)

**Description:** Attackers inject malicious SQL code into queries executed directly against the database, potentially allowing them to read, modify, or delete data, execute arbitrary commands, or compromise the database server.

**How Entity Framework Core Contributes:** EF Core allows developers to execute raw SQL queries using methods like `context.Database.ExecuteSqlRaw()` or `context.Database.SqlQuery<T>()`. If these methods are used with unsanitized user input directly embedded into the SQL string (especially with string interpolation), it creates a direct pathway for SQL injection.

**Example:**
```csharp
string userInput = GetUserInput(); // Imagine this comes from a web request
var query = $"SELECT * FROM Users WHERE Username = '{userInput}'"; // Vulnerable!
var users = context.Users.FromSqlRaw(query).ToList();
```
An attacker could input `' OR '1'='1` to bypass the `WHERE` clause and retrieve all users.

**Impact:** Critical. Full database compromise, data breach, data manipulation, denial of service.

**Risk Severity:** Critical

**Mitigation Strategies:**
* Always use parameterized queries:  EF Core's LINQ queries and `FromSqlInterpolated` automatically handle parameterization. For raw SQL, use placeholders and pass parameters separately.
* Input validation and sanitization:  Validate and sanitize user input before using it in any database query, even if using parameterized queries as a defense-in-depth measure.

## Attack Surface: [LINQ Injection](./attack_surfaces/linq_injection.md)

**Description:** Attackers manipulate the structure or logic of LINQ queries by influencing input that is used to dynamically build expressions. This can lead to unauthorized data access or unexpected application behavior.

**How Entity Framework Core Contributes:** EF Core allows for dynamic construction of LINQ queries based on user input or application logic. If this construction is not carefully handled, attackers might inject malicious conditions or manipulate the query structure.

**Example:**
```csharp
string sortColumn = GetUserInput("sort"); // User provides the column to sort by
Func<User, object> keySelector = null;
if (sortColumn == "Username") keySelector = u => u.Username;
else if (sortColumn == "Email") keySelector = u => u.Email;
// Imagine a scenario where an attacker could influence the 'sortColumn' value beyond expected inputs
var users = context.Users.OrderBy(keySelector).ToList();
```

**Impact:** Medium to High. Unauthorized data access, information disclosure, potential for denial of service if complex queries are generated.

**Risk Severity:** Medium

**Mitigation Strategies:**
* Whitelist allowed values: If user input determines query logic, validate and whitelist allowed values. Avoid directly using user input to construct lambda expressions or predicate builders without careful validation.
* Use safe abstractions: Consider using pre-defined query options or safe abstractions that limit the attacker's ability to manipulate the query structure.

## Attack Surface: [Information Disclosure through Over-eager Loading and Projection](./attack_surfaces/information_disclosure_through_over-eager_loading_and_projection.md)

**Description:** The application unintentionally retrieves and exposes more data than the user is authorized to access due to overly broad eager loading or projection in EF Core queries.

**How Entity Framework Core Contributes:** EF Core's `.Include()` method for eager loading and `.Select()` method for projections can, if not used carefully, lead to the retrieval of related entities or properties that contain sensitive information the current user should not see.

**Example:**
```csharp
// Assuming User has a navigation property 'SensitiveData'
var user = context.Users.Include(u => u.SensitiveData).FirstOrDefault(u => u.Id == currentUserId);
// Even if the view doesn't display SensitiveData, it was loaded and could be accessed.

// Or a broad projection:
var userData = context.Users.Where(u => u.Id == currentUserId).Select(u => new { u.Id, u.Username, u.PasswordHash }).FirstOrDefault(); // Exposing password hash!
```

**Impact:** Medium to High. Exposure of sensitive personal information, business secrets, or other confidential data.

**Risk Severity:** High

**Mitigation Strategies:**
* Use explicit projections with `.Select()`: Select only the necessary properties.
* Avoid over-eager loading: Load related entities only when needed. Consider using lazy loading (with caution regarding performance) or explicit loading.
* Implement authorization checks at the data layer: Ensure that even if data is loaded, access is restricted based on user roles and permissions.

## Attack Surface: [Mass Assignment Vulnerabilities](./attack_surfaces/mass_assignment_vulnerabilities.md)

**Description:** Attackers can modify unintended properties of an entity by providing malicious input during model binding or updates.

**How Entity Framework Core Contributes:** If EF Core entities are directly bound to user input without proper filtering or whitelisting of allowed properties, attackers can potentially modify properties they shouldn't, such as `IsAdmin` flags or sensitive internal fields.

**Example:**
```csharp
public class User {
    public int Id { get; set; }
    public string Username { get; set; }
    public string Email { get; set; }
    public bool IsAdmin { get; set; } // Sensitive property
}

// In a controller action:
public IActionResult UpdateUser(User user) { // Vulnerable if 'user' is directly bound from request
    _context.Users.Update(user);
    _context.SaveChanges();
    return Ok();
}
```
An attacker could send a request with `IsAdmin: true` to elevate their privileges.

**Impact:** High. Privilege escalation, data manipulation, unauthorized access to administrative functions.

**Risk Severity:** High

**Mitigation Strategies:**
* Use Data Transfer Objects (DTOs) or View Models:  Define separate classes for receiving user input and map only the allowed properties to your EF Core entities.
* Explicitly whitelist allowed properties: When updating entities, only update properties that are explicitly intended to be modified by the user.

## Attack Surface: [Database Migrations and Schema Manipulation](./attack_surfaces/database_migrations_and_schema_manipulation.md)

**Description:** Malicious actors gain access to the database migration process and inject harmful changes to the database schema.

**How Entity Framework Core Contributes:** EF Core Migrations manage database schema changes. If the migration process is not secured, attackers could inject malicious migrations to alter tables, add backdoors, or corrupt data.

**Example:** An attacker gaining access to the development environment or CI/CD pipeline and modifying a migration script to add a trigger that logs all user passwords.

**Impact:** Critical. Data corruption, introduction of backdoors, denial of service, complete database compromise.

**Risk Severity:** Critical

**Mitigation Strategies:**
* Secure the development and deployment pipeline: Implement strong access controls and authentication for development environments and CI/CD systems.
* Code review migrations: Treat migration code like any other application code and subject it to thorough code review.

