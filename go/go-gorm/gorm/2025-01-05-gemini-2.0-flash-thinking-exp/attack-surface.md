# Attack Surface Analysis for go-gorm/gorm

## Attack Surface: [SQL Injection via Unsafe Query Construction](./attack_surfaces/sql_injection_via_unsafe_query_construction.md)

*   **Attack Surface: SQL Injection via Unsafe Query Construction**
    *   **Description:** Attackers inject malicious SQL code into database queries, potentially leading to unauthorized data access, modification, or deletion.
    *   **How GORM Contributes:** GORM's flexibility allows developers to construct queries using string concatenation or formatting with user-provided input, bypassing parameterized query protection.
    *   **Example:**
        ```go
        var userInput string = "'; DROP TABLE users; --"
        db.Where("name = '" + userInput + "'").Find(&users)
        ```
    *   **Impact:** Critical. Full database compromise, data breach, data manipulation, denial of service.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Always use parameterized queries:**  Utilize GORM's built-in methods like `Where`, `First`, `Find` with placeholders (`?`) for user input.
        *   **Avoid string concatenation for query building:** Do not directly embed user input into SQL strings.
        *   **Use `gorm.Expr` carefully:** When using `gorm.Expr` for complex conditions, ensure the input is sanitized or validated.

## Attack Surface: [SQL Injection via `Raw` Queries](./attack_surfaces/sql_injection_via__raw__queries.md)

*   **Attack Surface: SQL Injection via `Raw` Queries**
    *   **Description:** Similar to the above, but specifically through the `db.Raw()` method, which executes raw SQL.
    *   **How GORM Contributes:** GORM provides the `db.Raw()` method for executing arbitrary SQL, which, if used with unsanitized user input, is a direct path to SQL injection.
    *   **Example:**
        ```go
        var userInput string = "'; DELETE FROM products; --"
        db.Raw("SELECT * FROM orders WHERE customer_id = ?", userInput).Scan(&orders)
        ```
    *   **Impact:** Critical. Full database compromise, data breach, data manipulation, denial of service.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Minimize use of `db.Raw()`:**  Prefer GORM's query builders for safer query construction.
        *   **Sanitize user input rigorously:** If `db.Raw()` is necessary, thoroughly sanitize and validate all user-provided data before incorporating it into the raw SQL string.
        *   **Use parameterized queries within `db.Raw()`:**  Even within `db.Raw()`, use placeholders (`?`) and pass arguments to the method.

## Attack Surface: [Mass Assignment Vulnerabilities](./attack_surfaces/mass_assignment_vulnerabilities.md)

*   **Attack Surface: Mass Assignment Vulnerabilities**
    *   **Description:** Attackers can modify unintended database fields by providing extra or malicious data during record creation or updates.
    *   **How GORM Contributes:** GORM's `Create` and `Updates` methods can directly map user-provided data (e.g., from HTTP requests) to database fields. Without proper control, attackers can set values for fields they shouldn't have access to.
    *   **Example:**
        ```go
        type User struct {
            ID        uint
            Username  string
            Password  string
            IsAdmin   bool
        }
        // Attacker sends JSON: {"username": "evil", "password": "secret", "is_admin": true}
        var userInput map[string]interface{} = map[string]interface{}{{"username": "evil", "password": "secret", "is_admin": true}}
        db.Model(&User{}).Create(userInput)
        ```
    *   **Impact:** High. Privilege escalation, unauthorized data modification, bypassing access controls.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Use `Select` for updates:** When using `Updates`, explicitly specify which fields can be updated using the `Select` method.
        *   **Use DTOs (Data Transfer Objects):** Define specific structs for data input that only contain the fields intended to be modified. Map user input to these DTOs and then use the DTO with GORM.
        *   **Whitelist allowed fields:**  Implement logic to explicitly allow only certain fields to be updated based on user roles or permissions.

## Attack Surface: [Insecure Use of Callbacks](./attack_surfaces/insecure_use_of_callbacks.md)

*   **Attack Surface: Insecure Use of Callbacks**
    *   **Description:** Security-sensitive operations are performed within GORM callbacks (e.g., `BeforeCreate`, `AfterUpdate`), and these callbacks can be bypassed or manipulated.
    *   **How GORM Contributes:** GORM's callback mechanism allows developers to execute code at specific points in the database lifecycle. If these callbacks are not designed securely, vulnerabilities can arise.
    *   **Example:** A `BeforeCreate` callback hashes a password, but the application allows updating the password directly without triggering the callback.
    *   **Impact:** High to Medium. Depending on the callback's function, this can lead to authentication bypass, data integrity issues, or privilege escalation.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Avoid relying solely on callbacks for security:** Implement security checks and logic outside of callbacks as well.
        *   **Ensure callbacks are consistently triggered:** Understand the conditions under which callbacks are executed and prevent bypass scenarios.
        *   **Carefully audit callback logic:** Thoroughly review the code within callbacks for potential vulnerabilities.

