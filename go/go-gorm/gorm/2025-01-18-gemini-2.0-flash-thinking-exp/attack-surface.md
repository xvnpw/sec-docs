# Attack Surface Analysis for go-gorm/gorm

## Attack Surface: [SQL Injection via Unsafe Query Construction](./attack_surfaces/sql_injection_via_unsafe_query_construction.md)

* **Description:** Attackers inject malicious SQL code into database queries, potentially leading to unauthorized data access, modification, or deletion.
    * **How GORM Contributes to the Attack Surface:**
        * Using `gorm.DB.Exec()` or `gorm.DB.Raw()` with unsanitized user input directly embedded in the SQL string.
        * Building dynamic queries using string concatenation with user-provided data.
        * Incorrectly using parameterized queries, such as not using placeholders for all user-controlled parts of the query.
    * **Example:**
        ```go
        // Vulnerable code
        userInput := "'; DROP TABLE users; --"
        db.Exec("SELECT * FROM users WHERE username = '" + userInput + "'")

        // Vulnerable code using Raw
        username := "'; DELETE FROM orders; --"
        db.Raw("SELECT * FROM users WHERE username = ?", username).Scan(&users)
        ```
    * **Impact:** Full database compromise, data breach, data loss, service disruption.
    * **Risk Severity:** Critical
    * **Mitigation Strategies:**
        * Always use parameterized queries with GORM's query builders (e.g., `Where` with placeholders `?`).
        * Avoid using `gorm.DB.Exec()` or `gorm.DB.Raw()` with direct user input. If necessary, carefully sanitize and validate input.
        * Use GORM's built-in query methods that handle parameterization automatically.

## Attack Surface: [Mass Assignment Vulnerabilities](./attack_surfaces/mass_assignment_vulnerabilities.md)

* **Description:** Attackers can modify unintended database columns by providing extra fields in input data when creating or updating records.
    * **How GORM Contributes to the Attack Surface:**
        * Using `gorm.DB.Create()` or `gorm.DB.Updates()` with data directly from user input (e.g., HTTP request bodies) without explicitly specifying allowed fields.
        * Not using `Select` or `Omit` to control which fields are updated.
    * **Example:**
        ```go
        // Vulnerable code - assuming User struct has an 'isAdmin' field
        type User struct {
            ID       uint
            Username string
            Password string
            IsAdmin  bool
        }

        // Insecurely creating a user from request data
        var newUser User
        c.BindJSON(&newUser) // Attacker might include "isAdmin": true in the JSON
        db.Create(&newUser)
        ```
    * **Impact:** Privilege escalation, data corruption, unauthorized modification of sensitive data.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * Explicitly specify the fields to be updated using `Select` when calling `Updates`.
        * Use DTOs (Data Transfer Objects) or dedicated input structs that only contain the expected fields from user input.
        * Utilize GORM's `Omit` to exclude specific fields from being updated.

## Attack Surface: [Abuse of Raw SQL Functionality](./attack_surfaces/abuse_of_raw_sql_functionality.md)

* **Description:** While providing flexibility, the ability to execute raw SQL queries can be a significant vulnerability if not handled carefully.
    * **How GORM Contributes to the Attack Surface:**
        * Using `gorm.DB.Exec()` or `gorm.DB.Raw()` without proper input sanitization or parameterization, essentially bypassing GORM's built-in protections.
        * Developers might be tempted to use raw SQL for complex queries without fully understanding the security implications.
    * **Example:**
        ```go
        // Vulnerable use of Raw
        tableName := c.Param("table") // User-controlled table name
        db.Raw("SELECT * FROM " + tableName).Scan(&results)
        ```
    * **Impact:** SQL injection, data breach, data manipulation, potential for arbitrary code execution depending on database capabilities.
    * **Risk Severity:** Critical
    * **Mitigation Strategies:**
        * Minimize the use of `gorm.DB.Exec()` and `gorm.DB.Raw()`.
        * If raw SQL is necessary, treat all user input as untrusted and implement robust sanitization and validation.
        * Prefer using GORM's query builders whenever possible.
        * Enforce strict code reviews for any code using raw SQL.

