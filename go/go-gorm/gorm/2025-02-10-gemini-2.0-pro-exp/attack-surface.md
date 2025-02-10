# Attack Surface Analysis for go-gorm/gorm

## Attack Surface: [SQL Injection](./attack_surfaces/sql_injection.md)

*   **Description:**  The introduction of malicious SQL code into database queries, allowing attackers to bypass security measures, access, modify, or delete data.
    *   **How GORM Contributes:** Improper use of `Raw`, `Expr`, `Find`, `Where`, `Select`, `Order`, `Group` or dynamic query building with unsanitized user input can bypass GORM's parameterized query protections. Struct tag injection is also a niche, but potentially critical, risk.
    *   **Example:**
        ```go
        // Vulnerable: User input directly concatenated into the query
        userInput := "'; DROP TABLE users; --"
        db.Raw("SELECT * FROM products WHERE name = '" + userInput + "'").Scan(&products)

        // Vulnerable: Using Expr with unsanitized input
        userInput := "1; DROP TABLE users; --"
        db.Where(gorm.Expr("id = ?", userInput)).Find(&products)
        ```
    *   **Impact:**  Complete database compromise, data breaches, data loss, data modification, denial of service.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Never use `db.Raw()` with unsanitized user input.**  Always use parameterized queries provided by GORM's higher-level functions.
        *   **When using `Expr`, ensure all user-supplied values are passed as parameters,** not concatenated into the expression string.
        *   **Avoid dynamic query building with string concatenation.** Use GORM's built-in methods (`Find`, `Where`, `First`, etc.) and pass user input as parameters.
        *   **Validate and sanitize all user input** before it reaches GORM, as an additional layer of defense (but *not* as a replacement for parameterized queries).
        *   **Regularly update GORM and database drivers** to the latest versions.
        *   **Implement strict code reviews** focusing on GORM usage.
        *   **Use static analysis tools** to detect potential SQL injection vulnerabilities.
        *   **Principle of Least Privilege:**  The database user should have minimal necessary permissions.
        *   **Never dynamically generate struct tags from user input.**

## Attack Surface: [Data Leakage](./attack_surfaces/data_leakage.md)

*   **Description:** Unintentional exposure of sensitive data due to overly permissive queries or improper field selection.
    *   **How GORM Contributes:**  Using `Find` without `Where` clauses, not using `Select` to restrict fields, and preloading unnecessary associations can lead to data leakage.
    *   **Example:**
        ```go
        // Vulnerable: Retrieves all user data, including sensitive fields
        db.Find(&users) // Potentially exposes hashed passwords, etc.
        ```
    *   **Impact:** Exposure of sensitive user data, PII, credentials, or internal system information.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Always use `Where` clauses to limit the scope of `Find` operations.** Retrieve only the necessary data.
        *   **Use `Select` to explicitly specify the fields to retrieve,** especially when dealing with sensitive data.
        *   **Carefully manage associations.** Use lazy loading or explicit preloading only when necessary.
        *   **Follow the principle of data minimization.**

## Attack Surface: [Data Tampering](./attack_surfaces/data_tampering.md)

*   **Description:** Unauthorized modification of data due to mass assignment vulnerabilities within GORM.
    *   **How GORM Contributes:**  Not controlling which fields can be updated through `Create` or `Update` (mass assignment).
    *   **Example:**
        ```go
        // Vulnerable: Allows updating any field in the user struct
        type UserUpdate struct {
            Name     string
            IsAdmin  bool // Attacker could set this to true
        }
        var updateData UserUpdate
        // ... (populate updateData from user input) ...
        db.Model(&user).Updates(updateData)
        ```
    *   **Impact:**  Unauthorized data modification, privilege escalation, data integrity issues.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Use `Select` or `Omit` with `Create` and `Update` to explicitly control which fields are modified.**
        *   **Input validation:** Validate all user input before it reaches GORM.

## Attack Surface: [Dependency Vulnerabilities (GORM Itself)](./attack_surfaces/dependency_vulnerabilities__gorm_itself_.md)

*   **Description:** Security vulnerabilities within the GORM library itself.
    *   **How GORM Contributes:** GORM, as a piece of software, may contain vulnerabilities.
    *   **Example:** A hypothetical vulnerability in GORM's SQL escaping mechanism.
    *   **Impact:** Varies depending on the specific vulnerability; could range from data leakage to remote code execution (in extreme cases).
    *   **Risk Severity:** Varies (High to Critical, depending on the vulnerability)
    *   **Mitigation Strategies:**
        *   **Regularly update GORM** to the latest version.
        *   **Monitor security advisories** specifically for GORM.
        *   **Use dependency scanning tools** and focus on GORM's reported vulnerabilities.

