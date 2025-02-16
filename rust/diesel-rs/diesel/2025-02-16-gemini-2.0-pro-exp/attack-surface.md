# Attack Surface Analysis for diesel-rs/diesel

## Attack Surface: [Raw SQL Injection](./attack_surfaces/raw_sql_injection.md)

*Description:* Execution of arbitrary SQL commands provided by an attacker, bypassing Diesel's type-safe query builder.
*Diesel's Contribution:* Diesel provides functions (`sql_query`, `execute`) that, if misused, allow raw SQL execution. This is the *primary* way Diesel can introduce SQL injection vulnerabilities. The core design of Diesel *attempts* to prevent this, but these functions offer an escape hatch that must be used with extreme caution.
*Example:*
```rust
// VULNERABLE CODE:
let user_input = req.params().get("id").unwrap(); // Untrusted input
let query = format!("SELECT * FROM users WHERE id = {}", user_input);
let results = diesel::sql_query(query).load::<User>(&mut connection);
```
An attacker could provide `1; DROP TABLE users; --` as the `id` parameter.
*Impact:* Complete database compromise, data theft, data modification, data deletion, denial of service.
*Risk Severity:* **Critical**
*Mitigation Strategies:*
    *   **Never use `sql_query` or `execute` with string formatting that incorporates *any* untrusted input.** This is paramount.
    *   **Always use Diesel's query builder for constructing queries.** This ensures proper parameterization.
    *   **If raw SQL *must* be used (extremely rare and discouraged), use `diesel::sql_query` with bound parameters:**
        ```rust
        // SAFER (but still strongly prefer the query builder):
        let user_input: i32 = req.params().get("id").unwrap().parse().unwrap(); // Validate and parse!
        let results = diesel::sql_query("SELECT * FROM users WHERE id = ?")
            .bind::<diesel::sql_types::Integer, _>(user_input)
            .load::<User>(&mut connection);
        ```
    *   **Input Validation:** Always validate and sanitize *all* user input, even when using the query builder, for defense-in-depth.
    * **Principle of Least Privilege:** Ensure that database user has only required permissions.

## Attack Surface: [Dynamic Table/Column Names (Indirect Injection)](./attack_surfaces/dynamic_tablecolumn_names__indirect_injection_.md)

*Description:* Allowing user input to influence table or column names used in queries, leading to potential information disclosure or other database manipulation.
*Diesel's Contribution:* Diesel does *not* automatically sanitize table or column identifiers. The query builder primarily focuses on parameterizing *values*, not the structural elements of the query (table and column names). This is a crucial distinction.
*Example:*
```rust
// VULNERABLE CODE:
let user_supplied_table = req.params().get("table").unwrap(); // Untrusted input
let query = format!("SELECT * FROM {}", user_supplied_table); // Directly using the input
let results = diesel::sql_query(query).load::<SomeType>(&mut connection);
```
An attacker could provide a different table name (e.g., `admin_credentials`) to access data they shouldn't.
*Impact:* Information disclosure (accessing unintended tables/columns), potential for more severe attacks depending on the database and application logic.
*Risk Severity:* **High**
*Mitigation Strategies:*
    *   **Avoid using user input to directly construct table or column names.** This is the best approach.
    *   **Whitelist Allowed Identifiers:** If dynamic table/column selection is *absolutely required*, maintain a *strict* whitelist of allowed values and validate user input against this whitelist *before* passing it to Diesel.
    *   **Use an Enum or Similar:** Represent allowed table/column choices with an enum or a similar type-safe construct, rather than using raw strings. This prevents arbitrary input and leverages Rust's type system.
    *   **Re-evaluate Design:** Seriously consider alternative design patterns that don't require dynamic table/column selection. Often, a well-designed schema can avoid this need entirely, significantly reducing risk.

## Attack Surface: [Migration Script Injection](./attack_surfaces/migration_script_injection.md)

*Description:* Execution of malicious SQL code embedded within database migration scripts.
*Diesel's Contribution:* Diesel's migration system executes SQL scripts. If these scripts are sourced from untrusted locations or are not properly reviewed, they can contain malicious code that Diesel will execute. Diesel *provides* the mechanism for running migrations; the vulnerability lies in the *content* of those migrations.
*Example:* An attacker could submit a pull request with a migration file containing `DROP TABLE users;` or insert malicious SQL to create a backdoor user.
*Impact:* Database compromise, data loss, data modification, denial of service, potential for complete system compromise.
*Risk Severity:* **High**
*Mitigation Strategies:*
    *   **Thoroughly Review All Migrations:** Carefully review and vet *all* database migration scripts before applying them, *especially* those from external contributors or generated automatically. Manual code review is essential.
    *   **Automated Code Analysis (for SQL):** Consider using automated code analysis tools specifically designed to scan SQL scripts for potentially malicious patterns (e.g., dynamic SQL, suspicious commands).
    *   **Controlled Migration Deployment:** Implement a controlled and auditable process for deploying migrations to production, with appropriate approvals, testing, and rollback capabilities.
    *   **Never Execute Migrations from Untrusted Sources:** Do not run migration scripts downloaded from the internet or provided by untrusted users without *extensive* scrutiny.

