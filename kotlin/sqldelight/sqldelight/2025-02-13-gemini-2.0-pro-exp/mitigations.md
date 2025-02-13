# Mitigation Strategies Analysis for sqldelight/sqldelight

## Mitigation Strategy: [Strict Parameterization and Whitelisting (SQLDelight-Centric)](./mitigation_strategies/strict_parameterization_and_whitelisting__sqldelight-centric_.md)

*   **Description:**
    1.  **SQLDelight Parameter Binding:**  For *all* dynamic values within SQL queries (WHERE clauses, values for INSERT/UPDATE, etc.), *exclusively* use SQLDelight's generated functions and their built-in parameter binding.  Do *not* use string concatenation to build any part of the SQL query with user-provided data.  SQLDelight's type-safe functions handle escaping and quoting.
    2.  **Whitelist Dynamic Identifiers (with SQLDelight):** If dynamic table or column names are *absolutely necessary*, create a hardcoded whitelist (e.g., a Kotlin `Set`, `Enum`, or a constant list).  Before using a dynamic identifier, validate it against this whitelist.  Reject any input not in the whitelist.  This validation happens *before* calling any SQLDelight function.
    3.  **Avoid `rawQuery`/`execute`:**  Minimize or completely eliminate the use of any `rawQuery` or `execute` functions (if your SQLDelight driver/dialect provides them) that accept raw SQL strings.  If their use is unavoidable, apply the *same* whitelisting and parameterization principles *within* the raw SQL string (highly discouraged).  Prioritize SQLDelight's generated, type-safe functions.
    4.  **Parameterized Custom SQL Functions:** If you define custom SQL functions within your `.sq` files, ensure that *these functions themselves* use parameterized queries internally.  Do not concatenate user-provided input directly within the custom function's SQL. Treat parameters to custom functions as potentially malicious.

*   **Threats Mitigated:**
    *   **SQL Injection (Severity: Critical):**  Directly prevents SQL injection by ensuring that all user-provided data is treated as data, not as executable code, through SQLDelight's parameter binding.
    *   **Data Leakage (Severity: High):** Indirectly reduces data leakage by preventing attackers from crafting queries that expose unintended data. This relies on the correct use of parameterization.
    *   **Denial of Service (Severity: Medium):** Reduces some DoS risks that exploit SQL injection to cause performance issues.

*   **Impact:**
    *   **SQL Injection:** Risk reduced to near zero if implemented correctly and comprehensively *within the context of SQLDelight usage*.
    *   **Data Leakage:** Significant risk reduction, preventing unauthorized data access via malicious SQLDelight queries.
    *   **Denial of Service:** Moderate risk reduction, preventing some DoS attack vectors related to SQL injection.

*   **Currently Implemented:**
    *   (Example) "All generated DAO methods from SQLDelight use parameter binding for WHERE clause conditions. Custom SQL functions in `MyFunctions.sq` also use parameterization."

*   **Missing Implementation:**
    *   (Example) "The `buildDynamicQuery` function in `ReportDao.kt` still uses string concatenation for table names. This needs to be refactored to use a whitelist and SQLDelight's generated functions."

## Mitigation Strategy: [Schema Definition and Migration (SQLDelight-Managed)](./mitigation_strategies/schema_definition_and_migration__sqldelight-managed_.md)

*   **Description:**
    1.  **SQLDelight `.sq` Files:** Define your database schema *exclusively* within SQLDelight's `.sq` files.  This includes table definitions, column types, indexes, and any custom SQL functions.
    2.  **SQLDelight Migrations:** Use SQLDelight's built-in migration capabilities to manage schema changes over time.  Create new `.sqm` migration files for each schema modification.
    3.  **Verify Migrations:** Use SQLDelight's `Schema.migrate` function (or equivalent, depending on your driver) to apply migrations and ensure the database schema is up-to-date.  This should be done during application startup.
    4.  **Consistent Data Types:** Ensure that the data types defined in your `.sq` files *precisely* match the expected data types in your application code and the underlying database.
    5. **Index Definition:** Define indexes within your `.sq` files to improve query performance.

*   **Threats Mitigated:**
    *   **Data Corruption (Severity: Medium):**  Reduces the risk of data corruption caused by inconsistencies between the application's expected schema (defined in `.sq` files) and the actual database schema.
    *   **Logic Errors (Severity: Medium):**  Minimizes logic errors arising from incorrect data type handling or schema mismatches.
    *   **Indirect SQL Injection (Severity: Low):** While not a primary defense, consistent schema management can help prevent some obscure injection attacks that exploit type mismatches.

*   **Impact:**
    *   **Data Corruption:** Moderately reduces the risk of data corruption.
    *   **Logic Errors:** Moderately reduces the risk of logic errors related to schema inconsistencies.
    *   **Indirect SQL Injection:** Provides a small, indirect reduction in the risk of certain types of SQL injection.

*   **Currently Implemented:**
    *   (Example) "The database schema is defined in `src/main/sqldelight/com/example/db`.  SQLDelight migrations are used, and `Schema.migrate` is called during application startup."

*   **Missing Implementation:**
    *   (Example) "There's no automated verification to ensure that the latest migration has been applied.  We need to add a check to ensure `Schema.migrate` is called with the correct version."

## Mitigation Strategy: [Proper use of SQLDelight API](./mitigation_strategies/proper_use_of_sqldelight_api.md)

* **Description:**
    1. Use generated query interfaces: Always use the query interfaces generated by SQLDelight. Avoid constructing SQL queries as strings.
    2. Avoid raw queries: Avoid using `rawQuery` or similar methods that execute raw SQL strings, especially with user-provided input.
    3. Use transactions appropriately: Wrap multiple related database operations in transactions to ensure data consistency. Use SQLDelight's transaction API.
    4. Close resources: Ensure that database connections and cursors are properly closed after use. SQLDelight's generated code often handles this automatically, but be mindful of manual resource management if used.

* **Threats Mitigated:**
    * **SQL Injection (Severity: Critical):** By avoiding raw queries and using generated interfaces, the risk of SQL injection is significantly reduced.
    * **Data Inconsistency (Severity: Medium):** Transactions ensure that related operations are either all completed successfully or all rolled back, preventing data inconsistency.
    * **Resource Leaks (Severity: Low):** Proper resource management prevents resource exhaustion and potential denial-of-service issues.

* **Impact:**
    * **SQL Injection:** Risk is significantly reduced by using the type-safe API.
    * **Data Inconsistency:** Transactions greatly reduce the risk of data inconsistency.
    * **Resource Leaks:** Proper resource management eliminates the risk of resource leaks.

* **Currently Implemented:**
    * (Example) "All database interactions use generated query interfaces. Transactions are used for operations involving multiple updates."

* **Missing Implementation:**
    * (Example) "The `legacyImport` function uses `rawQuery` to execute a batch import. This needs to be refactored to use SQLDelight's generated code and parameter binding."

