# Mitigation Strategies Analysis for go-gorm/gorm

## Mitigation Strategy: [Strict Raw SQL Usage Policy and Parameterized Queries (with GORM)](./mitigation_strategies/strict_raw_sql_usage_policy_and_parameterized_queries__with_gorm_.md)

**Description:**
1.  **Policy:** Minimize `db.Raw()` and `db.Exec()` usage.  Favor GORM's built-in methods (e.g., `Where`, `Find`, `Create`, `Update`, `Delete`) whenever possible.
2.  **Justification:**  Require written justification for *any* use of `db.Raw()` or `db.Exec()`, explaining why GORM's methods are insufficient.
3.  **GORM Parameterization:**  When `db.Raw()` or `db.Exec()` are *unavoidable*, *always* use GORM's parameterized query support.  Pass user input as arguments to these functions, *never* through string concatenation.  Example: `db.Raw("SELECT * FROM users WHERE name = ?", userInput)`.
4.  **Code Review:**  Code reviews *must* specifically check for violations:
    *   Unjustified use of `db.Raw()` or `db.Exec()`.
    *   Missing or incorrect parameterization.
5. **Training:** Train developers on GORM's parameterized query capabilities and the dangers of string concatenation in SQL.

**List of Threats Mitigated:**
*   **SQL Injection (Severity: Critical):** Exploiting vulnerabilities in raw SQL queries to bypass security, access data, modify data, or execute commands.  This is the *primary* threat addressed by this strategy.
*   **Data Leakage (Severity: High):**  Indirectly mitigated by preventing SQL injection, the main vector for unauthorized data access.
*   **Data Modification/Deletion (Severity: High):** Indirectly mitigated by preventing SQL injection.

**Impact:**
*   **SQL Injection:** Risk reduced from Critical to Very Low (with strict adherence and correct GORM parameterization).
*   **Data Leakage/Modification/Deletion:**  Significantly reduced as a consequence of preventing SQL injection.

**Currently Implemented:**
*   **Example:** Policy document exists (`docs/security_policy.md`), but enforcement is inconsistent. Parameterization is *generally* used with `db.Raw()`, but older code might have issues. CI pipeline uses `gosec`.

**Missing Implementation:**
*   **Example:**  Stricter code review enforcement. Formalized security review for *all* `db.Raw()`/`db.Exec()` usage. Automated scanning of legacy code for potential vulnerabilities.

## Mitigation Strategy: [Explicit Field Selection with GORM's `Select`](./mitigation_strategies/explicit_field_selection_with_gorm's__select_.md)

**Description:**
1.  **`Select` Usage:**  Always use GORM's `db.Select()` method when retrieving data to specify *exactly* which columns to return.  Example: `db.Select("id", "username").Find(&users)`.
2.  **Avoid `Find(&users)` Alone:**  Never use `db.Find(&users)` (or similar methods) without a `Select` clause, as this retrieves *all* columns, potentially exposing sensitive data.
3.  **Code Review:**  Code reviews must check for the consistent use of `db.Select()` to limit data retrieval.

**List of Threats Mitigated:**
*   **Data Leakage (Severity: High):**  Accidental exposure of sensitive data due to overly broad queries.
*   **Information Disclosure (Severity: Medium):**  Revealing database structure or sensitive fields unintentionally.

**Impact:**
*   **Data Leakage:** Risk significantly reduced by limiting the data retrieved from the database.
*   **Information Disclosure:** Risk reduced by controlling the data exposed.

**Currently Implemented:**
*   **Example:** `db.Select()` is used inconsistently throughout the codebase. Some areas retrieve all columns. Located in `/pkg/repository`.

**Missing Implementation:**
*   **Example:**  Standardize `db.Select()` usage across the entire codebase.  Code reviews must enforce this.

## Mitigation Strategy: [Controlled Mass Assignment with GORM's `Select` and `Omit`](./mitigation_strategies/controlled_mass_assignment_with_gorm's__select__and__omit_.md)

**Description:**
1.  **`Select` for Updates:**  When using GORM's `db.Model().Updates()`, *always* use `db.Select()` to explicitly list the fields allowed to be updated.  Example: `db.Model(&user).Select("Name", "Email").Updates(...)`.
2.  **`Omit` for Exclusion:**  Alternatively, use GORM's `db.Omit()` to exclude specific fields from updates.  Example: `db.Model(&user).Omit("IsAdmin").Updates(...)`.
3.  **Code Review:**  Code reviews must verify that *all* update operations using GORM use either `db.Select()` or `db.Omit()` to control which fields can be modified.

**List of Threats Mitigated:**
*   **Mass Assignment (Severity: High):**  Unauthorized modification of database fields (e.g., setting `isAdmin` to `true`) by manipulating input.

**Impact:**
*   **Mass Assignment:** Risk reduced from High to Very Low (with consistent use of GORM's `Select` or `Omit`).

**Currently Implemented:**
*   **Example:** `db.Select()` and `db.Omit()` are used in some update operations, but not consistently. Located in `/pkg/repository`.

**Missing Implementation:**
*   **Example:**  Code review to identify and fix any update operations lacking `db.Select()` or `db.Omit()`.  Standardize their usage across the codebase.

## Mitigation Strategy: [GORM's `Unscoped` Awareness and Soft Deletes](./mitigation_strategies/gorm's__unscoped__awareness_and_soft_deletes.md)

**Description:**
1.  **`Unscoped` Awareness:** Developers must be explicitly aware that GORM, *by default*, prevents accidental deletion of all records.  The `db.Unscoped()` method *must* be used to bypass this protection.
2.  **`Unscoped` Restriction:**  Severely restrict the use of `db.Unscoped()`.  Require strong justification and senior developer approval for any use.
3.  **Soft Delete Implementation:**  Utilize GORM's soft delete feature by adding a `gorm.DeletedAt` field to models.  This marks records as deleted instead of physically removing them.  Example:
    ```go
    type User struct {
        gorm.Model
        Name      string
        DeletedAt gorm.DeletedAt `gorm:"index"`
    }
    ```
4.  **Code Review:**  Code reviews must:
    *   Check for the presence of `gorm.DeletedAt` on models where soft deletes are appropriate.
    *   Verify that `db.Unscoped()` is used only with extreme caution and proper justification.

**List of Threats Mitigated:**
*   **Accidental Data Loss (Severity: High):**  Unintentional deletion of all records due to a missing `Where` clause in a `Delete` operation.

**Impact:**
*   **Accidental Data Loss:** Risk significantly reduced by GORM's default behavior, the restricted use of `db.Unscoped()`, and the implementation of soft deletes.

**Currently Implemented:**
*   **Example:** Soft deletes (`gorm.DeletedAt`) are implemented for most models. `db.Unscoped()` is rarely used. Located in `/pkg/models`.

**Missing Implementation:**
*   **Example:**  Formalize the approval process for any use of `db.Unscoped()`.  Ensure all relevant models have soft delete implemented.

## Mitigation Strategy: [Secure GORM Callback Implementation](./mitigation_strategies/secure_gorm_callback_implementation.md)

**Description:**
1.  **Minimize Callback Logic:** Keep GORM callback functions (e.g., `BeforeCreate`, `AfterUpdate`) simple. Avoid complex logic or external calls within callbacks.
2.  **Security-Focused Review:**  Code reviews must specifically examine GORM callbacks for security implications. Ensure they don't bypass security checks or introduce vulnerabilities.
3.  **GORM-Specific Testing:** Write unit and integration tests that specifically target GORM callbacks. Test various scenarios, including edge cases and error conditions, to ensure correct and secure behavior *within the GORM context*.
4. **Avoid Side Effects:** Minimize unintended side effects within GORM callbacks. Callbacks should primarily interact with the model being processed.
5. **Error Handling within GORM:** Implement proper error handling within GORM callbacks. If a callback encounters an error, handle it gracefully and potentially roll back the GORM transaction.

**List of Threats Mitigated:**
*   **Security Bypass (Severity: Medium to High):** Callbacks could bypass security checks.
*   **Data Inconsistency (Severity: Medium):** Poorly written callbacks could lead to inconsistent data.
*   **Logic Errors (Severity: Low to Medium):** Bugs in callbacks could cause unexpected behavior.

**Impact:**
*   **Security Bypass:** Risk reduced by careful design, review, and GORM-specific testing.
*   **Data Inconsistency:** Risk reduced by ensuring callbacks maintain data integrity within the GORM transaction.
*   **Logic Errors:** Risk reduced through thorough testing, specifically focusing on GORM's callback mechanism.

**Currently Implemented:**
*   **Example:** Some callbacks are implemented for auditing. Basic testing exists. Located in `/pkg/models`.

**Missing Implementation:**
*   **Example:** Dedicated security review of all GORM callbacks. Comprehensive testing, including edge cases and error handling within the GORM context. Refactor complex callbacks.

