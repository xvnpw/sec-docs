# Mitigation Strategies Analysis for magicalpanda/magicalrecord

## Mitigation Strategy: [Input Validation and Sanitization (Focus on Predicate Construction)](./mitigation_strategies/input_validation_and_sanitization__focus_on_predicate_construction_.md)

**Mitigation Strategy:** Secure Predicate Construction with Parameterization

**Description:**
1.  **Parameterized Predicates:**  *Always* use parameterized predicates (`[NSPredicate predicateWithFormat:@"attribute == %@", value]`) when constructing queries with user input or any external data within MagicalRecord methods.  Pass the user input as a separate argument to the predicate, *never* embed it directly into the format string using string interpolation. This is the core defense against predicate injection.
2.  **Avoid String Interpolation:** Explicitly avoid using string interpolation or concatenation to build predicate format strings. This is the most common mistake leading to vulnerabilities.
3. **Type Checking (for Predicate Values):** Before passing a value to a parameterized predicate, ensure it's of the correct Objective-C/Swift type expected by the Core Data attribute.  For example, if the attribute is an Integer, ensure the value is an `NSNumber` representing an integer.

**Threats Mitigated:**
*   **Predicate Injection:** (Severity: High) - Prevents attackers from manipulating MagicalRecord queries to retrieve unauthorized data or potentially cause unexpected behavior. This is the primary threat this strategy addresses.

**Impact:**
*   **Predicate Injection:** Risk reduced significantly (almost eliminated if parameterized predicates are used correctly and consistently).

**Currently Implemented:**
*   Parameterized predicates are used in most, but not all, places where user input is involved in queries.

**Missing Implementation:**
*   A few older parts of the codebase still use string concatenation for predicate construction. These need to be refactored.

## Mitigation Strategy: [Careful Use of `MR_import...` Methods](./mitigation_strategies/careful_use_of__mr_import_____methods.md)

**Mitigation Strategy:** Secure Data Import with Validation

**Description:**
1.  **Identify Import Points:**  List all uses of MagicalRecord's `MR_import...` methods (e.g., `MR_importFromObject:`, `MR_importFromArray:`, `MR_importValuesForKeysWithObject:`, etc.).
2.  **Data Type Validation (Post-Import):**  *After* using an `MR_import...` method, validate the data types of the imported attributes.  Ensure they match the expected Core Data attribute types.  This is crucial because MagicalRecord's import methods can be somewhat lenient.
3.  **Attribute-Specific Validation (Post-Import):** Apply additional validation rules (range checks, length limits, whitelist checks) to individual attributes *after* the import, based on their semantic meaning. This is a defense-in-depth measure.
4. **External ID Handling:** If importing data that includes external IDs (e.g., from a remote API), *do not* assume these IDs are unique within your local database.  Use MagicalRecord's methods to check for existing objects with the same external ID *before* importing, and handle potential conflicts appropriately (update, generate a new local ID, or reject). Use `MR_findFirstByAttribute:withValue:` or similar methods for this check.
5. **Error Handling:** Implement robust error handling within the import process, specifically checking for errors returned by MagicalRecord's import methods and Core Data save operations. Rollback or handle partial imports appropriately.

**Threats Mitigated:**
*   **Data Corruption:** (Severity: Medium) - Prevents invalid or unexpected data from being imported via MagicalRecord, which could lead to application instability.
*   **Data Integrity Violations:** (Severity: Medium) - Ensures that imported data conforms to the defined data model, even when using MagicalRecord's convenience methods.

**Impact:**
*   **Data Corruption:** Risk reduced significantly.
*   **Data Integrity Violations:** Risk reduced significantly.

**Currently Implemented:**
*   Basic data type validation is performed after some import operations.

**Missing Implementation:**
*   Consistent attribute-specific validation is missing after all `MR_import...` calls.
*   External ID handling is not consistently implemented.
*   Robust error handling with rollback is missing in several import routines.

## Mitigation Strategy: [Context Management and Thread Safety (MagicalRecord Specifics)](./mitigation_strategies/context_management_and_thread_safety__magicalrecord_specifics_.md)

**Mitigation Strategy:** Correct MagicalRecord Context Usage

**Description:**
1.  **Understand MagicalRecord's Contexts:**  Be explicitly aware of how MagicalRecord sets up its contexts. Use `[NSManagedObjectContext MR_defaultContext]` for UI-related operations. Use `[NSManagedObjectContext MR_contextForCurrentThread]` or `[NSManagedObjectContext MR_newBackgroundContext]` (and manage its lifecycle) for background operations. Avoid creating your own contexts unless absolutely necessary, and if you do, ensure you understand Core Data's context rules.
2.  **Background Operations (with MagicalRecord):**  Use MagicalRecord's methods designed for background operations, such as `[MagicalRecord saveWithBlock:]` or `[MagicalRecord saveWithBlockAndWait:]`, to perform data fetching, saving, and importing on background threads. This prevents blocking the main thread.
3.  **Context Isolation (with MagicalRecord Helpers):**  Even when using MagicalRecord, never access or modify `NSManagedObject` instances across different contexts. Use the object's `objectID` and MagicalRecord's fetch methods (e.g., `MR_findFirstByAttribute:withValue:inContext:`) to obtain a valid object instance in the correct context.
4.  **Save Strategies (MagicalRecord Specific):**  Use MagicalRecord's save methods (`saveWithBlock:`, `saveToPersistentStoreWithCompletion:`, etc.) correctly. Understand the differences between synchronous and asynchronous saves and choose the appropriate method for each situation. Avoid unnecessary saves.
5. **Error Handling (with MagicalRecord Saves):** Always check for errors when using MagicalRecord's save methods. Handle any errors appropriately, potentially rolling back changes or displaying an error message to the user.

**Threats Mitigated:**
*   **Data Corruption:** (Severity: Medium) - Incorrect MagicalRecord context usage can lead to data inconsistencies.
*   **Application Crashes:** (Severity: High) - Violating Core Data's threading rules, even through MagicalRecord, can lead to crashes.
*   **Denial of Service (DoS):** (Severity: Low) - Blocking the main thread with long-running operations, even those initiated through MagicalRecord, can make the app unresponsive.

**Impact:**
*   **Data Corruption:** Risk reduced significantly.
*   **Application Crashes:** Risk reduced significantly.
*   **Denial of Service (DoS):** Risk reduced significantly.

**Currently Implemented:**
*   MagicalRecord's convenience methods are generally used correctly for context management.
*   Background contexts are used for some long-running operations.

**Missing Implementation:**
*   Some data operations are still performed on the main thread, potentially causing UI issues.
*   Error handling is not consistently implemented for all MagicalRecord save operations.

## Mitigation Strategy: [Avoid Predicates Based on Sensitive Data (within MagicalRecord Context):](./mitigation_strategies/avoid_predicates_based_on_sensitive_data__within_magicalrecord_context_.md)

**Mitigation Strategy:** Secure Predicate Handling with MagicalRecord

**Description:**
1.  **Identify Sensitive Predicates:**  Review all uses of `NSPredicate` within MagicalRecord fetch requests (e.g., `MR_findAllWithPredicate:`, `MR_findFirstWithPredicate:`) and identify any that filter based on sensitive data.
2.  **Indirect Lookups (with MagicalRecord):**  If possible, avoid directly filtering on sensitive data within MagicalRecord predicates. Instead, use an intermediary, non-sensitive identifier (e.g., a customer ID instead of a credit card number) and use MagicalRecord to fetch based on that identifier.
3.  **Minimize Logging (of MagicalRecord Queries):**  Be extremely cautious about logging any MagicalRecord operations that involve `NSPredicate` objects, especially in production. If logging is necessary for debugging, ensure that any sensitive information within the predicate is redacted *before* logging. This applies to both the predicate string and any values passed to it.
4. **Hashed Comparisons (If Applicable):** If you must filter on sensitive data and indirect lookups aren't feasible, consider storing a one-way hash of the sensitive data and using MagicalRecord to compare against the *hash* in the predicate, not the plaintext value.

**Threats Mitigated:**
*   **Information Disclosure:** (Severity: High) - Prevents sensitive data from being exposed through logs, error messages, or database dumps if MagicalRecord queries (including predicates) are inadvertently revealed.

**Impact:**
*   **Information Disclosure:** Risk reduced significantly.

**Currently Implemented:**
*   Parameterized predicates are used (which helps, but doesn't fully address this).

**Missing Implementation:**
*   No indirect lookups are used to avoid filtering on sensitive data directly within MagicalRecord predicates.
*   MagicalRecord queries (including predicates) are sometimes logged without redaction.
* No use of hashed comparisons.

