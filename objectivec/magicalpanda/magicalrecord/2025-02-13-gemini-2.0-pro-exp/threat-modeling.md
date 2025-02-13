# Threat Model Analysis for magicalpanda/magicalrecord

## Threat: [Unintentional Data Exposure via Over-Fetching](./threats/unintentional_data_exposure_via_over-fetching.md)

*   **Description:** An attacker could potentially gain access to sensitive data by exploiting overly broad queries. MagicalRecord's convenience methods like `MR_findAll` and its variants, *when used without predicates or fetch limits*, directly enable this. The attacker doesn't need to exploit a separate vulnerability; the misuse of MagicalRecord *is* the vulnerability. The application might retrieve all records of an entity, and if this data is then inadvertently exposed (e.g., serialized to JSON), the attacker gains access.
    *   **Impact:** Leakage of sensitive user data, potentially leading to identity theft, financial loss, or reputational damage. Violation of privacy regulations (GDPR, CCPA, etc.).
    *   **Affected MagicalRecord Component:**
        *   `MR_findAll`
        *   `MR_findAllInContext:`
        *   `MR_findAllSortedBy:ascending:`
        *   `MR_findAllSortedBy:ascending:inContext:`
        *   `MR_findAllWithPredicate:` (when used with a trivially true predicate or no predicate)
        *   `MR_findAllWithPredicate:inContext:` (when used with a trivially true predicate or no predicate)
        *   Any method that retrieves all entities without proper filtering *when misused*.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Mandatory Predicates:**  Enforce a strict policy that *all* MagicalRecord queries *must* include a specific predicate, even if it seems unnecessary.
        *   **Mandatory Fetch Limits:**  Enforce a strict policy that *all* MagicalRecord queries *must* include a reasonable `fetchLimit`.
        *   **Data Access Layer (DAL):**  Implement a DAL that *completely hides* MagicalRecord's retrieval methods. The DAL should provide its own methods with mandatory predicate and limit parameters.
        *   **Code Reviews:**  Thoroughly review all data retrieval code, specifically looking for any use of MagicalRecord methods without predicates and limits.
        *   **Data Minimization:** Only fetch needed attributes using `setPropertiesToFetch` on the underlying request.

## Threat: [Unintentional Data Modification via Default Context Misuse](./threats/unintentional_data_modification_via_default_context_misuse.md)

*   **Description:** An attacker might indirectly cause unintended data modification by triggering actions in the application that rely on MagicalRecord's *default context* (`[NSManagedObjectContext MR_defaultContext]`). If developers are not careful, changes made in seemingly unrelated parts of the application can be inadvertently saved to the persistent store because they are operating on the same, shared default context. MagicalRecord's easy access to this default context, without explicit context management, directly facilitates this threat.
    *   **Impact:** Data corruption, loss of data integrity, potential application instability. Unauthorized changes to user data.
    *   **Affected MagicalRecord Component:**
        *   `[NSManagedObjectContext MR_defaultContext]` (and related context accessors)
        *   `MR_saveToPersistentStoreAndWait` (when used with the default context implicitly)
        *   `MR_saveToPersistentStoreWithCompletion:` (when used with the default context implicitly)
        *   `MR_saveWithBlock:` (when operating on the default context)
        *   `MR_saveWithBlockAndWait:` (when operating on the default context)
        *   Implicit saving behavior when using the default context.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Context Isolation:**  *Never* use the default context for user-initiated data modifications. Always create separate `NSManagedObjectContext` instances for different tasks.
        *   **Explicit Saving:**  Only save changes when explicitly intended and within the correct context.
        *   **Data Access Layer (DAL):**  The DAL should manage context lifecycles and saving operations, *completely hiding* the default context and forcing the use of explicitly created contexts.
        *   **Code Reviews:**  Carefully review all code that modifies data, specifically looking for any reliance on the default context.
        *  **Training:** Ensure developers have deep understanding of CoreData contexts.

