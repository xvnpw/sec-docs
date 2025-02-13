# Attack Surface Analysis for magicalpanda/magicalrecord

## Attack Surface: [Predicate Injection (Indirect)](./attack_surfaces/predicate_injection__indirect_.md)

*   **Description:**  Maliciously crafted input can alter the behavior of Core Data queries, leading to unauthorized data access or modification.
*   **MagicalRecord Contribution:** Simplifies the use of `NSPredicate`, making it easier to accidentally introduce vulnerabilities if user input is not properly handled.  The convenience methods encourage dynamic predicate creation, increasing the risk if not done carefully.
*   **Example:**  Using string formatting to build a predicate with unsanitized user input: `[NSPredicate predicateWithFormat:@"name == %@", userInput]`, where `userInput` contains malicious predicate syntax.
*   **Impact:**  Unauthorized data access, modification, or deletion.  Potential for limited code execution within the context of the database query.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Developers:**  **Always use parameterized predicates.**  Never directly embed user input into the predicate string. Use placeholders (`%@`, `%d`, etc.) and separate argument values.  Validate and sanitize all user input as a secondary defense.

## Attack Surface: [Data Exposure via Overly Broad Queries](./attack_surfaces/data_exposure_via_overly_broad_queries.md)

*   **Description:** Sensitive data is unintentionally exposed due to overly permissive data retrieval.
*   **MagicalRecord Contribution:** Provides simplified fetch methods (e.g., `findAll`, `findAllSortedBy:ascending:`) that, if misused, can retrieve more data than intended. These methods are *very* convenient, making them attractive to use even when a more specific query would be safer.
*   **Example:** `[User MR_findAll]` used in an API endpoint without proper server-side filtering exposes all user data.
*   **Impact:** Leakage of sensitive user information, PII, or internal data.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developers:** Use the most specific query possible (e.g., `findFirstByAttribute`, `findByAttribute`).  Implement robust server-side filtering and pagination *before* exposing data.  Never rely on client-side filtering alone.  Enforce strict data access controls.  Carefully consider the implications of each MagicalRecord fetch method used.

## Attack Surface: [Unintentional Data Modification/Deletion](./attack_surfaces/unintentional_data_modificationdeletion.md)

*   **Description:**  Data is accidentally deleted or modified due to logic errors or incorrect use of MagicalRecord's save/delete methods.
*   **MagicalRecord Contribution:**  Simplifies saving and deleting (e.g., `saveToPersistentStoreAndWait`, `MR_deleteEntity`), making it easier to make mistakes if not used carefully. The simplified API can obscure the underlying Core Data operations, leading to unintended consequences.
*   **Example:**  Calling `[wrongObject MR_deleteEntity]` due to a logic error, or concurrent saves without proper context management leading to data corruption.
*   **Impact:**  Data loss, data corruption, application instability.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developers:**  Thoroughly review all code paths using save/delete methods.  Implement robust error handling and transaction management.  Use nested contexts appropriately.  Consider "soft deletes" (flagging as deleted instead of physically removing). Implement audit logging to track all data modifications.

## Attack Surface: [Context Mismanagement](./attack_surfaces/context_mismanagement.md)

*   **Description:** Data inconsistencies, crashes, or deadlocks due to improper handling of Core Data contexts.
*   **MagicalRecord Contribution:** While aiming to simplify context management, MagicalRecord's abstractions can be misused, leading to concurrency issues if developers don't fully understand the underlying Core Data principles.  The convenience methods might encourage incorrect usage patterns.
*   **Example:** Using the default context (`MR_defaultContext`) on multiple threads without proper synchronization, or failing to save changes to the correct context.
*   **Impact:** Data corruption, application crashes, unpredictable behavior.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developers:** Understand Core Data's concurrency model thoroughly. Use MagicalRecord's context management features correctly (e.g., `MR_saveToPersistentStoreWithCompletion:`, `MR_contextForCurrentThread`, `MR_newMainQueueContext`). Avoid using the default context directly on background threads without careful consideration. Use nested contexts to isolate changes and improve performance. Always save changes to the appropriate context.

