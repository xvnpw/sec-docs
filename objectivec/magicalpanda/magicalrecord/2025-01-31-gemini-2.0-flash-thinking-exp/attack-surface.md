# Attack Surface Analysis for magicalpanda/magicalrecord

## Attack Surface: [Predicate Injection](./attack_surfaces/predicate_injection.md)

*   **Description:** Exploiting vulnerabilities in data queries by injecting malicious code into predicates, often through string manipulation with user-supplied input. This allows attackers to manipulate database queries beyond their intended scope.
*   **MagicalRecord Contribution:** MagicalRecord simplifies Core Data interaction, but still relies on `NSPredicate`.  If developers use string-based predicate construction with user input without proper sanitization when using MagicalRecord methods like `MR_findAllWithPredicate:`, it directly creates a predicate injection vulnerability. MagicalRecord's ease of use might inadvertently encourage less secure predicate construction practices if developers are not fully aware of the risks.
*   **Example:**
    *   **Scenario:** A search feature uses user input to filter data in Core Data using MagicalRecord.
    *   **Vulnerable Code:**
        ```objectivec
        NSString *userInput = /* User input from search field */;
        NSString *predicateString = [NSString stringWithFormat:@"userName == '%@'", userInput];
        NSPredicate *predicate = [NSPredicate predicateWithFormat:predicateString];
        NSArray *results = [User MR_findAllWithPredicate:predicate];
        ```
    *   **Attack:** An attacker inputs `'" OR '1'='1'` as `userInput`. This modifies the predicate to `userName == '' OR '1'='1'`, making it always true and potentially returning all user records, bypassing intended access controls.
*   **Impact:**
    *   Unauthorized data access and retrieval of sensitive information.
    *   Data leakage and privacy violations.
    *   Bypass of intended application logic and access controls.
    *   Potential for data manipulation or denial of service depending on the application's logic and data model.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Use Parameterized Predicates:**  **Crucially**, always use `NSPredicate` with placeholders (`?`, `%@`, etc.) and arguments when incorporating user input into predicates. This is the primary defense against predicate injection. MagicalRecord methods work seamlessly with parameterized predicates.
        ```objectivec
        NSString *userInput = /* User input from search field */;
        NSPredicate *predicate = [NSPredicate predicateWithFormat:@"userName == %@", userInput];
        NSArray *results = [User MR_findAllWithPredicate:predicate, userInput];
        ```
    *   **Avoid String-Based Predicate Construction with User Input:**  Never directly embed unsanitized user input into predicate strings.  Rely exclusively on parameterized predicates for dynamic queries.
    *   **Input Validation (Secondary):** While parameterized predicates are the primary solution, implement input validation to further restrict the type of input accepted and handle unexpected or malicious input formats, adding a layer of defense in depth.

