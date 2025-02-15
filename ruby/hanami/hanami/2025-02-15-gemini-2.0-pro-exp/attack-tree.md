# Attack Tree Analysis for hanami/hanami

Objective: Gain Unauthorized Access to Application Data/Functionality

## Attack Tree Visualization

                                      [Gain Unauthorized Access to Application Data/Functionality]
                                                                  \
                                                                   \
                      -->[Manipulate Hanami Application Logic]
                                     /       |       \
                                   /        |        \
            [Actions]  ... [Interactors] ... [Validators]
             /   \              |                 |
            /     \             |                 |
       ...  -->[A2][!]     -->[I2][!]          ...

## Attack Tree Path: [[A2] - Parameter Tampering due to Missing Input Validation (Actions)](./attack_tree_paths/_a2__-_parameter_tampering_due_to_missing_input_validation__actions_.md)

*   **Description:** An attacker manipulates input parameters sent to a Hanami Action.  The Action fails to properly validate these parameters, leading to unexpected behavior, data corruption, or security bypasses. This is a failure to utilize or a misconfiguration of Hanami's input handling and validation mechanisms (or a complete lack thereof).
*   **Likelihood:** High (Very common vulnerability)
*   **Impact:** Medium to High (Depends on the parameter and its use)
*   **Effort:** Low (Can be done manually or with basic tools)
*   **Skill Level:** Novice to Intermediate (Basic understanding of HTTP requests)
*   **Detection Difficulty:** Medium to Hard (Requires analyzing logs and potentially reverse-engineering the application)
*   **Mitigation:**
    *   Implement comprehensive input validation on *all* Action parameters.
    *   Use Hanami's built-in validation features (e.g., `dry-validation`). Define clear schemas and rules for each parameter.
    *   Validate data types, lengths, formats, and allowed values.
    *   Consider using a whitelist approach (allow only known-good values) rather than a blacklist approach (block known-bad values).
    *   Sanitize input *after* validation to remove any potentially harmful characters.
    *   Perform input validation at multiple layers (e.g., client-side, Action, and potentially even Repository) as a defense-in-depth strategy.

## Attack Tree Path: [[I2] - Improper Authorization Checks (Interactors)](./attack_tree_paths/_i2__-_improper_authorization_checks__interactors_.md)

*   **Description:** An attacker attempts to perform an action that they are not authorized to perform. The Interactor responsible for handling this action either lacks authorization checks entirely or has flawed checks that can be bypassed. This allows the attacker to access restricted data or functionality.
*   **Likelihood:** Medium (Common vulnerability)
*   **Impact:** High (Can lead to unauthorized access to data or functionality)
*   **Effort:** Low (Requires bypassing existing checks)
*   **Skill Level:** Intermediate (Understanding of authorization mechanisms)
*   **Detection Difficulty:** Medium (Requires analyzing logs and identifying unauthorized actions)
*   **Mitigation:**
    *   Implement robust authorization checks within *every* Interactor.
    *   Verify that the current user has the necessary permissions to perform the requested action *before* executing any business logic.
    *   Use a consistent authorization mechanism throughout the application (e.g., a role-based access control system).
    *   Consider using a dedicated authorization library or framework.
    *   Test authorization checks thoroughly, including negative test cases (attempting to access resources without the required permissions).
    *   Log all authorization attempts (both successful and failed) for auditing purposes.

## Attack Tree Path: [[RP1] - SQL Injection due to Unsafe Query Construction (Repositories)](./attack_tree_paths/_rp1__-_sql_injection_due_to_unsafe_query_construction__repositories_.md)

*    **Description:** An attacker injects malicious SQL code into a database query through unsanitized user input. This occurs when a Repository uses string concatenation or interpolation to build SQL queries, rather than using parameterized queries or the equivalent features provided by the ORM (`rom-rb`).
*    **Likelihood:** Low (Hanami's `rom-rb` integration encourages safe practices)
*    **Impact:** Very High (Complete database compromise, data theft, modification, or deletion)
*    **Effort:** Low to Medium (Depends on query complexity)
*    **Skill Level:** Intermediate to Advanced (SQL injection and database security knowledge)
*    **Detection Difficulty:** Medium (Automated scanners and manual code review can help)
*    **Mitigation:**
        *   **Strictly avoid string concatenation or interpolation** when building SQL queries with user-supplied data.
        *   **Always use parameterized queries** (prepared statements) or the equivalent features provided by `rom-rb`. This ensures that user input is treated as data, not as executable code.
        *   **Utilize `rom-rb`'s built-in query building methods** which are designed to prevent SQL injection.
        *   **Validate and sanitize input** *before* it reaches the database layer, as an additional layer of defense (but *never* rely on sanitization alone).
        *   **Employ the principle of least privilege:** The database user account used by the application should have only the minimum necessary permissions.
        *   **Regularly review and audit database queries** for potential vulnerabilities.

