# Attack Tree Analysis for mybatis/mybatis-3

Objective: Unauthorized Data Access/Arbitrary SQL Execution

## Attack Tree Visualization

```
                                      [Attacker's Goal: Unauthorized Data Access/Arbitrary SQL Execution]
                                                      |
                                                      |
                      [[1. SQL Injection (SQLi)]]
                                      |
                      ---------------------------------
                      |
    [[1.1 Dynamic SQL Misuse]]
                      |
    -------------------------
    |                       |
[[1.1.1 String Concatenation]] [[1.1.2 Improper Use of  ]]
    |      ===>             |       [    `$ {}` Interpolation]]
    |                       |
[[1.1.1.1 User-Controlled]] [[1.1.2.1 Attacker Controls]]
[[        Input in SQL  ]] [[        SQL Fragments  ]]
[[        String        ]] [[        via `${}`       ]]
```

## Attack Tree Path: [1. SQL Injection (SQLi)](./attack_tree_paths/1__sql_injection__sqli_.md)

*   **Description:** The overarching vulnerability category. Attackers inject malicious SQL code into application inputs, which are then executed by the database.
*   **Likelihood:** High
*   **Impact:** Very High (Complete database compromise, data theft, modification, potential server compromise)
*   **Effort:** Variable (Depends on the specific SQLi vulnerability)
*   **Skill Level:** Variable (Ranges from Low for basic SQLi to High for complex bypasses)
*   **Detection Difficulty:** Variable (Ranges from Medium to High)
*   **Mitigation:**
    *   Use parameterized queries (`#{}`) exclusively for user-provided data.
    *   Implement strict input validation (whitelisting preferred).
    *   Least privilege principle for database user accounts.
    *   Regular security audits and code reviews.

## Attack Tree Path: [1.1 Dynamic SQL Misuse](./attack_tree_paths/1_1_dynamic_sql_misuse.md)

*   **Description:** MyBatis's dynamic SQL features, if used incorrectly, create opportunities for SQL injection. This is the primary entry point for SQLi in MyBatis applications.
*   **Likelihood:** High (Dynamic SQL is a common feature, and misuse is frequent)
*   **Impact:** Very High (Leads directly to SQLi)
*   **Effort:** Low (Misusing dynamic SQL is easy)
*   **Skill Level:** Low (Basic understanding of MyBatis)
*   **Detection Difficulty:** Medium (Code review and static analysis can identify potential misuse)
*   **Mitigation:**
    *   Strict adherence to using `#{}` for all user-supplied data within dynamic SQL blocks.
    *   Careful review of all dynamic SQL logic.
    *   Avoid complex dynamic SQL logic where possible.

## Attack Tree Path: [1.1.1 String Concatenation](./attack_tree_paths/1_1_1_string_concatenation.md)

*   **Description:** Directly concatenating user input into SQL strings within MyBatis dynamic SQL blocks. This is *always* a vulnerability.
*   **Likelihood:** Medium (If developers are unaware of best practices)
*   **Impact:** Very High (Direct SQLi)
*   **Effort:** Very Low
*   **Skill Level:** Low
*   **Detection Difficulty:** Medium (Easily found with code review and static analysis)
*   **Mitigation:**
    *   *Never* concatenate user input directly into SQL strings.
    *   Use `#{}` exclusively.

## Attack Tree Path: [1.1.1.1 User-Controlled Input in SQL String](./attack_tree_paths/1_1_1_1_user-controlled_input_in_sql_string.md)

*   **Description:** The attacker provides input that is directly incorporated into the SQL query string without proper sanitization or escaping.
*   **Likelihood:** Medium (Direct consequence of string concatenation)
*   **Impact:** Very High (Direct SQLi)
*   **Effort:** Very Low
*   **Skill Level:** Low
*   **Detection Difficulty:** Medium
*   **Mitigation:** Same as `[[1.1.1 String Concatenation]]`

## Attack Tree Path: [1.1.2 Improper Use of `${}` Interpolation](./attack_tree_paths/1_1_2_improper_use_of__${}__interpolation.md)

*   **Description:** Using the `${}` interpolation syntax in MyBatis with user-provided data. `${}` performs direct string substitution *without* escaping, making it vulnerable to SQLi.
*   **Likelihood:** Medium (If developers misunderstand the difference between `#{}` and `${}`)
*   **Impact:** Very High (Direct SQLi)
*   **Effort:** Very Low
*   **Skill Level:** Low
*   **Detection Difficulty:** Medium (Easily found with code review and static analysis)
*   **Mitigation:**
    *   *Never* use `${}` with untrusted input.
    *   Always use `#{}` for user-provided data.
    *   ` ${}` should only be used for trusted, internally generated values (e.g., column names from a controlled list).

## Attack Tree Path: [1.1.2.1 Attacker Controls SQL Fragments via `${}`](./attack_tree_paths/1_1_2_1_attacker_controls_sql_fragments_via__${}_.md)

*   **Description:** The attacker is able to inject arbitrary SQL code fragments by controlling the value passed to a `${}` placeholder.
*   **Likelihood:** Medium (Direct consequence of improper `${}` use)
*   **Impact:** Very High (Direct SQLi)
*   **Effort:** Very Low
*   **Skill Level:** Low
*   **Detection Difficulty:** Medium
*   **Mitigation:** Same as `[[1.1.2 Improper Use of ${} Interpolation]]`

