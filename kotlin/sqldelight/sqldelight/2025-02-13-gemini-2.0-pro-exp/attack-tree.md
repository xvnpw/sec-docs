# Attack Tree Analysis for sqldelight/sqldelight

Objective: Unauthorized Data Access/Modification/Deletion or SQLDelight-Specific DoS [CRITICAL]

## Attack Tree Visualization

```
                                      +-----------------------------------------------------+
                                      |  Attacker Goal: Unauthorized Data Access/Modification/Deletion |
                                      |                 or SQLDelight-Specific DoS               | [CRITICAL]
                                      +-----------------------------------------------------+
                                                       |
          +-------------------------------------------------------------------------------------+
          |                                                                                     |
+-------------------------+                                                               +---------------------------------+
|  1. SQL Injection via   |                                                               | 3.  Resource Exhaustion via     |
|     .sq Files          |                                                               |     SQLDelight Features       |
+-------------------------+                                                               +---------------------------------+
          |                                                                                                 |
+---------+---------+                                                        +---------+---------+---------+---------+
| 1.1 Untrusted  |                                                        | 3.1  Unbounded  | 3.2  Complex  |
|  Input in .sq  |                                                        |      Queries    |      Joins   |
|    Files       | [CRITICAL]                                               | (e.g., SELECT  | (Many-to-Many)|
+-----------------+                                                        |     *) [CRITICAL]|  or Nested)  |
          |                                                                |                 | [CRITICAL]   |
+---------+---------+                                                        +---------+---------+
| 1.1.1  Bypassing |
|  SQLDelight's  |
|  Type Safety   |
| (e.g., using   |
|  string        |
|  interpolation |
|  in raw SQL)   | [CRITICAL]
+-----------------+
```

## Attack Tree Path: [1. SQL Injection via .sq Files (High-Risk Path)](./attack_tree_paths/1__sql_injection_via__sq_files__high-risk_path_.md)

*   **Overall Description:** This path represents the most significant threat: attackers injecting malicious SQL code through vulnerabilities in how the application handles user input within SQLDelight's `.sq` files.

*   **1.1 Untrusted Input in .sq Files** [CRITICAL]
    *   **Description:** This is the crucial entry point.  The vulnerability exists when untrusted user-supplied data is directly incorporated into the SQL queries defined in `.sq` files *without* proper sanitization or parameterization.  This is a fundamental violation of secure coding practices.
    *   **Likelihood:** Medium to High
    *   **Impact:** High to Very High
    *   **Effort:** Low to Medium
    *   **Skill Level:** Intermediate
    *   **Detection Difficulty:** Medium

*   **1.1.1 Bypassing SQLDelight's Type Safety (e.g., using string interpolation in raw SQL)** [CRITICAL]
    *   **Description:** This is the *most common and dangerous* specific instance of the above.  Developers might mistakenly believe that using `.sq` files automatically makes their queries safe.  However, if they use string concatenation or interpolation (e.g., `${userInput}` in Kotlin or similar constructs in other languages) to build the SQL query *within* the `.sq` file, they completely bypass SQLDelight's type safety and parameterized query mechanisms.
        *   **Example (Vulnerable):**
            ```sql
            -- In getUser.sq
            getUser:
            SELECT * FROM users WHERE username = '${userInput}';
            ```
        *   **Example (Safe):**
            ```sql
            -- In getUser.sq
            getUser:
            SELECT * FROM users WHERE username = ?;
            ```
            (And then the `userInput` is passed as a parameter when executing the query.)
    *   **Likelihood:** Medium to High
    *   **Impact:** High to Very High
    *   **Effort:** Low to Medium
    *   **Skill Level:** Intermediate
    *   **Detection Difficulty:** Medium

## Attack Tree Path: [3. Resource Exhaustion via SQLDelight Features](./attack_tree_paths/3__resource_exhaustion_via_sqldelight_features.md)

*    **Overall Description:** This path focuses on denial-of-service (DoS) attacks that exploit how SQLDelight handles queries, potentially leading to resource exhaustion on the database server or within the application itself.

*   **3.1 Unbounded Queries (e.g., SELECT *)** [CRITICAL]
    *   **Description:** Queries that retrieve an excessively large number of rows without any limits can overwhelm the database and the application.  A simple `SELECT * FROM a_very_large_table` without a `WHERE` clause or a `LIMIT` clause is a prime example.  This can consume excessive memory, CPU, and network bandwidth.
    *   **Likelihood:** Medium
    *   **Impact:** Medium to High
    *   **Effort:** Low
    *   **Skill Level:** Novice
    *   **Detection Difficulty:** Medium

*   **3.2 Complex Joins (Many-to-Many or Nested)** [CRITICAL]
    *   **Description:** Queries involving complex joins, especially many-to-many relationships or deeply nested subqueries, can be computationally expensive.  An attacker might craft a query specifically designed to maximize the processing load on the database server, leading to a DoS.
    *   **Likelihood:** Medium
    *   **Impact:** Medium to High
    *   **Effort:** Low to Medium
    *   **Skill Level:** Intermediate
    *   **Detection Difficulty:** Medium

