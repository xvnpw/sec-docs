# Attack Tree Analysis for dotnet/efcore

Objective: Unauthorized Data Access/Modification/Deletion or DoS via EF Core

## Attack Tree Visualization

                                     [Attacker's Goal: Unauthorized Data Access/Modification/Deletion or DoS via EF Core]
                                                        |
                                        ---------------------------------
                                        |
                      [1. SQL Injection (EF Core Specific)] [!]
                                        |
                      -----------------------------------
                      |
    [1.1 Raw SQL Queries] [!]
                      |
    ----------
    |
[1.1.1] [!]
FromSqlRaw/
ExecuteSqlRaw
with
Untrusted
Input
    |
    --->
    |
[1.1.2]
Untrusted Input
to String.Format()

                                        ---------------------------------
                                        |
                      [3. Inefficient Query Leading to DoS]
                                        |
                      -----------------------------------
                      |
    [3.2 N+1 Problem] --->
                      |
    ----------
    |
Missing Includes

## Attack Tree Path: [1. SQL Injection (EF Core Specific) [!] (Critical Node)](./attack_tree_paths/1__sql_injection__ef_core_specific___!___critical_node_.md)

*   **Description:** Exploiting vulnerabilities in how the application constructs SQL queries to gain unauthorized access to the database. This is a critical vulnerability because it can lead to complete data compromise.
*   **Likelihood:** Medium (Overall), High (for Raw SQL)
*   **Impact:** Very High
*   **Effort:** Low (for Raw SQL)
*   **Skill Level:** Intermediate (for Raw SQL)
*   **Detection Difficulty:** Medium

## Attack Tree Path: [1.1 Raw SQL Queries [!] (Critical Node)](./attack_tree_paths/1_1_raw_sql_queries__!___critical_node_.md)

*   **Description:** Using `FromSqlRaw` or `ExecuteSqlRaw` methods in EF Core without proper parameterization, allowing an attacker to inject malicious SQL code. This is the most direct and dangerous way to exploit SQL injection in EF Core.
*   **Likelihood:** High
*   **Impact:** Very High
*   **Effort:** Very Low
*   **Skill Level:** Intermediate
*   **Detection Difficulty:** Medium

## Attack Tree Path: [1.1.1 FromSqlRaw/ExecuteSqlRaw with Untrusted Input [!] (Critical Node)](./attack_tree_paths/1_1_1_fromsqlrawexecutesqlraw_with_untrusted_input__!___critical_node_.md)

*   **Description:** Directly passing user-supplied data, without any sanitization or validation, into the `FromSqlRaw` or `ExecuteSqlRaw` methods. This is the most straightforward form of SQL injection.
*   **Likelihood:** High
*   **Impact:** Very High
*   **Effort:** Very Low
*   **Skill Level:** Intermediate
*   **Detection Difficulty:** Medium
*   **Mitigation:** *Always* use parameterized queries. Never concatenate user input directly into SQL strings. Use the `FormattableString` overload or explicitly create `DbParameter` objects.

## Attack Tree Path: [1.1.2 Untrusted Input to String.Format() (High-Risk Path)](./attack_tree_paths/1_1_2_untrusted_input_to_string_format____high-risk_path_.md)

*   **Description:** Using `String.Format()` or string interpolation with untrusted input to build the SQL query string that is then passed to `FromSqlRaw` or `ExecuteSqlRaw`. This is a common mistake that leads to SQL injection.
*   **Likelihood:** High
*   **Impact:** Very High
*   **Effort:** Very Low
*   **Skill Level:** Intermediate
*   **Detection Difficulty:** Medium
*   **Mitigation:** Avoid using `String.Format()` or string interpolation to build SQL queries. Use parameterized queries instead. If you *must* use string formatting, ensure that *all* user-supplied values are passed as parameters, not directly embedded in the format string.

## Attack Tree Path: [3. Inefficient Query Leading to DoS](./attack_tree_paths/3__inefficient_query_leading_to_dos.md)

*    **Description:** Constructing queries in a way that causes excessive resource consumption on the database server, leading to a denial-of-service condition.

## Attack Tree Path: [3.2 N+1 Problem (High-Risk Path)](./attack_tree_paths/3_2_n+1_problem__high-risk_path_.md)

*   **Description:** Loading a list of entities and then, for each entity, executing a separate query to load related data. This results in a large number of database round trips, significantly degrading performance.
*   **Likelihood:** Very High
*   **Impact:** Medium
*   **Effort:** Very Low
*   **Skill Level:** Novice
*   **Detection Difficulty:** Easy
*   **Mitigation:** Use eager loading with `.Include()` and `.ThenInclude()` to load related data in a single query. Use projection (`Select()`) to retrieve only the necessary data. Use database profiling tools to identify and optimize slow queries.

