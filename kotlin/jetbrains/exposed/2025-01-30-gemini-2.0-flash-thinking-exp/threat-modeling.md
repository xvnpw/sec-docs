# Threat Model Analysis for jetbrains/exposed

## Threat: [SQL Injection via Raw SQL](./threats/sql_injection_via_raw_sql.md)

**Description:** An attacker could inject malicious SQL code by exploiting areas where developers use raw SQL fragments or expressions in Exposed queries without proper parameterization. This could be achieved by manipulating user inputs that are directly concatenated into SQL strings.

**Impact:**
*   Data Breach: Unauthorized access to sensitive data, including reading, modifying, or deleting data.
*   Data Integrity Compromise: Modification or deletion of critical data, leading to data corruption and application malfunction.
*   Account Takeover: Potential to bypass authentication and authorization mechanisms, leading to unauthorized access to user accounts.
*   Code Execution: In severe cases, depending on database permissions and vulnerabilities, attackers might be able to execute arbitrary code on the database server.

**Affected Exposed Component:** `SqlExpressionBuilder`, Custom DSL extensions, Raw SQL fragments.

**Risk Severity:** Critical

**Mitigation Strategies:**
*   **Prioritize DSL:**  Favor Exposed's DSL for query construction over raw SQL.
*   **Parameterization:** Always use parameterized queries and let Exposed handle parameter binding.
*   **Input Validation:** Sanitize and validate all user inputs before using them in queries, even when using the DSL.
*   **Code Review:** Conduct thorough code reviews to identify and eliminate any instances of raw SQL usage or potential injection points in custom DSL extensions.
*   **Static Analysis:** Employ static analysis tools to automatically detect potential SQL injection vulnerabilities.

