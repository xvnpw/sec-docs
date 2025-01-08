# Threat Model Analysis for doctrine/orm

## Threat: [DQL Injection](./threats/dql_injection.md)

**Description:** An attacker manipulates user input that is directly incorporated into a Doctrine Query Language (DQL) query without proper sanitization or parameterization. This allows the attacker to inject malicious DQL code, potentially bypassing application logic to access, modify, or delete data.

**Impact:** Unauthorized access to data, data manipulation, potential for privilege escalation if the application logic relies on the integrity of the queried data.

**Which https://github.com/doctrine/orm component is affected:** `Doctrine\ORM\EntityManager` (when executing DQL queries), `Doctrine\ORM\QueryBuilder` (if used insecurely).

**Risk Severity:** High

**Mitigation Strategies:**
*   **Always use parameterized queries or the QueryBuilder for DQL.** This ensures that user-provided data is treated as data, not as executable DQL code.
*   **Never concatenate user input directly into DQL strings.**
*   Implement input validation to ensure that user-provided data conforms to expected formats and types.

## Threat: [SQL Injection via Native Queries](./threats/sql_injection_via_native_queries.md)

**Description:** Even when using Doctrine ORM, applications might execute raw SQL queries using the `EntityManager::getConnection()->executeQuery()` or similar methods. If user input is directly embedded into these raw SQL queries without proper sanitization or parameterization, it can lead to traditional SQL injection vulnerabilities.

**Impact:** Full compromise of the database, allowing the attacker to read, modify, or delete any data. Potential for arbitrary code execution on the database server in some configurations.

**Which https://github.com/doctrine/orm component is affected:** `Doctrine\DBAL\Connection` (when executing native SQL queries).

**Risk Severity:** Critical

**Mitigation Strategies:**
*   **Treat native SQL queries with the same caution as any other SQL interaction.**
*   **Always use parameterized queries or prepared statements when executing native SQL.**
*   Avoid constructing SQL queries by concatenating user input.

