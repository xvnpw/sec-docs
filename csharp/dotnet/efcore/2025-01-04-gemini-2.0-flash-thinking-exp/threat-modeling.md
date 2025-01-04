# Threat Model Analysis for dotnet/efcore

## Threat: [SQL Injection via Raw SQL or Interpolated Strings](./threats/sql_injection_via_raw_sql_or_interpolated_strings.md)

*   **Description:** An attacker could inject malicious SQL code by manipulating user input that is directly incorporated into raw SQL queries using methods like `FromSqlRaw` or string interpolation within LINQ queries. The attacker could craft input that, when concatenated into the SQL query, executes unintended commands. This directly leverages EF Core's ability to execute raw SQL.
    *   **Impact:**  Unauthorized data access, modification, or deletion. Potential for privilege escalation within the database, allowing the attacker to execute administrative commands or access sensitive data beyond the application's intended scope.
    *   **Affected EF Core Component:**  `Microsoft.EntityFrameworkCore.Relational` namespace, specifically the `FromSqlRaw`, `ExecuteSqlRaw`, and methods that allow string interpolation in queries.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Always use parameterized queries:** Utilize `FromSqlInterpolated` or `ExecuteSqlInterpolated` which automatically handle parameterization.
        *   **Avoid string concatenation for building SQL queries:**  Rely on LINQ methods which inherently parameterize inputs.

## Threat: [Information Disclosure through Insecure Query Construction](./threats/information_disclosure_through_insecure_query_construction.md)

*   **Description:** An attacker might exploit poorly designed LINQ queries that unintentionally expose more data than necessary. This could happen due to missing filters, incorrect join conditions, or the retrieval of sensitive columns that are not intended for the user. The attacker could craft requests that trigger these queries, revealing confidential information through EF Core's query execution.
    *   **Impact:** Exposure of sensitive data to unauthorized users, potentially leading to privacy violations, compliance breaches, and reputational damage.
    *   **Affected EF Core Component:** `Microsoft.EntityFrameworkCore.Query` namespace, specifically the query translation and execution pipeline. The way LINQ expressions are translated into SQL.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Carefully review and test all queries:** Pay close attention to filtering and join conditions, especially when dealing with sensitive data.
        *   **Utilize projection (`Select`)**: Retrieve only the necessary data to minimize the risk of accidental information disclosure.
        *   **Consider query filters:** Implement global query filters to automatically apply authorization rules to queries.

## Threat: [Malicious Migrations](./threats/malicious_migrations.md)

*   **Description:** An attacker who gains unauthorized access to the development or deployment pipeline could potentially inject malicious code into EF Core migration scripts. These scripts are executed by EF Core with database administrator privileges and could be used to alter the database schema in harmful ways, insert malicious data, or even execute arbitrary commands on the database server through EF Core's migration functionality.
    *   **Impact:** Data corruption, data loss, backdoors in the database, denial of service, potential for complete database takeover.
    *   **Affected EF Core Component:** `Microsoft.EntityFrameworkCore.Migrations` namespace, specifically the migration generation and application processes.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Secure the development and deployment pipeline:** Implement strong authentication and authorization controls for accessing and modifying migration scripts.
        *   **Code review migration scripts:** Thoroughly review all migration scripts before applying them to production environments.
        *   **Automate migration deployments securely:** Use automated deployment tools with proper security controls.
        *   **Implement change tracking for migration scripts:** Maintain a history of changes to migration scripts.

