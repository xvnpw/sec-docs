# Threat Model Analysis for dotnet/efcore

## Threat: [LINQ Injection](./threats/linq_injection.md)

**Description:** An attacker crafts malicious input that is incorporated into a LINQ query through string interpolation or concatenation, bypassing parameterization. This allows the attacker to inject arbitrary SQL commands into the database query executed by EF Core.

**Impact:** Full database compromise, unauthorized data access, data modification, data deletion, denial of service.

**Affected EF Core Component:** `DbContext.Set<T>().FromSqlRaw()`, `DbContext.Set<T>().FromSqlInterpolated()`, LINQ query parsing and execution.

**Risk Severity:** Critical

**Mitigation Strategies:**
*   Always use parameterized queries with LINQ.
*   Avoid string interpolation and concatenation when building dynamic LINQ queries based on user input.
*   Use `FromSqlInterpolated` with extreme caution and only with trusted input. Prefer parameterized versions.
*   Implement robust input validation and sanitization before using any user input in query construction.
*   Conduct regular code reviews and security testing, specifically looking for dynamic query construction.

## Threat: [Raw SQL Injection via `FromSqlRaw`](./threats/raw_sql_injection_via__fromsqlraw_.md)

**Description:** An attacker provides malicious input that is directly embedded into a raw SQL query executed using `FromSqlRaw`. EF Core executes this raw SQL without parameterization, allowing the attacker to execute arbitrary SQL commands.

**Impact:** Full database compromise, unauthorized data access, data modification, data deletion, denial of service.

**Affected EF Core Component:** `DbContext.Set<T>().FromSqlRaw()`.

**Risk Severity:** Critical

**Mitigation Strategies:**
*   Minimize the use of `FromSqlRaw`. Prefer LINQ queries whenever possible.
*   If `FromSqlRaw` is necessary, always parameterize the raw SQL query using placeholders and passing parameters separately.
*   Strictly validate and sanitize all user inputs before incorporating them into raw SQL queries.
*   Apply the principle of least privilege to database user accounts used by the application.

## Threat: [Migration Script Tampering](./threats/migration_script_tampering.md)

**Description:** An attacker compromises the development or deployment pipeline and modifies EF Core migration scripts. Maliciously altered scripts can introduce backdoors, modify data during database updates, or cause database corruption when applied to production.

**Impact:** Database compromise, data corruption, unauthorized data modification, introduction of vulnerabilities, supply chain attack.

**Affected EF Core Component:** Migrations feature, database schema updates, deployment process.

**Risk Severity:** High

**Mitigation Strategies:**
*   Secure the development and deployment pipeline for migration scripts.
*   Use version control for migration scripts and track changes.
*   Conduct code reviews for migration scripts.
*   Implement automated testing of migrations in a staging environment.
*   Restrict access to migration scripts and deployment processes to authorized personnel.
*   Consider using signed migrations if tooling supports it to ensure script integrity.

