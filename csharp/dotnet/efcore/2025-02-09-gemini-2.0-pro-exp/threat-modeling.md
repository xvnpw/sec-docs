# Threat Model Analysis for dotnet/efcore

## Threat: [SQL Injection (via Raw SQL)](./threats/sql_injection__via_raw_sql_.md)

*   **Threat:** SQL Injection (via Raw SQL)

    *   **Description:** An attacker crafts malicious input that, when incorporated into a raw SQL query executed by EF Core's `FromSqlRaw` or `ExecuteSqlRaw` methods (or their interpolated counterparts), alters the query's logic. The attacker can read, modify, or delete data, or potentially execute commands on the database server. This occurs when developers don't properly parameterize raw SQL queries.
    *   **Impact:**
        *   Data breach (confidentiality violation).
        *   Data modification or deletion (integrity violation).
        *   Database server compromise.
        *   Potential for complete system takeover.
    *   **EF Core Component Affected:**
        *   `FromSqlRaw` method.
        *   `ExecuteSqlRaw` method.
        *   `DbSet.FromSqlInterpolated`
        *   `Database.ExecuteSqlInterpolated`
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Primary:** Avoid raw SQL queries. Use LINQ to Entities.
        *   **If unavoidable:** Always use parameterized queries with `FromSqlRaw` and `ExecuteSqlRaw`. Use the `@parameterName` syntax and pass values as separate parameters. *Never* concatenate user input.
        *   Strict input validation and sanitization (defense-in-depth).
        *   Principle of least privilege for the database user.

## Threat: [Inefficient Query-Induced Denial of Service (DoS)](./threats/inefficient_query-induced_denial_of_service__dos_.md)

*   **Threat:** Inefficient Query-Induced Denial of Service (DoS)

    *   **Description:** An attacker sends requests that trigger poorly optimized EF Core LINQ queries. These queries might involve large datasets, complex joins without indexes, or cause N+1 query problems. The goal is to overwhelm the database or application server, making the application unavailable. This is a direct threat because it exploits how EF Core translates LINQ to SQL.
    *   **Impact:**
        *   Application unavailability (denial of service).
        *   Performance degradation.
        *   Increased infrastructure costs.
    *   **EF Core Component Affected:**
        *   Any LINQ to Entities query (especially with `Include`, `ThenInclude`, `Where`, `OrderBy`, `GroupBy`).
        *   Lazy loading (if mismanaged).
        *   `DbContext` (overall query execution).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Optimize LINQ queries:
            *   `AsNoTracking()` when modification is not needed.
            *   Projections (`Select`) for necessary columns only.
            *   Judicious eager loading (`Include`, `ThenInclude`) to avoid N+1.
            *   `Skip` and `Take` for pagination.
        *   Input validation to limit query scope (max results, allowed filters).
        *   Monitor database performance; identify slow queries.
        *   Proper database indexing.
        *   Asynchronous methods (`ToListAsync`, `SaveChangesAsync`).
        *   Consider caching.

## Threat: [Data Tampering via Tracked Entity Manipulation](./threats/data_tampering_via_tracked_entity_manipulation.md)

*   **Threat:** Data Tampering via Tracked Entity Manipulation

    *   **Description:** An attacker gains access to the EF Core `DbContext` or tracked entities and modifies their properties *before* `SaveChanges` is called. This bypasses intended validation if it's only performed before attaching entities. This is a direct threat because it targets EF Core's change tracking mechanism.
    *   **Impact:**
        *   Data corruption (integrity violation).
        *   Unauthorized data modification.
        *   Bypass of business rules.
    *   **EF Core Component Affected:**
        *   `DbContext` and its `ChangeTracker`.
        *   Tracked entities.
        *   `SaveChanges` and `SaveChangesAsync` methods.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Don't expose `DbContext` or tracked entities to untrusted code. Use DTOs/ViewModels.
        *   Input validation and business rule checks *before* attaching entities *and* before modifying tracked entities.
        *   `AsNoTracking()` for read-only data.
        *   Unit of Work pattern to manage `DbContext` lifecycle.
        *   Optimistic concurrency control.

## Threat: [Unauthorized Data Access via Key Manipulation](./threats/unauthorized_data_access_via_key_manipulation.md)

*   **Threat:** Unauthorized Data Access via Key Manipulation

    *   **Description:**  An attacker manipulates client-provided primary or foreign keys to access data they shouldn't. This exploits scenarios where authorization is done *before* EF Core retrieves data, relying solely on the provided keys.  The *direct* EF Core aspect is that the attacker is manipulating inputs to EF Core's data retrieval methods.
    *   **Impact:**
        *   Data breach (confidentiality violation).
        *   Unauthorized data modification (integrity violation).
        *   Bypass of access controls.
    *   **EF Core Component Affected:**
        *   Any query retrieving data based on user-provided keys (e.g., `Find`, `FirstOrDefault`, LINQ queries with `Where`).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Robust authorization checks *after* EF Core retrieves data. Verify the user has permission to access the *retrieved* entities.
        *   Validate all input, especially IDs and foreign keys.
        *   Consider a dedicated authorization library/framework.

