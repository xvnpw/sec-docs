# Attack Surface Analysis for graphite-project/graphite-web

## Attack Surface: [Denial of Service (DoS) via Query Overload (`/render`)](./attack_surfaces/denial_of_service__dos__via_query_overload___render__.md)

**Description:** Attackers craft excessively complex or resource-intensive queries targeting the `/render` API endpoint to overwhelm the Graphite-Web server, causing denial of service.  This exploits Graphite-Web's query parsing and processing logic.

**Graphite-Web Contribution:** The `/render` API's flexible query language, including support for wildcards, globbing, nested functions, and large time ranges, allows for queries that can consume excessive CPU, memory, and I/O, *directly* within the Graphite-Web process.

**Example:**
```
/render?target=summarize(timeShift(group(seriesByTag('*=*')), '-1d'), '1d', 'sum')&from=-1000d&until=now
```
(This example uses excessive wildcards and a very large time range, forcing Graphite-Web to process a potentially massive amount of data.)

**Impact:** Service unavailability, impacting all monitoring and alerting capabilities that rely on Graphite-Web.

**Risk Severity:** Critical

**Mitigation Strategies:**
*   **Input Validation (Graphite-Web Specific):** Implement a query parser *within Graphite-Web* that rejects overly complex queries *before* they are executed.  This includes limiting:
    *   The number of wildcards (`*`) and globbing patterns.
    *   The depth of nested function calls.
    *   The maximum time range allowed in a query.
    *   The number of series that can be returned.
*   **Rate Limiting (Graphite-Web Specific):** Implement strict rate limiting per user/IP address for the `/render` API *within Graphite-Web*.  Consider different rate limits based on user roles or query complexity.
*   **Query Timeouts (Graphite-Web Specific):** Enforce strict timeouts for query execution *within Graphite-Web*.
*   **Resource Limits (Process Level):** Configure resource limits (CPU, memory) for the Graphite-Web process to prevent it from consuming all available system resources. This is a general mitigation, but important in this context.
*   **Caching (Graphite-Web Specific):** Implement caching *within Graphite-Web* for frequently accessed data to reduce the load on the backend and the query processing engine.
*   **Monitoring (Graphite-Web Specific):** Monitor query execution times and resource usage *within Graphite-Web* to detect and respond to DoS attempts. Log slow queries and resource-intensive operations.

## Attack Surface: [Path Traversal via Dashboard Loading (`/dashboard/load/<name>`)](./attack_surfaces/path_traversal_via_dashboard_loading___dashboardloadname__.md)

**Description:** Attackers manipulate the dashboard name parameter in the `/dashboard/load/<name>` endpoint, attempting to access arbitrary files on the server where Graphite-Web is running. This directly exploits how Graphite-Web handles dashboard loading.

**Graphite-Web Contribution:** If Graphite-Web uses the provided dashboard name directly in file system operations without proper sanitization or validation, it is vulnerable to path traversal.  The vulnerability lies *within* Graphite-Web's handling of the `/dashboard/load` endpoint.

**Example:**
```
/dashboard/load/../../../../etc/passwd
```

**Impact:** Exposure of sensitive files on the server, including configuration files, potentially leading to further system compromise.

**Risk Severity:** High

**Mitigation Strategies:**
*   **Input Sanitization (Graphite-Web Specific):** *Within Graphite-Web*, strictly sanitize the dashboard name parameter.  Reject any input containing directory traversal characters (`..`, `/`, `\`).  Use a whitelist of allowed characters (e.g., alphanumeric and underscores).
*   **Secure File Handling (Graphite-Web Specific):** *Within Graphite-Web*, store dashboards in a dedicated, restricted directory.  Do *not* use the dashboard name directly as a file path.  Instead, use a mapping (e.g., a database lookup or a safe naming scheme) to associate dashboard names with their actual storage locations.  This prevents direct file system access based on user input.
*   **Least Privilege (Process Level):** Run the Graphite-Web process with the least necessary privileges.  It should *not* have read access to sensitive system files. This is a general mitigation, but crucial in this context.

## Attack Surface: [Stored XSS/Query Injection via Dashboard Content](./attack_surfaces/stored_xssquery_injection_via_dashboard_content.md)

**Description:**  Attackers inject malicious JavaScript or Graphite queries into saved dashboard definitions, which are then executed when other users load the dashboard. This exploits how Graphite-Web stores and renders dashboard content.

**Graphite-Web Contribution:** If Graphite-Web does not properly sanitize dashboard content *before* storing it (e.g., in a database or file system) and *before* rendering it in the user interface, it is vulnerable to stored XSS and potentially malicious query execution. The vulnerability is *within* Graphite-Web's dashboard handling logic.

**Example:** An attacker (who has gained write access to dashboard storage) modifies a dashboard definition to include:
```json
{
  "title": "My Dashboard <img src=x onerror=alert(1)>",
  "targets": [
    { "target": "maliciousFunction(some.metric)" }
  ]
}
```

**Impact:** XSS attacks against other users viewing the dashboard, leading to session hijacking, data theft, or other malicious actions.  Potentially, execution of malicious Graphite queries, leading to DoS or other issues.

**Risk Severity:** High

**Mitigation Strategies:**
*   **Input Sanitization (Graphite-Web Specific):** *Within Graphite-Web*, strictly sanitize all user-provided input *before* saving dashboard definitions.  Escape or remove any potentially dangerous characters or code, specifically targeting HTML and JavaScript.
*   **Output Encoding (Graphite-Web Specific):** *Within Graphite-Web*, when rendering dashboard content, properly encode all data to prevent XSS.  Use a templating engine that automatically handles output encoding, or manually encode data before displaying it.
*   **Content Security Policy (CSP) (Browser-Side):** Implement a strong CSP to restrict the types of content that can be loaded and executed in the browser. This is a browser-side mitigation, but it's crucial for preventing XSS.
*   **Authentication and Authorization (Graphite-Web Specific):** *Within Graphite-Web*, strictly control who can create and modify dashboards. Implement role-based access control to limit the potential impact of a compromised account.

