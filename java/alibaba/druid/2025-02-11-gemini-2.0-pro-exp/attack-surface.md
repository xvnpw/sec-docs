# Attack Surface Analysis for alibaba/druid

## Attack Surface: [SQL Injection (via Druid Features)](./attack_surfaces/sql_injection__via_druid_features_.md)

*   **Description:**  Execution of unauthorized SQL commands through vulnerabilities in Druid's features or misconfigurations.
    *   **How Druid Contributes:** Druid's SQL Firewall (WallFilter), connection properties (like `connectionInitSqls`), and, to a lesser extent, its StatFilter can be exploited for SQL injection if misconfigured or if vulnerabilities exist within these components. The WebStatFilter, if exposed and vulnerable, could also be an indirect vector.
    *   **Example:** An attacker crafts a malicious SQL query that bypasses a weakly configured WallFilter (e.g., using obscure SQL syntax or exploiting a known WallFilter bypass) and is then executed against the database.  Or, an attacker provides input that is used to construct `connectionInitSqls` without proper sanitization.
    *   **Impact:**  Data breaches (reading sensitive data), data modification (altering or deleting data), database takeover, denial of service (by executing resource-intensive queries), and potentially even remote code execution (depending on the database and its configuration).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Parameterized Queries:** *Always* use parameterized queries (prepared statements) in the application code. This is the primary defense and should *never* be bypassed.  Druid's features are *secondary* defenses.
        *   **Harden WallFilter:** If the WallFilter is used, configure it with strict, well-defined rules.  Regularly review and update these rules.  Do *not* rely solely on the WallFilter.
        *   **Disable Unnecessary Features:** Disable the WebStatFilter, StatFilter, and any other Druid features that are not strictly required.
        *   **Secure WebStatFilter:** If the WebStatFilter *is* used, require strong authentication and authorization, and restrict access to trusted IP addresses.
        *   **Secure `connectionInitSqls`:** Avoid using user-supplied input to construct `connectionInitSqls`. If dynamic SQL is absolutely necessary, use a robust allow-list approach to strictly control the allowed SQL fragments.
        *   **Update Druid:** Regularly update Druid to the latest version to patch known vulnerabilities in its components (WallFilter, etc.).
        *   **Least Privilege:** Ensure the database user account used by Druid has only the minimum necessary privileges.

## Attack Surface: [Denial of Service (DoS) Targeting Druid's Connection Pool](./attack_surfaces/denial_of_service__dos__targeting_druid's_connection_pool.md)

*   **Description:**  Overwhelming Druid's connection pool, making the application unavailable to legitimate users.
    *   **How Druid Contributes:** Druid's core function is connection pooling.  Its configuration parameters directly control its resilience to connection exhaustion attacks.  Misconfiguration or vulnerabilities in Druid's connection handling logic can be exploited.
    *   **Example:** An attacker sends a large number of concurrent requests that require database connections, exceeding Druid's `maxActive` limit and preventing legitimate users from accessing the database.
    *   **Impact:**  Application unavailability, loss of service, potential financial losses.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Connection Pool Tuning:** Carefully configure Druid's connection pool parameters (`maxActive`, `minIdle`, `maxWait`, `removeAbandoned`, `removeAbandonedTimeout`, etc.) to balance performance and resilience against DoS attacks.  This is the *primary* mitigation strategy for this specific attack vector.
        *   **Secure JMX:** If JMX is enabled, secure it with strong authentication and authorization to prevent attackers from manipulating Druid's connection pool configuration.
        *   **Disable Unnecessary Monitoring:** Disable or restrict access to Druid's monitoring features (StatFilter, WebStatFilter) if they are not essential, as they could contribute to resource exhaustion.

