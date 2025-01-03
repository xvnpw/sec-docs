# Attack Surface Analysis for taosdata/tdengine

## Attack Surface: [Default Credentials](./attack_surfaces/default_credentials.md)

*   **Description:** TDengine, upon initial installation, has default administrative credentials (typically username `root` and password `taosdata`). If these are not changed, attackers can gain full administrative access.
    *   **How TDengine Contributes to the Attack Surface:** TDengine ships with pre-configured default credentials, making it vulnerable immediately after deployment if no action is taken.
    *   **Example:** An attacker scans for open TDengine ports (e.g., 6030) and attempts to log in using the `root` username and `taosdata` password, gaining complete control over the database.
    *   **Impact:** Full compromise of the TDengine instance, including access to all data, ability to modify or delete data, and potentially disrupt the service.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Immediately change the default password for the `root` user upon initial TDengine setup.
        *   Enforce strong password policies for all TDengine users.
        *   Regularly review and update user credentials.

## Attack Surface: [Unsecured TDengine Listener Ports](./attack_surfaces/unsecured_tdengine_listener_ports.md)

*   **Description:** TDengine listens on specific ports (e.g., 6030 for client connections, 6041 for HTTP RESTful API) by default. If these ports are exposed to untrusted networks without proper access controls, attackers can attempt to connect and exploit vulnerabilities.
    *   **How TDengine Contributes to the Attack Surface:** TDengine's architecture requires these ports for client communication and API access, inherently creating a network entry point.
    *   **Example:** An attacker from the internet can directly connect to the TDengine listener port and attempt brute-force attacks, exploit known vulnerabilities in the TDengine service, or launch denial-of-service attacks.
    *   **Impact:** Unauthorized access to the database, data breaches, denial of service, and potential remote code execution if vulnerabilities exist in the connection handling.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Use firewalls to restrict access to TDengine listener ports to only trusted IP addresses or networks.
        *   Implement network segmentation to isolate the TDengine instance.
        *   Consider using VPNs or other secure tunnels for remote access to TDengine.

## Attack Surface: [TDengine SQL Injection](./attack_surfaces/tdengine_sql_injection.md)

*   **Description:** If application code constructs TDengine SQL queries by directly concatenating user-provided input without proper sanitization or parameterization, attackers can inject malicious SQL code to manipulate the query's logic.
    *   **How TDengine Contributes to the Attack Surface:** TDengine uses a SQL-like query language, making it susceptible to SQL injection vulnerabilities if developers don't follow secure coding practices.
    *   **Example:** An application takes a timeseries name from user input and uses it directly in a query like `SELECT * FROM ${user_input};`. An attacker could input `mytable; DROP DATABASE mydatabase; --` to potentially drop the entire database.
    *   **Impact:** Unauthorized data access, data modification or deletion, potential execution of arbitrary commands within the TDengine context (though less common than in traditional SQL databases).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Always use parameterized queries or prepared statements when interacting with TDengine.
        *   Implement robust input validation and sanitization on all user-provided data before using it in TDengine queries.
        *   Adopt a least privilege approach for database users to limit the impact of successful injection attacks.

