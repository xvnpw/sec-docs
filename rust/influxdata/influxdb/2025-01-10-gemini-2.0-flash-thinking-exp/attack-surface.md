# Attack Surface Analysis for influxdata/influxdb

## Attack Surface: [Unauthenticated/Weakly Authenticated Write Endpoints](./attack_surfaces/unauthenticatedweakly_authenticated_write_endpoints.md)

**Description:**  InfluxDB's HTTP API for writing data is exposed without proper authentication mechanisms or with easily guessable/default credentials.

**How InfluxDB Contributes:** InfluxDB provides an HTTP API for data ingestion, and if not configured securely, this entry point is directly vulnerable.

**Example:** An attacker finds an open port (8086 by default) on a server running InfluxDB and uses `curl` to send arbitrary data points without needing credentials.

**Impact:** Data corruption, resource exhaustion (DoS), misleading analytics, potential for further system compromise if the attacker can insert data that triggers application vulnerabilities.

**Risk Severity:** Critical

**Mitigation Strategies:**
*   Enable and enforce authentication for the write API.
*   Use strong, unique credentials and rotate them regularly.
*   Restrict access to the write API using firewall rules or network segmentation.
*   Consider using TLS for all communication.

## Attack Surface: [InfluxQL/Flux Injection via Write/Query Endpoints](./attack_surfaces/influxqlflux_injection_via_writequery_endpoints.md)

**Description:**  The application constructs InfluxQL or Flux queries dynamically based on user input without proper sanitization, allowing attackers to inject malicious code.

**How InfluxDB Contributes:** InfluxDB uses InfluxQL and Flux as query languages, which, if not handled carefully, can be susceptible to injection attacks similar to SQL injection.

**Example:** A dashboard application takes a user-provided tag value and directly inserts it into an InfluxQL query like `SELECT * FROM measurements WHERE tag='userInput'`. An attacker could input `' OR '1'='1'` to bypass the intended filtering.

**Impact:** Data exfiltration, data modification or deletion, potential for denial of service by crafting resource-intensive queries, and in some cases, the ability to execute arbitrary commands on the database server (though less common than with traditional SQL).

**Risk Severity:** High

**Mitigation Strategies:**
*   **Use parameterized queries:**  This is the most effective way to prevent injection.
*   Implement input validation and sanitization on all user-provided data before incorporating it into InfluxQL/Flux queries.
*   Apply the principle of least privilege to database users, limiting their ability to execute destructive commands.

## Attack Surface: [Unauthenticated/Weakly Authenticated Read Endpoints](./attack_surfaces/unauthenticatedweakly_authenticated_read_endpoints.md)

**Description:** InfluxDB's HTTP API for querying data is exposed without proper authentication or with weak credentials.

**How InfluxDB Contributes:** InfluxDB provides an HTTP API for retrieving data, and unsecured access exposes sensitive time-series data.

**Example:** An attacker accesses the InfluxDB query API endpoint (e.g., `/query`) without needing credentials and retrieves sensitive metrics or business data.

**Impact:** Unauthorized access to sensitive data, potential for data breaches, and exposure of business-critical information.

**Risk Severity:** High

**Mitigation Strategies:**
*   Enable and enforce authentication for the query API.
*   Use strong, unique credentials and rotate them regularly.
*   Restrict access to the query API using firewall rules or network segmentation.
*   Consider using TLS for all communication.

## Attack Surface: [Exposure of InfluxDB Ports](./attack_surfaces/exposure_of_influxdb_ports.md)

**Description:** InfluxDB's default ports (e.g., 8086 for HTTP API, 8088 for the admin UI in older versions) are left open to the public internet without proper firewall restrictions.

**How InfluxDB Contributes:** InfluxDB, by design, listens on specific network ports for communication. Leaving these open widens the attack surface.

**Example:** A security scan reveals that port 8086 is open on a publicly accessible server running InfluxDB, allowing anyone on the internet to potentially interact with the API (depending on authentication).

**Impact:** Increased likelihood of exploitation of other vulnerabilities, potential for brute-force attacks on authentication, and unauthorized access to the database.

**Risk Severity:** High

**Mitigation Strategies:**
*   Implement strict firewall rules to allow access to InfluxDB ports only from trusted sources (e.g., the application server).
*   Use network segmentation to isolate the InfluxDB instance.
*   Avoid exposing InfluxDB directly to the public internet.

## Attack Surface: [Default Credentials](./attack_surfaces/default_credentials.md)

**Description:** The default administrative credentials for InfluxDB (if any exist or are easily guessable) are not changed after installation.

**How InfluxDB Contributes:**  Like many systems, InfluxDB might have default credentials that attackers are aware of.

**Example:** An attacker attempts to log in to the InfluxDB admin UI or API using common default usernames and passwords.

**Impact:** Complete compromise of the InfluxDB instance, allowing attackers to read, write, modify, or delete data, and potentially gain control of the underlying server.

**Risk Severity:** Critical

**Mitigation Strategies:**
*   Immediately change all default credentials upon installation.
*   Enforce strong password policies for all InfluxDB users.

