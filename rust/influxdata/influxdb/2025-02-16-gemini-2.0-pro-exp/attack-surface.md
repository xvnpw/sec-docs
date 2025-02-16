# Attack Surface Analysis for influxdata/influxdb

## Attack Surface: [Unauthenticated/Unauthorized API Access](./attack_surfaces/unauthenticatedunauthorized_api_access.md)

*Description:* Direct access to the InfluxDB HTTP API without proper authentication or with overly permissive authorization.
*InfluxDB Contribution:* InfluxDB provides the HTTP API as the primary interface for interaction.  If authentication is disabled or misconfigured, this API becomes a direct, unprotected entry point.
*Example:* An attacker sends a `curl` request to `http://<influxdb_host>:8086/query?q=SHOW DATABASES` without any credentials and receives a list of all databases.
*Impact:* Complete data compromise (read, write, delete), potential denial of service, potential server compromise (depending on vulnerabilities).
*Risk Severity:* **Critical**
*Mitigation Strategies:*
    *   **Enable Authentication:**  *Always* enable authentication in the InfluxDB configuration (`auth-enabled = true`).
    *   **Strong Passwords:**  Enforce strong, unique passwords for all InfluxDB users, especially the administrator.  Change the default admin password *immediately* after installation.
    *   **Principle of Least Privilege:**  Create users with the *minimum* necessary permissions.  Don't grant global write access if a user only needs read access to a specific database.  Use InfluxDB's built-in authorization features.
    *   **Network Segmentation:**  Use firewalls (host-based and network-based) to restrict access to the InfluxDB API port (8086 by default) to only authorized clients.  Do *not* expose the API to the public internet unless absolutely necessary and properly secured.
    *   **Reverse Proxy:**  Use a reverse proxy (Nginx, HAProxy) in front of InfluxDB to handle TLS termination, authentication, and potentially rate limiting.
    *   **Regular Audits:**  Periodically review user accounts and permissions.

## Attack Surface: [InfluxQL Injection](./attack_surfaces/influxql_injection.md)

*Description:* Exploiting vulnerabilities in how InfluxQL queries are constructed, allowing attackers to inject malicious code.
*InfluxDB Contribution:* InfluxDB uses InfluxQL as its query language.  If the application doesn't properly handle user input when building queries *within the application interacting with InfluxDB*, injection is possible. *This is primarily an application-level vulnerability, but InfluxDB is the target.*
*Example:* An application takes a database name as user input and directly concatenates it into a query: `query = "SELECT * FROM " + userInput`.  An attacker provides `"my_database"; DROP DATABASE "other_database"` as input, potentially deleting another database.
*Impact:* Data modification, data deletion, data exfiltration, potential denial of service.
*Risk Severity:* **High**
*Mitigation Strategies:*
    *   **Parameterized Queries:**  *Always* use parameterized queries (prepared statements) provided by your InfluxDB client library.  This is the *primary* defense.
    *   **Input Validation:**  Even with parameterized queries, validate and sanitize *all* user input.
    *   **Least Privilege:**  Ensure the InfluxDB user used by the application has only the necessary permissions.
    *   **Web Application Firewall (WAF):** A WAF can help detect and block common injection patterns (defense in depth).

## Attack Surface: [Denial of Service (DoS) via Resource Exhaustion](./attack_surfaces/denial_of_service__dos__via_resource_exhaustion.md)

*Description:* Overwhelming InfluxDB with requests or data, causing it to become unresponsive.
*InfluxDB Contribution:* InfluxDB, like any database, has resource limits (CPU, memory, disk I/O, network bandwidth).  Exceeding these limits can lead to a DoS. *InfluxDB's resource handling is the direct contributor.*
*Example:*
    *   An attacker sends a massive number of write requests with high-cardinality data.
    *   An attacker submits a complex query that requires scanning a huge amount of data.
    *   An attacker floods the network with requests to the InfluxDB API.
*Impact:* InfluxDB becomes unavailable, disrupting applications.
*Risk Severity:* **High**
*Mitigation Strategies:*
    *   **Rate Limiting:**  Implement rate limiting on the InfluxDB API (reverse proxy or within InfluxDB if supported).
    *   **Query Timeouts:**  Set reasonable timeouts for InfluxQL queries.
    *   **Resource Limits:**  Configure InfluxDB with appropriate resource limits (memory, etc.).
    *   **Data Schema Design:**  Avoid high-cardinality tag keys. Use downsampling and continuous queries.
    *   **Monitoring:**  Continuously monitor InfluxDB's resource usage.
    *   **Circuit Breakers:** Implement circuit breakers in your *application* to prevent cascading failures.

## Attack Surface: [Unencrypted Network Communication](./attack_surfaces/unencrypted_network_communication.md)

*Description:* Data transmitted between clients and InfluxDB in plain text, vulnerable to interception.
*InfluxDB Contribution:* InfluxDB supports both HTTP (unencrypted) and HTTPS (encrypted) communication.  If HTTPS is not enabled, communication is unencrypted. *InfluxDB's configuration options are the direct contributor.*
*Example:* An attacker on the same network uses a packet sniffer to capture InfluxDB API requests and responses.
*Impact:* Data exfiltration (credentials, sensitive data), potential man-in-the-middle attacks.
*Risk Severity:* **High**
*Mitigation Strategies:*
    *   **Enable HTTPS:**  *Always* enable HTTPS (TLS) in the InfluxDB configuration.  Obtain and configure valid SSL/TLS certificates.
    *   **Enforce HTTPS:** Configure your application and any reverse proxies to *only* use HTTPS.
    *   **Certificate Validation:** Ensure your client applications properly validate the InfluxDB server's certificate.

## Attack Surface: [Exploitation of Known Vulnerabilities (CVEs)](./attack_surfaces/exploitation_of_known_vulnerabilities__cves_.md)

*Description:* Attackers leveraging publicly disclosed vulnerabilities in InfluxDB.
*InfluxDB Contribution:* InfluxDB, as software, may have vulnerabilities. These are tracked as CVEs. *The existence of vulnerabilities within InfluxDB's codebase is the direct contribution.*
*Example:* An attacker exploits a known CVE in an older version of InfluxDB to gain remote code execution.
*Impact:* Varies widely. Can range from data exfiltration to complete server compromise.
*Risk Severity:* **High** to **Critical** (depending on the CVE)
*Mitigation Strategies:*
    *   **Patching:**  *Regularly* update InfluxDB to the latest stable version.
    *   **Vulnerability Scanning:** Use vulnerability scanners.
    *   **Monitor CVE Databases:** Regularly check vulnerability databases.

## Attack Surface: [Unsecured Backups](./attack_surfaces/unsecured_backups.md)

*Description:* Backups of the InfluxDB data are stored without proper security, making them vulnerable.
*InfluxDB Contribution:* InfluxDB provides backup and restore functionality. The security of the backup *files* is the responsibility of the user, but the *creation* of those files is a direct function of InfluxDB.
*Example:* Backups are stored on a publicly accessible location without encryption.
*Impact:* Data exfiltration.
*Risk Severity:* **High**
*Mitigation Strategies:*
    *   **Secure Storage:** Store backups in a secure location with restricted access.
    *   **Encryption:** Encrypt backups both in transit and at rest.
    *   **Access Control:** Implement strict access control policies for backup storage.
    *   **Regular Testing:** Regularly test the backup and restore process.

