# Attack Surface Analysis for mysql/mysql

## Attack Surface: [SQL Injection (SQLi)](./attack_surfaces/sql_injection__sqli_.md)

**Description:** Attackers inject malicious SQL code into application queries, manipulating the database.

**How MySQL Contributes:** MySQL's query execution engine directly processes these injected commands if input is not sanitized.

**Example:** A login form where the username field accepts `' OR '1'='1` leading to bypassing authentication.

**Impact:** Data breach, data manipulation, privilege escalation, denial of service.

**Risk Severity:** Critical

**Mitigation Strategies:**
*   **Use Parameterized Queries (Prepared Statements):** Treat user input as data, not executable code.
*   **Implement Input Validation and Sanitization:**  Strictly validate and sanitize all user-provided data before using it in SQL queries.
*   **Principle of Least Privilege:** Grant database users only the necessary permissions.
*   **Use an ORM (Object-Relational Mapper):**  Many ORMs handle query construction securely, reducing the risk of manual SQL injection.

## Attack Surface: [Insecure Storage of Database Credentials](./attack_surfaces/insecure_storage_of_database_credentials.md)

**Description:** Database credentials (username, password) are stored in plaintext or easily reversible formats within the application's configuration or codebase.

**How MySQL Contributes:**  MySQL requires credentials for access, making their secure storage paramount.

**Example:** Credentials hardcoded in a configuration file or stored in a weakly encrypted format.

**Impact:** Full compromise of the database, unauthorized access to sensitive data, potential lateral movement within the infrastructure.

**Risk Severity:** Critical

**Mitigation Strategies:**
*   **Use Environment Variables:** Store credentials as environment variables, managed separately from the application code.
*   **Utilize Secrets Management Systems:** Employ dedicated tools like HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault for secure credential storage and rotation.
*   **Avoid Hardcoding Credentials:** Never embed credentials directly in the application code.
*   **Encrypt Credentials at Rest:** If storing in files, use strong encryption mechanisms.

## Attack Surface: [Exposed MySQL Port (3306) to Public Internet](./attack_surfaces/exposed_mysql_port__3306__to_public_internet.md)

**Description:** The default MySQL port (3306) is accessible from the public internet without proper access controls.

**How MySQL Contributes:** MySQL listens on this port for incoming connections.

**Example:** A firewall rule allowing inbound traffic on port 3306 from any IP address.

**Impact:** Brute-force attacks on MySQL credentials, exploitation of known vulnerabilities in the MySQL server, potential for unauthorized access.

**Risk Severity:** High

**Mitigation Strategies:**
*   **Restrict Access via Firewall Rules:** Only allow connections to port 3306 from trusted IP addresses or within the internal network.
*   **Use a VPN or SSH Tunneling:** Securely tunnel connections to the MySQL server.
*   **Consider Non-Standard Ports (with caution):** While not a primary security measure, changing the default port can deter some automated attacks, but proper access controls are still essential.

## Attack Surface: [Abuse of `LOAD DATA INFILE`](./attack_surfaces/abuse_of__load_data_infile_.md)

**Description:** Attackers exploit the `LOAD DATA INFILE` statement to read arbitrary files from the server's filesystem or potentially execute code if the MySQL server has `FILE` privileges.

**How MySQL Contributes:** MySQL's `LOAD DATA INFILE` functionality, when not properly controlled, can be misused.

**Example:** An application feature allowing users to upload CSV files that are then processed using `LOAD DATA INFILE` without validating the file path or content.

**Impact:** Information disclosure (reading sensitive files), potential remote code execution if MySQL has `FILE` privileges.

**Risk Severity:** High

**Mitigation Strategies:**
*   **Disable `local-infile`:**  Disable the `local-infile` option on the MySQL server if not strictly necessary.
*   **Restrict `FILE` Privileges:**  Avoid granting the `FILE` privilege to database users that don't require it.
*   **Strictly Validate File Paths:** If `LOAD DATA INFILE` is required, ensure the application strictly validates the file paths and sources.
*   **Sanitize File Content:**  Thoroughly sanitize the content of uploaded files before using them with `LOAD DATA INFILE`.

