# Attack Surface Analysis for mysql/mysql

## Attack Surface: [Network Exposure](./attack_surfaces/network_exposure.md)

*   **Description:** Direct, unrestricted network access to the MySQL server.
*   **MySQL Contribution:** MySQL listens on a network port (default 3306) for client connections. Improperly configured firewalls or network settings can expose this port.
*   **Example:** An attacker scans for open port 3306 and finds the MySQL server exposed.
*   **Impact:** Unauthorized access, data breaches, data modification, denial of service.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Users:** Configure firewalls to allow connections *only* from trusted hosts.
    *   **Users:** Use a VPN or bastion host for administrative access.
    *   **Users:** Change the default MySQL port (3306).
    *   **Users:** Disable remote access if not necessary (set `bind-address` to `127.0.0.1`).

## Attack Surface: [Weak Authentication](./attack_surfaces/weak_authentication.md)

*   **Description:** Use of weak passwords, default credentials, or outdated authentication.
*   **MySQL Contribution:** MySQL provides authentication, and its strength depends on configuration and password policies.
*   **Example:** An attacker uses a dictionary attack to guess the `root` user's weak password.
*   **Impact:** Unauthorized access, data breaches, data modification, privilege escalation.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Users:** Enforce strong password policies.
    *   **Users:** Use strong authentication plugins like `caching_sha2_password` or `ed25519`.
    *   **Users:** Disable or rename the default `root` account.
    *   **Users:** Implement multi-factor authentication (MFA) where possible.
    *   **Users:** Regularly audit user accounts and privileges.

## Attack Surface: [Overly Permissive Privileges](./attack_surfaces/overly_permissive_privileges.md)

*   **Description:** Granting users more database privileges than needed.
*   **MySQL Contribution:** MySQL's privilege system allows fine-grained control, but misconfiguration can lead to excessive privileges.
*   **Example:** An application user has `SELECT` access to all databases.
*   **Impact:** Increased damage from compromised accounts, easier privilege escalation, data breaches.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Users:** Adhere to the principle of least privilege.
    *   **Users:** Create specific user accounts and grant only necessary privileges.
    *   **Users:** Avoid using `GRANT OPTION`.
    *   **Users:** Regularly review and audit user privileges.

## Attack Surface: [Unencrypted Connections](./attack_surfaces/unencrypted_connections.md)

*   **Description:** Data transmitted between client and server without encryption.
*   **MySQL Contribution:** MySQL supports both encrypted (TLS/SSL) and unencrypted connections; the default may not enforce encryption.
*   **Example:** An attacker performs a MITM attack on an unencrypted connection.
*   **Impact:** Interception of credentials and data, data breaches.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Users:** Enforce TLS/SSL encryption for all connections.
    *   **Users:** Configure MySQL with valid certificates.
    *   **Users:** Use the `REQUIRE SSL` clause in user grants.

## Attack Surface: [SQL Injection (MySQL-Specific)](./attack_surfaces/sql_injection__mysql-specific_.md)

* **Note:** While SQL Injection is primarily application-level vulnerability, I'm including it here because of the *MySQL-Specific* nuances that can be exploited, and because the impact is directly on the database.
*   **Description:** Exploiting vulnerabilities to inject malicious SQL, leveraging MySQL-specific features.
*   **MySQL Contribution:** MySQL's syntax, functions, and character set handling can be abused.
*   **Example:** An attacker uses MySQL comments (`--`) to bypass authentication.
*   **Impact:** Unauthorized access, data modification/deletion, schema manipulation, potential code execution.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *  This is primarily mitigated at application level.

## Attack Surface: [`LOAD DATA INFILE` Abuse](./attack_surfaces/_load_data_infile__abuse.md)

*   **Description:** Exploiting `LOAD DATA INFILE` to read arbitrary files.
*   **MySQL Contribution:** MySQL's `LOAD DATA INFILE` allows loading data from files.
*   **Example:** An attacker injects `LOAD DATA INFILE` to read `/etc/passwd`.
*   **Impact:** Exposure of sensitive system files, potential privilege escalation.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Users:** Restrict the `FILE` privilege.
    *   **Users:** Set `secure_file_priv` to a specific directory.

## Attack Surface: [Outdated MySQL Version](./attack_surfaces/outdated_mysql_version.md)

*   **Description:** Running a MySQL version with known vulnerabilities.
*   **MySQL Contribution:** Older versions may contain security vulnerabilities.
*   **Example:** An attacker exploits a known vulnerability in an outdated version.
*   **Impact:** System compromise, data breaches, data modification, denial of service.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Users:** Keep MySQL up-to-date with the latest stable release and patches.
    *   **Users:** Subscribe to security advisories.
    *   **Users:** Implement a regular patching schedule.

## Attack Surface: [Denial of Service (MySQL-Specific)](./attack_surfaces/denial_of_service__mysql-specific_.md)

*   **Description:** Attacks that exhaust MySQL server resources.
*   **MySQL Contribution:** MySQL has resource limits (connections, memory, threads) that can be targeted.
*   **Example:** An attacker opens many connections, exceeding `max_connections`.
*   **Impact:** Database unavailability, application downtime.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Users:** Configure appropriate resource limits in `my.cnf`.
    *   **Users:** Monitor server resource usage.

