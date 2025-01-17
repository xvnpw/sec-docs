# Attack Surface Analysis for mariadb/server

## Attack Surface: [Weak or Default Credentials](./attack_surfaces/weak_or_default_credentials.md)

*   **Description:** Using easily guessable or default passwords for MariaDB user accounts, especially administrative accounts.
    *   **How Server Contributes:** The server relies on user-provided credentials for authentication. If these are weak, the server's security is compromised.
    *   **Example:** An attacker uses a list of common passwords to attempt to log in as the `root` user or other privileged accounts.
    *   **Impact:** Full compromise of the database server, including access to all data, ability to modify data, and potentially execute operating system commands if UDFs are enabled.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Enforce strong password policies requiring complex passwords and regular password changes.
        *   Disable or rename default administrative accounts if possible.
        *   Implement account lockout policies after multiple failed login attempts.

## Attack Surface: [Exploitable Authentication Protocol Vulnerabilities](./attack_surfaces/exploitable_authentication_protocol_vulnerabilities.md)

*   **Description:**  Vulnerabilities within the MariaDB authentication protocol itself that could allow attackers to bypass authentication.
    *   **How Server Contributes:** The server implements and relies on the authentication protocol for secure connection establishment. Flaws in this implementation are server-specific.
    *   **Example:** A historical vulnerability in the MySQL/MariaDB authentication handshake allowed attackers to potentially guess the password hash through a series of connection attempts.
    *   **Impact:**  Unauthorized access to the database server without knowing valid credentials.
    *   **Risk Severity:** Critical (if actively exploitable vulnerabilities exist)
    *   **Mitigation Strategies:**
        *   Keep the MariaDB server updated to the latest stable version to patch known authentication protocol vulnerabilities.
        *   Consider using more secure authentication plugins if available and appropriate for the environment.

## Attack Surface: [SQL Injection Vulnerabilities within Server Code](./attack_surfaces/sql_injection_vulnerabilities_within_server_code.md)

*   **Description:** While often associated with application code, vulnerabilities can exist within MariaDB's own SQL parsing or execution logic that could be exploited through crafted SQL statements.
    *   **How Server Contributes:** The server is responsible for parsing and executing SQL queries. Bugs in this process can lead to unintended code execution or data access.
    *   **Example:** A specially crafted `SELECT` statement exploiting a parsing vulnerability could allow an attacker to read data they shouldn't have access to, even without direct write privileges.
    *   **Impact:** Data breaches, data manipulation, potential for denial of service.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Keep the MariaDB server updated to patch any identified SQL injection vulnerabilities within the server itself.
        *   While primarily an application concern, be aware of how server-side features like stored procedures or functions might interact with user-supplied input.

## Attack Surface: [Insecure SSL/TLS Configuration](./attack_surfaces/insecure_ssltls_configuration.md)

*   **Description:**  Using outdated or weak TLS versions or cipher suites for encrypted connections to the MariaDB server.
    *   **How Server Contributes:** The server handles the SSL/TLS negotiation and encryption. Insecure configurations expose communication to eavesdropping or man-in-the-middle attacks.
    *   **Example:** An attacker intercepts network traffic and is able to decrypt the communication because the server is using an outdated SSLv3 protocol with known vulnerabilities.
    *   **Impact:**  Exposure of sensitive data transmitted between clients and the server, including credentials and query data.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Configure the MariaDB server to use only strong and current TLS versions (TLS 1.2 or higher).
        *   Disable weak cipher suites.
        *   Regularly update the underlying SSL/TLS libraries used by the server.

## Attack Surface: [Exploitable User-Defined Functions (UDFs)](./attack_surfaces/exploitable_user-defined_functions__udfs_.md)

*   **Description:**  Allowing the creation and execution of User-Defined Functions (UDFs) by untrusted users.
    *   **How Server Contributes:** The server provides the functionality to create and execute UDFs, which are essentially shared libraries loaded into the server process.
    *   **Example:** A malicious user with `CREATE FUNCTION` privileges creates a UDF that executes arbitrary operating system commands on the server.
    *   **Impact:**  Complete compromise of the database server and potentially the underlying operating system.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Restrict the `CREATE FUNCTION` privilege to only trusted administrators.
        *   Carefully review any necessary UDFs for security vulnerabilities before deployment.
        *   Consider disabling UDF functionality if it's not required.

