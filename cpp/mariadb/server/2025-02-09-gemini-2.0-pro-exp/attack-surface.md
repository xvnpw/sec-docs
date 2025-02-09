# Attack Surface Analysis for mariadb/server

## Attack Surface: [SQL Injection (Server-Side Execution)](./attack_surfaces/sql_injection__server-side_execution_.md)

*   **Description:**  The server executes malicious SQL code injected by attackers due to application vulnerabilities.  This is a server-side issue because the server's SQL engine is the ultimate target.
*   **Server Contribution:** The server's SQL parser and execution engine are directly responsible for executing the injected code.  The server doesn't inherently prevent SQL injection; it relies on the application to sanitize input.
*   **Example:**  An application fails to parameterize a query, allowing an attacker to inject `' OR '1'='1` to bypass authentication or retrieve all data. The *server* executes this malicious query.
*   **Impact:** Data breaches, data modification, denial of service, potential remote code execution (via UDFs or stored procedures).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **(Server-Side Implication)** While primarily an application-level issue, the server administrator should ensure that any server-side components (stored procedures, functions, triggers, UDFs) are also free of SQL injection vulnerabilities.  Regularly audit these components.  Use `SQL SECURITY INVOKER` where appropriate to limit the privileges of stored routines.

## Attack Surface: [Weak Authentication and Authorization (Server Configuration)](./attack_surfaces/weak_authentication_and_authorization__server_configuration_.md)

*   **Description:**  Weak server-side configurations related to user accounts, passwords, and privileges.
*   **Server Contribution:** The server's authentication and authorization mechanisms (user accounts, grant tables, roles) are directly managed and enforced by the server.
*   **Example:**  The `root` account has a weak or blank password.  A user is granted `ALL PRIVILEGES` globally.  Brute-force attacks succeed against weak passwords.
*   **Impact:** Unauthorized access to the database, data breaches, data modification, denial of service, privilege escalation.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **(User/Admin)** Enforce strong password policies (length, complexity, regular changes) *on the server*.
    *   **(User/Admin)** Disable or rename default accounts (especially `root`) *on the server*.
    *   **(User/Admin)** Implement account lockout policies *on the server* after failed login attempts.
    *   **(User/Admin)** Use multi-factor authentication (MFA) where possible (via server plugins).
    *   **(User/Admin)** Adhere to the principle of least privilege: grant users only the minimum necessary privileges *on the server*. Use specific hostnames/IP addresses in grants.
    *   **(User/Admin)** Regularly audit user accounts, roles, and privileges *on the server*.

## Attack Surface: [Unencrypted Communication (Server Configuration)](./attack_surfaces/unencrypted_communication__server_configuration_.md)

*   **Description:** The server is not configured to require or enforce encrypted connections.
*   **Server Contribution:** The server's network listener configuration determines whether SSL/TLS is required, optional, or disabled.
*   **Example:** The server accepts connections without SSL/TLS, allowing network eavesdropping.
*   **Impact:** Data breaches (eavesdropping), man-in-the-middle attacks.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **(User/Admin)** *Require* SSL/TLS for all remote connections by configuring the server appropriately (e.g., setting `ssl=on` and configuring certificate paths).
    *   **(User/Admin)** Configure the server to use strong ciphers and protocols (e.g., TLS 1.3).
    *   **(User/Admin)** Properly configure and validate server certificates. Use a trusted Certificate Authority (CA).
    *   **(User/Admin)** Regularly update certificates and revoke compromised ones.

## Attack Surface: [Vulnerabilities in User-Defined Functions (UDFs) (Server-Side Code)](./attack_surfaces/vulnerabilities_in_user-defined_functions__udfs___server-side_code_.md)

*   **Description:**  UDFs loaded by the server contain vulnerabilities (e.g., buffer overflows).
*   **Server Contribution:** The server loads and executes the UDF code, making it directly vulnerable to flaws in that code.
*   **Example:**  A UDF with a buffer overflow allows an attacker to inject and execute arbitrary code *on the server*.
*   **Impact:**  Server crashes, remote code execution, privilege escalation.
*   **Risk Severity:** High to Critical
*   **Mitigation Strategies:**
    *   **(User/Admin)** Only use UDFs from trusted sources.
    *   **(Developer/User)** Thoroughly vet the code of any UDF before installing it on the server.
    *   **(User/Admin)** Consider using a sandboxed environment for UDF execution (if available).
    *   **(User/Admin)** Keep MariaDB and any UDFs updated to patch known vulnerabilities.

## Attack Surface: [Misconfigured `LOAD DATA INFILE` (Server Configuration)](./attack_surfaces/misconfigured__load_data_infile___server_configuration_.md)

*   **Description:**  The server's configuration allows unauthorized reading of files from the server's file system.
*   **Server Contribution:** The server's handling of the `LOAD DATA INFILE` statement and the `local_infile` and `secure_file_priv` system variables.
*   **Example:**  `local_infile` is enabled, and an attacker with the `FILE` privilege can read `/etc/passwd`.
*   **Impact:**  Information disclosure, potential privilege escalation.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **(User/Admin)** Disable `LOAD DATA LOCAL INFILE` if not needed (set `local_infile=OFF` in the configuration file).
    *   **(User/Admin)** If required, strictly control the `FILE` privilege and set `secure_file_priv` to a restricted directory.

## Attack Surface: [Unpatched Vulnerabilities (Server Software)](./attack_surfaces/unpatched_vulnerabilities__server_software_.md)

*   **Description:**  Known vulnerabilities in the MariaDB server software itself that have not been addressed.
*   **Server Contribution:** The vulnerability exists within the server's codebase.
*   **Example:**  A publicly disclosed remote code execution vulnerability in a specific MariaDB version.
*   **Impact:** Varies, but can include denial of service, remote code execution, and complete system compromise.
*   **Risk Severity:** Varies (High to Critical) depending on the specific vulnerability.
*   **Mitigation Strategies:**
    * **(User/Admin)** Keep MariaDB server updated to the latest stable release. Apply security patches promptly.
    * **(User/Admin)** Subscribe to MariaDB security announcements.
    * **(User/Admin)** Use a vulnerability scanner to identify unpatched vulnerabilities on the server.

