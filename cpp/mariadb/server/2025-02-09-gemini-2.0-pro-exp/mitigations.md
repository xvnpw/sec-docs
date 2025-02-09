# Mitigation Strategies Analysis for mariadb/server

## Mitigation Strategy: [Plugin Hardening (Server-Side)](./mitigation_strategies/plugin_hardening__server-side_.md)

*   **Mitigation Strategy:**  Minimize Attack Surface via Authentication Plugin Management (Server Configuration).

*   **Description:**
    1.  **Identify Enabled Plugins:** (Server-side) Use the `SHOW PLUGINS;` SQL command (executed on the server) to list all currently active plugins.
    2.  **Determine Necessity:** (Server-side) Evaluate the necessity of each *active* authentication plugin from a *server perspective*. Does the server *require* this plugin for any connected clients?
    3.  **Disable Unnecessary Plugins:** (Server-side) Use the `UNINSTALL PLUGIN plugin_name;` command (executed on the server) to disable unnecessary plugins.
    4.  **Configuration File Verification:** (Server-side) Edit the MariaDB configuration file (e.g., `my.cnf`, `my.ini`) on the server to remove or comment out any `plugin-load-add` directives for disabled plugins.
    5.  **Regular Review:** (Server-side) Schedule periodic reviews (performed by the DBA or server administrator) to re-evaluate plugin necessity.

*   **Threats Mitigated:**
    *   **Authentication Bypass (Severity: Critical):** Server-side vulnerabilities in authentication plugins.
    *   **Privilege Escalation (Severity: High):** Server-side exploitation of plugin vulnerabilities.
    *   **Brute-Force Attacks (Severity: Medium):** Reduces the server's attack surface for plugin-specific brute-forcing.

*   **Impact:** (Same as before, but focused on server-side impact)
    *   **Authentication Bypass:** High - Removes server-side vulnerabilities.
    *   **Privilege Escalation:** High - Reduces server-side exploitation.
    *   **Brute-Force Attacks:** Moderate - Reduces server attack surface.

*   **Currently Implemented:** [ *Server-side implementation status* ]

*   **Missing Implementation:** [ *Server-side missing implementation* ]

## Mitigation Strategy: [User Account Management (Server-Side Enforcement)](./mitigation_strategies/user_account_management__server-side_enforcement_.md)

*   **Mitigation Strategy:**  Enforce Robust Account Lockout and Password Policies (Server Configuration).

*   **Description:**
    1.  **`FAILED_LOGIN_ATTEMPTS`:** (Server-side) Set the `FAILED_LOGIN_ATTEMPTS` variable in the MariaDB configuration file (e.g., `my.cnf`) or using `SET GLOBAL`.
    2.  **`PASSWORD_LOCK_TIME`:** (Server-side) Set the `PASSWORD_LOCK_TIME` variable in the configuration file or using `SET GLOBAL`.
    3.  **`password_history`:** (Server-side) Set the `password_history` variable in the configuration file or using `SET GLOBAL`.
    4.  **`user_lock` Plugin (Optional):** (Server-side) Install and configure the `user_lock` plugin on the server if needed.
    5.  **`password_lifetime`:** (Server-side) Set the `password_lifetime` variable.
    6.  **Monitoring:** (Server-side) Monitor the `mysql.user` table and server logs for locked accounts.

*   **Threats Mitigated:**
    *   **Brute-Force Attacks (Severity: Medium):** Server enforces lockout, hindering brute-forcing.
    *   **Credential Stuffing (Severity: Medium):** Server enforces lockout and password history.
    *   **Account Takeover (Severity: High):** Server limits the attack window.

*   **Impact:** (Server-side enforcement impact)
    *   **Brute-Force Attacks:** High - Server directly blocks attempts.
    *   **Credential Stuffing:** Medium - Server enforces policies.
    *   **Account Takeover:** High - Server provides a critical defense layer.

*   **Currently Implemented:** [ *Server-side implementation status* ]

*   **Missing Implementation:** [ *Server-side missing implementation* ]

## Mitigation Strategy: [`skip-grant-tables` Mitigation (Server Configuration)](./mitigation_strategies/_skip-grant-tables__mitigation__server_configuration_.md)

*   **Mitigation Strategy:**  Eliminate `--skip-grant-tables` Usage (Server Configuration).

*   **Description:**
    1.  **Configuration File Audit:** (Server-side) Inspect the MariaDB configuration files on the server.
    2.  **Startup Script Review:** (Server-side) Examine startup scripts on the server.
    3.  **Emergency Recovery Procedure:** (Server-side) Develop a server-specific recovery procedure *without* `--skip-grant-tables`.
    4.  **Alerting/Monitoring:** (Server-side) Implement server-side monitoring to detect `--skip-grant-tables` usage.

*   **Threats Mitigated:**
    *   **Complete Authentication Bypass (Severity: Critical):** Prevents server-level bypass.

*   **Impact:**
    *   **Complete Authentication Bypass:** Eliminates the risk on the server.

*   **Currently Implemented:** [ *Server-side implementation status* ]

*   **Missing Implementation:** [ *Server-side missing implementation* ]

## Mitigation Strategy: [`old_passwords` Mitigation (Server Configuration)](./mitigation_strategies/_old_passwords__mitigation__server_configuration_.md)

*   **Mitigation Strategy:** Disable Legacy Password Hashing (Server Configuration).

*   **Description:**
    1.  **Configuration File:** (Server-side) Edit the MariaDB configuration file on the server.
    2.  **Locate `old_passwords`:** (Server-side) Find the variable.
    3.  **Set to Secure Value:** (Server-side) Set to `OFF` or `2`.
    4.  **Restart MariaDB:** (Server-side) Restart the server.
    5.  **Verify:** (Server-side) Connect and run `SELECT @@old_passwords;`.
    6. **Update existing passwords:** (Server-side) After changing, update *all* user passwords on the server using `ALTER USER`.

*   **Threats Mitigated:**
    *   **Password Cracking (Severity: High):** Server enforces strong hashing.
    *   **Offline Attacks (Severity: High):** Server stores hashes securely.

*   **Impact:**
    *   **Password Cracking:** Very High - Server uses modern hashing.
    *   **Offline Attacks:** High - Server protects stored hashes.

*   **Currently Implemented:** [ *Server-side implementation status* ]

*   **Missing Implementation:** [ *Server-side missing implementation* ]

## Mitigation Strategy: [Strict `sql_mode` Configuration (Server Configuration)](./mitigation_strategies/strict__sql_mode__configuration__server_configuration_.md)

*   **Mitigation Strategy:** Enforce Strict SQL Mode (Server Configuration).

*   **Description:**
    1.  **Configuration File:** (Server-side) Edit the MariaDB configuration file on the server.
    2.  **Locate `sql_mode`:** (Server-side) Find the variable.
    3.  **Set Strict Values:** (Server-side) Set to a strict combination (e.g., `STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION`).
    4.  **Consider Additional Options:** (Server-side) Evaluate other options.
    5.  **Restart MariaDB:** (Server-side) Restart the server.
    6.  **Testing:** (Application-side, but triggered by server change) Test the application.
    7. **Session-Level Control (Optional):** (Server-side) If needed, allow temporary session-level changes with caution.

*   **Threats Mitigated:**
    *   **SQL Injection (Severity: Medium):** Server-side enforcement of stricter rules.
    *   **Data Corruption (Severity: Medium):** Server prevents invalid data insertion.
    *   **Logic Errors (Severity: Low):** Server helps catch errors.

*   **Impact:**
    *   **SQL Injection:** Moderate - Server provides an additional layer.
    *   **Data Corruption:** High - Server ensures data integrity.
    *   **Logic Errors:** Low to Moderate - Server helps identify issues.

*   **Currently Implemented:** [ *Server-side implementation status* ]

*   **Missing Implementation:** [ *Server-side missing implementation* ]

## Mitigation Strategy: [Strong TLS/SSL Configuration (Server Configuration)](./mitigation_strategies/strong_tlsssl_configuration__server_configuration_.md)

*   **Mitigation Strategy:** Enforce Strong TLS/SSL for Encrypted Connections (Server Configuration).

*   **Description:**
    1.  **Certificate and Key Files:** (Server-side) Obtain valid TLS/SSL certificates and private keys. Place them in a secure location on the server.
    2.  **Configuration File:** (Server-side) Edit the MariaDB configuration file (e.g., `my.cnf`, `my.ini`).
    3.  **TLS/SSL Options:** (Server-side) Configure the following options (in the `[mysqld]` section):
        *   `ssl_ca`: Path to the Certificate Authority (CA) certificate file.
        *   `ssl_cert`: Path to the server's certificate file.
        *   `ssl_key`: Path to the server's private key file.
        *   `ssl_cipher`:  Specify a list of *strong* cipher suites.  Consult resources like the Mozilla SSL Configuration Generator for recommended ciphers.  Regularly update this list.  Example: `ssl_cipher = 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256'` (This is just an example; use a current, recommended list).
        *   `tls_version`:  Specify allowed TLS versions.  Example: `tls_version = TLSv1.2,TLSv1.3` (Disable older versions like TLSv1.0 and TLSv1.1).
        *   `require_secure_transport`: Set to `ON` to *require* TLS/SSL for all client connections.
    4.  **File Permissions:** (Server-side) Ensure the private key file (`ssl_key`) has very restrictive permissions (e.g., readable only by the MariaDB user).
    5.  **Restart MariaDB:** (Server-side) Restart the server.
    6.  **Verification:** (Server-side) Use tools like `openssl s_client` to connect to the server and verify the TLS/SSL configuration (cipher suite, certificate validity, etc.).
    7. **Client Certificate Verification (Optional):** (Server-side) If requiring client certificates, configure `ssl_client_ca` and set `ssl_verify_server_cert` to `ON`.

*   **Threats Mitigated:**
    *   **Man-in-the-Middle (MitM) Attacks (Severity: High):**  Ensures encrypted communication, preventing eavesdropping and data tampering.
    *   **Data Breaches (Severity: High):**  Protects sensitive data transmitted between the client and server.
    *   **Impersonation (Severity: High):**  Validates the server's identity to the client (and optionally, the client's identity to the server).

*   **Impact:**
    *   **MitM Attacks:** High - Prevents eavesdropping and tampering.
    *   **Data Breaches:** High - Protects data in transit.
    *   **Impersonation:** High - Ensures server (and optionally client) authenticity.

*   **Currently Implemented:** [ *Server-side implementation status* ]

*   **Missing Implementation:** [ *Server-side missing implementation* ]

## Mitigation Strategy: [Connection Limits (Server Configuration)](./mitigation_strategies/connection_limits__server_configuration_.md)

*   **Mitigation Strategy:**  Configure Connection Limits to Prevent Resource Exhaustion (Server Configuration).

*   **Description:**
    1.  **Configuration File:** (Server-side) Edit the MariaDB configuration file.
    2.  **`max_connections`:** (Server-side) Set the maximum number of simultaneous client connections allowed.  This should be based on your server's resources and expected workload.  Start with a reasonable value and adjust as needed.
    3.  **`max_user_connections`:** (Server-side) Set the maximum number of simultaneous connections allowed *per user*.  This prevents a single user from monopolizing server resources.
    4.  **`max_connect_errors`:** (Server-side) Set the maximum number of consecutive connection errors allowed from a single host before the host is blocked.  This helps mitigate brute-force attacks.
    5.  **Monitoring:** (Server-side) Regularly monitor connection usage (e.g., using `SHOW STATUS LIKE 'Threads_connected';`) and adjust limits as needed.

*   **Threats Mitigated:**
    *   **Denial of Service (DoS) (Severity: Medium):**  Prevents attackers from overwhelming the server with connection requests.
    *   **Resource Exhaustion (Severity: Medium):**  Limits resource consumption by individual users or connections.
    *   **Brute-Force Attacks (Severity: Medium):**  `max_connect_errors` helps block brute-force attempts.

*   **Impact:**
    *   **DoS:** Medium to High - Limits the impact of connection-based DoS attacks.
    *   **Resource Exhaustion:** Medium - Prevents resource starvation.
    *   **Brute-Force Attacks:** Moderate - `max_connect_errors` provides some protection.

*   **Currently Implemented:** [ *Server-side implementation status* ]

*   **Missing Implementation:** [ *Server-side missing implementation* ]

## Mitigation Strategy: [Query Timeouts and Resource Limits (Server Configuration)](./mitigation_strategies/query_timeouts_and_resource_limits__server_configuration_.md)

*   **Mitigation Strategy:**  Implement Timeouts and Resource Limits to Prevent Query-Based DoS (Server Configuration).

*   **Description:**
    1.  **Configuration File:** (Server-side) Edit the MariaDB configuration file.
    2.  **`max_execution_time`:** (Server-side) Set the maximum execution time (in milliseconds) for `SELECT` statements.  This prevents long-running queries from consuming resources indefinitely.
    3.  **`wait_timeout`:** (Server-side) Set the number of seconds the server waits for activity on a *non-interactive* connection before closing it.
    4.  **`interactive_timeout`:** (Server-side) Set the number of seconds the server waits for activity on an *interactive* connection before closing it.
    5.  **Resource Groups (Optional, Advanced):** (Server-side) If using MariaDB 10.4 or later, consider using resource groups to assign different resource limits (CPU, memory) to different users or groups of connections. This provides finer-grained control.
    6. **Monitoring:** (Server-side) Monitor query execution times and resource usage.

*   **Threats Mitigated:**
    *   **Denial of Service (DoS) (Severity: Medium):**  Prevents attackers from using long-running or resource-intensive queries to cause DoS.
    *   **Resource Exhaustion (Severity: Medium):**  Limits the resources consumed by individual queries.

*   **Impact:**
    *   **DoS:** Medium to High - Limits the impact of query-based DoS attacks.
    *   **Resource Exhaustion:** Medium - Prevents resource starvation by individual queries.

*   **Currently Implemented:** [ *Server-side implementation status* ]

*   **Missing Implementation:** [ *Server-side missing implementation* ]

## Mitigation Strategy: [Thread Pool Configuration (If Applicable) (Server Configuration)](./mitigation_strategies/thread_pool_configuration__if_applicable___server_configuration_.md)

*   **Mitigation Strategy:**  Optimize Thread Pool Configuration for Performance and Stability (Server Configuration).

*   **Description:** (Only applicable if using the thread pool feature)
    1.  **Determine if Thread Pool is Enabled:** (Server-side) Check if the `thread_handling` variable is set to `pool-of-threads`.
    2.  **Configuration File:** (Server-side) Edit the MariaDB configuration file.
    3.  **`thread_pool_size`:** (Server-side) Set the number of thread groups in the pool.  This should be based on the number of CPU cores and expected workload.
    4.  **`thread_pool_max_threads`:** (Server-side) Set the maximum number of threads allowed in the pool.
    5.  **`thread_pool_idle_timeout`:** (Server-side) Set the time (in seconds) before an idle thread is removed from the pool.
    6.  **Monitoring:** (Server-side) Monitor thread pool statistics (e.g., using `SHOW STATUS LIKE 'Threadpool%';`) to ensure it's configured optimally.

*   **Threats Mitigated:**
    *   **Denial of Service (DoS) (Severity: Low to Medium):**  Improper thread pool configuration can lead to performance degradation and potential DoS.
    *   **Performance Degradation (Severity: Low to Medium):**  Optimizing the thread pool improves server performance and responsiveness.

*   **Impact:**
    *   **DoS:** Low to Medium - Prevents thread exhaustion and performance issues.
    *   **Performance Degradation:** Low to Medium - Improves server responsiveness.

*   **Currently Implemented:** [ *Server-side implementation status* ]

*   **Missing Implementation:** [ *Server-side missing implementation* ]

## Mitigation Strategy: [Audit Plugin for Suspicious Activity (Server Configuration)](./mitigation_strategies/audit_plugin_for_suspicious_activity__server_configuration_.md)

*   **Mitigation Strategy:**  Enable and Configure the MariaDB Audit Plugin for Security Monitoring (Server Configuration).

*   **Description:**
    1.  **Installation:** (Server-side) If not already installed, install the MariaDB Audit Plugin (usually `server_audit.so` or similar).
    2.  **Configuration File:** (Server-side) Edit the MariaDB configuration file.
    3.  **Enable the Plugin:** (Server-side) Add the necessary options to load and configure the plugin.  Consult the MariaDB documentation for the specific options for your version.  Common options include:
        *   `server_audit_logging`: Set to `ON` to enable logging.
        *   `server_audit_events`:  Specify the types of events to log (e.g., `CONNECT`, `QUERY`, `TABLE`).
        *   `server_audit_file_path`:  Specify the path to the audit log file.
        *   `server_audit_file_rotate_size`: Set the maximum size of the audit log file before it's rotated.
        *   `server_audit_file_rotations`: Set the number of rotated log files to keep.
    4.  **Restart MariaDB:** (Server-side) Restart the server.
    5.  **Monitoring:** (Server-side) Regularly review the audit log file for suspicious activity.  Consider using log analysis tools to automate this process.

*   **Threats Mitigated:**
    *   **Various (Severity: Varies):**  Provides an audit trail for security investigations and helps detect suspicious activity.  The specific threats mitigated depend on the events being logged.  Examples include:
        *   **Unauthorized Access Attempts:** Log failed login attempts.
        *   **Data Breaches:** Log access to sensitive tables.
        *   **Malicious Queries:** Log suspicious SQL statements.
        *   **Configuration Changes:** Log changes to server configuration.

*   **Impact:**
    *   **Detection and Investigation:** High - Provides valuable information for security analysis and incident response.
    *   **Prevention:** Indirect - Helps identify vulnerabilities and attack patterns, allowing for proactive mitigation.

*   **Currently Implemented:** [ *Server-side implementation status* ]

*   **Missing Implementation:** [ *Server-side missing implementation* ]

## Mitigation Strategy: [General Data Directory Security (Server-Side OS Configuration)](./mitigation_strategies/general_data_directory_security__server-side_os_configuration_.md)

*   **Mitigation Strategy:**  Secure the MariaDB Data Directory with Strict File System Permissions (Operating System Level).

*   **Description:**
    1.  **Identify Data Directory:** (Server-side) Determine the location of the MariaDB data directory (usually `/var/lib/mysql` or similar).
    2.  **Operating System Commands:** (Server-side) Use operating system commands (e.g., `chown`, `chmod` on Linux/Unix) to set the correct ownership and permissions.
        *   **Ownership:** The data directory and all its contents should be owned by the MariaDB user (usually `mysql`) and group (usually `mysql`).
        *   **Permissions:**  The directory should have permissions set to `700` (read, write, and execute for the owner only).  Files within the directory should typically have permissions set to `600` (read and write for the owner only).
    3.  **Verification:** (Server-side) Use `ls -l` (or equivalent) to verify the permissions.
    4.  **Regular Audits:** (Server-side) Periodically check the permissions to ensure they haven't been changed.

*   **Threats Mitigated:**
    *   **Unauthorized Data Access (Severity: Critical):**  Prevents unauthorized users (on the server's operating system) from directly accessing the database files.
    *   **Data Tampering (Severity: High):**  Prevents unauthorized modification of the database files.

*   **Impact:**
    *   **Unauthorized Data Access:** High - Prevents direct file access.
    *   **Data Tampering:** High - Prevents direct file modification.

*   **Currently Implemented:** [ *Server-side implementation status* ]

*   **Missing Implementation:** [ *Server-side missing implementation* ]

## Mitigation Strategy: [Binary Log Security (If Enabled) (Server Configuration)](./mitigation_strategies/binary_log_security__if_enabled___server_configuration_.md)

*   **Mitigation Strategy:**  Protect Binary Log Files (Server Configuration and OS Configuration).

*   **Description:** (Only applicable if binary logging is enabled)
    1.  **Determine if Enabled:** (Server-side) Check the `log_bin` variable.
    2.  **Configuration File:** (Server-side) Edit the MariaDB configuration file.
    3.  **`log_bin`:** (Server-side) Ensure binary logging is enabled if required (for replication, point-in-time recovery, etc.).
    4.  **`log_bin_index`:** (Server-side) Specifies the index file for binary logs.
    5.  **File Permissions:** (Server-side, OS-level) Set strict file system permissions on the binary log files and the index file (similar to the data directory – owned by the MariaDB user, with limited access).
    6.  **Encryption (Optional):** (Server-side) Consider enabling binary log encryption (`binlog_encryption`) if the logs contain sensitive data.
    7.  **Rotation and Deletion:** (Server-side) Configure a secure rotation and deletion policy for binary logs (e.g., using `expire_logs_days`).
    8. **Monitoring:** Regularly check disk space usage related to binary logs.

*   **Threats Mitigated:**
    *   **Data Exposure (Severity: Medium to High):**  Protects sensitive data that might be present in the binary logs (e.g., executed SQL statements).
    *   **Unauthorized Access (Severity: Medium):**  Prevents unauthorized users from reading the binary logs.

*   **Impact:**
    *   **Data Exposure:** Medium to High - Reduces the risk of sensitive data leakage.
    *   **Unauthorized Access:** Medium - Prevents unauthorized access to log data.

*   **Currently Implemented:** [ *Server-side implementation status* ]

*   **Missing Implementation:** [ *Server-side missing implementation* ]

## Mitigation Strategy: [Error Log Security (Server Configuration and OS Configuration)](./mitigation_strategies/error_log_security__server_configuration_and_os_configuration_.md)

*   **Mitigation Strategy:**  Secure the MariaDB Error Log (Server Configuration and OS Configuration).

*   **Description:**
    1.  **Configuration File:** (Server-side) Edit the MariaDB configuration file.
    2.  **`log_error`:** (Server-side) Specifies the path to the error log file.
    3.  **File Permissions:** (Server-side, OS-level) Set strict file system permissions on the error log file (similar to the data directory).
    4.  **Content Review:** (Server-side) Regularly review the error log for any signs of security issues or misconfigurations.
    5.  **Avoid Sensitive Data:** (Server-side and Application-side) Ensure that sensitive information (like passwords) is *not* logged to the error log. This often requires careful configuration of both the server and the application.

*   **Threats Mitigated:**
    *   **Information Disclosure (Severity: Low to Medium):**  Prevents unauthorized users from reading the error log, which might contain information useful to an attacker.

*   **Impact:**
    *   **Information Disclosure:** Low to Medium - Reduces the risk of leaking potentially useful information.

*   **Currently Implemented:** [ *Server-side implementation status* ]

*   **Missing Implementation:** [ *Server-side missing implementation* ]

## Mitigation Strategy: [Disable `LOAD DATA LOCAL INFILE` (If Not Needed) (Server Configuration)](./mitigation_strategies/disable__load_data_local_infile___if_not_needed___server_configuration_.md)

*   **Mitigation Strategy:**  Disable `LOAD DATA LOCAL INFILE` to Prevent File Access (Server Configuration).

*   **Description:**
    1.  **Configuration File:** (Server-side) Edit the MariaDB configuration file.
    2.  **`local_infile`:** (Server-side) Set `local_infile=OFF`.
    3.  **Restart MariaDB:** (Server-side) Restart the server.

*   **Threats Mitigated:**
    *   **File Access Vulnerability (Severity: Medium to High):**  Prevents attackers from using `LOAD DATA LOCAL INFILE` to read arbitrary files from the *client's* filesystem.  Note: This is a vulnerability that originates on the *client* side, but the server can disable the feature to prevent exploitation.

*   **Impact:**
    *   **File Access Vulnerability:** High - Eliminates the risk of this specific attack vector.

*   **Currently Implemented:** [ *Server-side implementation status* ]

*   **Missing Implementation:** [ *Server-side missing implementation* ]

## Mitigation Strategy: [Regular Patching and Updates (Server Maintenance)](./mitigation_strategies/regular_patching_and_updates__server_maintenance_.md)

*   **Mitigation Strategy:**  Keep the MariaDB Server Updated (Server Maintenance).

*   **Description:**
    1.  **Subscribe to Announcements:** (Server-side) Subscribe to MariaDB security announcements and mailing lists.
    2.  **Patching Process:** (Server-side) Establish a regular patching process that includes:
        *   Testing patches in a non-production environment.
        *   Scheduling downtime for applying patches to the production server.
        *   Verifying the server's functionality after patching.
    3.  **Version Upgrades:** (Server-side) Plan for and execute major version upgrades when necessary to receive security updates and new features.

*   **Threats Mitigated:**
    *   **Exploitation of Known Vulnerabilities (Severity: Varies, often High or Critical):**  Addresses vulnerabilities that have been publicly disclosed and patched.

*   **Impact:**
    *   **Exploitation of Known Vulnerabilities:** High - The most effective way to protect against known exploits.

*   **Currently Implemented:** [ *Server-side implementation status* ]

*   **Missing Implementation:** [ *Server-side missing implementation* ]

## Mitigation Strategy: [Disable Unnecessary Features (Server Configuration)](./mitigation_strategies/disable_unnecessary_features__server_configuration_.md)

* **Mitigation Strategy:** Reduce Attack Surface by Disabling Unused Server Features.

* **Description:**
    1. **Review Server Configuration:** (Server-side) Examine the MariaDB configuration file and identify any features, plugins, or user-defined functions (UDFs) that are not actively used by your application or required for server operation.
    2. **Disable Unused Components:** (Server-side)
        * **Plugins:** Use `UNINSTALL PLUGIN` to disable unnecessary plugins.
        * **Features:** Comment out or remove configuration options related to unused features (e.g., specific storage engines, networking protocols).
        * **UDFs:** Remove unnecessary UDFs from the `mysql.func` table.
    3. **Restart MariaDB:** (Server-side) Restart the server after making changes.
    4. **Regular Review:** (Server-side) Periodically review the enabled features and disable any that have become unnecessary.

* **Threats Mitigated:**
    * **Exploitation of Vulnerabilities in Unused Components (Severity: Varies):** Reduces the attack surface by removing potential targets for attackers.

* **Impact:**
    * **Exploitation of Vulnerabilities:** Moderate - Reduces the overall risk by minimizing the number of potential vulnerabilities.

* **Currently Implemented:** [ *Server-side implementation status* ]

* **Missing Implementation:** [ *Server-side missing implementation* ]

