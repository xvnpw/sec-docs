# Threat Model Analysis for oracle/node-oracledb

## Threat: [SQL Injection via Unsanitized Input](./threats/sql_injection_via_unsanitized_input.md)

*   **Description:** An attacker crafts malicious input that, when incorporated into a SQL query without proper sanitization or parameterization, alters the intended query logic. The attacker might use techniques like adding extra SQL clauses (e.g., `UNION SELECT`, `OR 1=1`), commenting out parts of the query, or injecting commands to be executed. This directly exploits how `node-oracledb` handles query execution if bind variables are *not* used.
    *   **Impact:**
        *   Data exfiltration (reading sensitive data).
        *   Data modification (altering or deleting data).
        *   Privilege escalation (gaining higher database privileges).
        *   Database server compromise (in extreme cases, executing OS commands).
    *   **Affected Component:** Primarily affects functions that execute SQL queries, such as `connection.execute()`, `connection.queryStream()`, and `connection.executeMany()`, when used with string concatenation to build SQL queries instead of bind variables.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Mandatory Use of Bind Variables:** *Always* use parameterized queries (bind variables) for *all* data passed to SQL queries. This is the primary and most effective defense. `node-oracledb` provides excellent support for bind variables.
        *   **Input Validation:** Validate all user-supplied input to ensure it conforms to expected data types, lengths, and formats. This is a secondary defense, *not* a replacement for bind variables.
        *   **Whitelisting:** If possible, use whitelists to restrict input to a known set of safe values.
        *   **Avoid Dynamic SQL Generation:** Minimize or eliminate the dynamic generation of SQL queries based on user input.

## Threat: [Credential Exposure](./threats/credential_exposure.md)

*   **Description:** Database credentials (username, password, connect string) used by `node-oracledb` are exposed to unauthorized individuals. This could happen through various means: hardcoding credentials in source code, storing them in insecure configuration files, exposing them in environment variables that are accessible to unauthorized processes, or leaking them through logging. This directly impacts how `node-oracledb` establishes connections.
    *   **Impact:** Complete database compromise – an attacker can connect to the database with the exposed credentials and perform any action allowed by those credentials.
    *   **Affected Component:** All parts of `node-oracledb` that use database credentials, including `oracledb.getConnection()`, `oracledb.createPool()`, and any functions that implicitly establish a connection.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Never Hardcode Credentials:** Do not store credentials directly in the source code.
        *   **Use Secure Configuration Management:** Use a secure configuration management system (e.g., HashiCorp Vault, AWS Secrets Manager, Azure Key Vault) to store and retrieve credentials.
        *   **Secure Environment Variables:** If using environment variables, ensure they are properly secured and only accessible to the Node.js process.
        *   **Avoid Logging Credentials:** Never log database credentials or connect strings.
        *   **Regular Credential Rotation:** Rotate database credentials regularly.

## Threat: [Unencrypted Database Connection (MitM)](./threats/unencrypted_database_connection__mitm_.md)

*   **Description:** The connection between the Node.js application and the Oracle Database is not encrypted, allowing an attacker to intercept and potentially modify the data in transit (Man-in-the-Middle attack). This directly relates to how `node-oracledb` establishes the network connection.
    *   **Impact:**
        *   Data exfiltration (reading sensitive data in transit).
        *   Data tampering (modifying data in transit).
    *   **Affected Component:** The network connection established by `node-oracledb`. This is influenced by the connect string and the Oracle Database server's configuration, but the *client-side* handling of encryption is within `node-oracledb`.
    *   **Risk Severity:** High (if TLS is not used)
    *   **Mitigation Strategies:**
        *   **Use TLS/SSL:** Ensure that the connection is encrypted using TLS/SSL. This typically involves configuring the Oracle Database server for TLS and using a connect string that specifies encryption (e.g., using `(PROTOCOL=TCPS)`).
        *   **Verify Server Certificate:** Configure `node-oracledb` to verify the database server's certificate to prevent MitM attacks using forged certificates. This can be done using the `sslVerify` option.
        *   **Use Oracle Net Services:** Configure Oracle Net Services to enforce encryption.

## Threat: [Using Outdated or Vulnerable `node-oracledb` Version](./threats/using_outdated_or_vulnerable__node-oracledb__version.md)

* **Description:** The application uses an outdated version of the `node-oracledb` driver that contains known security vulnerabilities.  This is a direct threat to the driver itself.
    * **Impact:** Varies depending on the specific vulnerability, but could range from information disclosure to remote code execution (potentially critical).
    * **Affected Component:** The entire `node-oracledb` module.
    * **Risk Severity:** Varies (High to Critical, depending on the vulnerability)
    * **Mitigation Strategies:**
        * **Regular Updates:** Keep the `node-oracledb` driver up to date with the latest version. Regularly check for updates and apply them promptly.
        * **Dependency Management:** Use a dependency management tool (e.g., npm, yarn) to manage the `node-oracledb` dependency and ensure it's updated regularly.
        * **Vulnerability Scanning:** Use vulnerability scanning tools to identify known vulnerabilities in the application's dependencies, including `node-oracledb`.

