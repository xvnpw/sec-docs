# Attack Surface Analysis for oracle/node-oracledb

## Attack Surface: [SQL Injection](./attack_surfaces/sql_injection.md)

*   **Description:**  Injection of malicious SQL code through user-supplied input that is not properly sanitized or parameterized.  This is the most direct and severe threat when using a database driver.
    *   **node-oracledb Contribution:** `node-oracledb` is the *direct interface* used to execute SQL queries.  Insecure use of this interface (concatenating user input into SQL strings) is the root cause of the vulnerability.
    *   **Example:**
        ```javascript
        // VULNERABLE CODE:
        const userId = req.query.userId; // User-supplied input
        const sql = `SELECT * FROM users WHERE id = ${userId}`;
        connection.execute(sql, [], (err, result) => { ... });
        ```
        Attacker input: `1; DROP TABLE users--`
    *   **Impact:**  Data breach, data modification, data deletion, database server compromise, complete application takeover.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Primary:** *Always* use parameterized queries (bind variables).  `node-oracledb` provides excellent support:
            ```javascript
            // SECURE CODE:
            const userId = req.query.userId;
            const sql = `SELECT * FROM users WHERE id = :userId`; // Named bind variable
            connection.execute(sql, { userId: userId }, (err, result) => { ... });
            ```
        *   **Secondary (Defense in Depth):**  Strict input validation (type, length, format), but *never* as the sole defense.
        *   **Tertiary:**  Consider a well-vetted ORM that *provably* uses parameterized queries.

## Attack Surface: [Credential Exposure](./attack_surfaces/credential_exposure.md)

*   **Description:**  Database credentials needed by `node-oracledb` are stored or transmitted insecurely.
    *   **node-oracledb Contribution:** `node-oracledb` *requires* credentials to connect.  The application's handling of these credentials, directly impacting how `node-oracledb` connects, is the vulnerability.
    *   **Example:**  Hardcoding credentials in the source code:
        ```javascript
        // VULNERABLE CODE:
        const connection = await oracledb.getConnection({
            user: "myuser",
            password: "mypassword", // HARDCODED!
            connectString: "mydbserver:1521/myservice"
        });
        ```
    *   **Impact:**  Unauthorized database access, data breach, data modification, data deletion, potential database server compromise.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Primary:** Use a secure secrets management solution (HashiCorp Vault, AWS Secrets Manager, etc.).
        *   **Secondary:** Use environment variables *carefully* (avoid exposure in logs, child processes).  `.env` files *only* for local development.
        *   **Tertiary:**  Consider Oracle Wallet (if appropriate for the deployment).
        *   **Never:** Commit credentials to version control.

## Attack Surface: [Connection String Injection](./attack_surfaces/connection_string_injection.md)

*   **Description:**  Malicious manipulation of the connection string parameters provided to `node-oracledb`.
    *   **node-oracledb Contribution:** `node-oracledb` *directly uses* the connection string to establish the database connection.  If this string is built from untrusted input, it's a direct vulnerability.
    *   **Example:**  Dynamically constructing the connection string from user input:
        ```javascript
        // VULNERABLE CODE:
        const userProvidedHostname = req.body.hostname; // Untrusted input
        const connectString = `${userProvidedHostname}:1521/myservice`;
        const connection = await oracledb.getConnection({
            user: "myuser",
            password: "mypassword",
            connectString: connectString // Vulnerable
        });
        ```
    *   **Impact:**  Connection to a malicious database, data leakage, potential code execution on the attacker's server.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Primary:**  *Never* construct connection strings dynamically from user input.  Use configuration files or environment variables for *all* connection parameters.
        *   **Secondary:** If absolutely unavoidable, use a strict whitelist of allowed values for *each* parameter.

## Attack Surface: [Unpatched `node-oracledb` or Oracle Instant Client Vulnerabilities](./attack_surfaces/unpatched__node-oracledb__or_oracle_instant_client_vulnerabilities.md)

*   **Description:**  Exploitation of known vulnerabilities in the `node-oracledb` driver itself or the required Oracle Instant Client.
    *   **node-oracledb Contribution:**  The vulnerability exists *directly within* `node-oracledb` or its underlying dependency.
    *   **Example:**  A hypothetical buffer overflow in `node-oracledb`'s LOB handling.
    *   **Impact:**  Varies, but could range from DoS to arbitrary code execution on the application or database server.
    *   **Risk Severity:** High (can be Critical depending on the specific vulnerability)
    *   **Mitigation Strategies:**
        *   **Primary:** Keep `node-oracledb` and the Oracle Instant Client up to date.  Use `npm outdated` or `yarn outdated`.  Subscribe to Oracle security advisories.
        *   **Secondary:** Use a Software Composition Analysis (SCA) tool.

## Attack Surface: [Lack of TLS Encryption](./attack_surfaces/lack_of_tls_encryption.md)

*   **Description:**  Communication between the application and the database server is not encrypted, allowing for eavesdropping.
    *   **node-oracledb Contribution:** `node-oracledb` handles the connection to the database. If TLS is not configured, the connection will be unencrypted.
    *   **Example:** Using a `connectString` with the `tcp` protocol instead of `tcps`.
        ```javascript
        //VULNERABLE
        const connection = await oracledb.getConnection({
            user: "myuser",
            password: "mypassword",
            connectString: "mydbserver:1521/myservice" // Uses TCP, not TCPS
        });
        ```
    *   **Impact:**  Interception of credentials, queries, and data transmitted between the application and the database (Man-in-the-Middle attack).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Primary:** Always use TLS encryption. Configure `node-oracledb` to use a secure connection (TCPS protocol in the `connectString`).
        *   **Secondary:** Configure and verify the database server's certificate to prevent MITM attacks. Use a trusted Certificate Authority (CA).

