# Attack Surface Analysis for oracle/node-oracledb

## Attack Surface: [SQL Injection via Unsafe Query Construction](./attack_surfaces/sql_injection_via_unsafe_query_construction.md)

**Description:**  Occurs when user-controlled input is directly embedded into SQL queries without proper sanitization or parameterization. This allows attackers to inject malicious SQL code.
* **How node-oracledb Contributes:** `node-oracledb` provides the `connection.execute()` method, which can be used with dynamically constructed SQL strings. If developers concatenate user input directly into these strings, it creates an entry point for SQL injection.
* **Example:**
```javascript
    const sql = "SELECT * FROM users WHERE username = '" + req.query.username + "'";
    connection.execute(sql);
```
    An attacker could provide `'; DROP TABLE users; --` as the username.
* **Impact:**  Data breaches, data manipulation, unauthorized access, denial of service.
* **Risk Severity:** Critical
* **Mitigation Strategies:**
    * **Always use parameterized queries or prepared statements:** This ensures that user input is treated as data, not executable code. `node-oracledb` supports parameterized queries using bind variables.
    * **Input validation and sanitization:**  Validate and sanitize user input to remove or escape potentially malicious characters before using it in queries (though parameterization is the preferred method).

## Attack Surface: [Exposure of Database Credentials](./attack_surfaces/exposure_of_database_credentials.md)

**Description:** Sensitive database credentials (username, password, connection string) are stored insecurely, making them accessible to attackers.
* **How node-oracledb Contributes:** `node-oracledb` requires connection details to establish a database connection. If these details are hardcoded in the application, stored in easily accessible configuration files without encryption, or exposed through environment variables without proper protection, it creates a vulnerability.
* **Example:**
```javascript
oracledb.getConnection({
  user: 'myuser',
  password: 'mysecretpassword',
  connectString: 'localhost/XE'
});
```
    These credentials might be found in version control or configuration files.
* **Impact:** Unauthorized database access, data breaches, data manipulation.
* **Risk Severity:** Critical
* **Mitigation Strategies:**
    * **Use secure credential management:** Store credentials in secure vaults (e.g., HashiCorp Vault, AWS Secrets Manager, Azure Key Vault) or use environment variables with restricted access.
    * **Avoid hardcoding credentials:** Never directly embed credentials in the application code.
    * **Encrypt configuration files:** If storing credentials in configuration files is unavoidable, encrypt them.
    * **Implement proper access controls:** Limit access to configuration files and environment variables containing credentials.

## Attack Surface: [Dependency Vulnerabilities in node-oracledb and its Dependencies](./attack_surfaces/dependency_vulnerabilities_in_node-oracledb_and_its_dependencies.md)

**Description:** Vulnerabilities exist in `node-oracledb` itself or in its underlying dependencies, including the Oracle Client libraries.
* **How node-oracledb Contributes:** `node-oracledb` relies on native Oracle Client libraries for database interaction. Vulnerabilities in these libraries or in other JavaScript dependencies can be exploited if not patched.
* **Example:** A known vulnerability in a specific version of the Oracle Client library could be exploited if the application uses that version through `node-oracledb`.
* **Impact:**  Remote code execution, denial of service, information disclosure, depending on the specific vulnerability.
* **Risk Severity:** High to Critical (depending on the vulnerability)
* **Mitigation Strategies:**
    * **Regularly update node-oracledb:** Keep `node-oracledb` updated to the latest stable version to benefit from bug fixes and security patches.
    * **Manage dependencies:** Use a package manager (npm or yarn) and regularly audit and update dependencies, including the Oracle Client libraries. Consider using tools like `npm audit` or `yarn audit`.
    * **Monitor for security advisories:** Stay informed about security vulnerabilities affecting `node-oracledb` and its dependencies.

## Attack Surface: [Connection String Injection](./attack_surfaces/connection_string_injection.md)

**Description:**  Parts of the database connection string are dynamically constructed based on user input or external sources without proper validation.
* **How node-oracledb Contributes:** If the application dynamically builds the `connectString` parameter for `oracledb.getConnection()` using untrusted input, attackers might be able to inject malicious connection parameters.
* **Example:**
```javascript
    const connectString = `(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=${req.query.dbHost})(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=mydb)))`;
    oracledb.getConnection({
      user: '...',
      password: '...',
      connectString: connectString
    });
```
    An attacker could manipulate `req.query.dbHost` to point to a malicious database server.
* **Impact:** Connecting to unintended databases, potential man-in-the-middle attacks, data breaches.
* **Risk Severity:** High
* **Mitigation Strategies:**
    * **Avoid dynamic construction of connection strings:** If possible, use a fixed and securely stored connection string.
    * **Strict input validation:** If dynamic construction is necessary, rigorously validate and sanitize all input used to build the connection string against a whitelist of allowed values.
    * **Principle of least privilege:** Ensure the database user used by the application has only the necessary permissions.

