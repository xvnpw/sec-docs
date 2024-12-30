* **Attack Surface: SQL Injection via Unsafe Parameter Handling**
    * **Description:** Attackers inject malicious SQL code into database queries by manipulating user-supplied input that is not properly sanitized or parameterized.
    * **How MyBatis-3 Contributes:** MyBatis allows the use of `${}` for direct string substitution in SQL queries. If user input is directly placed within `${}`, MyBatis will insert it verbatim into the SQL, bypassing any parameterization and creating a direct SQL injection vulnerability.
    * **Example:**
        ```xml
        <select id="getUserByName" resultType="User">
          SELECT * FROM users WHERE username = '${username}'
        </select>
        ```
        If `username` is obtained directly from user input without sanitization (e.g., `'; DROP TABLE users; --`), this will execute malicious SQL.
    * **Impact:**  Full database compromise, including data breaches, data manipulation, denial of service, and potentially remote code execution on the database server.
    * **Risk Severity:** Critical
    * **Mitigation Strategies:**
        * **Always use parameterized queries (`#{}`) for user-provided input.** MyBatis properly escapes values within `#{}` to prevent SQL injection.
        * **Avoid using `${}` for user-controlled data.** If absolutely necessary, implement robust input validation and sanitization before using `${}`.

* **Attack Surface: XML External Entity (XXE) Injection in Mapper Files**
    * **Description:** Attackers exploit vulnerabilities in XML parsers to include and process malicious external entities, potentially leading to information disclosure, denial of service, or server-side request forgery (SSRF).
    * **How MyBatis-3 Contributes:** MyBatis uses an XML parser to process mapper files. If the parser is not configured securely, it might be vulnerable to XXE attacks when processing malicious XML content within these files. This is more likely if external DTDs or entities are referenced.
    * **Example:** An attacker with write access to mapper files could inject the following:
        ```xml
        <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
        <select id="someQuery" resultType="User">
          SELECT '&xxe;' as data FROM users
        </select>
        ```
        This could potentially read the `/etc/passwd` file.
    * **Impact:** Information disclosure (reading local files), denial of service, server-side request forgery (SSRF).
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **Disable external entity resolution in the XML parser used by MyBatis.** This is typically done by configuring the `DocumentBuilderFactory` or `SAXParserFactory`.
        * **Restrict access to mapper files.** Ensure only authorized personnel can modify these files.

* **Attack Surface: Plugin Vulnerabilities**
    * **Description:** MyBatis plugins, if not developed securely or obtained from untrusted sources, can introduce vulnerabilities into the application.
    * **How MyBatis-3 Contributes:** MyBatis allows the use of plugins to intercept and modify the framework's behavior. Malicious plugins can execute arbitrary code, modify queries, or access sensitive data.
    * **Example:** A malicious plugin could intercept all SQL queries and log sensitive data or modify the queries to extract additional information.
    * **Impact:**  Full application compromise, including data breaches, data manipulation, and potentially remote code execution.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **Only use plugins from trusted and reputable sources.**
        * **Thoroughly review the code of any custom or third-party plugins before using them.**

* **Attack Surface: Dynamic SQL Evaluation Risks**
    * **Description:** Improper use of dynamic SQL features, especially when combined with user input, can lead to vulnerabilities beyond simple SQL injection.
    * **How MyBatis-3 Contributes:** MyBatis provides powerful dynamic SQL features using XML tags like `<if>`, `<choose>`, `<foreach>`, etc. If user input influences the structure of these dynamic SQL statements without proper validation, it can lead to unexpected and potentially harmful query construction.
    * **Example:**
        ```xml
        <select id="searchUsers" resultType="User">
          SELECT * FROM users
          <if test="sortColumn != null">
            ORDER BY ${sortColumn} ${sortOrder}
          </if>
        </select>
        ```
        If `sortColumn` is user-controlled without validation, an attacker could inject arbitrary SQL into the `ORDER BY` clause.
    * **Impact:**  SQL injection, data breaches, data manipulation, and potentially denial of service.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **Validate and sanitize user input that influences dynamic SQL construction.**
        * **Avoid using `${}` for dynamic column or table names based on user input.**