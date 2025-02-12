# Attack Surface Analysis for mybatis/mybatis-3

## Attack Surface: [SQL Injection (SQLi)](./attack_surfaces/sql_injection__sqli_.md)

*   **Description:**  Attackers inject malicious SQL code into database queries, bypassing security, accessing/modifying/deleting data, and potentially executing commands on the database server.
    *   **MyBatis-3 Contribution:** MyBatis's dynamic SQL capabilities, specifically the `${}` string substitution, create direct injection points if misused.  `#{}` is safe, `${}` is *not*.
    *   **Example:**
        ```xml
        <!-- Vulnerable Mapper -->
        <select id="getUser" resultType="User">
          SELECT * FROM users WHERE username = '${userInput}';
        </select>
        ```
        If `userInput` is `'; DROP TABLE users; --`, the `users` table is deleted.
    *   **Impact:**  Complete database compromise, data breaches, data loss, data modification, potential server compromise.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Mandatory:** *Always* use `#{}` for parameter binding. This ensures proper escaping and parameterization, leveraging prepared statements.
        *   **Input Validation:**  Strict input validation *before* data reaches MyBatis. Validate types, lengths, and allowed characters.
        *   **Whitelisting:** For dynamic elements (column names, sort orders), use whitelists to restrict allowed values. *Never* directly concatenate user input.
        *   **Least Privilege:**  The database user account used by MyBatis should have the *minimum* necessary privileges.
        *   **Code Reviews:**  Scrutinize all uses of `${}`.  Ensure they are absolutely necessary and rigorously validated.
        * **Static Analysis:** Employ static analysis tools to automatically detect potential SQLi in MyBatis mappers.

## Attack Surface: [Second-Order SQL Injection](./attack_surfaces/second-order_sql_injection.md)

*   **Description:**  Attackers inject malicious data that is *stored* in the database.  Later, when that stored data is used *unsafely* (via `${}`) in a MyBatis query, the injection occurs.
    *   **MyBatis-3 Contribution:** MyBatis relies on the developer to consistently use `#{}` for *all* data retrieval, even data that appears "safe."  The framework itself doesn't distinguish.
    *   **Example:**
        1.  Attacker injects `'; DELETE FROM users; --` into a `comments` table (via a separate vulnerability).
        2.  A MyBatis query unsafely retrieves and uses this comment:
            ```xml
            <select id="displayComment" resultType="String">
              SELECT 'Comment: ${comment}' FROM comments WHERE id = #{commentId};
            </select>
            ```
            The `DELETE` statement executes.
    *   **Impact:** Data loss, modification, potential database compromise (similar to direct SQLi).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Universal `#{}` Usage:**  Use `#{}` for *all* data retrieval from the database, without exception.  Treat *all* database data as potentially tainted.
        *   **Input Validation (at all entry points):** Prevent malicious data from being stored initially. Validate input at *every* application entry point.
        *   **Output Encoding:** If displaying retrieved data, use proper output encoding (e.g., HTML encoding) to mitigate related vulnerabilities like XSS.

## Attack Surface: [XML External Entity (XXE) Injection (If Applicable)](./attack_surfaces/xml_external_entity__xxe__injection__if_applicable_.md)

*   **Description:** Attackers inject malicious XML with external entity references, potentially reading local files, accessing internal resources, or causing a DoS.
    *   **MyBatis-3 Contribution:** *If* MyBatis processes user-supplied XML (e.g., dynamically loaded mapper files) *and* the XML parser is insecurely configured, this vulnerability exists.  This is less common in standard MyBatis usage but *critical* if present.
    *   **Example:** User uploads an XML mapper file:
        ```xml
        <!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
          "http://mybatis.org/dtd/mybatis-3-mapper.dtd" [
          <!ENTITY xxe SYSTEM "file:///etc/passwd">
        ]>
        <mapper namespace="example">
          <select id="test" resultType="string">
            SELECT '&xxe;'
          </select>
        </mapper>
        ```
        This could expose `/etc/passwd`.
    *   **Impact:** File disclosure, internal network access, DoS, potential RCE.
    *   **Risk Severity:** High (if user-supplied XML is processed)
    *   **Mitigation Strategies:**
        *   **Disable External Entities:**  *Crucially*, configure the XML parser used by MyBatis to *disable* external entity and DTD resolution. This is the primary defense. Use secure `DocumentBuilderFactory` settings (see previous, more detailed response for Java example).
        *   **Avoid User-Supplied XML:**  The best mitigation is to *not* allow users to upload or directly provide XML that MyBatis will process.
        *   **Strict XML Validation:** If user-supplied XML is unavoidable, implement *very* strict validation against a predefined, restrictive schema.

