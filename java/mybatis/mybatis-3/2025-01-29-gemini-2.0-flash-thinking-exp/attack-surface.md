# Attack Surface Analysis for mybatis/mybatis-3

## Attack Surface: [SQL Injection Vulnerabilities](./attack_surfaces/sql_injection_vulnerabilities.md)

*   **Description:** Attackers inject malicious SQL code into application queries, allowing them to bypass security controls, access unauthorized data, modify data, or execute arbitrary commands on the database server.
*   **MyBatis Contribution:** MyBatis executes SQL queries defined in mappers. Using `${}` for variable substitution in XML mappers or string concatenation in annotation-based SQL directly embeds user input into SQL queries without proper escaping, creating SQL injection vulnerabilities.
*   **Example:**
    *   **Vulnerable Mapper (XML):**
        ```xml
        <select id="getUserByName" resultType="User">
          SELECT * FROM users WHERE username = '${username}'
        </select>
        ```
    *   **Malicious Input:**  `' OR '1'='1`
    *   **Resulting SQL:** `SELECT * FROM users WHERE username = '' OR '1'='1'` (This would return all users, bypassing username authentication).
*   **Impact:**
    *   Data Breach (confidentiality loss)
    *   Data Manipulation (integrity loss)
    *   Account Takeover
    *   Denial of Service
    *   Potential for Remote Code Execution (depending on database privileges and capabilities)
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Always use `#{}` for parameter substitution in XML mappers and parameterized queries in annotations.** This uses `PreparedStatement` placeholders, which escape user input and prevent SQL injection.
    *   **Avoid using `${}` for user-controlled input.** Reserve `${}` for truly dynamic SQL elements that are not user-provided and are carefully controlled within the application logic.
    *   **Implement Input Validation and Sanitization:** Validate and sanitize user input on the application side before passing it to MyBatis, even when using `#{}` as an additional defense layer.
    *   **Apply the Principle of Least Privilege to Database Users:** Grant the database user used by the application only the necessary permissions to minimize the impact of a successful SQL injection attack.
    *   **Use Static Analysis Security Testing (SAST) tools:**  SAST tools can help identify potential SQL injection vulnerabilities in MyBatis mapper files.

## Attack Surface: [XML External Entity (XXE) Injection Vulnerabilities (Configuration Files)](./attack_surfaces/xml_external_entity__xxe__injection_vulnerabilities__configuration_files_.md)

*   **Description:** Attackers exploit vulnerabilities in XML parsing to inject external entities into XML configuration files. This can lead to local file disclosure, Server-Side Request Forgery (SSRF), or Denial of Service (DoS).
*   **MyBatis Contribution:** MyBatis parses XML configuration files (e.g., `mybatis-config.xml`, mapper XML files) during application startup. If the XML parser is not configured to disable external entity processing, MyBatis applications become vulnerable.
*   **Example:**
    *   **Malicious XML Configuration (e.g., injected into `mybatis-config.xml` if possible, or a crafted malicious config file if application can be tricked into loading it):**
        ```xml
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE root [
          <!ENTITY xxe SYSTEM "file:///etc/passwd">
        ]>
        <configuration>
          <properties>
            <property name="example" value="&xxe;"/>
          </properties>
          </configuration>
        ```
    *   **Impact:** When MyBatis parses this configuration, it will attempt to resolve the external entity `&xxe;`, potentially reading the `/etc/passwd` file.
*   **Impact:**
    *   Local File Disclosure (confidentiality loss)
    *   Server-Side Request Forgery (SSRF)
    *   Denial of Service (DoS)
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Disable External Entity Processing in XML Parsers:** Configure the `DocumentBuilderFactory` used by MyBatis to disable external entity resolution features. This should be done programmatically when creating the `SqlSessionFactoryBuilder`.
        ```java
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-entities", false);
        // ... use factory to build SqlSessionFactory
        ```

## Attack Surface: [Deserialization Vulnerabilities (Custom Type Handlers and Plugins)](./attack_surfaces/deserialization_vulnerabilities__custom_type_handlers_and_plugins_.md)

*   **Description:** Insecure deserialization of data within custom Type Handlers or Plugins can allow attackers to execute arbitrary code on the server by crafting malicious serialized objects.
*   **MyBatis Contribution:** MyBatis allows custom Type Handlers and Plugins to extend its functionality. If these components handle deserialization of data from untrusted sources (e.g., database, requests), vulnerabilities can arise.
*   **Example:**
    *   **Vulnerable Custom Type Handler:** A custom Type Handler might deserialize binary data from a database column using Java serialization without proper security measures.
    *   **Malicious Attack:** An attacker could inject malicious serialized Java objects into the database column. When the vulnerable Type Handler deserializes this data, it could execute arbitrary code.
*   **Impact:**
    *   Remote Code Execution (critical impact)
    *   Full system compromise
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Avoid Deserialization of Untrusted Data:** Minimize or eliminate deserialization of data from untrusted sources within custom Type Handlers and Plugins.
    *   **Use Secure Deserialization Practices:** If deserialization is necessary, use secure methods. Prefer safe serialization formats like JSON. If Java serialization is unavoidable, implement robust input validation and consider using secure deserialization libraries or techniques to mitigate risks (e.g., object filtering, whitelisting).
    *   **Code Review and Security Audits:** Thoroughly review custom Type Handlers and Plugins for deserialization vulnerabilities. Conduct regular security audits.
    *   **Principle of Least Privilege:** Limit the privileges of the application process to reduce the impact of successful code execution.

