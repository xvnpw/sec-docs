# Threat Model Analysis for mybatis/mybatis-3

## Threat: [SQL Injection via Dynamic SQL Misuse](./threats/sql_injection_via_dynamic_sql_misuse.md)

*   **Description:** An attacker crafts malicious input that is incorporated into a dynamically generated SQL query within a MyBatis mapper.  This exploits the use of string substitution (`${}`) instead of parameterized queries (`#{}`). The attacker can inject SQL code to bypass authentication, read, modify, or delete data, and potentially gain control of the database server.
*   **Impact:**
    *   Data breach (unauthorized access to sensitive data).
    *   Data modification or deletion.
    *   Database server compromise (in severe cases).
    *   Denial of Service (DoS) through resource exhaustion or database corruption.
*   **MyBatis-3 Component Affected:**
    *   XML Mapper files: Dynamic SQL elements (`<if>`, `<choose>`, `<when>`, `<otherwise>`, `<where>`, `<set>`, `<foreach>`) and any direct use of `${}` within SQL.
    *   `@SelectProvider`, `@UpdateProvider`, `@InsertProvider`, `@DeleteProvider` annotations: Java code within provider classes that dynamically constructs SQL strings.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strictly Prefer `#{}` (Parameterized Queries):**  Use `#{}` for *all* user-supplied values. This ensures proper parameter binding.
    *   **Input Validation:**  Implement rigorous input validation *before* data reaches the MyBatis layer. Validate data types, lengths, formats, and allowed characters. Use whitelisting.
    *   **Avoid `${}` (String Substitution):** Minimize the use of `${}`. If absolutely necessary, rigorously validate and escape user input using a database-specific escaping library *before* use. This is a high-risk practice.
    *   **Mandatory Code Reviews:** Focus on dynamic SQL usage and input handling within mappers.
    *   **Static Analysis:** Use tools to detect potential SQL injection in MyBatis configurations and mappers.
    *   **Least Privilege:** Database user accounts should have minimal necessary privileges.
    *   **Secure Provider Classes:** Apply the same rigorous input validation and escaping to `@...Provider` annotations as with XML mappers.

## Threat: [XML External Entity (XXE) Injection](./threats/xml_external_entity__xxe__injection.md)

*   **Description:** An attacker exploits a misconfigured XML parser to process malicious XML containing external entity references.  While MyBatis 3 is generally secure by default, an attacker might attempt to influence the loading of a malicious mapper XML file or, with write access to a mapper file, inject malicious XML. This can lead to local file disclosure, Server-Side Request Forgery (SSRF), and DoS.
*   **Impact:**
    *   Disclosure of local files on the server.
    *   Server-Side Request Forgery (SSRF).
    *   Denial of Service (DoS).
*   **MyBatis-3 Component Affected:**
    *   `org.apache.ibatis.builder.xml.XMLMapperBuilder`: Parses mapper XML files.
    *   `org.apache.ibatis.parsing.XPathParser`: The underlying XML parser. Its configuration is crucial.
    *   MyBatis configuration file (`mybatis-config.xml`):  Settings related to XML parsing could be misconfigured here (though less direct).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Disable DTDs and External Entities:** Ensure the XML parser used by MyBatis (via Java XML parsing libraries) is configured to *disable* DTDs and external entity resolution. Verify `XMLMapperBuilder` uses a securely configured `XPathParser`.
    *   **Controlled Mapper Loading:** Load mapper XML files from trusted locations (e.g., the application's classpath). *Do not* allow dynamic loading based on user input.
    *   **Input Validation (Indirect):** Validate any input that *indirectly* influences mapper file loading (e.g., file paths).

## Threat: [Deserialization of Untrusted Data (Uncommon, but High Risk)](./threats/deserialization_of_untrusted_data__uncommon__but_high_risk_.md)

*   **Description:** An attacker provides malicious serialized data that, when deserialized by a custom MyBatis `TypeHandler`, results in arbitrary code execution. This is less common, as MyBatis doesn't typically deserialize in this way, but it's possible with custom implementations.
*   **Impact:**
    *   Remote Code Execution (RCE) – complete control over the application server.
*   **MyBatis-3 Component Affected:**
    *   Custom `TypeHandler` implementations: Any `TypeHandler` that deserializes data from a database column or other untrusted source.
    *   `org.apache.ibatis.type.TypeHandler`: The base interface for type handlers.
*   **Risk Severity:** High (if applicable, but generally low probability)
*   **Mitigation Strategies:**
    *   **Avoid Deserializing Untrusted Data:** Do *not* create `TypeHandler` implementations that deserialize data from untrusted sources.
    *   **Input Validation and Whitelisting (If Necessary):** If deserialization is absolutely required, implement extremely strict input validation and whitelisting *before* deserialization. Use a safe deserialization library or approach. Consider safer serialization formats (e.g., JSON with a schema) instead of Java serialization.
    *   **Code Reviews:** Thoroughly review any custom `TypeHandler` implementations for potential deserialization vulnerabilities.

