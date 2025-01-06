# Attack Tree Analysis for mybatis/mybatis-3

Objective: Compromise Application via MyBatis Exploitation

## Attack Tree Visualization

```
Attack Tree for Compromising Application Using MyBatis-3 (High-Risk Sub-Tree)

Objective: Compromise Application via MyBatis Exploitation

└── AND Compromise Application
    └── OR [HIGH RISK PATH] Exploit SQL Injection via MyBatis [CRITICAL]
        ├── AND [T1.1] Inject Malicious SQL through Dynamic SQL
        │   └── [T1.1.1] Unsanitized User Input in Dynamic SQL Fragments [CRITICAL]
        ├── AND [T1.2] Bypass Parameterization [CRITICAL]
        │   └── [T1.2.1] Using `${}` instead of `#{}` for User-Controlled Values [CRITICAL]
    └── OR [HIGH RISK PATH] Exploit XML Injection/External Entity (XXE) in MyBatis Configuration [CRITICAL]
        ├── AND [T2.1] Manipulate MyBatis Configuration Files [CRITICAL]
        │   ├── [T2.1.1] Inject Malicious XML in `mybatis-config.xml` [CRITICAL]
        │   └── [T2.1.2] Inject Malicious XML in Mapper Files [CRITICAL]
        └── AND [T2.2] Exploit External Entity (XXE) in DTD/Schema Handling [CRITICAL]
            └── [T2.2.1] Include Malicious External Entities in Configuration or Mapper Files [CRITICAL]
```


## Attack Tree Path: [High-Risk Path: Exploit SQL Injection via MyBatis](./attack_tree_paths/high-risk_path_exploit_sql_injection_via_mybatis.md)

* Attack Vector: Inject Malicious SQL through Dynamic SQL
    * Critical Node: Unsanitized User Input in Dynamic SQL Fragments
        * Description: Attackers inject malicious SQL code into dynamic SQL queries by providing unsanitized input. MyBatis's dynamic SQL features (like `<if>`, `<where>`) construct SQL queries based on conditions. If user-provided data is directly included in these constructs without proper sanitization or parameterization, it allows attackers to manipulate the final SQL query executed against the database.
        * Impact: Data breach (access to sensitive data), data modification or deletion, potential remote code execution (depending on database privileges and capabilities).
        * Mitigation:
            * Always use parameterized queries (`#{}`) for user input, even within dynamic SQL blocks where possible.
            * If parameterization is not feasible, rigorously sanitize user input to escape or remove potentially harmful SQL characters and keywords.
            * Implement input validation to ensure user input conforms to expected formats and lengths.

* Attack Vector: Bypass Parameterization
    * Critical Node: Using `${}` instead of `#{}` for User-Controlled Values
        * Description: MyBatis offers two ways to include values in SQL queries: `#{}` (parameterization) and `${}` (string substitution). `#{}` is secure as it treats the value as a parameter, preventing SQL injection. However, `${}` directly substitutes the value as a string, making it vulnerable if user input is used. Attackers can exploit this by crafting malicious SQL within the user-provided value.
        * Impact: Data breach, data modification or deletion, potential remote code execution.
        * Mitigation:
            * **Strictly avoid using `${}` for any user-controlled input.**  This is the most critical mitigation.
            * Enforce this rule through code reviews, static analysis tools, and developer training.
            * If `${}` is absolutely necessary for non-user-controlled values (e.g., for table or column names), carefully review and control the source of these values.

## Attack Tree Path: [High-Risk Path: Exploit XML Injection/External Entity (XXE) in MyBatis Configuration](./attack_tree_paths/high-risk_path_exploit_xml_injectionexternal_entity__xxe__in_mybatis_configuration.md)

* Attack Vector: Manipulate MyBatis Configuration Files
    * Critical Node: Inject Malicious XML in `mybatis-config.xml`
        * Description: The `mybatis-config.xml` file configures MyBatis. If an attacker can inject malicious XML into this file (e.g., if it's dynamically generated based on user input or loaded from an untrusted source), they can alter MyBatis's behavior, potentially leading to remote code execution or other vulnerabilities.
        * Impact: Remote code execution, information disclosure, denial of service.
        * Mitigation:
            * Ensure `mybatis-config.xml` is loaded from a trusted source and is not influenced by user input.
            * Implement strict access controls to prevent unauthorized modification of the configuration file.

    * Critical Node: Inject Malicious XML in Mapper Files
        * Description: MyBatis mapper files define the SQL queries. Injecting malicious XML into these files can allow attackers to inject arbitrary SQL or manipulate MyBatis's behavior.
        * Impact: SQL injection (leading to data breach, etc.), remote code execution (if malicious SQL is crafted).
        * Mitigation:
            * Ensure mapper files are loaded from trusted sources and are not dynamically generated based on user input.
            * Implement strict access controls to prevent unauthorized modification of mapper files.

* Attack Vector: Exploit External Entity (XXE) in DTD/Schema Handling
    * Critical Node: Include Malicious External Entities in Configuration or Mapper Files
        * Description: XML External Entity (XXE) vulnerabilities occur when an XML parser processes external entities defined in a Document Type Definition (DTD) or XML schema. If external entity processing is enabled and the XML source (MyBatis configuration or mapper files) is not fully trusted, an attacker can include malicious external entities that, when parsed, can lead to:
            * Local file disclosure: Reading arbitrary files from the server.
            * Server-Side Request Forgery (SSRF): Making the server perform requests to internal or external systems.
            * Denial of Service: Exhausting server resources.
        * Impact: Local file disclosure, Server-Side Request Forgery (SSRF), denial of service.
        * Mitigation:
            * **Disable external entity processing in the XML parser used by MyBatis.** This is the most effective mitigation. Configure the XML parser to disallow DTDs and external entities.
            * If external entity processing is absolutely necessary, ensure that configuration and mapper files are loaded from completely trusted sources and are never influenced by user input.
            * Sanitize XML content if dynamic generation is unavoidable (though highly discouraged for security reasons).

