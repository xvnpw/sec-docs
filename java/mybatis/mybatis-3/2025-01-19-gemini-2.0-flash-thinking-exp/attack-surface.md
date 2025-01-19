# Attack Surface Analysis for mybatis/mybatis-3

## Attack Surface: [SQL Injection via `${}` (String Substitution)](./attack_surfaces/sql_injection_via__${}___string_substitution_.md)

*   **Description:**  Attackers can inject malicious SQL code into the database by manipulating user-controlled input that is directly substituted into SQL queries using the `${}` syntax in MyBatis mapper files.
    *   **How MyBatis-3 Contributes to the Attack Surface:** MyBatis provides the `${}` syntax, which bypasses prepared statements and directly inserts the provided string into the SQL query. This makes the application vulnerable if user input is used with this syntax without proper sanitization.
    *   **Example:**
        ```xml
        <select id="getUserByName" resultType="User">
          SELECT * FROM users WHERE username = '${username}'
        </select>
        ```
        If `username` is obtained directly from user input (e.g., a web form), an attacker could provide an input like `' OR '1'='1` to bypass authentication or execute other malicious SQL.
    *   **Impact:**
        *   Data Breach: Access to sensitive data.
        *   Data Modification: Inserting, updating, or deleting data.
        *   Authentication Bypass: Circumventing login mechanisms.
        *   Remote Code Execution (in some database environments).
    *   **Risk Severity:** **Critical**
    *   **Mitigation Strategies:**
        *   **Always use `#{}`, not `${}` for user-provided input.**  `#{}` uses prepared statements, which automatically escape and parameterize values, preventing SQL injection.
        *   If `${}` is absolutely necessary (e.g., for dynamic table or column names), implement strict input validation and sanitization to ensure only expected values are used.

## Attack Surface: [XML External Entity (XXE) Injection in Configuration Files](./attack_surfaces/xml_external_entity__xxe__injection_in_configuration_files.md)

*   **Description:** Attackers can exploit vulnerabilities in the XML parser used by MyBatis to process configuration files (e.g., `mybatis-config.xml`, mapper XMLs) by including malicious external entities.
    *   **How MyBatis-3 Contributes to the Attack Surface:** MyBatis relies on an XML parser to read and process its configuration files. If this parser is not configured securely, it can be vulnerable to XXE attacks.
    *   **Example:** An attacker could modify a configuration file (if they have access) or potentially influence the loading of an external DTD to include a malicious external entity that reads local files or performs Server-Side Request Forgery (SSRF).
    *   **Impact:**
        *   Local File Disclosure: Reading arbitrary files from the server.
        *   Server-Side Request Forgery (SSRF): Making requests to internal or external resources.
        *   Denial of Service (DoS).
    *   **Risk Severity:** **High**
    *   **Mitigation Strategies:**
        *   **Disable external entity processing in the XML parser.** This can be done programmatically or through configuration settings depending on the specific XML parser being used. For example, when using Java's built-in XML processing, set features like `FEATURE_SECURE_PROCESSING` to `true` and disable external DTDs and parameter entities.
        *   **Restrict access to MyBatis configuration files.** Ensure only authorized personnel can modify these files.
        *   **Validate the content of configuration files.** Although not a primary defense against XXE, validating the structure and content can help detect unexpected changes.

## Attack Surface: [Insecure Resource Loading in Configuration](./attack_surfaces/insecure_resource_loading_in_configuration.md)

*   **Description:** If MyBatis is configured to load resources (e.g., mapper files) from untrusted sources or locations without proper validation, attackers could inject malicious files.
    *   **How MyBatis-3 Contributes to the Attack Surface:** MyBatis allows specifying file paths or classpath resources for loading configuration files and mapper files. If the application doesn't carefully control the source of these paths, it can be vulnerable.
    *   **Example:** If the application allows users to specify a path to a mapper file, an attacker could provide a path to a malicious XML file containing arbitrary SQL or other harmful content.
    *   **Impact:**
        *   Arbitrary SQL Execution: Loading malicious mapper files could lead to the execution of attacker-controlled SQL queries.
        *   Configuration Manipulation: Injecting malicious configuration settings.
    *   **Risk Severity:** **High**
    *   **Mitigation Strategies:**
        *   **Hardcode or strictly control the paths to MyBatis configuration and mapper files.** Avoid allowing user input to directly influence these paths.
        *   **Validate the integrity of loaded resources.** Consider using checksums or digital signatures to verify the authenticity of configuration files.
        *   **Restrict file system permissions** to prevent unauthorized modification of configuration files.

## Attack Surface: [Deserialization Vulnerabilities in Custom Type Handlers (Indirect)](./attack_surfaces/deserialization_vulnerabilities_in_custom_type_handlers__indirect_.md)

*   **Description:** If custom Type Handlers are implemented to deserialize data from the database (e.g., JSON, serialized Java objects), vulnerabilities in the deserialization process can lead to arbitrary code execution.
    *   **How MyBatis-3 Contributes to the Attack Surface:** MyBatis allows developers to create custom Type Handlers to handle specific data type conversions. If these handlers involve deserialization of untrusted data, they can become an attack vector.
    *   **Example:** A custom Type Handler might deserialize a JSON string retrieved from the database. If the JSON library used has known deserialization vulnerabilities, an attacker could craft a malicious JSON payload that, when deserialized, executes arbitrary code.
    *   **Impact:**
        *   Remote Code Execution.
    *   **Risk Severity:** **High**
    *   **Mitigation Strategies:**
        *   **Avoid deserializing untrusted data in Type Handlers if possible.**
        *   **If deserialization is necessary, use secure deserialization techniques and libraries.**  Consider using allow-lists instead of block-lists for classes allowed to be deserialized.
        *   **Keep deserialization libraries up to date** to patch known vulnerabilities.

## Attack Surface: [Malicious Plugins](./attack_surfaces/malicious_plugins.md)

*   **Description:** If MyBatis is configured to load plugins from untrusted sources, malicious plugins could be injected into the application, allowing for arbitrary code execution or other malicious activities.
    *   **How MyBatis-3 Contributes to the Attack Surface:** MyBatis allows the use of plugins to extend its functionality. If the application doesn't control the source of these plugins, it can be vulnerable.
    *   **Example:** An attacker could provide a malicious plugin that intercepts SQL execution and modifies data or performs other harmful actions.
    *   **Impact:**
        *   Remote Code Execution.
        *   Data Manipulation.
        *   Complete application compromise.
    *   **Risk Severity:** **Critical**
    *   **Mitigation Strategies:**
        *   **Only load plugins from trusted and verified sources.**
        *   **Implement a mechanism to verify the integrity and authenticity of plugins before loading them.**
        *   **Restrict file system permissions** to prevent unauthorized placement of plugin files.

