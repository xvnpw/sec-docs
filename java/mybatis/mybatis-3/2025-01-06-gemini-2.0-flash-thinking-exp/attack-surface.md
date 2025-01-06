# Attack Surface Analysis for mybatis/mybatis-3

## Attack Surface: [SQL Injection via Unsafe Parameter Handling](./attack_surfaces/sql_injection_via_unsafe_parameter_handling.md)

**Description:** Attackers inject malicious SQL code into queries by manipulating user-supplied input that is not properly sanitized or parameterized.

**How MyBatis-3 Contributes:** The `${}` syntax in MyBatis mapper files directly substitutes parameter values into the SQL query string without escaping. This makes the application vulnerable if user input is used with this syntax.

**Example:** A mapper file has a query like: `SELECT * FROM users WHERE username = '${username}'`. If a user provides `'; DROP TABLE users; --` as the username, the resulting query becomes `SELECT * FROM users WHERE username = ''; DROP TABLE users; --'`, potentially dropping the users table.

**Impact:**  Complete database compromise, including data breach, data modification, data deletion, and potentially gaining control over the database server.

**Risk Severity:** Critical

**Mitigation Strategies:**
* **Always use the `# {}` syntax for parameter substitution.** This uses prepared statements, which automatically handle escaping and prevent SQL injection.
* **Avoid using the `${}` syntax unless absolutely necessary and with extreme caution.** If it must be used, ensure rigorous input validation and sanitization on the application side.

## Attack Surface: [Configuration Vulnerabilities (Insecure XML Configuration)](./attack_surfaces/configuration_vulnerabilities__insecure_xml_configuration_.md)

**Description:** Attackers exploit vulnerabilities in how MyBatis loads and processes its configuration files (`mybatis-config.xml` and mapper files).

**How MyBatis-3 Contributes:** MyBatis relies on XML files for configuration. If these files are dynamically generated or modified based on untrusted input without proper sanitization, it can lead to vulnerabilities.

**Example:** An application dynamically generates a mapper file path based on user input. An attacker could manipulate this input to point to a malicious mapper file hosted on an external server, potentially leading to remote code execution if the malicious mapper contains `<script>` tags or other dangerous elements.

**Impact:**  Remote code execution, information disclosure, denial of service, or modification of application behavior.

**Risk Severity:** High

**Mitigation Strategies:**
* **Treat MyBatis configuration files as sensitive resources and protect them from unauthorized modification.**
* **Avoid dynamically generating or modifying MyBatis configuration files based on user input.**

## Attack Surface: [External Entity Expansion (XXE) in XML Configuration](./attack_surfaces/external_entity_expansion__xxe__in_xml_configuration.md)

**Description:** Attackers exploit vulnerabilities in the XML parser used by MyBatis to include and process external entities, potentially leading to information disclosure or denial of service.

**How MyBatis-3 Contributes:** MyBatis uses an XML parser to process its configuration files. If the parser is not configured to prevent external entity resolution, it's vulnerable to XXE attacks.

**Example:** A malicious actor crafts a `mybatis-config.xml` or mapper file containing an external entity definition that points to a local file (`SYSTEM "file:///etc/passwd"`) or an external resource. If the XML parser resolves this entity, it could disclose sensitive information.

**Impact:**  Information disclosure (reading local files), denial of service (by referencing large or infinite resources), and potentially remote code execution in some scenarios.

**Risk Severity:** High

**Mitigation Strategies:**
* **Disable external entity processing in the XML parser used by MyBatis.** This is typically done by configuring the `DocumentBuilderFactory` or `SAXParserFactory`.

## Attack Surface: [Deserialization Vulnerabilities in Type Handlers](./attack_surfaces/deserialization_vulnerabilities_in_type_handlers.md)

**Description:** Attackers exploit vulnerabilities in custom type handlers that deserialize data from untrusted sources without proper validation, potentially leading to remote code execution.

**How MyBatis-3 Contributes:** MyBatis allows developers to create custom type handlers to handle specific data types. If these handlers deserialize data (e.g., from a database column) without proper security measures, they can be vulnerable.

**Example:** A custom type handler deserializes a Java object from a database column. An attacker could insert a malicious serialized object into the database. When MyBatis retrieves this data and the custom type handler deserializes it, it could lead to remote code execution.

**Impact:**  Remote code execution, allowing the attacker to gain full control of the application server.

**Risk Severity:** Critical

**Mitigation Strategies:**
* **Avoid deserializing data from untrusted sources in custom type handlers if possible.**
* **If deserialization is necessary, use secure deserialization techniques and validate the data before deserialization.**

## Attack Surface: [SQL Injection in Dynamic SQL Fragments](./attack_surfaces/sql_injection_in_dynamic_sql_fragments.md)

**Description:** Similar to the first point, but specifically focusing on how dynamic SQL constructs can be misused to create SQL injection vulnerabilities.

**How MyBatis-3 Contributes:** While the `# {}` syntax is generally safe, developers might still construct SQL fragments dynamically and concatenate them, potentially introducing SQL injection if user input is involved in this concatenation.

**Example:** A developer dynamically builds a `WHERE` clause by concatenating strings, including user-provided filter criteria without proper sanitization. This can lead to SQL injection.

**Impact:**  Complete database compromise, including data breach, data modification, data deletion, and potentially gaining control over the database server.

**Risk Severity:** Critical

**Mitigation Strategies:**
* **Avoid string concatenation when building dynamic SQL fragments.**
* **Utilize MyBatis's built-in dynamic SQL features with proper parameterization (`#{}`).**

