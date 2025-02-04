# Threat Model Analysis for doctrine/orm

## Threat: [DQL Injection (Critical)](./threats/dql_injection__critical_.md)

*   **Threat:** DQL Injection
*   **Description:** An attacker crafts malicious input that is injected into dynamically constructed Doctrine Query Language (DQL) queries. By manipulating user-controlled input fields used to build DQL strings, the attacker can execute arbitrary DQL commands. This allows them to bypass intended data access restrictions and potentially read or modify sensitive data.
*   **Impact:**
    *   Data Breach: Unauthorized access to sensitive information stored in the database.
    *   Data Manipulation: Modification, deletion, or corruption of data within the database.
    *   Unauthorized Actions: Bypassing application logic and performing actions not intended for the user.
*   **Affected ORM Component:**
    *   `Doctrine\ORM\QueryBuilder` (when used to build dynamic queries without proper parameterization)
    *   `Doctrine\ORM\EntityManager` (when directly executing string-based DQL queries)
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Always use Parameterized Queries:**  Utilize `QueryBuilder`'s `setParameter()` methods or prepared statements when constructing DQL queries dynamically.
    *   **Avoid String Concatenation in DQL:**  Never build DQL queries by directly concatenating user input strings.
    *   **Input Validation:**  Validate and sanitize user inputs before using them in DQL queries, even with parameterized queries, to ensure data types and expected formats.
    *   **Code Review:**  Conduct thorough code reviews of DQL query construction logic to identify potential injection vulnerabilities.
    *   **Static Analysis Tools:** Employ static analysis tools to automatically detect potential DQL injection flaws in the codebase.

## Threat: [Native SQL Injection via `executeStatement()` (Critical)](./threats/native_sql_injection_via__executestatement_____critical_.md)

*   **Threat:** Native SQL Injection via `executeStatement()`
*   **Description:** An attacker exploits the use of `EntityManager->getConnection()->executeStatement()` or similar methods to execute raw SQL queries. If user input is directly embedded into these native SQL queries without proper sanitization, the attacker can inject arbitrary SQL commands directly into the database. This bypasses Doctrine's DQL protection and can lead to full database compromise.
*   **Impact:**
    *   Full Database Compromise: Complete control over the database server and all its data.
    *   Data Exfiltration: Stealing sensitive data from the database.
    *   Data Destruction: Deleting or corrupting critical data, leading to data loss.
    *   Denial of Service: Disrupting database operations and potentially the entire application.
*   **Affected ORM Component:**
    *   `Doctrine\DBAL\Connection` (accessed via `EntityManager->getConnection()`)
    *   `Doctrine\ORM\EntityManager` (when using methods that execute native SQL)
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Minimize Native SQL Usage:**  Avoid using native SQL queries whenever possible. Rely on DQL and QueryBuilder for database interactions.
    *   **Parameterized Native SQL Queries:** If native SQL is absolutely necessary, always use parameterized queries and prepared statements provided by the database connection.
    *   **Strict Input Sanitization:**  Thoroughly validate and sanitize all user inputs that are used in native SQL queries. Treat native SQL with extreme caution.
    *   **Principle of Least Privilege (Database User):**  Grant the database user used by the application only the minimum necessary privileges to limit the impact of a successful SQL injection.
    *   **Code Review (Native SQL):**  Extensively review any code sections that utilize native SQL for potential injection vulnerabilities.

## Threat: [Mass Assignment Vulnerabilities (High)](./threats/mass_assignment_vulnerabilities__high_.md)

*   **Threat:** Mass Assignment Vulnerabilities
*   **Description:** An attacker sends malicious or unexpected data in a request (e.g., during form submissions or API calls) that is then directly used to update entity properties without proper filtering or validation. If entity properties are not correctly configured to prevent mass assignment, an attacker can modify properties they should not have access to, potentially altering application state, bypassing business logic, or even escalating privileges in some scenarios.
*   **Impact:**
    *   Data Corruption: Modifying data fields with incorrect or unauthorized values, leading to data integrity issues.
    *   Unauthorized Data Modification: Changing data that the user should not have permission to alter, potentially violating business rules.
    *   Privilege Escalation (Potentially): In specific cases, attackers might be able to modify user roles or permissions if these are managed as entity properties and are vulnerable to mass assignment.
*   **Affected ORM Component:**
    *   Entity properties defined with `@Column` annotation (if not properly configured to control update access)
    *   `Doctrine\ORM\EntityManager` (when persisting or updating entities, especially using methods like `merge()` with untrusted data)
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Explicitly Control Property Updates:**  Carefully define which entity properties can be modified during updates. Avoid blindly accepting and applying all user-provided data to entities.
    *   **Data Transfer Objects (DTOs):**  Utilize DTOs to receive and validate input data. Map only validated and allowed data from DTOs to entity properties.
    *   **Input Validation and Filtering:** Implement robust input validation and filtering to ensure only expected and permitted data is used to update entities.
    *   **Avoid Direct Binding of Request Data to Entities:**  Do not directly bind request data to entities without validation and filtering steps in between.
    *   **Use `$em->persist()` for New Entities and `$em->merge()` with Caution:** Understand the difference between `$em->persist()` and `$em->merge()`. Be particularly cautious when using `$em->merge()` with untrusted data, as it can update existing entities based on provided data, potentially leading to mass assignment issues if not handled carefully.

