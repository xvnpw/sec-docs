# Attack Surface Analysis for hibernate/hibernate-orm

## Attack Surface: [HQL/JPQL Injection](./attack_surfaces/hqljpql_injection.md)

*   **Description:** Attackers inject malicious HQL or JPQL code into input fields or parameters that are then used to construct database queries. This allows them to bypass application logic, access unauthorized data, modify data, or even execute arbitrary database commands.
    *   **How Hibernate-ORM Contributes:** Hibernate executes the provided HQL/JPQL queries. If these queries are built by concatenating user-supplied input without proper sanitization or parameterization, it creates a direct pathway for injection attacks.
    *   **Example:** An application has a search functionality where users can search for products by name. The following vulnerable code might be used:
        ```java
        String productName = request.getParameter("productName");
        String hql = "FROM Product WHERE name = '" + productName + "'";
        List<Product> products = session.createQuery(hql).list();
        ```
        An attacker could input `' OR 1=1 --` as the `productName`, resulting in the query `FROM Product WHERE name = '' OR 1=1 --'`, which would return all products.
    *   **Impact:** Critical. Complete compromise of data confidentiality, integrity, and availability. Potential for remote code execution on the database server in some scenarios.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Always use parameterized queries:** Utilize Hibernate's parameter binding features (e.g., `createQuery("FROM Product WHERE name = :name").setParameter("name", productName)`) to ensure user input is treated as data, not executable code.
        *   **Input validation and sanitization:** While parameterization is the primary defense, validate and sanitize user input to prevent unexpected characters or malicious patterns.

## Attack Surface: [Native SQL Injection](./attack_surfaces/native_sql_injection.md)

*   **Description:** Similar to HQL/JPQL injection, but occurs when using Hibernate's `createSQLQuery` method to execute native SQL queries constructed with unsanitized user input.
    *   **How Hibernate-ORM Contributes:** Hibernate provides the functionality to execute raw SQL queries. If these queries are dynamically built with user input, Hibernate facilitates the execution of potentially malicious SQL.
    *   **Example:**
        ```java
        String tableName = request.getParameter("tableName");
        String sql = "SELECT * FROM " + tableName;
        List<?> results = session.createSQLQuery(sql).list();
        ```
        An attacker could input `users; DROP TABLE products; --` as the `tableName`, potentially leading to data loss.
    *   **Impact:** Critical. Similar to HQL/JPQL injection, with the potential for more direct database manipulation due to the nature of native SQL.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Avoid dynamic construction of native SQL queries based on user input whenever possible.**
        *   **If absolutely necessary, use parameterized queries with `createSQLQuery`:**  Utilize named parameters and bind user input to them.
        *   **Strict input validation and sanitization:** Thoroughly validate and sanitize any user input used in native SQL queries.

## Attack Surface: [Insecure Handling of Dynamic Entity/Table Names](./attack_surfaces/insecure_handling_of_dynamic_entitytable_names.md)

*   **Description:** When entity or table names are dynamically determined based on user input without proper validation, attackers can manipulate these names to access or modify unintended data.
    *   **How Hibernate-ORM Contributes:** Hibernate allows for dynamic entity and table names in certain configurations or through reflection-based approaches. If user input directly influences this process, it creates a vulnerability.
    *   **Example:** An application allows users to access data from different "databases" based on their input:
        ```java
        String databaseName = request.getParameter("dbName");
        String hql = "FROM " + databaseName + ".User"; // Vulnerable
        List<?> users = session.createQuery(hql).list();
        ```
        An attacker could input a sensitive table name instead of a valid "database" name.
    *   **Impact:** High. Unauthorized access to sensitive data, potential for data modification or deletion depending on database permissions.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Avoid dynamic entity/table names based on direct user input.**
        *   **Use whitelisting:** If dynamic names are necessary, strictly validate user input against a predefined list of allowed names.

## Attack Surface: [Insecure Configuration and Externalized Properties](./attack_surfaces/insecure_configuration_and_externalized_properties.md)

*   **Description:** Sensitive information, such as database credentials, is stored in configuration files (e.g., `hibernate.cfg.xml`, `persistence.xml`) or environment variables without proper protection.
    *   **How Hibernate-ORM Contributes:** Hibernate relies on these configuration files to establish database connections. If these files are accessible or contain plain-text credentials, it creates a significant security risk.
    *   **Example:** A `hibernate.cfg.xml` file contains:
        ```xml
        <property name="hibernate.connection.username">admin</property>
        <property name="hibernate.connection.password">password123</property>
        ```
        If this file is accessible through a web server misconfiguration or compromised system, attackers can obtain database credentials.
    *   **Impact:** Critical. Full compromise of the database, allowing attackers to access, modify, or delete all data.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Never store plain-text credentials in configuration files.**
        *   **Use secure credential management solutions:** Employ environment variables, vault services (like HashiCorp Vault), or encrypted configuration files.
        *   **Restrict access to configuration files:** Ensure only authorized personnel and processes can access these files.

