# Attack Surface Analysis for jetbrains/exposed

## Attack Surface: [SQL Injection Vulnerabilities](./attack_surfaces/sql_injection_vulnerabilities.md)

* **Description:** Attackers inject malicious SQL code into database queries, potentially leading to unauthorized data access, modification, or deletion.
    * **How Exposed Contributes to the Attack Surface:**
        * **Raw SQL Queries:** Exposed allows developers to execute raw SQL queries using `SqlExpressionBuilder.raw()`. If user input is directly incorporated into these raw queries without proper sanitization or parameterization, it creates a direct path for SQL injection.
        * **Dynamic Query Construction with String Interpolation:** While Exposed encourages using its DSL, developers might inadvertently use string interpolation to build parts of queries dynamically, especially when dealing with complex or less common scenarios. This can bypass Exposed's built-in protection mechanisms.
        * **Incorrect Usage of Parameter Binding:** Even when using Exposed's DSL, incorrect assumptions about how parameters are handled or improper usage of functions can lead to vulnerabilities if user input is not treated as a parameter.
    * **Example:**
    ```kotlin
    // Vulnerable code using raw SQL with string interpolation
    fun findUserByName(name: String): ResultRow? = transaction {
        Users.select(SqlExpressionBuilder.raw("name = '$name'")).singleOrNull()
    }

    // Attacker input: ' OR 1=1 --
    // Resulting SQL: SELECT ... FROM users WHERE name = ''' OR 1=1 --'
    ```
    * **Impact:** Full database compromise, data breach, data manipulation, denial of service.
    * **Risk Severity:** Critical.
    * **Mitigation Strategies:**
        * **Prefer Exposed's DSL:** Utilize Exposed's type-safe DSL for query construction whenever possible. This inherently parameterizes values, reducing the risk of SQL injection.
        * **Avoid Raw SQL:** Minimize the use of `SqlExpressionBuilder.raw()`. If absolutely necessary, ensure all user-provided data is properly parameterized.
        * **Use Parameterized Queries with Raw SQL:** When using raw SQL, utilize parameter binding mechanisms provided by Exposed (e.g., passing arguments to `raw()`).

## Attack Surface: [Schema Manipulation Vulnerabilities (Indirect)](./attack_surfaces/schema_manipulation_vulnerabilities__indirect_.md)

* **Description:**  Attackers exploit vulnerabilities in the application's logic related to schema management, potentially leading to unauthorized modifications of the database structure.
    * **How Exposed Contributes to the Attack Surface:**
        * **Schema DSL:** Exposed provides a DSL for defining and modifying database schemas. If the application logic incorrectly uses this DSL based on untrusted input or without proper authorization, it can lead to schema manipulation.
    * **Example:**
    ```kotlin
    // Vulnerable code allowing schema modification based on user input (highly discouraged)
    fun createTable(tableName: String) = transaction {
        SchemaUtils.create(object : Table(tableName) {
            val id = integer("id").autoIncrement()
            override val primaryKey = PrimaryKey(id)
        })
    }
    ```
    * **Impact:** Data loss, data corruption, denial of service, potential execution of arbitrary code depending on the database system.
    * **Risk Severity:** High.
    * **Mitigation Strategies:**
        * **Restrict Schema Modification Privileges:** The database user used by the application should generally not have permissions to modify the schema in production environments.
        * **Secure Schema Migration Process:** Implement a secure and reviewed process for applying schema migrations. Avoid automating migrations based on untrusted input.

## Attack Surface: [Authorization Bypass (Indirect)](./attack_surfaces/authorization_bypass__indirect_.md)

* **Description:** Attackers bypass authorization checks in the application logic to access or manipulate data they are not authorized to.
    * **How Exposed Contributes to the Attack Surface:**
        * **Data Access Layer:** Exposed provides the tools for data access. If the application logic relies solely on Exposed for data retrieval without implementing proper authorization checks based on user roles or permissions, vulnerabilities can arise.
        * **Incorrectly Scoped Queries:**  Developers might write queries that retrieve more data than necessary, potentially exposing sensitive information even if the initial access was authorized.
    * **Example:**
    ```kotlin
    // Vulnerable code lacking authorization checks
    fun getUserProfile(userId: Int): ResultRow? = transaction {
        Users.select { Users.id eq userId }.singleOrNull()
    }
    // No check to ensure the currently logged-in user is allowed to view this profile.
    ```
    * **Impact:** Unauthorized access to sensitive data, potential data breaches, modification of data without proper authorization.
    * **Risk Severity:** High.
    * **Mitigation Strategies:**
        * **Implement Robust Authorization Checks:** Implement authorization logic within the application layer to verify user permissions before accessing data using Exposed.
        * **Scope Queries Appropriately:** Ensure queries only retrieve the necessary data based on the current user's permissions.

