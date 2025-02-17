# Attack Tree Analysis for typeorm/typeorm

Objective: To gain unauthorized access to, modify, or delete data within the database managed by TypeORM, or to cause a denial-of-service (DoS) condition specifically leveraging TypeORM's functionality.

## Attack Tree Visualization

```
                                     Compromise Application Data/Functionality via TypeORM
                                                    |
        ---------------------------------------------------------------------------------
        |                                                               |
  1. Unauthorized Data Access/Modification                               2. Denial of Service (DoS)
        |
  -------------------------                                       -------------------------
  |                       |                                       |
1.1 SQL Injection   1.2  Bypassing (Omitted as not                  2.1 Connection Pool
    (via TypeORM)     entirely High-Risk)                             Exhaustion [HIGH RISK]
        |                                                               |
  ------- -------                                               ------- -------
  |     | |     |                                               |             |
1.1.1 1.1.2 1.1.3                                             2.1.1         2.1.2
Raw   Find  Query                                               Config        Slow/
Query  One/  Builder                                             Flaw          Complex
Flaws  Many  Flaws                                               Allowing      Queries
[CRIT] Flaws [HIGH                                               Too Many      (Many
[HIGH  RISK]                                                     Connections   Connections)
RISK]

```

## Attack Tree Path: [1. Unauthorized Data Access/Modification](./attack_tree_paths/1__unauthorized_data_accessmodification.md)

*   **1.1 SQL Injection (via TypeORM)**

    *   **1.1.1 Raw Query Flaws `[CRITICAL]` `[HIGH RISK]`**
        *   **Description:** The attacker exploits vulnerabilities in the application's use of TypeORM's `query()` method by injecting malicious SQL code through unsanitized user input. TypeORM does *not* automatically sanitize raw queries.
        *   **How it works:**
            1.  The application accepts user input (e.g., from a form field, URL parameter, API request).
            2.  This input is directly concatenated into a raw SQL query string without proper sanitization or parameterization.
            3.  The `query()` method is called with the malicious SQL string.
            4.  The database server executes the injected SQL code, potentially granting the attacker unauthorized access to data, allowing them to modify or delete data, or even execute arbitrary commands on the database server.
        *   **Example:**
            ```javascript
            // Vulnerable Code:
            const userInput = req.query.username; // Unsanitized user input
            const query = `SELECT * FROM users WHERE username = '${userInput}'`;
            const result = await connection.query(query);

            // Attacker Input:  '; DROP TABLE users; --
            // Resulting Query: SELECT * FROM users WHERE username = ''; DROP TABLE users; --'
            ```
        *   **Mitigation:**
            *   **Never use `query()` with unsanitized user input.** This is the most crucial mitigation.
            *   Always use parameterized queries or the QueryBuilder.
            *   Implement strict input validation and sanitization.

    *   **1.1.2 `findOne`/`findMany` Flaws `[HIGH RISK]`**
        *   **Description:** The attacker exploits vulnerabilities in how the application uses TypeORM's `findOne`, `findMany`, and related methods (e.g., `find`, `findByIds`) by injecting malicious SQL code through unsanitized user input within the `where` clause (or other options like `order`, `select`).
        *   **How it works:**
            1.  The application accepts user input.
            2.  This input is used to construct the `where` clause (or other options) of a `findOne`/`findMany` call without proper escaping or parameterization.  Direct string concatenation is the most common culprit.
            3.  TypeORM translates the options into a SQL query. If the input is crafted maliciously, it can alter the intended query logic.
            4.  The database server executes the modified query.
        *   **Example:**
            ```javascript
            // Vulnerable Code:
            const userInput = req.query.id; // Unsanitized user input
            const user = await connection.getRepository(User).findOne({
                where: `id = ${userInput}` // Vulnerable: Direct concatenation
            });

            // Attacker Input:  1 OR 1=1
            // Resulting (approximate) Query: SELECT * FROM users WHERE id = 1 OR 1=1
            ```
        *   **Mitigation:**
            *   Always use parameterized queries within the `where` clause (and other options).
            *   Use the object notation for `where` clauses whenever possible:
                ```javascript
                // Safer:
                const user = await connection.getRepository(User).findOne({
                    where: { id: userInput } // TypeORM handles parameterization
                });
                ```
            *   Implement strict input validation and sanitization.

    *   **1.1.3 Query Builder Flaws `[HIGH RISK]`**
        *   **Description:** Similar to `findOne`/`findMany` flaws, the attacker exploits vulnerabilities in the application's use of TypeORM's QueryBuilder API by injecting malicious SQL code through unsanitized user input in methods like `where`, `andWhere`, `orWhere`, `orderBy`, etc.
        *   **How it works:**
            1.  The application accepts user input.
            2.  This input is directly concatenated into parts of the query being built using the QueryBuilder, without proper escaping or parameterization.
            3.  TypeORM constructs the SQL query from the QueryBuilder calls.
            4.  The database server executes the modified query.
        *   **Example:**
            ```javascript
            // Vulnerable Code:
            const userInput = req.query.sortOrder; // Unsanitized user input
            const users = await connection.getRepository(User)
                .createQueryBuilder("user")
                .orderBy(`user.name ${userInput}`) // Vulnerable: Direct concatenation
                .getMany();

            // Attacker Input:  ; DROP TABLE users; --
            ```
        *   **Mitigation:**
            *   Always use parameterized queries with the QueryBuilder:
                ```javascript
                // Safer:
                const users = await connection.getRepository(User)
                    .createQueryBuilder("user")
                    .orderBy("user.name", userInput) // TypeORM handles parameterization (for ASC/DESC)
                    .getMany();
                ```
                Or, for more complex cases:
                ```javascript
                const users = await connection.getRepository(User)
                    .createQueryBuilder("user")
                    .orderBy("user.name", "ASC") // Hardcode safe values
                    .addOrderBy("user.id", userInput) // Parameterize if needed
                    .getMany();
                ```
            *   Implement strict input validation and sanitization, especially for values used in `orderBy`, `groupBy`, etc.

## Attack Tree Path: [2. Denial of Service (DoS)](./attack_tree_paths/2__denial_of_service__dos_.md)

*   **2.1 Connection Pool Exhaustion `[HIGH RISK]`**
    *   **Description:** The attacker overwhelms the application's database connection pool, preventing legitimate users from accessing the application.
    *   **How it works (General):**
        1.  The attacker sends a large number of requests to the application.
        2.  Each request requires a database connection.
        3.  If the number of concurrent requests exceeds the connection pool's maximum size, new requests will be blocked or fail until connections become available.
        4.  If the attacker can sustain a high rate of requests, the application becomes unavailable to legitimate users.

    *   **2.1.1 Configuration Flaw Allowing Too Many Connections:**
        *   **Description:** The TypeORM connection pool is misconfigured with an excessively large maximum number of connections.
        *   **How it works (Specific):** The attacker exploits the large connection pool size by opening many connections simultaneously, potentially exhausting resources on the *database server* itself, even if the application server has resources to spare.
        *   **Mitigation:** Configure the connection pool with a reasonable `max` value based on expected load and database server capacity.

    *   **2.1.2 Slow/Complex Queries (Many Connections):**
        *   **Description:** The attacker triggers the execution of many slow or complex database queries, holding connections open for extended periods and exhausting the connection pool.
        *   **How it works (Specific):**
            1.  The attacker identifies or crafts input that results in slow or resource-intensive database queries.
            2.  The attacker sends many requests with this malicious input.
            3.  Each request holds a database connection open for a long time while the slow query executes.
            4.  The connection pool is quickly exhausted.
        *   **Mitigation:**
            *   Optimize database queries. Use indexes, avoid full table scans, and carefully design your data model.
            *   Implement query timeouts.
            *   Implement rate limiting and request throttling.

