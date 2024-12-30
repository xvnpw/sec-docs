```
Title: High-Risk Attack Sub-Tree for Doctrine ORM

Objective: Compromise Application Using Doctrine ORM Vulnerabilities

Sub-Tree:

└── Compromise Application via Doctrine ORM
    ├── Gain Unauthorized Data Access [HIGH RISK PATH]
    │   ├── Exploit SQL Injection Vulnerabilities [CRITICAL NODE]
    │   │   ├── DQL Injection [CRITICAL NODE]
    │   │   │   ├── Manipulate WHERE clauses
    │   │   │   ├── Inject subqueries
    │   │   ├── Native SQL Injection [CRITICAL NODE]
    │   │   │   └── Directly inject malicious SQL into native queries
    ├── Manipulate Application State [HIGH RISK PATH]
    │   ├── Data Modification via Injection [CRITICAL NODE]
    │   │   ├── DQL Injection (UPDATE/DELETE) [CRITICAL NODE]
    │   │   ├── Native SQL Injection (UPDATE/DELETE) [CRITICAL NODE]

Detailed Breakdown of Attack Vectors for High-Risk Paths and Critical Nodes:

High-Risk Path 1: Gain Unauthorized Data Access via SQL Injection

* Attack Vector: DQL Injection (Manipulate WHERE clauses)
    * Description: Attacker crafts malicious input that is incorporated into a Doctrine Query Language (DQL) query's WHERE clause without proper sanitization or parameterization.
    * Goal: Bypass intended access controls and retrieve data the attacker is not authorized to see.
    * Example: Modifying a query like `SELECT u FROM User u WHERE u.username = :username` to `SELECT u FROM User u WHERE u.username = 'admin' OR '1'='1'` to retrieve all user data.

* Attack Vector: DQL Injection (Inject subqueries)
    * Description: Attacker injects malicious subqueries into a DQL statement.
    * Goal: Execute arbitrary SQL queries against the database, potentially extracting data from other tables or performing other unauthorized actions.
    * Example: Injecting a subquery like `SELECT u FROM User u WHERE u.id IN (SELECT id FROM AdminUsers)` to retrieve data from a restricted table.

* Attack Vector: Native SQL Injection
    * Description: If the application uses native SQL queries and incorporates user-provided input without proper sanitization or parameterization, an attacker can inject arbitrary SQL commands.
    * Goal: Gain direct access to the database and execute any SQL command, including data retrieval, modification, or even dropping tables.
    * Example: In a native query like `SELECT * FROM users WHERE username = '"+userInput+"'`, injecting `'; DROP TABLE users; --` to delete the users table.

High-Risk Path 2: Manipulate Application State via Data Modification through Injection

* Attack Vector: DQL Injection (UPDATE/DELETE)
    * Description: Similar to data access, but the attacker crafts malicious input to modify or delete data using DQL UPDATE or DELETE statements.
    * Goal: Alter application state, corrupt data, or delete records.
    * Example: Injecting into an update query like `UPDATE Product p SET p.price = :price WHERE p.id = :id` to set the price to an extremely low value for all products.

* Attack Vector: Native SQL Injection (UPDATE/DELETE)
    * Description: Injecting malicious SQL into native UPDATE or DELETE queries.
    * Goal: Directly modify or delete data in the database.
    * Example: In a native delete query like `DELETE FROM orders WHERE order_id = '"+userInput+"'`, injecting `' OR '1'='1'` to delete all orders.

Critical Nodes Breakdown:

* DQL Injection:
    * Description: Exploiting vulnerabilities in the construction of DQL queries where user input is not properly handled.
    * Impact: Can lead to unauthorized data access, data modification, or even privilege escalation depending on the injected commands.

* Native SQL Injection:
    * Description: Exploiting vulnerabilities when using raw SQL queries, allowing attackers to execute arbitrary SQL commands.
    * Impact: Grants the attacker full control over the database, leading to critical data breaches, data manipulation, or denial of service.

* DQL Injection (UPDATE/DELETE):
    * Description: Specifically targeting DQL update and delete operations to manipulate data.
    * Impact: Can result in data corruption, loss of data integrity, or unauthorized modification of application state.

* Native SQL Injection (UPDATE/DELETE):
    * Description: Similar to general native SQL injection, but specifically used to modify or delete data.
    * Impact: Direct and potentially irreversible changes to the database, leading to significant data loss or corruption.
