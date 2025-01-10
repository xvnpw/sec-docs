# Threat Model Analysis for typeorm/typeorm

## Threat: [SQL Injection via Raw Queries](./threats/sql_injection_via_raw_queries.md)

* **Description:** An attacker crafts malicious SQL code within user-supplied input that is then directly embedded into a raw SQL query executed using TypeORM's `query()` method. This allows the attacker to bypass application logic and directly interact with the database. They might read sensitive data, modify data, delete data, or even execute administrative commands on the database server.
* **Impact:** Data breach (confidentiality loss), data manipulation (integrity loss), data deletion (availability loss), potential for privilege escalation on the database.
* **Affected TypeORM Component:** `QueryRunner` (specifically the `query()` method).
* **Risk Severity:** Critical
* **Mitigation Strategies:**
    * **Never directly embed user input into raw SQL queries.**
    * **Always use parameterized queries (also known as prepared statements) with placeholders for user-provided values when using the `query()` method.** TypeORM supports parameter binding for raw queries.
    * **Sanitize and validate user input on the application layer before using it in database queries, even with parameterized queries (as a defense in depth).**

## Threat: [SQL Injection via Unsafe Query Builder Usage](./threats/sql_injection_via_unsafe_query_builder_usage.md)

* **Description:** An attacker manipulates user input that is directly incorporated into the conditions or parameters of a query built using TypeORM's Query Builder without proper sanitization or parameterization. This can lead to the execution of unintended SQL queries, similar to raw SQL injection. For example, manipulating the `where` clause or `orderBy` clause.
* **Impact:** Data breach, data manipulation, data deletion, potential for privilege escalation on the database.
* **Affected TypeORM Component:** `QueryBuilder` (specifically methods like `where`, `andWhere`, `orWhere`, `orderBy`, `setParameter`, but improper usage is the main issue).
* **Risk Severity:** High
* **Mitigation Strategies:**
    * **Avoid directly embedding user input into Query Builder methods that construct SQL conditions.**
    * **Utilize the Query Builder's parameter binding features (e.g., using objects as conditions or the `setParameter()` method) to safely incorporate user input.**
    * **Sanitize and validate user input on the application layer before using it in Query Builder methods.**
    * **Be cautious when using dynamic query building based on user input and ensure proper escaping or parameterization.**

## Threat: [Schema Manipulation via Synchronization in Production](./threats/schema_manipulation_via_synchronization_in_production.md)

* **Description:** If the `synchronize: true` option is enabled in the TypeORM configuration in a production environment, TypeORM will automatically alter the database schema to match the defined entities upon application startup. An attacker who gains control over the application's configuration or code could potentially modify entity definitions and cause unintended changes to the database schema, potentially leading to data loss or security vulnerabilities.
* **Impact:** Data loss (availability loss), potential introduction of security vulnerabilities through schema changes.
* **Affected TypeORM Component:** `Connection` (specifically the `synchronize` option).
* **Risk Severity:** Critical
* **Mitigation Strategies:**
    * **Never enable `synchronize: true` in production environments.**
    * **Use database migrations for managing schema changes in a controlled and versioned manner.** TypeORM provides migration tools.

