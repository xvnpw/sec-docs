# Attack Surface Analysis for typeorm/typeorm

## Attack Surface: [SQL Injection via Raw Queries](./attack_surfaces/sql_injection_via_raw_queries.md)

*   **Description:** Attackers can inject malicious SQL code into database queries, potentially leading to unauthorized data access, modification, or deletion.
    *   **How TypeORM Contributes:** The `query()` method allows developers to execute raw SQL strings directly. If these strings are constructed using unsanitized user input, it creates an entry point for SQL injection.
    *   **Example:**
        ```typescript
        const userId = req.params.id; // User-provided input
        const users = await connection.query(`SELECT * FROM users WHERE id = ${userId}`); // Vulnerable
        ```
    *   **Impact:** Critical. Complete database compromise, data breaches, data manipulation, and potential denial of service.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Always use parameterized queries:** Utilize TypeORM's query builder or repository methods with parameter binding.
        *   **Avoid the `query()` method with user input:** If raw SQL is absolutely necessary, sanitize and validate input rigorously or use parameterized queries within the `query()` method.

## Attack Surface: [SQL Injection via `createQueryBuilder` with Unsafe Input](./attack_surfaces/sql_injection_via__createquerybuilder__with_unsafe_input.md)

*   **Description:** Even when using the query builder, improper handling of user input when constructing conditions can lead to SQL injection.
    *   **How TypeORM Contributes:**  Dynamically building `where` clauses or other parts of the query using string concatenation with user input bypasses TypeORM's built-in protection.
    *   **Example:**
        ```typescript
        const searchParam = req.query.search; // User-provided input
        const users = await userRepository
          .createQueryBuilder('user')
          .where(`user.name LIKE '%${searchParam}%'`) // Vulnerable
          .getMany();
        ```
    *   **Impact:** Critical. Similar to raw query SQL injection, leading to database compromise.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Use parameter binding with `createQueryBuilder`:** Utilize the `.where('user.name LIKE :name', { name: `%${searchParam}%` })` syntax.
        *   **Avoid string concatenation for dynamic conditions:**  Use the query builder's methods for constructing conditions safely.

## Attack Surface: [Mass Assignment Vulnerability](./attack_surfaces/mass_assignment_vulnerability.md)

*   **Description:** Attackers can modify unintended entity properties by providing extra data during create or update operations.
    *   **How TypeORM Contributes:** If entities are not explicitly protected, TypeORM will map incoming data to entity properties based on matching names, potentially allowing modification of sensitive fields.
    *   **Example:**
        ```typescript
        // User entity with an isAdmin property
        const userData = req.body; // Request body might contain isAdmin: true
        const newUser = userRepository.create(userData); // If isAdmin is not protected, it might be set
        await userRepository.save(newUser);
        ```
    *   **Impact:** High. Privilege escalation, unauthorized data modification, and potential bypass of business logic.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Use `@Allow` and `@Exclude` decorators:** Explicitly define which properties can be mass-assigned.
        *   **Utilize Data Transfer Objects (DTOs):** Create specific DTOs for input data to control which fields are accepted and mapped to entities.
        *   **Avoid directly passing request bodies to `create` or `save`:** Sanitize and validate input before mapping to entities.

## Attack Surface: [Unintended Schema Changes with `synchronize: true` in Production](./attack_surfaces/unintended_schema_changes_with__synchronize_true__in_production.md)

*   **Description:** Enabling `synchronize: true` in production can lead to unintended database schema modifications or data loss if the application logic or TypeORM configuration is flawed or manipulated.
    *   **How TypeORM Contributes:** TypeORM automatically attempts to synchronize the database schema with the defined entities when `synchronize: true` is enabled.
    *   **Example:** A code change introduces a new entity property, and upon deployment, TypeORM automatically alters the database table, potentially causing data loss if not handled carefully.
    *   **Impact:** High. Data loss, application instability, and potential service disruption.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Never use `synchronize: true` in production environments.**
        *   **Utilize database migrations:** Implement and manage database schema changes using TypeORM's migration feature or other migration tools.
        *   **Review and test migrations thoroughly before applying them to production.**

