# Attack Surface Analysis for typeorm/typeorm

## Attack Surface: [SQL Injection via Raw SQL Queries](./attack_surfaces/sql_injection_via_raw_sql_queries.md)

**Description:** Attackers inject malicious SQL code into raw queries executed by the application, allowing them to manipulate the database.

**TypeORM Contribution:** TypeORM's `query()` and `createQueryRunner().query()` methods enable execution of raw SQL. Unsanitized user input in these queries creates SQL injection vulnerabilities.

**Example:**
```typescript
const userId = req.params.id; // User-provided input
const rawQuery = `SELECT * FROM users WHERE id = ${userId}`; // Vulnerable concatenation
const user = await connection.query(rawQuery);
```
An attacker could use `userId` like `'1 OR 1=1--'` to bypass intended filtering.

**Impact:** Critical. Full database compromise, data breach, data manipulation, data deletion, denial of service.

**Risk Severity:** Critical.

**Mitigation Strategies:**
*   **Prioritize `QueryBuilder` and Repository Methods:** Use TypeORM's abstractions for safer query construction.
*   **Parameterize Raw SQL:** When raw SQL is necessary, always use parameterized queries to separate SQL code and user input.
*   **Input Validation and Sanitization:** Validate and sanitize all user inputs before using them in any queries.

## Attack Surface: [SQL Injection via Dynamic Query Builder Construction](./attack_surfaces/sql_injection_via_dynamic_query_builder_construction.md)

**Description:**  SQL injection vulnerabilities arising from dynamically building `QueryBuilder` queries with unsanitized user input in conditions.

**TypeORM Contribution:** `QueryBuilder`'s flexibility can be misused if user input is directly concatenated into `where`, `andWhere`, etc., leading to injection.

**Example:**
```typescript
const username = req.query.username; // User-provided input
const users = await userRepository.createQueryBuilder("user")
    .where("user.username = '" + username + "'") // Vulnerable concatenation
    .getMany();
```
An attacker could use `username` like `'admin' OR '1'='1'` to bypass username checks.

**Impact:** Critical. Database compromise, data breach, unauthorized data access, data manipulation, denial of service.

**Risk Severity:** Critical.

**Mitigation Strategies:**
*   **Use Parameterized Conditions in `QueryBuilder`:** Utilize parameter placeholders (`:paramName`) and `setParameters()` for safe input integration.
*   **Input Validation and Sanitization:** Validate and sanitize user inputs before using them in `QueryBuilder` conditions.
*   **Prefer `FindOptionsWhere` for Simple Queries:** For basic finds, `FindOptionsWhere` offers safer object-based condition specification.

## Attack Surface: [Mass Assignment Vulnerabilities](./attack_surfaces/mass_assignment_vulnerabilities.md)

**Description:** Attackers modify unintended entity properties by providing extra parameters in data payloads used for entity creation or updates.

**TypeORM Contribution:** TypeORM's `save()` method automatically populates entity properties from input objects. Unprotected entities are vulnerable to mass assignment.

**Example:**
```typescript
class User {
    id: number;
    username: string;
    isAdmin: boolean; // Sensitive property
}

async updateUser(req: Request, res: Response) {
    const user = await userRepository.findOneBy({ id: req.params.id });
    Object.assign(user, req.body); // Mass assignment
    await userRepository.save(user);
}
```
An attacker could send `PUT /users/1 { "username": "hacker", "isAdmin": true }` to potentially gain admin privileges.

**Impact:** High. Privilege escalation, unauthorized data modification, data integrity issues.

**Risk Severity:** High.

**Mitigation Strategies:**
*   **Use DTOs (Data Transfer Objects):** Define strict DTOs to control allowed input fields for entity operations.
*   **Explicitly Define Allowed Fields:**  Map request data to DTOs and then to entities, controlling property updates.
*   **Guard Properties with Access Control:** Implement authorization checks before entity updates.
*   **Readonly Properties:** Mark sensitive entity properties as `readonly` to prevent direct mass assignment.

## Attack Surface: [Eager Loading Over-fetching and Data Exposure](./attack_surfaces/eager_loading_over-fetching_and_data_exposure.md)

**Description:** Eager loading relationships can unintentionally fetch and expose sensitive data from related entities that users are not authorized to access.

**TypeORM Contribution:** TypeORM's `relations` option and eager loading configurations can lead to over-fetching if not managed carefully, exposing related data.

**Example:**
```typescript
class User {
    id: number;
    username: string;
    @OneToMany(() => Secret, secret => secret.user, { eager: true })
    secrets: Secret[]; // Sensitive secrets are eagerly loaded
}

async getUser(req: Request, res: Response) {
    const user = await userRepository.findOneBy({ id: req.params.id });
    res.send(user); // Secrets are included in response, potentially unauthorized
}
```
Publicly accessible `getUser` endpoint might expose sensitive `secrets` data due to eager loading.

**Impact:** Medium to High. Data breach, sensitive information disclosure, performance degradation.

**Risk Severity:** High (when sensitive data is exposed).

**Mitigation Strategies:**
*   **Prefer Lazy Loading:** Use lazy loading by default and eager load only when necessary.
*   **Control Eager Loading Explicitly:** Use `relations` option in find operations to specify relationships to load as needed.
*   **Projection and Select Statements:** Use `select` options or `QueryBuilder`'s `select()` to fetch only required fields.
*   **Authorization Filtering on Relationships:** Implement authorization checks to filter related data based on user permissions.

