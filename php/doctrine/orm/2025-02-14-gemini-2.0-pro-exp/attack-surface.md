# Attack Surface Analysis for doctrine/orm

## Attack Surface: [SQL Injection (Indirect)](./attack_surfaces/sql_injection__indirect_.md)

*   **Description:** Exploitation of vulnerabilities where user-supplied data is incorporated into database queries without proper sanitization, allowing attackers to execute arbitrary SQL commands.
    *   **ORM Contribution:** Doctrine *aims* to prevent SQL injection, but incorrect usage (bypassing its protective mechanisms) creates vulnerabilities. The ORM provides tools that, if misused, *directly* lead to injection. This is the core issue.
    *   **Example:**
        ```php
        // VULNERABLE: Concatenating user input directly into DQL
        $username = $_GET['username']; // Untrusted input
        $query = $entityManager->createQuery("SELECT u FROM MyEntity u WHERE u.username = '" . $username . "'");
        $user = $query->getSingleResult();

        // CORRECT: Using setParameter()
        $username = $_GET['username']; // Untrusted input
        $query = $entityManager->createQuery("SELECT u FROM MyEntity u WHERE u.username = :username");
        $query->setParameter('username', $username);
        $user = $query->getSingleResult();
        ```
    *   **Impact:**
        *   Data breaches (reading sensitive data).
        *   Data modification (altering or deleting data).
        *   Database server compromise (in severe cases).
        *   Complete application takeover.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Always use the QueryBuilder and `setParameter()`:** This is the *primary* and most effective defense.  Never concatenate user input into DQL or SQL strings.
        *   **Avoid raw SQL queries whenever possible:** If raw SQL is unavoidable, use prepared statements *within* the raw SQL and bind parameters meticulously.
        *   **Validate and whitelist all user input:** Even if using `setParameter()`, validate input types and lengths.  Whitelist allowed values where possible (e.g., for sort order options).
        *   **Escape special characters in `LIKE` clauses (if manual construction is unavoidable):** Use `Connection::quote()` or equivalent, but prefer the QueryBuilder's built-in handling.
        *   **Review custom DQL functions:** Ensure they are properly parameterized and do not introduce injection vulnerabilities.

## Attack Surface: [Data Exposure / Information Disclosure](./attack_surfaces/data_exposure__information_disclosure.md)

*   **Description:** Unintentional leakage of sensitive data due to improper handling of database interactions or error conditions.
    *   **ORM Contribution:** Doctrine's features (lazy loading, hydration, error messages) can, if misused, *directly* expose more data than intended. The ORM's mechanisms are the source of the potential exposure.
    *   **Example:**
        ```php
        // VULNERABLE: Returning an entire entity to the frontend
        $user = $entityManager->find(User::class, $userId);
        return new JsonResponse($user); // Exposes all User fields, potentially including sensitive ones

        // BETTER: Using a DTO (Data Transfer Object)
        $user = $entityManager->find(User::class, $userId);
        $userDto = new UserDto($user->getId(), $user->getUsername()); // Only expose ID and username
        return new JsonResponse($userDto);

        // OR: Using SELECT to fetch only specific fields
        $query = $entityManager->createQuery('SELECT u.id, u.username FROM MyEntity u WHERE u.id = :id');
        $query->setParameter('id', $userId);
        $userData = $query->getResult();
        return new JsonResponse($userData);
        ```
    *   **Impact:**
        *   Exposure of sensitive user data (passwords, PII, etc.).
        *   Revelation of database schema details.
        *   Facilitation of other attacks (e.g., SQL injection).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Use `select()` to fetch only necessary fields:** Avoid fetching entire entities when only a subset of data is needed.
        *   **Manage lazy loading carefully:** Be aware of when and where lazy loading occurs.  Consider eager loading or DTOs for sensitive associations.
        *   **Disable detailed error messages and the Doctrine profiler in production:** These can reveal sensitive information.
        *   **Use DTOs or serialization groups:** Control which fields are exposed when serializing entities (e.g., to JSON).
        *   **Implement strong access controls:** Ensure users can only access data they are authorized to see.

## Attack Surface: [Object Injection (Unlikely, but Possible)](./attack_surfaces/object_injection__unlikely__but_possible_.md)

*   **Description:**  Injection of malicious objects through unsafe deserialization, potentially leading to arbitrary code execution.
    *   **ORM Contribution:**  Highly unlikely with default Doctrine configurations, but a misconfiguration or unusual usage pattern could theoretically create a vulnerability *directly* related to how Doctrine hydrates objects.
    *   **Example:**  An application deserializes user-provided data (e.g., from a form submission or API request) and uses that data to hydrate a Doctrine entity *without* validation.
    *   **Impact:**
        *   Arbitrary code execution.
        *   Complete application compromise.
    *   **Risk Severity:** Critical (but low probability)
    *   **Mitigation Strategies:**
        *   **Avoid deserializing untrusted data directly into Doctrine entities.**
        *   **Use a safe serialization format (like JSON) and validate the data *before* hydrating entities.**
        *   **If PHP's native serialization is absolutely necessary, ensure it's *only* used with trusted data.**

