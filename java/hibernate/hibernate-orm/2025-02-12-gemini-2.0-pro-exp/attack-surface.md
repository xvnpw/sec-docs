# Attack Surface Analysis for hibernate/hibernate-orm

## Attack Surface: [HQL/JPQL Injection](./attack_surfaces/hqljpql_injection.md)

*   **Description:** Exploitation of vulnerabilities in Hibernate Query Language (HQL) or Java Persistence Query Language (JPQL) queries, allowing attackers to manipulate query logic and potentially access, modify, or delete data. This is the ORM equivalent of SQL injection.
*   **How Hibernate-ORM Contributes:** Hibernate *introduces* HQL/JPQL as query languages.  Without Hibernate, this specific attack vector wouldn't exist.
*   **Example:**
    ```java
    // Vulnerable code:
    String userInput = request.getParameter("username");
    String hql = "FROM User u WHERE u.username = '" + userInput + "'";
    Query query = session.createQuery(hql);
    List<User> users = query.list();
    ```
    An attacker supplying `' OR '1'='1` for `username` would retrieve all users.
*   **Impact:**
    *   Unauthorized data access.
    *   Data modification.
    *   Data deletion.
    *   Potential database compromise.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Parameterized Queries (Mandatory):** *Always* use parameterized queries:
        ```java
        String userInput = request.getParameter("username");
        String hql = "FROM User u WHERE u.username = :username";
        Query query = session.createQuery(hql);
        query.setParameter("username", userInput);
        List<User> users = query.list();
        ```
    *   **Named Queries (Recommended):** Use named queries with parameters.
    *   **Criteria API (Used Safely):** Ensure all user input is treated as parameters and type-checked.
    *   **Input Validation (Defense in Depth):** Validate input *before* it reaches Hibernate.
    * **Avoid dynamic HQL/JPQL:** Avoid building HQL/JPQL queries dynamically based on user input.

## Attack Surface: [Second-Level Cache Poisoning](./attack_surfaces/second-level_cache_poisoning.md)

*   **Description:** Attackers manipulate data within Hibernate's second-level cache, injecting malicious data that will be served to other users.
*   **How Hibernate-ORM Contributes:** The second-level cache is a *core feature* of Hibernate ORM.  The vulnerability arises from how Hibernate manages this cache.
*   **Example:**
    An application caches entity objects. If an attacker can modify an entity (e.g., a `User` object with elevated privileges) and get that modified entity stored in the cache, subsequent requests might retrieve the attacker-controlled, privileged object, bypassing security checks.
*   **Impact:**
    *   Serving incorrect/malicious data.
    *   Bypassing security checks (if cached objects are used in authorization).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Strict Input Validation (Paramount):** Validate *all* data *before* it is used to populate the cache.
    *   **Cache Key Control:** Ensure cache keys are not user-controllable.
    *   **Secure Deserialization (If Applicable):** Use robust deserialization safeguards if using a distributed cache with serialization.
    *   **Cache Eviction Policies:** Configure appropriate eviction policies.

## Attack Surface: [Filter Manipulation](./attack_surfaces/filter_manipulation.md)

*   **Description:** Exploitation of vulnerabilities in Hibernate filters, allowing attackers to manipulate query logic and potentially access, modify, or delete data.
*   **How Hibernate-ORM Contributes:** Hibernate provides filters as a way to add additional WHERE clauses to queries. Improper use opens the door to injection.
*   **Example:**
    ```java
    //Vulnerable code
    String userInput = request.getParameter("age");
    session.enableFilter("ageFilter").setParameter("age", userInput);
    ```
    If user provides input `1); DROP TABLE users; --` it will lead to SQL injection.
*   **Impact:**
    *   Unauthorized data access (reading sensitive data).
    *   Data modification.
    *   Data deletion.
    *   Potential for complete database compromise.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Parameterized Queries (Mandatory):** Always use parameterized queries:
        ```java
        String userInput = request.getParameter("age");
        session.enableFilter("ageFilter").setParameter("age", Integer.valueOf(userInput));
        ```
    *   **Input Validation (Defense in Depth):** Validate all user input at the application level *before* it reaches Hibernate.
    * **Avoid dynamic filter condition:** Avoid building filter condition dynamically based on user input.

