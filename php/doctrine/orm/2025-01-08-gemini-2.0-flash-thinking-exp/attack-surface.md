# Attack Surface Analysis for doctrine/orm

## Attack Surface: [Doctrine Query Language (DQL) Injection](./attack_surfaces/doctrine_query_language__dql__injection.md)

*   **How ORM Contributes to the Attack Surface:** Doctrine uses its own query language, DQL, which is similar to SQL but operates on entities and their properties. Constructing DQL queries by directly embedding user input without proper sanitization allows attackers to inject malicious DQL code. This is a direct consequence of using Doctrine's query building mechanisms.
    *   **Example:**  A search functionality that builds a DQL query like: `$entityManager->createQuery("SELECT u FROM App\Entity\User u WHERE u.username LIKE '%" . $_GET['search'] . "%'")->getResult();`. An attacker could input `%' OR 1=1 --` to bypass the intended query logic.
    *   **Impact:** Unauthorized data access, modification, or deletion. Potential for complete database compromise depending on database privileges.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Always use parameter binding:**  Pass user input as parameters to DQL queries instead of directly embedding them in the query string. Doctrine handles the necessary escaping. Example: `$entityManager->createQuery("SELECT u FROM App\Entity\User u WHERE u.username LIKE :username")->setParameter('username', '%' . $_GET['search'] . '%')->getResult();`

## Attack Surface: [Native SQL Injection](./attack_surfaces/native_sql_injection.md)

*   **How ORM Contributes to the Attack Surface:** While Doctrine provides an abstraction layer, developers can still execute native SQL queries using `$entityManager->getConnection()->executeQuery()`. If user input is directly concatenated into these native SQL queries without proper escaping, it becomes vulnerable to traditional SQL injection. This occurs when developers bypass Doctrine's abstraction and directly interact with the database connection provided by the ORM.
    *   **Example:** `$connection->executeQuery("SELECT * FROM users WHERE username = '" . $_GET['username'] . "'");`. An attacker could input `' OR '1'='1` to bypass authentication.
    *   **Impact:** Unauthorized data access, modification, or deletion. Potential for complete database compromise.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Prefer DQL with parameter binding:**  Whenever possible, use DQL with parameter binding instead of native SQL queries.
        *   **Use prepared statements with parameter binding for native queries:** When native SQL is necessary, use prepared statements and bind parameters to prevent SQL injection. Example: `$stmt = $connection->prepare("SELECT * FROM users WHERE username = :username"); $stmt->bindValue('username', $_GET['username']); $stmt->execute();`

## Attack Surface: [Mass Assignment Vulnerabilities](./attack_surfaces/mass_assignment_vulnerabilities.md)

*   **How ORM Contributes to the Attack Surface:** Doctrine allows setting entity properties directly from user input, for example, when handling form submissions. If not carefully controlled, attackers can potentially modify unintended entity properties, including sensitive attributes or relationships. This is a direct consequence of how Doctrine manages entity state and allows data population.
    *   **Example:**  A form submission directly updates a `User` entity: `$user->setUsername($_POST['username']); $user->setRoles($_POST['roles']);`. If the form includes a `roles` field and it's not properly protected, an attacker could elevate their privileges.
    *   **Impact:** Data corruption, privilege escalation, unauthorized modification of application state.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Use form handling libraries with whitelisting:**  Utilize form handling components (like Symfony Forms) that allow defining which fields can be bound to entity properties, effectively whitelisting allowed input.
        *   **Explicitly set allowed properties:**  Instead of directly binding all input, explicitly set only the intended properties.
        *   **Implement proper authorization checks:**  Ensure users have the necessary permissions to modify the properties they are attempting to change.

## Attack Surface: [Schema Tool Misuse in Production](./attack_surfaces/schema_tool_misuse_in_production.md)

*   **How ORM Contributes to the Attack Surface:** Doctrine's Schema Tool can automatically update the database schema based on entity definitions. If an attacker gains unauthorized access to this functionality in a production environment, they could potentially alter the database structure, leading to data loss, corruption, or the introduction of vulnerabilities. This risk is directly tied to the powerful schema management capabilities provided by Doctrine.
    *   **Example:** An attacker gains access to a deployment script that uses the Schema Tool to update the database. They could modify the entity definitions to add new columns or tables that facilitate data exfiltration.
    *   **Impact:** Data loss, data corruption, introduction of new vulnerabilities, denial of service.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Restrict access to the Schema Tool in production:**  The Schema Tool should generally not be used directly in production environments. Use database migrations for schema changes.
        *   **Implement secure deployment pipelines:**  Ensure that deployment processes are secure and prevent unauthorized modification of deployment scripts.
        *   **Use database migrations for schema changes:** Database migrations provide a controlled and versioned way to manage schema changes, reducing the risk of accidental or malicious modifications.

