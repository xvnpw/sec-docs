# Attack Tree Analysis for dotnet/efcore

Objective: Compromise Application via EF Core Vulnerabilities **[CRITICAL NODE]**

## Attack Tree Visualization

Attack Goal: Compromise Application via EF Core Vulnerabilities **[CRITICAL NODE]**
    └── **[HIGH-RISK PATH]** 1. Exploit Data Access Vulnerabilities **[CRITICAL NODE]**
        ├── **[HIGH-RISK PATH]** 1.1. SQL Injection Attacks **[CRITICAL NODE]**
        │   ├── **[HIGH-RISK PATH]** 1.1.1. Raw SQL Query Injection **[CRITICAL NODE]**
        │   │   └── **[HIGH-RISK PATH]** 1.1.1.1. Execute Malicious SQL via `FromSqlRaw`, `ExecuteSqlRaw` **[CRITICAL NODE]**
        ├── **[HIGH-RISK PATH]** 1.2. Insecure Direct Object Reference (IDOR) via Data Access **[CRITICAL NODE]**
        │   └── **[HIGH-RISK PATH]** 1.2.1. Access or Modify Data of Other Users **[CRITICAL NODE]**
        │       └── **[HIGH-RISK PATH]** 1.2.1.1. Manipulate entity IDs in requests to access unauthorized data (e.g., `/api/orders/{orderId}`) **[CRITICAL NODE]**
        └── **[HIGH-RISK PATH]** 1.3. Mass Assignment Vulnerabilities **[CRITICAL NODE]**
            └── **[HIGH-RISK PATH]** 1.3.1. Modify Unintended Properties **[CRITICAL NODE]**
                └── **[HIGH-RISK PATH]** 1.3.1.1. Send requests with unexpected properties to modify sensitive or protected data fields during entity updates/creates **[CRITICAL NODE]**

## Attack Tree Path: [1. Attack Goal: Compromise Application via EF Core Vulnerabilities [CRITICAL NODE]](./attack_tree_paths/1__attack_goal_compromise_application_via_ef_core_vulnerabilities__critical_node_.md)

*   **Description:** The ultimate objective of the attacker is to successfully compromise the application by exploiting weaknesses related to EF Core. This could involve gaining unauthorized access to data, manipulating data, or disrupting application functionality.

## Attack Tree Path: [2. [HIGH-RISK PATH] 1. Exploit Data Access Vulnerabilities [CRITICAL NODE]](./attack_tree_paths/2___high-risk_path__1__exploit_data_access_vulnerabilities__critical_node_.md)

*   **Description:** This is a primary attack vector focusing on weaknesses in how the application accesses data using EF Core. Successful exploitation allows attackers to bypass intended data access controls.
*   **Attack Vectors:**
    *   SQL Injection Attacks
    *   Insecure Direct Object Reference (IDOR) via Data Access
    *   Mass Assignment Vulnerabilities

## Attack Tree Path: [3. [HIGH-RISK PATH] 1.1. SQL Injection Attacks [CRITICAL NODE]](./attack_tree_paths/3___high-risk_path__1_1__sql_injection_attacks__critical_node_.md)

*   **Description:** Exploiting vulnerabilities that allow attackers to inject malicious SQL code into database queries executed by EF Core. This can lead to complete database compromise.
*   **Attack Vectors:**
    *   Raw SQL Query Injection
    *   (Less likely in High-Risk category, but still a concern) LINQ Injection
    *   (Less likely in High-Risk category, but still a concern if used) Stored Procedure Injection
    *   (Less likely in High-Risk category, but still a concern) Blind SQL Injection

## Attack Tree Path: [4. [HIGH-RISK PATH] 1.1.1. Raw SQL Query Injection [CRITICAL NODE]](./attack_tree_paths/4___high-risk_path__1_1_1__raw_sql_query_injection__critical_node_.md)

*   **Description:**  Specifically targeting the use of raw SQL methods in EF Core (like `FromSqlRaw`, `ExecuteSqlRaw`, `SqlQuery`) where developers might concatenate user input directly into SQL strings without proper parameterization.
*   **Attack Vectors:**
    *   **[HIGH-RISK PATH] 1.1.1.1. Execute Malicious SQL via `FromSqlRaw`, `ExecuteSqlRaw` [CRITICAL NODE]:**
        *   **Description:** Attackers craft malicious input that, when concatenated into raw SQL queries, alters the query's logic.
        *   **Example:**  An attacker could inject SQL code into a username field used in a `FromSqlRaw` query to bypass authentication or retrieve all user data.
        *   **Impact:** Critical - Full database compromise, data breach, data manipulation, denial of service.

## Attack Tree Path: [5. [HIGH-RISK PATH] 1.2. Insecure Direct Object Reference (IDOR) via Data Access [CRITICAL NODE]](./attack_tree_paths/5___high-risk_path__1_2__insecure_direct_object_reference__idor__via_data_access__critical_node_.md)

*   **Description:** Exploiting vulnerabilities where the application exposes direct references to database objects (entity IDs) in URLs or API endpoints without proper authorization.
*   **Attack Vectors:**
    *   **[HIGH-RISK PATH] 1.2.1. Access or Modify Data of Other Users [CRITICAL NODE]:**
        *   **Description:** Attackers attempt to access or modify data belonging to other users by manipulating entity IDs in requests.
        *   **Attack Vectors:**
            *   **[HIGH-RISK PATH] 1.2.1.1. Manipulate entity IDs in requests to access unauthorized data (e.g., `/api/orders/{orderId}`) [CRITICAL NODE]:**
                *   **Description:** Attackers change the `orderId` in a URL like `/api/orders/{orderId}` to access orders belonging to other users if authorization is not properly implemented.
                *   **Example:**  Changing `/api/orders/123` to `/api/orders/456` to view another user's order details.
                *   **Impact:** Medium-High - Unauthorized data access, potential data modification, privacy violation.

## Attack Tree Path: [6. [HIGH-RISK PATH] 1.3. Mass Assignment Vulnerabilities [CRITICAL NODE]](./attack_tree_paths/6___high-risk_path__1_3__mass_assignment_vulnerabilities__critical_node_.md)

*   **Description:** Exploiting vulnerabilities where the application blindly accepts and assigns user-provided data to entity properties during create or update operations without proper filtering or whitelisting.
*   **Attack Vectors:**
    *   **[HIGH-RISK PATH] 1.3.1. Modify Unintended Properties [CRITICAL NODE]:**
        *   **Description:** Attackers send requests with unexpected properties to modify sensitive or protected data fields during entity updates or creations.
        *   **Attack Vectors:**
            *   **[HIGH-RISK PATH] 1.3.1.1. Send requests with unexpected properties to modify sensitive or protected data fields during entity updates/creates [CRITICAL NODE]:**
                *   **Description:**  Submitting extra fields in a JSON payload during an update request, hoping to modify properties like `IsAdmin` or `Salary` that should not be user-editable.
                *   **Example:** Sending a request to update user profile with a JSON body like `{ "name": "John Doe", "isAdmin": true }` when `isAdmin` should only be modified by administrators.
                *   **Impact:** Medium-High - Unauthorized data modification, privilege escalation, data integrity violation.

