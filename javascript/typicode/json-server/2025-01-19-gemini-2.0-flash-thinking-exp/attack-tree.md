# Attack Tree Analysis for typicode/json-server

Objective: Gain Unauthorized Control or Access to Application Data by Exploiting `json-server` Weaknesses.

## Attack Tree Visualization

```
*   ***Achieve Attacker's Goal*** [CRITICAL NODE]
    *   ***Exploit Lack of Authentication/Authorization*** [CRITICAL NODE]
        *   ***Modify Data Without Authorization***
            *   Send Malicious PUT/POST/DELETE Requests
        *   ***Read Sensitive Data Without Authorization***
            *   Send Unauthorized GET Requests
    *   ***Exploit Default Settings and Lack of Security Features*** [CRITICAL NODE]
        *   ***Access Debugging/Development Endpoints (if enabled)***
            *   Access `/__rules`, `/__db` endpoints
```


## Attack Tree Path: [Critical Node: Achieve Attacker's Goal](./attack_tree_paths/critical_node_achieve_attacker's_goal.md)

This represents the successful culmination of any of the high-risk paths.

*   **Impact:** Full control over the application's data, potential for further exploitation of the application or underlying infrastructure.

## Attack Tree Path: [Critical Node: Exploit Lack of Authentication/Authorization](./attack_tree_paths/critical_node_exploit_lack_of_authenticationauthorization.md)

This fundamental vulnerability allows attackers to bypass access controls.

*   **Impact:** Enables unauthorized data modification, retrieval, and deletion.

## Attack Tree Path: [High-Risk Path: Modify Data Without Authorization](./attack_tree_paths/high-risk_path_modify_data_without_authorization.md)

*   **Attack Vector: Send Malicious PUT/POST/DELETE Requests**
    *   **How:** Due to the absence of authentication, an attacker can directly send HTTP PUT, POST, or DELETE requests to modify, create, or delete data in the `db.json` file.
    *   **Likelihood:** High - trivial to execute.
    *   **Impact:** High - data manipulation, corruption, or deletion.
    *   **Effort:** Low - requires basic HTTP tools (e.g., `curl`, browser developer tools).
    *   **Skill Level:** Low - basic understanding of HTTP.
    *   **Detection Difficulty:** Medium - depends on monitoring of write operations.

## Attack Tree Path: [High-Risk Path: Read Sensitive Data Without Authorization](./attack_tree_paths/high-risk_path_read_sensitive_data_without_authorization.md)

*   **Attack Vector: Send Unauthorized GET Requests**
    *   **How:** Without authentication, any attacker can send HTTP GET requests to retrieve data from the `db.json` file.
    *   **Likelihood:** High - trivial to execute.
    *   **Impact:** High - exposure of potentially sensitive data.
    *   **Effort:** Low - requires basic HTTP tools (e.g., `curl`, browser).
    *   **Skill Level:** Low - basic understanding of HTTP.
    *   **Detection Difficulty:** Medium - depends on monitoring of data access patterns.

## Attack Tree Path: [Critical Node: Exploit Default Settings and Lack of Security Features](./attack_tree_paths/critical_node_exploit_default_settings_and_lack_of_security_features.md)

This highlights the risks associated with using `json-server` in its default, insecure configuration.

*   **Impact:** Information disclosure, potential for further exploitation.

## Attack Tree Path: [High-Risk Path: Access Debugging/Development Endpoints (if enabled)](./attack_tree_paths/high-risk_path_access_debuggingdevelopment_endpoints__if_enabled_.md)

*   **Attack Vector: Access `/__rules`, `/__db` endpoints**
    *   **How:** If left enabled, these endpoints provide direct access to the routing rules (`/__rules`) and the entire database content (`/__db`).
    *   **Likelihood:** Medium - depends on whether these endpoints are inadvertently left enabled in production.
    *   **Impact:** High - full disclosure of database content and routing logic.
    *   **Effort:** Low - requires knowing the endpoint URLs and using a web browser or HTTP tool.
    *   **Skill Level:** Low-Medium - requires understanding of URL structures.
    *   **Detection Difficulty:** Medium - access to these specific endpoints can be monitored.

