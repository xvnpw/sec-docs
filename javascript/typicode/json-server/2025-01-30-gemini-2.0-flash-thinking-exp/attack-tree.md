# Attack Tree Analysis for typicode/json-server

Objective: Compromise Application via `json-server` Exploitation (High-Risk Paths)

## Attack Tree Visualization

[HIGH RISK] Compromise Application via json-server Exploitation [HIGH RISK]
├───(OR) [HIGH RISK] 1. Exploit Data Exposure Vulnerabilities [HIGH RISK]
│   └───(AND) [HIGH RISK] 1.1. Unauthorized Data Access via Default API Endpoints [HIGH RISK]
│       └───(OR) [HIGH RISK] 1.1.1. Direct Access to Sensitive Data [HIGH RISK]
│           └───(AND) 1.1.1.2. Send GET requests to retrieve data [HIGH RISK]
├───(OR) [HIGH RISK] 2. Exploit Data Manipulation Vulnerabilities [HIGH RISK]
│   └───(AND) [HIGH RISK] 2.1. Unauthorized Data Modification via Default API Endpoints [HIGH RISK]
│       ├───(OR) [HIGH RISK] 2.1.1. Modify Existing Data [HIGH RISK]
│       │   └───(AND) 2.1.1.2. Send PUT/PATCH requests with malicious data [HIGH RISK]
│       ├───(OR) [HIGH RISK] 2.1.2. Create New Data [HIGH RISK]
│       │   └───(AND) 2.1.2.2. Send POST request with malicious data [HIGH RISK]
│       └───(OR) [HIGH RISK] 2.1.3. Delete Existing Data [HIGH RISK]
│           └───(AND) 2.1.3.2. Send DELETE requests to remove critical data [HIGH RISK]
└───(OR) [HIGH RISK] 4. Exploit Insecure Defaults and Lack of Security Features [HIGH RISK]
    └───(AND) [HIGH RISK] 4.1. Lack of Authentication and Authorization [HIGH RISK]
        └───(AND) [HIGH RISK] 4.1.2. Perform unauthorized actions (read, write, delete data) [HIGH RISK]

## Attack Tree Path: [1. Exploit Data Exposure Vulnerabilities (High Risk)](./attack_tree_paths/1__exploit_data_exposure_vulnerabilities__high_risk_.md)

*   **1.1. Unauthorized Data Access via Default API Endpoints (High Risk):**
    *   **Attack Vector:** `json-server` by default exposes all data from `db.json` through RESTful API endpoints without any authentication. If sensitive data is present in `db.json` and the `json-server` instance is accessible (even unintentionally), attackers can directly retrieve this data.
    *   **1.1.1. Direct Access to Sensitive Data (High Risk):**
        *   **Attack Step:**
            *   **1.1.1.2. Send GET requests to retrieve data (High Risk):**
                *   **Description:** Attackers send HTTP GET requests to predictable or discovered API endpoints (e.g., `/users`, `/secrets`, `/admin`).
                *   **Likelihood:** High
                *   **Impact:** High (if sensitive data is exposed, such as user credentials, API keys, personal information)
                *   **Effort:** Low
                *   **Skill Level:** Low
                *   **Detection Difficulty:** Low (easily logged, but high volume might obscure individual requests).
        *   **Example Scenario:** An attacker discovers a publicly accessible development server running `json-server`. They guess the endpoint `/users` and send a GET request to `http://vulnerable-server.example.com/users`. The server responds with a JSON array containing user data from `db.json`, including usernames and passwords.

## Attack Tree Path: [2. Exploit Data Manipulation Vulnerabilities (High Risk)](./attack_tree_paths/2__exploit_data_manipulation_vulnerabilities__high_risk_.md)

*   **2.1. Unauthorized Data Modification via Default API Endpoints (High Risk):**
    *   **Attack Vector:** `json-server` allows full CRUD operations (Create, Read, Update, Delete) on the data in `db.json` via default API endpoints, without any authentication or authorization. This allows attackers to modify, create, or delete data.
    *   **2.1.1. Modify Existing Data (High Risk):**
        *   **Attack Step:**
            *   **2.1.1.2. Send PUT/PATCH requests with malicious data (High Risk):**
                *   **Description:** Attackers send HTTP PUT or PATCH requests to API endpoints (e.g., `/posts/1`) with modified JSON data in the request body.
                *   **Likelihood:** High (if unauthorized access is gained)
                *   **Impact:** Medium to High (data corruption, data poisoning, application malfunction if downstream applications rely on this data)
                *   **Effort:** Low
                *   **Skill Level:** Low
                *   **Detection Difficulty:** Medium (requires monitoring data changes and API modification requests).
        *   **Example Scenario:** An attacker wants to deface a demo application using `json-server` as a backend. They send a PUT request to `http://vulnerable-server.example.com/posts/1` with modified content for post ID 1, changing the title and body to malicious or defacement content.

    *   **2.1.2. Create New Data (High Risk):**
        *   **Attack Step:**
            *   **2.1.2.2. Send POST request with malicious data (High Risk):**
                *   **Description:** Attackers send HTTP POST requests to API endpoints (e.g., `/posts`) with malicious JSON data in the request body.
                *   **Likelihood:** High (if unauthorized access is gained)
                *   **Impact:** Medium to High (data poisoning, potential injection of XSS payloads if data is displayed in a web application, downstream application issues)
                *   **Effort:** Low
                *   **Skill Level:** Low
                *   **Detection Difficulty:** Medium (requires monitoring data content and API creation requests).
        *   **Example Scenario:** An attacker injects an XSS payload into the `db.json` by sending a POST request to `http://vulnerable-server.example.com/comments` with a comment containing `<script>alert('XSS')</script>`. When a user views the comments section of the application, the XSS payload executes.

    *   **2.1.3. Delete Existing Data (High Risk):**
        *   **Attack Step:**
            *   **2.1.3.2. Send DELETE requests to remove critical data (High Risk):**
                *   **Description:** Attackers send HTTP DELETE requests to API endpoints (e.g., `/posts/1`) to remove data records.
                *   **Likelihood:** Medium (less common attacker goal than modification, but possible for sabotage or disruption)
                *   **Impact:** Medium (data loss, service disruption, application malfunction if critical data is deleted)
                *   **Effort:** Low
                *   **Skill Level:** Low
                *   **Detection Difficulty:** Medium (requires monitoring data changes and API deletion requests).
        *   **Example Scenario:** An attacker wants to disrupt a demo application. They send DELETE requests to `http://vulnerable-server.example.com/posts` for all post IDs, effectively removing all blog posts from the application.

## Attack Tree Path: [4. Exploit Insecure Defaults and Lack of Security Features (High Risk)](./attack_tree_paths/4__exploit_insecure_defaults_and_lack_of_security_features__high_risk_.md)

*   **4.1. Lack of Authentication and Authorization (High Risk):**
    *   **Attack Vector:** `json-server` is designed for development and prototyping and intentionally omits authentication and authorization features. This is the fundamental security flaw that enables all other high-risk attacks.
    *   **4.1.2. Perform unauthorized actions (read, write, delete data) (High Risk):**
        *   **Description:** Due to the lack of authentication and authorization, any attacker who can reach the `json-server` API can perform any CRUD operation on the data.
        *   **Likelihood:** High (inherent to `json-server`'s design)
                *   **Impact:** High (enables all data exposure and manipulation attacks listed above)
        *   **Effort:** None (this is the default behavior)
        *   **Skill Level:** None (no special skills required)
        *   **Detection Difficulty:** Very Low (this is not an attack to detect, but the *cause* of vulnerability).
        *   **Example Scenario:**  Because `json-server` has no authentication, anyone on the network (or internet if exposed) can access the API and perform any action they want on the data, leading to data breaches, data corruption, or denial of service.

