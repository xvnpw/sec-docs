# Attack Tree Analysis for typicode/json-server

Objective: Compromise Application Using typicode/json-server

## Attack Tree Visualization

```
Compromise Application Using typicode/json-server [CRITICAL NODE]
└── [HIGH RISK PATH] Exploit Lack of Authentication/Authorization [CRITICAL NODE]
    ├── [HIGH RISK PATH] Bypass Non-Existent Authentication
    │   └── [HIGH RISK PATH] Access Sensitive Data Without Credentials [CRITICAL NODE]
    └── [HIGH RISK PATH] Modify Data Without Authorization [CRITICAL NODE]
        ├── [HIGH RISK PATH] Create Unauthorized Resources (POST)
        ├── [HIGH RISK PATH] Update Existing Resources Without Authorization (PUT/PATCH)
        └── [HIGH RISK PATH] Delete Resources Without Authorization (DELETE)
└── [HIGH RISK PATH] Exploit Default Behaviors and Configurations [CRITICAL NODE]
    └── [HIGH RISK PATH] Access Database File Directly (If Accessible) [CRITICAL NODE]
        └── [HIGH RISK PATH] Read or Modify the `db.json` File [CRITICAL NODE]
```


## Attack Tree Path: [Compromise Application Using typicode/json-server [CRITICAL NODE]](./attack_tree_paths/compromise_application_using_typicodejson-server__critical_node_.md)

* **Compromise Application Using typicode/json-server [CRITICAL NODE]:**
    * This is the ultimate goal of the attacker and represents a successful breach of the application's security.

## Attack Tree Path: [[HIGH RISK PATH] Exploit Lack of Authentication/Authorization [CRITICAL NODE]](./attack_tree_paths/_high_risk_path__exploit_lack_of_authenticationauthorization__critical_node_.md)

* **[HIGH RISK PATH] Exploit Lack of Authentication/Authorization [CRITICAL NODE]:**
    * **Attack Vector:**  `json-server` does not implement any authentication or authorization mechanisms by default.
    * **How it works:** An attacker can directly interact with the API endpoints without providing any credentials or proving they have the necessary permissions.
    * **Why it's high-risk:** This is a fundamental security flaw that allows for widespread unauthorized access and modification of data.

## Attack Tree Path: [[HIGH RISK PATH] Bypass Non-Existent Authentication](./attack_tree_paths/_high_risk_path__bypass_non-existent_authentication.md)

    * **[HIGH RISK PATH] Bypass Non-Existent Authentication:**
        * **Attack Vector:** Since no authentication is required, the attacker simply makes requests to the API endpoints.
        * **How it works:** The attacker sends HTTP requests to access resources without needing to authenticate.
        * **Why it's high-risk:** It's trivial to exploit due to the complete absence of security measures.

## Attack Tree Path: [[HIGH RISK PATH] Access Sensitive Data Without Credentials [CRITICAL NODE]](./attack_tree_paths/_high_risk_path__access_sensitive_data_without_credentials__critical_node_.md)

        * **[HIGH RISK PATH] Access Sensitive Data Without Credentials [CRITICAL NODE]:**
            * **Attack Vector:**  Accessing data through GET requests to API endpoints.
            * **How it works:** Attackers can retrieve data by sending GET requests to the relevant API endpoints, potentially exposing sensitive information.
            * **Why it's high-risk:** Leads to a direct breach of data confidentiality.

## Attack Tree Path: [[HIGH RISK PATH] Modify Data Without Authorization [CRITICAL NODE]](./attack_tree_paths/_high_risk_path__modify_data_without_authorization__critical_node_.md)

    * **[HIGH RISK PATH] Modify Data Without Authorization [CRITICAL NODE]:**
        * **Attack Vector:** Using POST, PUT, PATCH, and DELETE requests to manipulate data.
        * **How it works:** Attackers can create, update, or delete resources by sending appropriately crafted HTTP requests without authorization.
        * **Why it's high-risk:** Leads to data corruption, manipulation of application state, and potential data loss.

## Attack Tree Path: [[HIGH RISK PATH] Create Unauthorized Resources (POST)](./attack_tree_paths/_high_risk_path__create_unauthorized_resources__post_.md)

        * **[HIGH RISK PATH] Create Unauthorized Resources (POST):**
            * **Attack Vector:** Sending POST requests to create new data entries.
            * **How it works:** Attackers can add arbitrary data to the application's dataset.
            * **Why it's high-risk:** Can lead to data pollution and potentially disrupt application logic.

## Attack Tree Path: [[HIGH RISK PATH] Update Existing Resources Without Authorization (PUT/PATCH)](./attack_tree_paths/_high_risk_path__update_existing_resources_without_authorization__putpatch_.md)

        * **[HIGH RISK PATH] Update Existing Resources Without Authorization (PUT/PATCH):**
            * **Attack Vector:** Sending PUT or PATCH requests to modify existing data entries.
            * **How it works:** Attackers can alter existing data, potentially corrupting information or manipulating application behavior.
            * **Why it's high-risk:** Can lead to data integrity issues and business logic errors.

## Attack Tree Path: [[HIGH RISK PATH] Delete Resources Without Authorization (DELETE)](./attack_tree_paths/_high_risk_path__delete_resources_without_authorization__delete_.md)

        * **[HIGH RISK PATH] Delete Resources Without Authorization (DELETE):**
            * **Attack Vector:** Sending DELETE requests to remove data entries.
            * **How it works:** Attackers can delete data, leading to data loss and disruption of application functionality.
            * **Why it's high-risk:** Results in irreversible data loss and potential service disruption.

## Attack Tree Path: [[HIGH RISK PATH] Exploit Default Behaviors and Configurations [CRITICAL NODE]](./attack_tree_paths/_high_risk_path__exploit_default_behaviors_and_configurations__critical_node_.md)

* **[HIGH RISK PATH] Exploit Default Behaviors and Configurations [CRITICAL NODE]:**
    * **Attack Vector:** Relying on default configurations that may expose the underlying data file.
    * **How it works:** If the `db.json` file is accessible due to misconfiguration, attackers can directly interact with it.
    * **Why it's high-risk:** Bypasses the API entirely, granting direct access to the raw data.

## Attack Tree Path: [[HIGH RISK PATH] Access Database File Directly (If Accessible) [CRITICAL NODE]](./attack_tree_paths/_high_risk_path__access_database_file_directly__if_accessible___critical_node_.md)

    * **[HIGH RISK PATH] Access Database File Directly (If Accessible) [CRITICAL NODE]:**
        * **Attack Vector:** Directly accessing the `db.json` file on the server's file system.
        * **How it works:** If the file is accessible through web server misconfiguration or insecure file permissions, attackers can read or modify it.
        * **Why it's high-risk:** Provides complete access to the application's data.

## Attack Tree Path: [[HIGH RISK PATH] Read or Modify the `db.json` File [CRITICAL NODE]](./attack_tree_paths/_high_risk_path__read_or_modify_the__db_json__file__critical_node_.md)

        * **[HIGH RISK PATH] Read or Modify the `db.json` File [CRITICAL NODE]:**
            * **Attack Vector:** Reading the file to exfiltrate data or modifying it to inject or alter information.
            * **How it works:** Attackers can download the `db.json` file to read its contents or upload a modified version to manipulate the data.
            * **Why it's high-risk:** Leads to a complete data breach or allows for arbitrary data manipulation.

