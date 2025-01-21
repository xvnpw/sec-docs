# Attack Tree Analysis for hanami/hanami

Objective: Compromise Hanami Application via Hanami-Specific Vulnerabilities

## Attack Tree Visualization

```
* Compromise Hanami Application
    * AND
        * Exploit Action Vulnerabilities
            * **[HIGH RISK PATH]** Mass Assignment Vulnerability **[CRITICAL NODE]**
            * **[HIGH RISK PATH]** Missing or Insufficient Authorization in Actions **[CRITICAL NODE]**
        * Exploit View/Template Rendering Vulnerabilities
            * **[HIGH RISK PATH]** Server-Side Template Injection (SSTI) **[CRITICAL NODE]**
        * Exploit Data Layer (Entities/Repositories) Vulnerabilities
            * **[HIGH RISK PATH]** ORM Injection via Repository Manipulation **[CRITICAL NODE]**
        * Exploit Configuration and Deployment Vulnerabilities Specific to Hanami
            * **[HIGH RISK PATH]** Exposure of Sensitive Configuration Data **[CRITICAL NODE]**
```


## Attack Tree Path: [Mass Assignment Vulnerability [HIGH RISK PATH] [CRITICAL NODE]](./attack_tree_paths/mass_assignment_vulnerability__high_risk_path___critical_node_.md)

**Attack Vector:** Attackers can include unexpected parameters in a request. If the Hanami action directly uses these parameters to update model attributes without proper filtering or whitelisting, malicious data can be injected. This leverages Hanami's data mapping capabilities against the application.
    * **Risk:** This is a high-risk path because it has a medium likelihood of occurrence (developers might inadvertently trust request data) and can lead to a moderate to significant impact, potentially allowing attackers to modify sensitive data or escalate privileges. It's a critical node due to the direct impact on data integrity and potential for unauthorized actions.
    * **Mitigation:**  The primary mitigation is to avoid directly using request parameters to update model attributes. Implement strong parameter filtering and use explicit attribute assignment, only allowing expected parameters.

## Attack Tree Path: [Missing or Insufficient Authorization in Actions [HIGH RISK PATH] [CRITICAL NODE]](./attack_tree_paths/missing_or_insufficient_authorization_in_actions__high_risk_path___critical_node_.md)

**Attack Vector:** Attackers can attempt to access Hanami actions without proper authorization checks. This exploits potential oversights in how authorization is implemented or enforced within the application's action lifecycle.
    * **Risk:** This is a high-risk path due to its medium likelihood (developers might forget or incorrectly implement authorization checks) and significant impact. Successful exploitation can grant unauthorized access to sensitive functionalities and data. It's a critical node because it directly undermines access control mechanisms.
    * **Mitigation:** Implement robust authorization checks within each Hanami action. Utilize Hanami's provided mechanisms or custom solutions to verify user permissions before allowing access to sensitive resources or functionalities.

## Attack Tree Path: [Server-Side Template Injection (SSTI) [HIGH RISK PATH] [CRITICAL NODE]](./attack_tree_paths/server-side_template_injection__ssti___high_risk_path___critical_node_.md)

**Attack Vector:** Attackers can inject malicious code into template variables that are not properly escaped by Hanami's rendering engine (like ERB or Haml). If user-provided data is directly embedded into templates without sanitization, the template engine will interpret and execute the injected code on the server.
    * **Risk:** This is a high-risk path because, while the likelihood might be lower depending on developer practices, the impact is critical. Successful exploitation can lead to remote code execution, allowing the attacker to gain complete control over the server. It's a critical node due to this severe potential impact.
    * **Mitigation:**  Always escape user-provided data when rendering it in templates. Be extremely cautious when using `raw` or similar unescaped output methods. Regularly update template engine dependencies to patch known vulnerabilities.

## Attack Tree Path: [ORM Injection via Repository Manipulation [HIGH RISK PATH] [CRITICAL NODE]](./attack_tree_paths/orm_injection_via_repository_manipulation__high_risk_path___critical_node_.md)

**Attack Vector:** Attackers can craft malicious input that, when processed by Hanami's repository layer (using ROM), leads to unintended database queries or modifications. This is similar to SQL injection but specific to the ORM layer.
    * **Risk:** This is a high-risk path with a low to medium likelihood (depending on how repositories are implemented) but a significant to critical impact. Successful exploitation can lead to data breaches, data manipulation, or even complete database compromise. It's a critical node due to the potential for severe database-related damage.
    * **Mitigation:** Avoid constructing dynamic database queries based on user input within Hanami repositories. Utilize parameterized queries or ROM's query builder securely to prevent the injection of malicious SQL.

## Attack Tree Path: [Exposure of Sensitive Configuration Data [HIGH RISK PATH] [CRITICAL NODE]](./attack_tree_paths/exposure_of_sensitive_configuration_data__high_risk_path___critical_node_.md)

**Attack Vector:** Attackers can gain access to configuration files or environment variables managed by Hanami that contain sensitive information such as API keys, database credentials, or other secrets. This can occur due to insecure storage, improper access controls, or misconfigured deployment environments.
    * **Risk:** This is a high-risk path with a medium likelihood (depending on configuration practices) and a critical impact. If attackers gain access to sensitive configuration data, they can potentially compromise the entire application and its associated resources. It's a critical node because it represents a single point of failure that can lead to widespread compromise.
    * **Mitigation:** Securely store and manage sensitive configuration data using environment variables or dedicated secrets management tools. Avoid hardcoding secrets in the application code or configuration files. Implement strict access controls on configuration files and environment variable storage.

