# Attack Tree Analysis for mybatis/mybatis-3

Objective: Attacker's Goal: To compromise application that use given project by exploiting weaknesses or vulnerabilities within the project itself.

## Attack Tree Visualization

```
* Achieve Application Compromise (AND)
    * Exploit SQL Injection Vulnerabilities (OR)
        * String Substitution in `${}` (AND) *** HIGH-RISK PATH ***
            * Inject Malicious SQL Fragments Directly *** CRITICAL NODE ***
        * Second-Order SQL Injection (AND) *** HIGH-RISK PATH ***
            * Trigger MyBatis Query That Uses This Malicious Data Without Proper Sanitization *** CRITICAL NODE ***
    * Exploit Insecure Configuration (OR) *** HIGH-RISK PATH ***
        * Access Sensitive Database Credentials (AND) *** CRITICAL NODE ***
```


## Attack Tree Path: [Exploit String Substitution in `${}`](./attack_tree_paths/exploit_string_substitution_in__${}_.md)

**Attack Vector:**  This path exploits the direct string substitution feature of MyBatis using the `${}` syntax in mapper XML files. When user-controlled input is directly placed within `${}`, it is inserted into the SQL query without any escaping or parameterization.
* **Critical Node: Inject Malicious SQL Fragments Directly**
    * **Insight:** `${}` performs direct string substitution, making it highly vulnerable to SQL injection if user-controlled data is used. An attacker can craft malicious SQL fragments within the input that will be directly executed against the database.
    * **Mitigation:** **Avoid using `${}` with user-controlled input.** If dynamic SQL is necessary, use MyBatis's `<if>`, `<choose>`, `<where>`, `<set>` tags or a safe query builder library.

## Attack Tree Path: [Second-Order SQL Injection](./attack_tree_paths/second-order_sql_injection.md)

**Attack Vector:** This path involves two stages. First, the attacker injects malicious data into the database through some other application functionality that doesn't involve MyBatis directly (or where the vulnerability exists). Second, a MyBatis query is executed that retrieves and uses this previously injected malicious data *without* proper sanitization, leading to SQL injection.
* **Critical Node: Trigger MyBatis Query That Uses This Malicious Data Without Proper Sanitization**
    * **Insight:** Even if direct input is sanitized, data stored in the database can be malicious and exploited later by MyBatis queries. If MyBatis retrieves and uses this data in a dynamic query without proper escaping or parameterization, it can lead to SQL injection.
    * **Mitigation:** Sanitize data both on input and when retrieved from the database before using it in MyBatis queries. Implement consistent encoding and validation practices across the application.

## Attack Tree Path: [Exploit Insecure Configuration](./attack_tree_paths/exploit_insecure_configuration.md)

**Attack Vector:** This path focuses on compromising the application by gaining access to sensitive database credentials used by MyBatis. If these credentials are stored insecurely, an attacker can retrieve them and directly access the database, bypassing application security.
* **Critical Node: Access Sensitive Database Credentials**
    * **Insight:** While not a direct MyBatis vulnerability, insecure storage of database credentials used by MyBatis can lead to compromise. If configuration files containing credentials are accessible or if credentials are hardcoded or weakly encrypted, attackers can easily obtain them.
    * **Mitigation:** Store database credentials securely using environment variables, dedicated secrets management tools, or encrypted configuration files. Avoid hardcoding credentials in configuration files or source code. Ensure proper file system permissions to restrict access to configuration files.

