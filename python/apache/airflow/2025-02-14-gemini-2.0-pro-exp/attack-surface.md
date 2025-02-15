# Attack Surface Analysis for apache/airflow

## Attack Surface: [DAG Code Injection](./attack_surfaces/dag_code_injection.md)

*   **Description:**  Execution of arbitrary code on Airflow worker nodes through malicious or compromised DAG files. This is the *defining* attack vector for Airflow.
*   **How Airflow Contributes:** Airflow's core function is to execute DAGs, which are Python code. This inherent design makes code injection the primary and most dangerous threat.
*   **Example:** An attacker uploads a DAG file containing a Python script that opens a reverse shell, exfiltrates data, or installs malware. The DAG is then scheduled and executed by Airflow.
*   **Impact:** Complete compromise of worker nodes, potential lateral movement to other systems, data exfiltration, and disruption of Airflow operations.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strict DAG File Access Control:** Implement *least privilege* access to the DAGs folder. The webserver should have *read-only* access, and *no* user should have direct write access. Use a controlled deployment process (e.g., Git-based deployments with CI/CD, requiring pull requests and approvals).
    *   **Code Review:** Mandatory, thorough code reviews for *all* DAGs before deployment, focusing on security best practices (input validation, avoiding `eval`, secure handling of external data).
    *   **Static Analysis:** Use static analysis tools (e.g., Bandit, Pylint with security plugins) to automatically scan DAGs for potential vulnerabilities (code injection, hardcoded secrets, insecure function usage).
    *   **Sandboxing/Isolation:** Run Airflow workers in isolated environments (containers, VMs) with minimal privileges. Utilize `PythonVirtualenvOperator` or `KubernetesPodOperator` for task-level isolation, creating separate environments for each task.
    *   **Secrets Management:** *Never* store secrets directly in DAG files. Use Airflow's built-in mechanisms (Variables, Connections) or integrate with a dedicated secrets management solution (e.g., HashiCorp Vault, AWS Secrets Manager, Azure Key Vault). Secrets should be injected into the task environment, not hardcoded.
    *   **File Integrity Monitoring (FIM):** Implement FIM to detect unauthorized changes to DAG files. This provides an alert if a DAG file is modified outside the approved deployment process.

## Attack Surface: [Authentication and Authorization Bypass (Web UI)](./attack_surfaces/authentication_and_authorization_bypass__web_ui_.md)

*   **Description:** Unauthorized access to the Airflow Web UI due to weak authentication or misconfigured authorization, leading to control over DAG execution.
*   **How Airflow Contributes:** The Airflow Web UI is the primary interface for managing and monitoring DAGs. Weaknesses here directly expose Airflow's core functionality.
*   **Example:** An attacker uses default or easily guessed credentials to log in to the Airflow UI and then uploads a malicious DAG, or triggers an existing DAG with unintended consequences.
*   **Impact:** Control over DAG execution, access to sensitive information (if exposed in the UI – though this should be avoided), potential for DAG code injection.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strong Authentication:** Disable the default `airflow` user *immediately*. Enforce strong password policies (length, complexity, regular changes). Implement robust authentication mechanisms (LDAP, OAuth 2.0, Kerberos) with proper configuration and regular security audits.
    *   **Role-Based Access Control (RBAC):** Utilize Airflow's RBAC to grant *least privilege* access. Carefully define roles and permissions, and regularly audit them.  Ensure users only have the permissions they absolutely need.
    *   **Multi-Factor Authentication (MFA):** Implement MFA for *all* user accounts, especially those with administrative privileges or access to sensitive DAGs.
    *   **Web Application Firewall (WAF):** Consider using a WAF to provide an additional layer of protection against authentication attacks (brute-force, credential stuffing).  The WAF can also help mitigate other web-based attacks.

## Attack Surface: [Metadata Database Compromise (Direct Manipulation of Airflow State)](./attack_surfaces/metadata_database_compromise__direct_manipulation_of_airflow_state_.md)

*   **Description:** Unauthorized access to or modification of the Airflow metadata database, allowing direct manipulation of Airflow's internal state. This is distinct from general database security; it's about the *specific impact* on Airflow.
*   **How Airflow Contributes:** Airflow relies on the metadata database to store *all* information about DAGs, tasks, schedules, and execution history.  Direct access bypasses Airflow's intended controls.
*   **Example:** An attacker gains access to the database and modifies the `next_dagrun` field of a DAG to trigger it immediately, bypassing any scheduling constraints or security checks.  They could also alter task states to mark failed tasks as successful, or vice-versa.
*   **Impact:** Disruption of Airflow operations, potential for data manipulation (bypassing normal DAG logic), and, if secrets are improperly stored in the database (which should *never* happen), data exfiltration.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Secure Database Access:** Use strong, unique passwords and secure authentication for the database. Restrict network access to the database to *only* the necessary Airflow components (webserver, scheduler, workers) using network segmentation and firewalls.
    *   **Least Privilege Database User:** Create a dedicated database user for Airflow with *only* the necessary permissions (read, write, update, delete on specific Airflow tables). *Never* use the database root user or a user with overly broad permissions.
    *   **Database Auditing:** Enable database-level auditing to track all access and changes to the database. This provides a record of who accessed the database and what changes were made.
    *   **Regular Backups:** Implement a robust backup and recovery strategy for the metadata database, with regular testing of the recovery process.
    *   **Encryption:** Encrypt the database at rest and in transit to protect the data from unauthorized access.
    *   **Avoid Storing Secrets:** Absolutely *never* store sensitive information (API keys, passwords, etc.) directly in the metadata database. Use Airflow's secrets management features or an external secrets manager.

