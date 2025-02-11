# Attack Surface Analysis for jenkinsci/job-dsl-plugin

## Attack Surface: [Unvalidated DSL Script Injection](./attack_surfaces/unvalidated_dsl_script_injection.md)

*   **Description:** Execution of arbitrary Groovy code injected into the Job DSL script.
    *   **How Job DSL Plugin Contributes:** The plugin's core function is to execute Groovy code, making it a direct conduit for RCE if input is not validated.
    *   **Example:** An attacker modifies a seed job's SCM URL parameter to point to a malicious script hosted on a compromised server. The script contains code to exfiltrate credentials or install a backdoor.
    *   **Impact:** Complete compromise of the Jenkins master, allowing the attacker to execute arbitrary commands, access sensitive data, and potentially pivot to other systems.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Secure SCM:** Store DSL scripts in a secure, access-controlled SCM repository with mandatory code reviews.
        *   **Input Validation:** Rigorously validate *all* external inputs, including parameters, URLs, and file paths, using a whitelist approach. Reject any input that doesn't match expected patterns.
        *   **Script Security Plugin:** *Mandatory*. Use the Script Security plugin to sandbox Groovy execution and require administrator approval for scripts.
        *   **Least Privilege:** Run Jenkins with the least necessary privileges.
        *   **Avoid Dynamic DSL:** Minimize dynamic DSL generation; if unavoidable, use secure templating and strict input sanitization.

## Attack Surface: [Unsafe Groovy Method Usage](./attack_surfaces/unsafe_groovy_method_usage.md)

*   **Description:** Exploitation of powerful Groovy methods (e.g., file system access, shell command execution) within the DSL script.
    *   **How Job DSL Plugin Contributes:** The plugin executes Groovy, providing access to these potentially dangerous methods.
    *   **Example:** A DSL script uses `"/bin/sh -c 'rm -rf /'".execute()`, attempting to delete the entire file system.
    *   **Impact:** Data breaches, system compromise, denial of service.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Script Security Plugin:** Use the Script Security plugin to restrict access to dangerous methods, requiring explicit approval.
        *   **Code Review:** Thoroughly review DSL scripts for the use of unsafe methods.
        *   **Avoid Shell Commands:** Prefer Jenkins built-in steps or plugins over direct shell command execution (`.execute()`).
        *   **Restrict File System Access:** Limit file system access to the necessary minimum, using relative paths within the workspace whenever possible.

## Attack Surface: [Resource Exhaustion (CPU/Memory/Disk)](./attack_surfaces/resource_exhaustion__cpumemorydisk_.md)

*   **Description:** A malicious or poorly written DSL script consumes excessive resources, making Jenkins unresponsive.
    *   **How Job DSL Plugin Contributes:** The plugin executes the script, which can contain resource-intensive operations.
    *   **Example:** A DSL script contains an infinite loop: `while(true) {}`. Another example is a script that creates thousands of jobs in a tight loop. A third example is a script that uses a vulnerable regular expression against a large input string, leading to ReDoS.
    *   **Impact:** Jenkins becomes unavailable, disrupting CI/CD pipelines.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Resource Limits:** Use containerization (Docker) to enforce resource limits on Jenkins.
        *   **Timeouts:** Set timeouts for DSL script execution.
        *   **Code Review:** Review scripts for potential infinite loops, excessive job creation, and large file operations.
        *   **ReDoS Prevention:** Use safe regular expression practices; avoid complex nested quantifiers. Use tools to analyze regex for ReDoS vulnerabilities.
        *   **Monitoring:** Monitor Jenkins resource usage to detect and respond to DoS attempts.

## Attack Surface: [Exposure of Sensitive Data](./attack_surfaces/exposure_of_sensitive_data.md)

*   **Description:** Unintentional leakage of credentials, API keys, or other sensitive information.
    *   **How Job DSL Plugin Contributes:** The plugin executes scripts that might handle or generate sensitive data.
    *   **Example:** A DSL script hardcodes an AWS access key: `def awsKey = "AKIAIOSFODNN7EXAMPLE"`. Another example is a script that logs a database password to the console.
    *   **Impact:** Compromise of connected services, data breaches.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Credential Management:** *Never* hardcode secrets. Use Jenkins' built-in credential management system.
        *   **Secure Logging:** Avoid logging sensitive information to the console.
        *   **Code Review:** Review scripts to ensure they don't expose secrets.
        *   **Secure Job Configuration:** Ensure generated job configurations use credential bindings, not plain text secrets.

## Attack Surface: [Manipulation of Existing Jobs](./attack_surfaces/manipulation_of_existing_jobs.md)

* **Description:** A compromised DSL script modifies existing job configurations to gain higher privileges.
    * **How Job DSL Plugin Contributes:** The plugin's primary function is to create and modify jobs, making it a tool for this type of attack.
    * **Example:** A DSL script modifies an existing job's build steps to include a shell command that adds a new user with administrator privileges to the system.
    * **Impact:** Attacker gains control over existing jobs and potentially the entire Jenkins instance.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        *   **Access Control:** Implement strict access control policies to limit who can modify job configurations.
        *   **Job Configuration History:** Enable job configuration history to track changes and allow rollbacks.
        *   **Auditing:** Regularly audit job configurations for unauthorized modifications.
        *   **Pipeline as Code:** Use Pipeline as Code for build steps, applying the same security principles as for Job DSL scripts.

