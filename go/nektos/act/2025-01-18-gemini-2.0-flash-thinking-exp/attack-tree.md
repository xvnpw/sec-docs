# Attack Tree Analysis for nektos/act

Objective: Execute arbitrary code within the application's environment or gain unauthorized access to resources accessible by the application, by leveraging vulnerabilities in how the application uses `act`.

## Attack Tree Visualization

```
**Threat Model: Compromising Applications Using `act` - Focused on High-Risk Paths and Critical Nodes**

**Attacker's Goal:** Execute arbitrary code within the application's environment or gain unauthorized access to resources accessible by the application, by leveraging vulnerabilities in how the application uses `act`.

**Sub-Tree of High-Risk Paths and Critical Nodes:**

Compromise Application via act [CRITICAL NODE]
* Inject Malicious Workflow Content [HIGH-RISK PATH START]
    * Modify Existing Workflow File [CRITICAL NODE]
    * Introduce Malicious Workflow File
* Exploit Runner Environment Vulnerabilities
    * Leverage Docker Image Vulnerabilities
        * Application Configuration Allows Unvalidated Base Images [CRITICAL NODE]
        * Exploit Known Vulnerabilities in Default Image [HIGH-RISK PATH START]
            * act Uses Outdated or Vulnerable Default Image [CRITICAL NODE]
    * Achieve Container Escape [HIGH-RISK PATH START]
        * Application Incorrectly Exposes Docker Socket [CRITICAL NODE]
* Exploit Action Vulnerabilities
    * Use Malicious Action [HIGH-RISK PATH START]
        * Application Configuration Allows Unvalidated Public Actions [CRITICAL NODE]
    * Exploit Vulnerabilities in Legitimate Actions [HIGH-RISK PATH START]
        * act Does Not Isolate Action Dependencies Effectively [CRITICAL NODE]
        * act Executes Action Code Without Sufficient Sandboxing [CRITICAL NODE]
* Abuse Secret Handling [HIGH-RISK PATH START]
    * Expose Secrets via Logging
        * act Logs Secret Values During Workflow Execution [CRITICAL NODE]
```


## Attack Tree Path: [Inject Malicious Workflow Content](./attack_tree_paths/inject_malicious_workflow_content.md)

**Attack Vector:** An attacker gains write access to the file system where workflow files are stored (either by modifying an existing file or introducing a new one). They then inject malicious YAML code into a workflow. When `act` executes this workflow, the malicious code is executed within the runner environment.
* **Critical Nodes Involved:**
    * **Compromise Application via act:** The ultimate goal.
    * **Modify Existing Workflow File:** A direct way to inject malicious content.
* **Mitigation Strategies:**
    * Implement strict access controls on workflow file directories.
    * Use file integrity monitoring to detect unauthorized changes.
    * Implement code review processes for workflow changes.
    * Sanitize and validate any user input that could influence workflow file content or paths.

## Attack Tree Path: [Exploit Known Vulnerabilities in Default Image](./attack_tree_paths/exploit_known_vulnerabilities_in_default_image.md)

**Attack Vector:** `act` uses an outdated or vulnerable default Docker image. An attacker leverages known vulnerabilities within this image to compromise the container environment, potentially leading to container escape or arbitrary code execution.
* **Critical Nodes Involved:**
    * **Compromise Application via act:** The ultimate goal.
    * **act Uses Outdated or Vulnerable Default Image:** The core vulnerability enabling this path.
* **Mitigation Strategies:**
    * Regularly update `act` to benefit from updates to the default image.
    * Consider using a minimal and hardened base image for `act` if customization is possible.
    * Implement vulnerability scanning for the Docker image used by `act`.

## Attack Tree Path: [Achieve Container Escape](./attack_tree_paths/achieve_container_escape.md)

**Attack Vector:** An attacker exploits misconfigurations or vulnerabilities to escape the Docker container in which the workflow is running. This grants them access to the host system.
* **Critical Nodes Involved:**
    * **Compromise Application via act:** The ultimate goal.
    * **Application Incorrectly Exposes Docker Socket:** A critical misconfiguration enabling easy container escape.
* **Mitigation Strategies:**
    * Never expose the Docker socket within containers unless absolutely necessary and with extreme caution.
    * Implement strong container isolation practices.
    * Keep the host operating system and Docker daemon up-to-date with security patches.

## Attack Tree Path: [Use Malicious Action](./attack_tree_paths/use_malicious_action.md)

**Attack Vector:** The application allows the use of public GitHub Actions without proper validation. An attacker specifies a malicious public action designed to compromise the runner environment or access sensitive data.
* **Critical Nodes Involved:**
    * **Compromise Application via act:** The ultimate goal.
    * **Application Configuration Allows Unvalidated Public Actions:** The configuration flaw enabling this attack.
* **Mitigation Strategies:**
    * Implement a strict whitelist of trusted public actions.
    * Implement mechanisms to review and audit the code of public actions before use.
    * Consider using private or internally developed actions for sensitive tasks.

## Attack Tree Path: [Exploit Vulnerabilities in Legitimate Actions](./attack_tree_paths/exploit_vulnerabilities_in_legitimate_actions.md)

**Attack Vector:** Legitimate actions contain vulnerabilities, either in their dependencies or in their own code. If `act` doesn't properly isolate action dependencies or sandbox action execution, these vulnerabilities can be exploited.
* **Critical Nodes Involved:**
    * **Compromise Application via act:** The ultimate goal.
    * **act Does Not Isolate Action Dependencies Effectively:** Lack of isolation increases the attack surface.
    * **act Executes Action Code Without Sufficient Sandboxing:** Allows insecure action code to cause harm.
* **Mitigation Strategies:**
    * Explore mechanisms within `act` or the application's setup to isolate action dependencies.
    * Regularly scan action dependencies for known vulnerabilities.
    * If possible, review the code of actions for potential security flaws.

## Attack Tree Path: [Abuse Secret Handling](./attack_tree_paths/abuse_secret_handling.md)

**Attack Vector:** `act` logs the values of secrets during workflow execution, making them accessible to anyone with access to the logs.
* **Critical Nodes Involved:**
    * **Compromise Application via act:** The ultimate goal.
    * **act Logs Secret Values During Workflow Execution:** The direct cause of secret exposure.
* **Mitigation Strategies:**
    * Configure `act` to redact secret values from logs.
    * Educate developers on secure logging practices and the risks of exposing secrets.
    * Implement secure secret management practices and avoid printing secrets in workflow commands.

