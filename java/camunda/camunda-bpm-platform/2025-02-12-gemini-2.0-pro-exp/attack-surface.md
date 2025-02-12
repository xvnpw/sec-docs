# Attack Surface Analysis for camunda/camunda-bpm-platform

## Attack Surface: [1. Unprotected Process Engine API (REST/Java)](./attack_surfaces/1__unprotected_process_engine_api__restjava_.md)

*Description:* Exposure of the Camunda engine's core API endpoints without proper authentication and authorization. This is a fundamental part of how Camunda operates.
*Camunda Contribution:* Camunda *provides* these APIs as the primary means of interacting with the engine. Their existence and functionality are inherent to the platform.
*Example:* An attacker uses the publicly accessible REST API (`/engine-rest/process-instance`) to start hundreds of instances of a resource-intensive process, causing a denial-of-service. Or, they modify process variables containing sensitive data.
*Impact:* Denial of service, unauthorized data access/modification, unauthorized process execution, complete system compromise (if the attacker can then deploy malicious models).
*Risk Severity:* **Critical**
*Mitigation Strategies:*
    *   **Authentication:** Implement strong authentication (OAuth 2.0, JWT, Basic Auth with robust password policies, API keys).  This is *mandatory*.
    *   **Authorization:** Use Camunda's built-in authorization service (or a custom implementation, but Camunda's is recommended) to enforce fine-grained access control. Grant only the *minimum* necessary permissions.
    *   **Network Segmentation:**  Isolate the Camunda engine from untrusted networks. Use a firewall.
    *   **API Rate Limiting:** Implement rate limiting to prevent abuse.
    *   **Input Validation:**  While Camunda does some internal validation, validate all input *you* send to the API to prevent unexpected behavior.
    *   **Regular Auditing:** Monitor API access logs.

## Attack Surface: [2. Malicious Process Definition Deployment](./attack_surfaces/2__malicious_process_definition_deployment.md)

*Description:*  Deployment of BPMN, DMN, or CMMN models containing malicious code or configurations *through Camunda's deployment mechanisms*.
*Camunda Contribution:* Camunda's core function is to *execute* these process definitions. The deployment mechanism is a built-in, essential feature.
*Example:* An attacker deploys a BPMN model via the REST API with a script task that executes arbitrary shell commands, gaining system access.
*Impact:*  Arbitrary code execution, data exfiltration, system compromise, denial of service.
*Risk Severity:* **Critical**
*Mitigation Strategies:*
    *   **Secure Deployment Endpoints:**  Protect the deployment API (REST/Java) with strong authentication and authorization (as with the general engine API).
    *   **Model Validation:** Implement strict *server-side* validation of deployed models *before* Camunda processes them. Use a whitelist of allowed elements, attributes, scripts, and expressions.  This is crucial; don't rely on client-side checks.
    *   **Sandboxed Scripting:** Configure Camunda to use a secure scripting engine with sandboxing capabilities. This limits the damage a malicious script can do.
    *   **Disable Auto-Deployment:** Disable auto-deployment from the classpath in production.
    *   **Deployment Pipeline:** Use a dedicated deployment pipeline with automated security checks *integrated with Camunda's deployment process*.

## Attack Surface: [3. Script Task Code Injection (within Camunda's execution context)](./attack_surfaces/3__script_task_code_injection__within_camunda's_execution_context_.md)

*Description:*  Injection of malicious code into script tasks *that Camunda is responsible for executing*.
*Camunda Contribution:* Camunda *provides* the scripting engine and executes the scripts within its context. The vulnerability arises from how Camunda handles and executes these scripts.
*Example:* A process variable containing unsanitized user input is directly used within a JavaScript script task *that Camunda executes*. The attacker provides malicious JavaScript.
*Impact:* Arbitrary code execution (within the Camunda engine's context), data exfiltration, potential for system compromise.
*Risk Severity:* **High**
*Mitigation Strategies:*
    *   **Input Sanitization:** Sanitize *all* data used in script tasks, even if it comes from other parts of the process.  Treat *all* process variables as potentially tainted.
    *   **Sandboxed Scripting:**  Use a secure, sandboxed scripting engine (configure this within Camunda).
    *   **External Scripts:** Avoid inline scripts. Store scripts externally and reference them. This makes auditing and control easier.
    *   **Principle of Least Privilege:** Configure the Camunda engine (and its scripting engine) to run with the minimum necessary privileges.
    *   **Code Review (of process definitions):** Review *process definitions* for how they use scripts.

## Attack Surface: [4. Expression Language Injection (within Camunda's evaluation)](./attack_surfaces/4__expression_language_injection__within_camunda's_evaluation_.md)

*Description:* Injection of malicious code into expressions that *Camunda evaluates*.
*Camunda Contribution:* Camunda *uses and evaluates* these expressions as part of its core functionality.
*Example:* A condition in a gateway uses an expression evaluating unsanitized user input. The attacker provides a malicious expression.
*Impact:* Data exfiltration, potential for limited code execution (depending on the expression language and context), unauthorized access to process data.
*Risk Severity:* **High**
*Mitigation Strategies:*
    *   **Input Sanitization:** Sanitize *all* data used in expressions, treating process variables as potentially tainted.
    *   **Parameterized Expressions:** Use parameterized expressions where possible (this is often supported by the expression language).
    *   **Avoid Dynamic Expressions:** Minimize dynamic expressions based on untrusted input.
    *   **Contextual Output Encoding:** If expressions *must* include potentially tainted data, ensure proper contextual output encoding is used *by the expression evaluator* (this is a Camunda configuration concern).

