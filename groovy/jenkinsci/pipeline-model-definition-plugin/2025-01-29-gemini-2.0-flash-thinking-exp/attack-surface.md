# Attack Surface Analysis for jenkinsci/pipeline-model-definition-plugin

## Attack Surface: [Script Injection via `script` Block](./attack_surfaces/script_injection_via__script__block.md)

*   **Description:**  Execution of arbitrary Groovy code within the Jenkins master or agent context due to insufficient input sanitization or validation within `script` blocks in declarative pipelines.
*   **Pipeline-Model-Definition-Plugin Contribution:** The plugin's declarative syntax, while aiming for structure, still allows embedding Groovy code in `script` blocks. This feature, if misused, becomes a direct vector for script injection.
*   **Example:** A pipeline takes a user-provided parameter `userInput`. The pipeline includes a `script` block that directly uses this parameter:
    ```groovy
    pipeline {
        agent any
        parameters {
            string(name: 'userInput', defaultValue: '', description: 'Enter input')
        }
        stages {
            stage('Example') {
                steps {
                    script {
                        println "User input: ${params.userInput}"
                        // Vulnerable code:
                        evaluate(params.userInput)
                    }
                }
            }
        }
    }
    ```
    If a user provides malicious Groovy code as `userInput`, the `evaluate()` function will execute it.
*   **Impact:** Full compromise of the Jenkins master or agent, depending on where the script executes. Attackers can gain complete control, steal secrets, modify configurations, or launch further attacks.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Avoid `script` blocks when possible:**  Utilize declarative steps and plugins instead of raw Groovy scripting.
    *   **Input Sanitization:**  Never directly use user-provided input (parameters, environment variables) in `script` blocks without rigorous sanitization and validation.
    *   **Principle of Least Privilege:** Run pipelines with the minimum necessary permissions.
    *   **Code Review:**  Thoroughly review any `script` blocks for potential injection vulnerabilities.
    *   **Static Analysis:** Use static analysis tools to detect potential script injection risks in pipeline definitions.

## Attack Surface: [Command Injection via `sh` and `powershell` Steps](./attack_surfaces/command_injection_via__sh__and__powershell__steps.md)

*   **Description:** Execution of arbitrary shell commands on the Jenkins agent due to insufficient sanitization of user-provided input used within `sh` or `powershell` steps.
*   **Pipeline-Model-Definition-Plugin Contribution:** The plugin provides `sh` and `powershell` steps as core functionalities within declarative pipelines, making command execution readily available. If input to these steps is not handled carefully, it opens the door to command injection.
*   **Example:** A pipeline takes a parameter `fileName`. The pipeline uses `sh` step to process this file:
    ```groovy
    pipeline {
        agent any
        parameters {
            string(name: 'fileName', defaultValue: '', description: 'Enter file name')
        }
        stages {
            stage('Example') {
                steps {
                    sh "cat ${params.fileName}" // Vulnerable code
                }
            }
        }
    }
    ```
    If a user provides a malicious filename like `; rm -rf /`, the `sh` command becomes `cat ; rm -rf /`, leading to command injection.
*   **Impact:** Compromise of the Jenkins agent. Attackers can execute arbitrary commands, potentially gaining access to sensitive data on the agent, modifying files, or using the agent as a pivot point for further attacks.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Input Sanitization and Escaping:**  Properly sanitize and escape user-provided input before using it in `sh` or `powershell` commands. Use parameterized queries or safe command construction methods provided by scripting languages.
    *   **Avoid String Interpolation:**  Prefer safer methods of command construction that avoid direct string interpolation of user input.
    *   **Principle of Least Privilege (Agent):** Run agents with minimal necessary privileges to limit the impact of command injection.
    *   **Command Whitelisting (where feasible):**  Restrict the commands that can be executed within `sh` or `powershell` steps to a predefined whitelist.

## Attack Surface: [Parameter Injection](./attack_surfaces/parameter_injection.md)

*   **Description:**  Exploiting pipeline parameters to inject malicious input that is then processed unsafely within the pipeline, leading to script injection, command injection, or other vulnerabilities.
*   **Pipeline-Model-Definition-Plugin Contribution:** The plugin heavily relies on parameters for user input and pipeline configuration within declarative pipelines.  If pipelines are not designed with security in mind, parameters become a primary entry point for malicious input.
*   **Example:**  A pipeline parameter `buildCommand` is intended to specify a build command. However, it's directly used in a `sh` step without validation:
    ```groovy
    pipeline {
        agent any
        parameters {
            string(name: 'buildCommand', defaultValue: 'mvn clean install', description: 'Build command')
        }
        stages {
            stage('Build') {
                steps {
                    sh "${params.buildCommand}" // Vulnerable code
                }
            }
        }
    }
    ```
    An attacker could set `buildCommand` to `mvn clean install && malicious_command` to inject and execute arbitrary commands.
*   **Impact:**  Varies depending on how the injected parameter is used. Can range from command injection on agents to script injection on the master, leading to system compromise or data breaches.
*   **Risk Severity:** **High** to **Critical** (depending on the context of parameter usage)
*   **Mitigation Strategies:**
    *   **Parameter Validation:**  Strictly validate all pipeline parameters against expected formats and values. Reject invalid input.
    *   **Input Sanitization:** Sanitize parameter values before using them in scripts or commands.
    *   **Treat Parameters as Untrusted:** Always treat parameters as potentially malicious user input and handle them with caution.
    *   **Use Parameter Types Wisely:** Utilize specific parameter types (e.g., choice, boolean) to restrict input options and reduce the attack surface compared to free-form string parameters.

## Attack Surface: [Agent Misconfiguration leading to Sensitive Data Exposure](./attack_surfaces/agent_misconfiguration_leading_to_sensitive_data_exposure.md)

*   **Description:** Pipelines processing sensitive data being executed on unintended or less secure Jenkins agents due to misconfiguration of the `agent` directive in declarative pipelines, leading to potential data exposure.
*   **Pipeline-Model-Definition-Plugin Contribution:** The `agent` directive is a core feature of declarative pipelines, allowing specification of where pipelines should run. Misconfiguration here directly leads to pipelines running in potentially vulnerable environments.
*   **Example:** A pipeline designed to handle confidential customer data is mistakenly configured to run on a shared, less secure agent due to an incorrect label in the `agent` directive:
    ```groovy
    pipeline {
        agent { label 'incorrect-agent-label' } // Misconfiguration - points to less secure agent
        stages {
            // ... pipeline steps processing sensitive data ...
        }
    }
    ```
    This could expose sensitive customer data processed by the pipeline to a less secure environment, increasing the risk of unauthorized access or data breaches.
*   **Impact:** Information disclosure, exposure of sensitive data to less secure environments, potential data breaches, compliance violations.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Careful Agent Labeling and Configuration:**  Accurately configure agent labels and rigorously test pipeline `agent` directives to ensure pipelines are directed to the intended, secure agents.
    *   **Agent Security Hardening:**  Harden all Jenkins agents, and especially dedicate specific, highly secured agents for pipelines processing sensitive data.
    *   **Regular Agent Audits:**  Periodically audit agent configurations and pipeline `agent` directives, particularly for pipelines handling sensitive information, to ensure correct and secure assignments.
    *   **Principle of Least Privilege (Agents):**  Grant agents only the necessary permissions and access, and strictly segregate agents based on the sensitivity of the pipelines they execute.

## Attack Surface: [Tool Misconfiguration and Use of Vulnerable Tools Exposing Agents](./attack_surfaces/tool_misconfiguration_and_use_of_vulnerable_tools_exposing_agents.md)

*   **Description:**  Exploiting vulnerabilities arising from misconfigured or vulnerable tools specified using the `tools` directive in declarative pipelines, potentially leading to agent compromise.
*   **Pipeline-Model-Definition-Plugin Contribution:** The `tools` directive allows pipelines to declare required tools (JDK, Maven, etc.). Misconfiguration or vulnerabilities in the tool setup process or the tools themselves can be exploited, directly impacting the agent.
*   **Example:** A pipeline specifies an outdated and vulnerable version of a build tool using the `tools` directive:
    ```groovy
    pipeline {
        agent any
        tools {
            maven 'vulnerable-maven-version' // Misconfiguration - using outdated, vulnerable version
        }
        stages {
            // ... pipeline steps using Maven ...
        }
    }
    ```
    If the specified Maven version has known vulnerabilities, the agent running the pipeline becomes vulnerable to exploits targeting that Maven version.
*   **Impact:** Compromise of the Jenkins agent if a vulnerable tool is exploited. Attackers could leverage tool vulnerabilities to gain unauthorized access to the agent, execute arbitrary code, or steal sensitive information.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Use Latest Tool Versions:**  Always use the latest stable and security-patched versions of tools.
    *   **Tool Version Management and Enforcement:**  Implement a robust tool version management strategy and enforce the use of approved and secure tool versions within pipelines.
    *   **Tool Source Verification and Integrity Checks:**  Verify the integrity and authenticity of tool installations to prevent the introduction of compromised or malicious tools.
    *   **Regular Vulnerability Scanning of Tools:**  Regularly scan installed tools for known vulnerabilities and implement a process for patching or updating vulnerable tools promptly.
    *   **Agent Isolation and Monitoring:** Isolate agents as much as possible and implement robust monitoring to detect and respond to any suspicious activity potentially related to tool exploitation.

