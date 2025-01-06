# Attack Surface Analysis for jenkinsci/pipeline-model-definition-plugin

## Attack Surface: [Unsanitized Input in `script` Steps](./attack_surfaces/unsanitized_input_in__script__steps.md)

*   **Attack Surface:** Unsanitized Input in `script` Steps

    *   **Description:** The `script` step within Declarative Pipelines allows embedding arbitrary Groovy code. If user-provided input or data from external sources is directly used within these `script` blocks without proper sanitization, it can lead to script injection vulnerabilities.
    *   **How Pipeline-Model-Definition-Plugin Contributes:**  The plugin provides the mechanism to execute arbitrary Groovy code within the pipeline definition through the `script` step.
    *   **Example:** A pipeline takes a user-provided filename as a parameter and uses it directly in a `script` step:
        ```groovy
        pipeline {
            agent any
            parameters {
                string(name: 'FILENAME', defaultValue: 'output.txt', description: 'Name of the output file')
            }
            stages {
                stage('Process File') {
                    steps {
                        script {
                            def filename = params.FILENAME
                            sh "cat ${filename}" // Vulnerable to command injection if filename contains malicious commands
                        }
                    }
                }
            }
        }
        ```
    *   **Impact:** Remote code execution on the Jenkins agent, potentially compromising the entire Jenkins instance or connected systems.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Avoid using `script` steps when possible.** Opt for dedicated pipeline steps or plugins that handle specific tasks securely.
        *   **Sanitize all user-provided input and data from external sources** before using it in `script` blocks. Use appropriate escaping or validation techniques.
        *   **Enforce strict code reviews** for pipelines utilizing `script` steps, paying close attention to how external data is handled.

## Attack Surface: [Command Injection via `environment` Directive](./attack_surfaces/command_injection_via__environment__directive.md)

*   **Attack Surface:** Command Injection via `environment` Directive

    *   **Description:** The `environment` directive allows setting environment variables. If the values assigned to these variables are constructed using unsanitized user input or data from external sources, it can lead to command injection vulnerabilities when these variables are used in subsequent shell commands or scripts.
    *   **How Pipeline-Model-Definition-Plugin Contributes:** The plugin provides the `environment` directive, making it easy to define and use environment variables within the pipeline definition.
    *   **Example:** A pipeline takes a user-provided value for a tool path and sets it as an environment variable:
        ```groovy
        pipeline {
            agent any
            parameters {
                string(name: 'TOOL_PATH', defaultValue: '/usr/bin/some_tool', description: 'Path to the tool')
            }
            environment {
                CUSTOM_TOOL = "${params.TOOL_PATH}" // Vulnerable if TOOL_PATH contains malicious commands
            }
            stages {
                stage('Run Tool') {
                    steps {
                        sh "\$CUSTOM_TOOL --version" // Malicious commands in TOOL_PATH will be executed
                    }
                }
            }
        }
        ```
    *   **Impact:** Remote code execution on the Jenkins agent.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Avoid constructing environment variable values directly from user input.**
        *   **Use the Credentials Binding plugin** to securely manage and inject sensitive information instead of relying on environment variables derived from user input.
        *   **Sanitize any data used to construct environment variable values.**

## Attack Surface: [Abuse of `agent` Directive for Resource Exploitation](./attack_surfaces/abuse_of__agent__directive_for_resource_exploitation.md)

*   **Attack Surface:**  Abuse of `agent` Directive for Resource Exploitation

    *   **Description:** The `agent` directive specifies where the pipeline should run. If not properly controlled, malicious actors with the ability to define pipelines could potentially target specific agents with high resource availability or access to sensitive networks, leading to resource exhaustion or unauthorized access.
    *   **How Pipeline-Model-Definition-Plugin Contributes:** The plugin provides the `agent` directive as a core feature for defining where pipelines execute.
    *   **Example:** An attacker creates a pipeline that specifically targets a powerful build agent with access to internal networks to perform resource-intensive tasks or network scanning.
        ```groovy
        pipeline {
            agent { label 'powerful-agent-with-internal-access' } // Targeting a specific agent
            stages {
                stage('Resource Intensive Task') {
                    steps {
                        sh 'while true; do some_resource_intensive_command; done'
                    }
                }
            }
        }
        ```
    *   **Impact:** Denial of service on specific build agents, potential unauthorized access to internal networks if the targeted agent has such access.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Implement strict access control for pipeline creation and modification.**
        *   **Carefully manage agent labels and restrict their usage based on user roles and pipeline requirements.**
        *   **Monitor resource utilization on build agents** to detect suspicious activity.

