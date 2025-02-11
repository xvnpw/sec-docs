# Attack Tree Analysis for jenkinsci/pipeline-model-definition-plugin

Objective: Execute Arbitrary Code on Jenkins Controller/Agent

## Attack Tree Visualization

Execute Arbitrary Code on Jenkins Controller/Agent [CRITICAL]
                        |
        ---------------------------------
        |				|
2.  Abuse Legitimate Pipeline Features [CRITICAL]
        |
---------------------------------
|				|
2.1 Shared Library      2.2 Misuse of
    Injection (External     `node` block
    Code) [CRITICAL]		    |
        |				-----------------
-----------------		       |				|
|				|		2.2.1 Run		2.2.2 Access
2.1.1 Control		2.1.2		Arbitrary		Sensitive
Shared Library		Compromise		Commands on		Data on
Repository		Shared			Agent [CRITICAL]	Agent
				Library
				Source

## Attack Tree Path: [Abuse Legitimate Pipeline Features [CRITICAL]](./attack_tree_paths/abuse_legitimate_pipeline_features__critical_.md)

*   **Description:** This is a critical node because it represents attacks that exploit the intended functionality of the plugin, making them harder to prevent solely through patching. These attacks leverage features designed for flexibility and power, but can be manipulated for malicious purposes.
*   **Why Critical:** Exploiting legitimate features bypasses many traditional security measures that focus on preventing *unintended* behavior.

## Attack Tree Path: [2.1 Shared Library Injection (External Code) [CRITICAL]](./attack_tree_paths/2_1_shared_library_injection__external_code___critical_.md)

*   **Description:** Shared libraries are external Groovy code repositories that can be used by Declarative Pipelines. This is a powerful feature, but also a significant attack vector because it allows for the introduction of code from outside the immediate pipeline definition.
*   **Why Critical:** Shared libraries represent a trust boundary. Compromising a shared library allows an attacker to affect *multiple* pipelines that use it.

## Attack Tree Path: [2.1.1 Control Shared Library Repository](./attack_tree_paths/2_1_1_control_shared_library_repository.md)

*   **Description:** Gaining control of the repository hosting a shared library (e.g., GitHub, Bitbucket). This could be achieved through account takeover, social engineering, or exploiting vulnerabilities in the repository hosting service.
*   **Likelihood:** Low
*   **Impact:** Very High
*   **Effort:** High
*   **Skill Level:** Advanced
*   **Detection Difficulty:** Medium

## Attack Tree Path: [2.1.2 Compromise Shared Library Source](./attack_tree_paths/2_1_2_compromise_shared_library_source.md)

*   **Description:** Influencing the pipeline definition to load a malicious shared library from an attacker-controlled location. This could involve modifying the `Jenkinsfile` to point to a different repository or a specific malicious version.
*   **Likelihood:** Medium
*   **Impact:** Very High
*   **Effort:** Medium
*   **Skill Level:** Intermediate
*   **Detection Difficulty:** Medium

## Attack Tree Path: [2.2 Misuse of `node` block](./attack_tree_paths/2_2_misuse_of__node__block.md)

*    **Description:** The `node` block is used to specify where a pipeline stage will execute, either on the controller or a specific agent. It's a core part of pipeline execution and offers significant power, making it a target for abuse.

## Attack Tree Path: [2.2.1 Run Arbitrary Commands on Agent [CRITICAL] (High-Risk Path)](./attack_tree_paths/2_2_1_run_arbitrary_commands_on_agent__critical___high-risk_path_.md)

*   **Description:** The `node` block allows the execution of shell scripts or other commands on the designated agent. An attacker can inject malicious commands into these scripts or build steps. This is the most direct and likely path to code execution.
*   **Likelihood:** High
*   **Impact:** High
*   **Effort:** Low
*   **Skill Level:** Intermediate
*   **Detection Difficulty:** Easy
*   **Why High-Risk:** This is a direct exploitation of a core feature. The likelihood is high because it's *designed* to run commands; the attacker just needs to control *which* commands. The impact is high (agent compromise), and the effort is low. While detection is easy, the ease of exploitation makes it a high-risk path.

## Attack Tree Path: [2.2.2 Access Sensitive Data on Agent](./attack_tree_paths/2_2_2_access_sensitive_data_on_agent.md)

*   **Description:** If an agent has access to sensitive data (credentials, API keys, etc.), an attacker who gains code execution on the agent can steal this data.
*   **Likelihood:** Medium
*   **Impact:** High
*   **Effort:** Medium
*   **Skill Level:** Intermediate
*   **Detection Difficulty:** Medium

