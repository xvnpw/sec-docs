# Attack Tree Analysis for nektos/act

Objective: Execute Arbitrary Code on Host/CI Environment via `act`

## Attack Tree Visualization

                                     [Attacker's Goal: Execute Arbitrary Code on Host/CI Environment via act]
                                                        |
                                     ---------------------------------------------------(CR)-------------------------------------------------
                                     |                                                                                 |
                [1. Manipulate Workflow Execution]                                                     [2. Exploit act's Internal Vulnerabilities]
                         |                                                                                                 |
      -----------------------------------------(HR)-------------------------------                      -------------------------------------------------
      |                  |                    |                                                                         |
[1.1 Inject        [1.2 Override    [1.3 Tamper with                                                              [2.3 Logic Flaws in
**Malicious**        Workflow     Workflow Files]                                                                  **act's Docker/**
**Workflow]**       Secrets]                                                                                              **Image Handling]**(CR)
      |                                       |
  ----------                         -------------------(HR)-----------------
  |                                  |        |        |
[**1.1.1**(HR)                   [1.3.1 [**1.3.2**(HR)  [1.3.3
**Use      Use       Directly  Use       Symlink
Public   GitHub    Modify    GitHub    Attack to
Repo     API to    .github/  Actions   Replace
with     Trigger   workflows  Market-   Workflow
Malicious Workflow            place     File
Workflow  with                 Actions   with
File]**(CR)    Malicious              Version]**(CR)
         Payload]               

## Attack Tree Path: [Critical Node: 1. Manipulate Workflow Execution](./attack_tree_paths/critical_node_1__manipulate_workflow_execution.md)

Description: This is the overarching category for attacks that involve manipulating how `act` executes GitHub Actions workflows. It's a critical node because it represents the most likely and accessible attack surface.
Why it's critical: `act`'s primary function is to run workflows.  Controlling this process is the most direct path to code execution.

## Attack Tree Path: [High-Risk Path: 1.1 Inject Malicious Workflow](./attack_tree_paths/high-risk_path_1_1_inject_malicious_workflow.md)

Description: This path focuses on getting `act` to execute a workflow that contains malicious code.
Why it's high-risk: It's the most straightforward way to introduce malicious code, leveraging `act`'s core functionality.

## Attack Tree Path: [Critical Node & High-Risk Path & Critical Path: 1.1.1 Use Public Repo with Malicious Workflow File](./attack_tree_paths/critical_node_&_high-risk_path_&_critical_path_1_1_1_use_public_repo_with_malicious_workflow_file.md)

Description: An attacker creates a public GitHub repository containing a workflow file (`.github/workflows/*.yaml`) with malicious commands embedded within `run` steps or by using malicious actions. A user, unaware of the malicious code, runs this workflow using `act`.
Attack Vector Breakdown:
Likelihood: Medium. Relies on user error (running untrusted workflows).
Impact: High. Complete code execution on the host system.
Effort: Low. Creating a malicious repository is easy.
Skill Level: Intermediate. Requires understanding of GitHub Actions and crafting malicious payloads.
Detection Difficulty: Medium. Requires careful inspection of the workflow file; automated tools might miss subtle malicious code.
Why it's critical/high-risk/critical path: This is the easiest, most direct, and therefore most likely method for an attacker to achieve their goal.

## Attack Tree Path: [High-Risk Path: 1.3 Tamper with Workflow Files](./attack_tree_paths/high-risk_path_1_3_tamper_with_workflow_files.md)

Description: This path focuses on modifying existing workflow files to include malicious code.
Why it's high-risk: Although it requires some level of access, the impact is very high.

## Attack Tree Path: [Critical Node & High-Risk Path & Critical Path: 1.3.2 Use GitHub Actions Marketplace Actions with Malicious Version](./attack_tree_paths/critical_node_&_high-risk_path_&_critical_path_1_3_2_use_github_actions_marketplace_actions_with_mal_f87797f2.md)

Description: An attacker publishes a malicious version of a GitHub Actions Marketplace action, or compromises an existing action.  A user running `act` with a workflow that uses this compromised action will unknowingly execute the malicious code.
Attack Vector Breakdown:
Likelihood: Medium. Relies on a compromised or malicious action in the Marketplace. More likely with less popular actions.
Impact: High. Code execution within the context of the action, potentially leading to broader system compromise.
Effort: Medium. Requires creating or compromising a Marketplace action.
Skill Level: Intermediate. Requires understanding of how to create and publish actions.
Detection Difficulty: Medium. Requires checking the action's code and reputation; users often trust Marketplace actions.
Why it's critical/high-risk/critical path: This represents a significant supply chain vulnerability, and users often blindly trust Marketplace actions.

## Attack Tree Path: [1.2 Override Workflow Secrets](./attack_tree_paths/1_2_override_workflow_secrets.md)

Description: If `act` uses the GitHub API, compromised credentials could allow an attacker to override secrets used in a workflow.
Why it's high-risk: Although it requires compromised API credentials, the impact is very high.

## Attack Tree Path: [1.2.2 Use Crafted Events to Bypass Checks](./attack_tree_paths/1_2_2_use_crafted_events_to_bypass_checks.md)

Description: `act` simulates GitHub Actions events. An attacker might craft a malicious event payload that bypasses security checks within the workflow or within `act` itself.
Why it's high-risk: Requires understanding `act`'s event simulation and finding vulnerabilities in how it handles events.

## Attack Tree Path: [1.3.1 Directly Modify .github/workflows Directory](./attack_tree_paths/1_3_1_directly_modify__githubworkflows_directory.md)

Description: If an attacker gains write access to the `.github/workflows` directory, they can directly modify the workflow files to include malicious code.
Why it's high-risk: Although it requires direct file system access, the impact is very high.

## Attack Tree Path: [1.3.3 Symlink Attack to Replace Workflow File](./attack_tree_paths/1_3_3_symlink_attack_to_replace_workflow_file.md)

Description: An attacker could potentially use a symlink attack to replace a legitimate workflow file with a malicious one.
Why it's high-risk: Although it requires specific file system vulnerabilities, the impact is very high.

## Attack Tree Path: [Critical Node & Critical Path: 2.3 Logic Flaws in act's Docker/Image Handling](./attack_tree_paths/critical_node_&_critical_path_2_3_logic_flaws_in_act's_dockerimage_handling.md)

Description: `act` relies heavily on Docker.  Logic flaws in how `act` handles Docker images (pulling, creating containers, mounting volumes) could be exploited to escape the container sandbox, gain elevated privileges, or access sensitive data.
Attack Vector Breakdown:
Likelihood: Medium. `act`'s complex interaction with Docker increases the attack surface.
Impact: High. Could lead to container escape, privilege escalation, or access to sensitive data.
Effort: High. Requires finding and exploiting a logic flaw in `act`'s Docker handling.
Skill Level: Expert. Requires deep understanding of Docker security and `act`'s internals.
Detection Difficulty: Hard. Requires careful analysis of `act`'s Docker interaction and potentially dynamic analysis.
Why it's critical/critical path: This represents a vulnerability in `act`'s core functionality, and successful exploitation could lead to complete system compromise.

