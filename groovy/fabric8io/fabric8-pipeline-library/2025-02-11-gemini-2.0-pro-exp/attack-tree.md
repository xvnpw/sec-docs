# Attack Tree Analysis for fabric8io/fabric8-pipeline-library

Objective: [[Execute Arbitrary Code on Cluster]] (Impact: Very High)

## Attack Tree Visualization

```
                                     [[Attacker's Goal: Execute Arbitrary Code on Cluster]]
                                                    ||
                                                    ||
        =================================================================================
        ||                                                                               ||
[Sub-Goal 1: Compromise Pipeline Execution]                                 [[Sub-Goal 3: Leverage Misconfiguration]]
(Likelihood: Medium)                                                                (Likelihood: Medium)
        ||
        ||---------------------------------
        ||                               ||
        ||                               ||                                              ||
[[1.1: Inject Malicious Code]]   [[1.2: Manipulate Pipeline]]                        [[3.1: Overly Permissive RBAC]]  [[3.2: Unvalidated Inputs]]
(Likelihood: Medium)            (Likelihood: Medium)                                 (Likelihood: Medium)            (Likelihood: Medium)
        ||               ||                                              ||              ||              |
        ||               ||                                              ||              ||              |
[[1.1.1: Git Repo]] [[1.2.1: Modify]]                                 [[3.1.1: Pods]] [[3.1.2: Secrets]] [[3.2.1: Jenkinsfile]] [[3.2.2: Shared Library]]
[[**Poisoning**]]     [[**Jenkinsfile**]]                                 [[**Creation**]]  [[**Access**]]        [[**Parameters**]]       [[**Parameters**]]
        ||               ||                                              ||              ||              ||
        ||               ||                                              ||              ||              ||
[[1.1.2: Compromise]] [[1.2.2: Intercept]]
[[**Dependency**]]      [[**Pipeline Trigger**]]
        ||
        ||
[[1.1.3: Malicious]]
[[**Pull Request**]]

```

## Attack Tree Path: [Sub-Goal 1: Compromise Pipeline Execution](./attack_tree_paths/sub-goal_1_compromise_pipeline_execution.md)

*   **[[Sub-Goal 1: Compromise Pipeline Execution]]**
    *   **Likelihood:** Medium
    *   **Description:** The attacker aims to gain control over the execution of the CI/CD pipeline, which typically has elevated privileges within the Kubernetes/OpenShift cluster.

## Attack Tree Path: [1.1: Inject Malicious Code](./attack_tree_paths/1_1_inject_malicious_code.md)

*   **[[1.1: Inject Malicious Code]]**
    *   **Likelihood:** Medium
    *   **Description:** The attacker introduces malicious code into the pipeline's execution flow.

## Attack Tree Path: [1.1.1: Git Repo Poisoning](./attack_tree_paths/1_1_1_git_repo_poisoning.md)

*   **[[1.1.1: Git Repo Poisoning]]**
        *   **Likelihood:** Low
        *   **Impact:** Very High
        *   **Effort:** High
        *   **Skill Level:** Advanced
        *   **Detection Difficulty:** Medium
        *   **Description:** The attacker compromises the Git repository, modifying code or the Jenkinsfile directly. This could involve pushing malicious commits, altering branches, or compromising developer credentials.

## Attack Tree Path: [1.1.2: Compromise Dependency](./attack_tree_paths/1_1_2_compromise_dependency.md)

*   **[[1.1.2: Compromise Dependency]]**
        *   **Likelihood:** Medium
        *   **Impact:** High
        *   **Effort:** Medium to High
        *   **Skill Level:** Intermediate to Advanced
        *   **Detection Difficulty:** Hard
        *   **Description:** The attacker compromises a library or tool used by the application or the fabric8-pipeline-library. This leverages supply chain vulnerabilities.

## Attack Tree Path: [1.1.3: Malicious Pull Request](./attack_tree_paths/1_1_3_malicious_pull_request.md)

*   **[[1.1.3: Malicious Pull Request]]**
        *   **Likelihood:** Medium
        *   **Impact:** High
        *   **Effort:** Low to Medium
        *   **Skill Level:** Intermediate
        *   **Detection Difficulty:** Medium
        *   **Description:** The attacker submits a pull request containing hidden malicious code, relying on social engineering and insufficient code review.

## Attack Tree Path: [1.2: Manipulate Pipeline Definition/Trigger](./attack_tree_paths/1_2_manipulate_pipeline_definitiontrigger.md)

*   **[[1.2: Manipulate Pipeline Definition/Trigger]]**
        *   **Likelihood:** Medium
        *   **Description:** The attacker alters the pipeline's behavior without directly modifying checked-in source code.

## Attack Tree Path: [1.2.1: Modify Jenkinsfile Directly](./attack_tree_paths/1_2_1_modify_jenkinsfile_directly.md)

*   **[[1.2.1: Modify Jenkinsfile Directly]]**
            *   **Likelihood:** Low
            *   **Impact:** Very High
            *   **Effort:** High
            *   **Skill Level:** Advanced
            *   **Detection Difficulty:** Medium
            *   **Description:** The attacker gains write access to the Jenkinsfile and inserts malicious commands.

## Attack Tree Path: [1.2.2: Intercept Pipeline Trigger](./attack_tree_paths/1_2_2_intercept_pipeline_trigger.md)

*   **[[1.2.2: Intercept Pipeline Trigger]]**
            *   **Likelihood:** Medium
            *   **Impact:** High
            *   **Effort:** Medium
            *   **Skill Level:** Intermediate
            *   **Detection Difficulty:** Medium to Hard
            *   **Description:** The attacker intercepts and modifies the parameters of a pipeline trigger (e.g., a webhook), injecting malicious values.

## Attack Tree Path: [Sub-Goal 3: Leverage Misconfiguration](./attack_tree_paths/sub-goal_3_leverage_misconfiguration.md)

*   **[[Sub-Goal 3: Leverage Misconfiguration]]**
    *   **Likelihood:** Medium
    *   **Description:** The attacker exploits misconfigurations in the Kubernetes/OpenShift environment or the pipeline's setup.

## Attack Tree Path: [3.1: Overly Permissive RBAC](./attack_tree_paths/3_1_overly_permissive_rbac.md)

*   **[[3.1: Overly Permissive RBAC]]**
        *   **Likelihood:** Medium
        *   **Impact:** High
        *   **Effort:** Low
        *   **Skill Level:** Intermediate
        *   **Detection Difficulty:** Medium
        *   **Description:** The service account used by the pipeline has excessive permissions within the cluster.

## Attack Tree Path: [3.1.1: Pod Creation](./attack_tree_paths/3_1_1_pod_creation.md)

*   **[[3.1.1: Pod Creation]]**
            *   **Likelihood:** Medium
            *   **Impact:** High
            *   **Effort:** Low
            *   **Skill Level:** Intermediate
            *   **Detection Difficulty:** Medium
            *   **Description:** The service account can create pods in any namespace, allowing deployment of malicious containers.

## Attack Tree Path: [3.1.2: Secrets Access](./attack_tree_paths/3_1_2_secrets_access.md)

*   **[[3.1.2: Secrets Access]]**
            *   **Likelihood:** Medium
            *   **Impact:** Very High
            *   **Effort:** Low
            *   **Skill Level:** Intermediate
            *   **Detection Difficulty:** Medium
            *   **Description:** The service account can access sensitive secrets, leading to credential theft and further compromise.

## Attack Tree Path: [3.2: Unvalidated Inputs](./attack_tree_paths/3_2_unvalidated_inputs.md)

*   **[[3.2: Unvalidated Inputs]]**
        *   **Likelihood:** Medium
        *   **Impact:** High
        *   **Effort:** Low to Medium
        *   **Skill Level:** Intermediate
        *   **Detection Difficulty:** Medium to Hard
        *   **Description:** The pipeline accepts user-provided inputs without proper validation or sanitization.

## Attack Tree Path: [3.2.1: Jenkinsfile Parameters](./attack_tree_paths/3_2_1_jenkinsfile_parameters.md)

*   **[[3.2.1: Jenkinsfile Parameters]]**
            *   **Likelihood:** Medium
            *   **Impact:** High
            *   **Effort:** Low to Medium
            *   **Skill Level:** Intermediate
            *   **Detection Difficulty:** Medium
            *   **Description:** Jenkinsfile parameters are used directly in shell commands or other sensitive operations without validation, leading to code injection.

## Attack Tree Path: [3.2.2: Shared Library Parameters](./attack_tree_paths/3_2_2_shared_library_parameters.md)

*   **[[3.2.2: Shared Library Parameters]]**
            *   **Likelihood:** Medium
            *   **Impact:** High
            *   **Effort:** Low to Medium
            *   **Skill Level:** Intermediate
            *   **Detection Difficulty:** Medium to Hard
            *   **Description:** Shared library functions (including those from fabric8-pipeline-library) accept parameters without proper validation, leading to code injection.

