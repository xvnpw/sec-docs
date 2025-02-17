# Attack Tree Analysis for aws/aws-cdk

Objective: Gain Unauthorized Access and Control of AWS Resources

## Attack Tree Visualization

[[Gain Unauthorized Access and Control of AWS Resources]]
        /                               \
       /                                 \
[[Compromise CDK Deployment Pipeline]]     [Exploit CDK Application Code Vulnerabilities]
       /                                         /           |
      /                                         /            |
[Manipulate CDK                          [[Insecure CDK  [[Insufficient
  Source Code]                             Dependencies]]  IAM Policies]]
     /     \                                /      \        /      \
    /       \                              /        \      /        \
[[Modify   [Inject                      ***Supply  ***Use Outdated [[Overly   [[Lack of
 CDK     Malicious                    Chain   or Vulnerable  Permissive Least
 Code    Constructs]                   Attack]  CDK Libs]]   Policies]]  Privilege]]
 Directly]]
    |
***Commit to
  Repo]***

## Attack Tree Path: [High-Risk Path 1](./attack_tree_paths/high-risk_path_1.md)

**Commit to Repo -> Modify CDK Code Directly -> Compromise CDK Deployment Pipeline -> Gain Unauthorized Access...**:

*   **Commit to Repo:**
    *   **Description:** The attacker gains write access to the source code repository (e.g., GitHub, CodeCommit). This could be through stolen credentials, social engineering, or exploiting vulnerabilities in the repository's access controls.
    *   **Likelihood:** Low to Medium (depends on repository security)
    *   **Impact:** Very High
    *   **Effort:** Medium
    *   **Skill Level:** Intermediate
    *   **Detection Difficulty:** Medium

*   **Modify CDK Code Directly:** (See description above)

*   **Compromise CDK Deployment Pipeline:** (See description above)

*   **Gain Unauthorized Access and Control of AWS Resources:** (See description above)

## Attack Tree Path: [High-Risk Path 2](./attack_tree_paths/high-risk_path_2.md)

***Supply Chain Attack -> Insecure CDK Dependencies -> Exploit CDK Application Code Vulnerabilities -> Gain Unauthorized Access...***:

*   **Supply Chain Attack:**
    *   **Description:** The attacker compromises a third-party library that the CDK application depends on. This is a highly sophisticated attack that targets the software supply chain.
    *   **Likelihood:** Low
    *   **Impact:** Very High
    *   **Effort:** Very High
    *   **Skill Level:** Expert
    *   **Detection Difficulty:** Very Hard

*   **Insecure CDK Dependencies:** (See description above)

*   **Exploit CDK Application Code Vulnerabilities:** This is a general category; the specific vulnerability exploited depends on the compromised dependency.

*   **Gain Unauthorized Access and Control of AWS Resources:** (See description above)

## Attack Tree Path: [High-Risk Path 3](./attack_tree_paths/high-risk_path_3.md)

***Use Outdated or Vulnerable CDK Libs -> Insecure CDK Dependencies -> Exploit CDK Application Code Vulnerabilities -> Gain Unauthorized Access...***:

*   **Use Outdated or Vulnerable CDK Libs:**
    *   **Description:** The CDK application uses versions of the CDK libraries or other dependencies that contain known vulnerabilities.
    *   **Likelihood:** Medium
    *   **Impact:** Medium to High
    *   **Effort:** Low
    *   **Skill Level:** Intermediate
    *   **Detection Difficulty:** Easy

*   **Insecure CDK Dependencies:** (See description above)

*   **Exploit CDK Application Code Vulnerabilities:** This is a general category; the specific vulnerability exploited depends on the outdated library.

*   **Gain Unauthorized Access and Control of AWS Resources:** (See description above)

## Attack Tree Path: [Critical Node: [[Gain Unauthorized Access and Control of AWS Resources]]](./attack_tree_paths/critical_node___gain_unauthorized_access_and_control_of_aws_resources__.md)

*   **Description:** The ultimate objective of the attacker, representing complete control over the AWS resources provisioned by the CDK application. This could lead to data theft, service disruption, financial loss, or reputational damage.

## Attack Tree Path: [Critical Node: [[Compromise CDK Deployment Pipeline]]](./attack_tree_paths/critical_node___compromise_cdk_deployment_pipeline__.md)

*   **Description:** Gaining control over the CI/CD pipeline used to deploy the CDK application. This allows the attacker to inject malicious code or configurations into the infrastructure.
*    **Child Nodes:**
    *   [Manipulate CDK Source Code]

## Attack Tree Path: [Critical Node: [[Insecure CDK Dependencies]]](./attack_tree_paths/critical_node___insecure_cdk_dependencies__.md)

*   **Description:** The CDK application relies on vulnerable or compromised third-party libraries.
*   **Child Nodes:**
    *   ***Supply Chain Attack***
    *   ***Use Outdated or Vulnerable CDK Libs***

## Attack Tree Path: [Critical Node: [[Insufficient IAM Policies]]](./attack_tree_paths/critical_node___insufficient_iam_policies__.md)

*   **Description:** The IAM roles and policies defined by the CDK application are too broad, granting excessive permissions.
*   **Child Nodes:**
    *   [[Overly Permissive Policies]]
    *   [[Lack of Least Privilege]]

## Attack Tree Path: [Node: [Manipulate CDK Source Code]](./attack_tree_paths/node__manipulate_cdk_source_code_.md)

* **Description:** Directly altering the CDK code to introduce malicious changes.
* **Child Nodes:**
    * [[Modify CDK Code Directly]]
    * [Inject Malicious Constructs]

## Attack Tree Path: [Node: [[Modify CDK Code Directly]]](./attack_tree_paths/node___modify_cdk_code_directly__.md)

*   **Description:** The attacker gains access to the source code repository and directly modifies the CDK code.
*   **Child Nodes:**
    *   ***Commit to Repo***

## Attack Tree Path: [Node: [Inject Malicious Constructs]](./attack_tree_paths/node__inject_malicious_constructs_.md)

*   **Description:** The attacker introduces or modifies CDK constructs to perform unintended actions.

## Attack Tree Path: [Critical Node: [[Overly Permissive Policies]]](./attack_tree_paths/critical_node___overly_permissive_policies__.md)

*    **Description:** IAM roles and policies are configured with excessive permissions, granting more access than necessary.
*    **Likelihood:** Medium
*    **Impact:** High
*    **Effort:** Low
*    **Skill Level:** Intermediate
*    **Detection Difficulty:** Medium

## Attack Tree Path: [Critical Node: [[Lack of Least Privilege]]](./attack_tree_paths/critical_node___lack_of_least_privilege__.md)

*    **Description:** The principle of least privilege is not followed, and resources are granted more permissions than they strictly require for their intended function.
*    **Likelihood:** High
*    **Impact:** Medium to High
*    **Effort:** Low
*    **Skill Level:** Intermediate
*    **Detection Difficulty:** Medium

