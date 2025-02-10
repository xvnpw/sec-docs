# Attack Tree Analysis for harness/harness

Objective: Gain Unauthorized Access to/Manipulate Harness Resources via Compromised Application using Go SDK

## Attack Tree Visualization

Goal: Gain Unauthorized Access to/Manipulate Harness Resources via Compromised Application using Go SDK
├── 1.  Improper Authentication/Authorization to Harness Platform  [HIGH-RISK] [CRITICAL]
│   ├── 1.1  Hardcoded API Keys/Service Account Tokens in Application Code [CRITICAL]
│   │   ├── 1.1.1  Source Code Leak (e.g., public Git repository, accidental exposure) [HIGH-RISK]
│   │   └── 1.1.3  Developer Error (e.g., accidentally committing credentials) [HIGH-RISK]
│   ├── 1.2  Weak or Misconfigured API Key/Token Permissions [CRITICAL]
│   │   ├── 1.2.1  Overly Permissive API Key (e.g., granting full admin access) [HIGH-RISK]
│   │   └── 1.2.3  Failure to Rotate API Keys/Tokens Regularly [HIGH-RISK]
│   └── 1.4  Compromised Delegate [CRITICAL]
│       ├── 1.4.1 Delegate is running on compromised host [HIGH-RISK]
│       └── 1.4.2 Delegate has access to sensitive information [HIGH-RISK]
├── 2.  Injection Attacks Targeting Harness API via SDK
│   ├── 2.1  Manipulating SDK Calls to Execute Unauthorized Actions
│   │   ├── 2.1.1  Crafting Malicious Input to SDK Functions (e.g., pipeline names, parameters) [HIGH-RISK]
└── 4.  Supply Chain Attacks Targeting the SDK Itself [HIGH-RISK] [CRITICAL]
    ├── 4.1  Compromised SDK Dependency [CRITICAL]
    │   ├── 4.1.1  Malicious Code Injected into a Dependency Used by the SDK [HIGH-RISK]
    │   └── 4.1.2  Dependency Confusion Attack (using a malicious package with a similar name) [HIGH-RISK]

## Attack Tree Path: [1. Improper Authentication/Authorization to Harness Platform [HIGH-RISK] [CRITICAL]](./attack_tree_paths/1__improper_authenticationauthorization_to_harness_platform__high-risk___critical_.md)

*   **Description:** This is the most critical area, focusing on how an attacker can gain unauthorized access to the Harness platform due to weaknesses in authentication or authorization.

## Attack Tree Path: [1.1 Hardcoded API Keys/Service Account Tokens in Application Code [CRITICAL]](./attack_tree_paths/1_1_hardcoded_api_keysservice_account_tokens_in_application_code__critical_.md)

*   **Description:**  Credentials directly embedded in the application's source code.

## Attack Tree Path: [1.1.1 Source Code Leak [HIGH-RISK]](./attack_tree_paths/1_1_1_source_code_leak__high-risk_.md)

*   **Description:**  Accidental or intentional exposure of the source code containing hardcoded credentials.  Examples include pushing to a public repository, misconfigured S3 buckets, or compromised developer workstations.
*   Likelihood: Medium
*   Impact: High
*   Effort: Very Low
*   Skill Level: Novice
*   Detection Difficulty: Medium

## Attack Tree Path: [1.1.3 Developer Error [HIGH-RISK]](./attack_tree_paths/1_1_3_developer_error__high-risk_.md)

*   **Description:**  A developer accidentally commits credentials to a version control system or leaves them in a publicly accessible location.
*   Likelihood: Medium
*   Impact: High
*   Effort: Very Low
*   Skill Level: Novice
*   Detection Difficulty: Medium

## Attack Tree Path: [1.2 Weak or Misconfigured API Key/Token Permissions [CRITICAL]](./attack_tree_paths/1_2_weak_or_misconfigured_api_keytoken_permissions__critical_.md)

*   **Description:**  API keys or tokens that have excessive privileges or are not properly managed.

## Attack Tree Path: [1.2.1 Overly Permissive API Key [HIGH-RISK]](./attack_tree_paths/1_2_1_overly_permissive_api_key__high-risk_.md)

*   **Description:**  An API key is granted more permissions than necessary, potentially giving an attacker full control over Harness resources.
*   Likelihood: Medium
*   Impact: Very High
*   Effort: Very Low
*   Skill Level: Novice
*   Detection Difficulty: Medium

## Attack Tree Path: [1.2.3 Failure to Rotate API Keys/Tokens Regularly [HIGH-RISK]](./attack_tree_paths/1_2_3_failure_to_rotate_api_keystokens_regularly__high-risk_.md)

*   **Description:**  API keys or tokens are not rotated on a regular schedule, increasing the window of opportunity for an attacker who obtains an old key.
*   Likelihood: High
*   Impact: High
*   Effort: Very Low
*   Skill Level: Novice
*   Detection Difficulty: Medium

## Attack Tree Path: [1.4 Compromised Delegate [CRITICAL]](./attack_tree_paths/1_4_compromised_delegate__critical_.md)

*   **Description:** The Harness Delegate, which executes tasks on behalf of the Harness platform, is compromised.

## Attack Tree Path: [1.4.1 Delegate is running on compromised host [HIGH-RISK]](./attack_tree_paths/1_4_1_delegate_is_running_on_compromised_host__high-risk_.md)

*   **Description:** The host machine running the Delegate is compromised, giving the attacker access to the Delegate's credentials and capabilities.
*   Likelihood: Medium
*   Impact: High
*   Effort: Medium
*   Skill Level: Intermediate to Advanced
*   Detection Difficulty: Medium

## Attack Tree Path: [1.4.2 Delegate has access to sensitive information [HIGH-RISK]](./attack_tree_paths/1_4_2_delegate_has_access_to_sensitive_information__high-risk_.md)

*   **Description:** The Delegate is configured to have access to sensitive information (e.g., secrets, credentials) that it doesn't need, increasing the impact of a compromise.
*   Likelihood: Medium
*   Impact: High
*   Effort: Low
*   Skill Level: Intermediate
*   Detection Difficulty: Medium

## Attack Tree Path: [2. Injection Attacks Targeting Harness API via SDK](./attack_tree_paths/2__injection_attacks_targeting_harness_api_via_sdk.md)



## Attack Tree Path: [2.1 Manipulating SDK Calls to Execute Unauthorized Actions](./attack_tree_paths/2_1_manipulating_sdk_calls_to_execute_unauthorized_actions.md)



## Attack Tree Path: [2.1.1 Crafting Malicious Input to SDK Functions [HIGH-RISK]](./attack_tree_paths/2_1_1_crafting_malicious_input_to_sdk_functions__high-risk_.md)

*   **Description:**  An attacker provides specially crafted input to the SDK functions that are not properly validated, leading to unintended actions on the Harness platform.  This could involve manipulating pipeline names, parameters, or other data.
*   Likelihood: Medium
*   Impact: Medium to High
*   Effort: Medium
*   Skill Level: Intermediate
*   Detection Difficulty: Medium

## Attack Tree Path: [4. Supply Chain Attacks Targeting the SDK Itself [HIGH-RISK] [CRITICAL]](./attack_tree_paths/4__supply_chain_attacks_targeting_the_sdk_itself__high-risk___critical_.md)

*   **Description:** Attacks that target the SDK's dependencies or build process, rather than the application using the SDK.

## Attack Tree Path: [4.1 Compromised SDK Dependency [CRITICAL]](./attack_tree_paths/4_1_compromised_sdk_dependency__critical_.md)

*   **Description:**  A dependency used by the Harness Go SDK is compromised, either directly or through a dependency confusion attack.

## Attack Tree Path: [4.1.1 Malicious Code Injected into a Dependency Used by the SDK [HIGH-RISK]](./attack_tree_paths/4_1_1_malicious_code_injected_into_a_dependency_used_by_the_sdk__high-risk_.md)

*   **Description:**  An attacker injects malicious code into a legitimate dependency used by the SDK.
*   Likelihood: Low (But increasing in frequency)
*   Impact: High
*   Effort: Medium to High
*   Skill Level: Advanced
*   Detection Difficulty: Hard

## Attack Tree Path: [4.1.2 Dependency Confusion Attack [HIGH-RISK]](./attack_tree_paths/4_1_2_dependency_confusion_attack__high-risk_.md)

*   **Description:**  An attacker publishes a malicious package with a name similar to a legitimate dependency, tricking the build system into using the malicious package.
*   Likelihood: Low (But increasing in frequency)
*   Impact: High
*   Effort: Medium
*   Skill Level: Intermediate to Advanced
*   Detection Difficulty: Hard

