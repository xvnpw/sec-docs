# Attack Tree Analysis for jordansissel/fpm

Objective: Gain Unauthorized Code Execution or Distribute Malicious Package via fpm

## Attack Tree Visualization

Goal: Gain Unauthorized Code Execution or Distribute Malicious Package via fpm
├── 1.  Exploit fpm's Package Building Process
│   ├── 1.1  Dependency Confusion/Hijacking during Build  [HIGH RISK]
│   │   ├── 1.1.1  Target a dependency specified in the fpm input (e.g., Gemfile, package.json, requirements.txt) [CRITICAL]
│   │   │   ├── 1.1.1.1  Publish a malicious package with the same name to a public repository...
│   │   └── 1.1.2  Target a transitive dependency (a dependency of a dependency)... [CRITICAL]
│   ├── 1.2  Malicious Input Files
│   │   ├── 1.2.1.3  Social engineering to trick a developer into including malicious code. [HIGH RISK]
│   │   └── 1.2.2  Provide a malicious `--after-install`, `--before-install`, ... script. [HIGH RISK] [CRITICAL]
│   │       └── 1.2.2.1  Craft a script that executes arbitrary commands.
└── 2.  Exploit fpm's Package Installation Process (Less Likely, but Possible)
    ├── 2.1  Tamper with the Package Repository
    │   ├── 2.1.1  Compromise the server hosting the package repository. [CRITICAL]
    │   │   └── 2.1.1.1  Replace a legitimate package with a malicious one.
    └── 2.3 Local fpm binary exploitation [HIGH RISK]
        └── 2.3.1 If attacker has local access, they can replace fpm binary with malicious one. [CRITICAL]
            └── 2.3.1.1  Replace fpm with a script or binary that performs malicious actions when invoked.

## Attack Tree Path: [1.1 Dependency Confusion/Hijacking during Build [HIGH RISK]](./attack_tree_paths/1_1_dependency_confusionhijacking_during_build__high_risk_.md)

*   **Description:** This attack exploits the way package managers resolve dependencies.  The attacker publishes a malicious package with the same name as a legitimate dependency, hoping the package manager will choose the malicious version.
*   **Sub-Vectors:**
    *   **1.1.1 Target a dependency specified in the fpm input [CRITICAL]:**
        *   **Description:**  The attacker targets a direct dependency listed in the project's dependency file (e.g., `Gemfile`, `package.json`).
        *   **1.1.1.1 Publish a malicious package...:**
            *   Likelihood: **Medium**
            *   Impact: **High**
            *   Effort: **Low**
            *   Skill Level: **Intermediate**
            *   Detection Difficulty: **Medium**
    *   **1.1.2 Target a transitive dependency [CRITICAL]:**
        *   **Description:** The attacker targets a dependency of a dependency, making it harder to detect.
        *   Likelihood: **Medium**
        *   Impact: **High**
        *   Effort: **Low-Medium**
        *   Skill Level: **Intermediate-Advanced**
        *   Detection Difficulty: **Hard**

## Attack Tree Path: [1.2 Malicious Input Files](./attack_tree_paths/1_2_malicious_input_files.md)

*   **1.2.1.3 Social engineering to trick a developer [HIGH RISK]:**
    *   **Description:** The attacker uses social engineering techniques to persuade a developer to include malicious code or configuration in the project.
    *   Likelihood: **Medium**
    *   Impact: **High**
    *   Effort: **Low-Medium**
    *   Skill Level: **Intermediate**
    *   Detection Difficulty: **Medium**
*   **1.2.2 Provide a malicious `--after-install`, etc. script [HIGH RISK] [CRITICAL]:**
    *   **Description:**  The attacker provides a malicious script to be executed during the package installation or removal process.
    *   **1.2.2.1 Craft a script that executes arbitrary commands:**
        *   Likelihood: **Medium**
        *   Impact: **High**
        *   Effort: **Low**
        *   Skill Level: **Intermediate**
        *   Detection Difficulty: **Medium**

## Attack Tree Path: [2.1 Tamper with the Package Repository](./attack_tree_paths/2_1_tamper_with_the_package_repository.md)

*   **2.1.1 Compromise the server hosting the package repository. [CRITICAL]**
    *   **Description:** The attacker gains control of the server hosting the package repository and replaces legitimate packages with malicious ones.
    *   **2.1.1.1 Replace a legitimate package with a malicious one:**
        *   Likelihood: **Low**
        *   Impact: **Very High**
        *   Effort: **High**
        *   Skill Level: **Advanced**
        *   Detection Difficulty: **Medium**

## Attack Tree Path: [2.3 Local fpm binary exploitation [HIGH RISK]](./attack_tree_paths/2_3_local_fpm_binary_exploitation__high_risk_.md)

*   **2.3.1 If attacker has local access, they can replace fpm binary... [CRITICAL]**
    *   **Description:** The attacker, having gained local access to the system, replaces the legitimate `fpm` binary with a malicious version.
    *   **2.3.1.1 Replace fpm with a script or binary...:**
        *   Likelihood: **Medium**
        *   Impact: **High**
        *   Effort: **Low**
        *   Skill Level: **Intermediate**
        *   Detection Difficulty: **Medium**

