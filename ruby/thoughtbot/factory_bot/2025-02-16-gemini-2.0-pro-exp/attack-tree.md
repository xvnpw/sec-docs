# Attack Tree Analysis for thoughtbot/factory_bot

Objective: Gain unauthorized access to data, modify data, or disrupt application functionality via factory_bot

## Attack Tree Visualization

Goal: Gain unauthorized access to data, modify data, or disrupt application functionality via factory_bot

├── (OR) 1.  Data Leakage / Unauthorized Access [HIGH-RISK]
│   ├── (AND) 1.1  Exploiting Overly Permissive Factories [HIGH-RISK]
│   │   ├── 1.1.1  Factories create users with default admin privileges (OR) [CRITICAL]
│   │   │   ├── 1.1.1.1  Developers forget to override default admin attribute in tests. [CRITICAL]
│   │   │   └── 1.1.1.2  Factories are used in production seed data with admin privileges.
│   │   ├── 1.1.2  Factories expose sensitive attributes by default (e.g., password hashes, API keys) (OR) [CRITICAL]
│   │   │   ├── 1.1.2.1  Developers don't explicitly exclude sensitive attributes in factory definitions. [CRITICAL]
│   │   │   └── 1.1.2.2  Factories generate predictable sensitive data (e.g., weak passwords).
├── (OR) 2.  Data Modification / Integrity Violation [HIGH-RISK]
│   ├── (AND) 2.3  Exploiting Traits for Malicious Data [HIGH-RISK]
│       ├── 2.3.1  Traits designed for testing are misused to create malicious data in production. [CRITICAL]
│       └── 2.3.2  Traits are used to bypass security checks or access controls.

## Attack Tree Path: [1. Data Leakage / Unauthorized Access [HIGH-RISK]](./attack_tree_paths/1__data_leakage__unauthorized_access__high-risk_.md)

*   **1.1 Exploiting Overly Permissive Factories [HIGH-RISK]**
    *   **Description:** Factories are defined in a way that makes them inherently vulnerable to misuse, either by creating objects with excessive privileges or by exposing sensitive information.
    *   **1.1.1 Factories create users with default admin privileges (OR) [CRITICAL]**
        *   **Description:**  The factory for a user model is configured to assign administrative privileges by default, without requiring explicit action from the developer.
        *   **1.1.1.1 Developers forget to override default admin attribute in tests. [CRITICAL]**
            *   **Description:**  When using the factory in tests, developers fail to explicitly set the admin attribute to `false`, resulting in the creation of unintended admin users.
            *   **Likelihood:** Medium
            *   **Impact:** Very High
            *   **Effort:** Very Low
            *   **Skill Level:** Novice
            *   **Detection Difficulty:** Medium
        *   **1.1.1.2 Factories are used in production seed data with admin privileges.**
            *   **Description:** The vulnerable factory is mistakenly used in scripts that populate the production database, leading to the creation of admin users in the live environment.
            *   **Likelihood:** Low
            *   **Impact:** Very High
            *   **Effort:** Very Low
            *   **Skill Level:** Novice
            *   **Detection Difficulty:** Hard
    *   **1.1.2 Factories expose sensitive attributes by default (OR) [CRITICAL]**
        *   **Description:** The factory definition includes sensitive attributes (like password hashes or API keys) without proper protection or obfuscation.
        *   **1.1.2.1 Developers don't explicitly exclude sensitive attributes in factory definitions. [CRITICAL]**
            *   **Description:**  The factory is defined without explicitly excluding sensitive attributes, making them accessible through methods like `attributes_for`.
            *   **Likelihood:** Medium
            *   **Impact:** High
            *   **Effort:** Very Low
            *   **Skill Level:** Novice
            *   **Detection Difficulty:** Medium
        *   **1.1.2.2 Factories generate predictable sensitive data (e.g., weak passwords).**
            *   **Description:** The factory uses hardcoded or easily guessable values for sensitive attributes, making them vulnerable to brute-force or dictionary attacks.
            *   **Likelihood:** Medium
            *   **Impact:** High
            *   **Effort:** Very Low
            *   **Skill Level:** Novice
            *   **Detection Difficulty:** Medium

## Attack Tree Path: [2. Data Modification / Integrity Violation [HIGH-RISK]](./attack_tree_paths/2__data_modification__integrity_violation__high-risk_.md)

*   **2.3 Exploiting Traits for Malicious Data [HIGH-RISK]**
    *   **Description:**  Factory traits, which are designed to modify object attributes for specific scenarios, are misused to create malicious data or bypass security controls.
    *   **2.3.1 Traits designed for testing are misused to create malicious data in production. [CRITICAL]**
        *   **Description:** A trait intended for testing purposes (e.g., creating an invalid user or a user with specific permissions) is accidentally or maliciously used in production code or seed scripts.
        *   **Likelihood:** Low
        *   **Impact:** High
        *   **Effort:** Very Low
        *   **Skill Level:** Novice
        *   **Detection Difficulty:** Hard
    *   **2.3.2 Traits are used to bypass security checks or access controls.**
        *   **Description:** A trait is specifically crafted to override security-related attributes or bypass access control mechanisms, allowing an attacker to gain unauthorized privileges or modify protected data.
        *   **Likelihood:** Low
        *   **Impact:** High
        *   **Effort:** Low
        *   **Skill Level:** Intermediate
        *   **Detection Difficulty:** Very Hard

