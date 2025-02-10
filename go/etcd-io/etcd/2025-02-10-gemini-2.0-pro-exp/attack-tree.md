# Attack Tree Analysis for etcd-io/etcd

Objective: Compromise etcd Data/Cluster

## Attack Tree Visualization

[[Attacker Goal: Compromise etcd Data/Cluster]]
                    |
    =================================================
    ||
[[1. Unauthorized Access to etcd API]]
    ||
==============================
||             ||
[[1.1 Weak/   [[1.2 Default/
No Auth]]   Leaked Creds]]
                    |
    =================================================
                    |
        [2. Exploit etcd Vulnerabilities]
                    |
        --------------------------------
                    |
        [2.3 Logic Errors in etcd]
                    |
        --------------------------------
                    |
        [2.3.1 Incorrect Role Assignments]
                    |
        ================================
                    ||
        [[2.3.1.1 Overly Permissive Roles]]

## Attack Tree Path: [Attacker Goal: Compromise etcd Data/Cluster](./attack_tree_paths/attacker_goal_compromise_etcd_datacluster.md)

*   **Description:** The ultimate objective of the attacker is to gain unauthorized access to, modify, or delete data within the etcd cluster. This can lead to application disruption, data breaches, or privilege escalation within the application.
    *   **Likelihood:** N/A (This is the goal, not an attack step)
    *   **Impact:** Very High
    *   **Effort:** N/A
    *   **Skill Level:** N/A
    *   **Detection Difficulty:** N/A

## Attack Tree Path: [1. Unauthorized Access to etcd API](./attack_tree_paths/1__unauthorized_access_to_etcd_api.md)

*   **Description:** The attacker gains access to the etcd API without proper authorization. This is a critical entry point for many attacks.
    *   **Likelihood:** High (Due to common misconfigurations and credential leaks)
    *   **Impact:** Very High (Full control over etcd data)
    *   **Effort:** Varies (Depends on the specific method used)
    *   **Skill Level:** Varies (Depends on the specific method used)
    *   **Detection Difficulty:** Varies (Depends on monitoring and logging)

## Attack Tree Path: [1.1 Weak/No Auth](./attack_tree_paths/1_1_weakno_auth.md)

*   **Description:** The etcd cluster is configured without any authentication or with easily guessable passwords.
    *   **Likelihood:** Medium
    *   **Impact:** Very High
    *   **Effort:** Very Low
    *   **Skill Level:** Novice
    *   **Detection Difficulty:** Very Easy (If authentication logs are monitored)

## Attack Tree Path: [1.2 Default/Leaked Creds](./attack_tree_paths/1_2_defaultleaked_creds.md)

*   **Description:** The attacker obtains default credentials (if they haven't been changed) or credentials that have been leaked through various means (code repositories, compromised servers, social engineering).
    *   **Likelihood:** Medium
    *   **Impact:** Very High
    *   **Effort:** Low
    *   **Skill Level:** Intermediate
    *   **Detection Difficulty:** Medium (Requires monitoring for unauthorized access and credential use)

## Attack Tree Path: [2. Exploit etcd Vulnerabilities](./attack_tree_paths/2__exploit_etcd_vulnerabilities.md)

* **Description:** This is a general category, and not a critical node itself, but it leads to the critical node below. It represents the attacker leveraging flaws in the etcd software.
    * **Likelihood:** Varies
    * **Impact:** Varies
    * **Effort:** Varies
    * **Skill Level:** Varies
    * **Detection Difficulty:** Varies

## Attack Tree Path: [2.3 Logic Errors in etcd](./attack_tree_paths/2_3_logic_errors_in_etcd.md)

* **Description:** This is a general category, and not a critical node itself. It represents flaws in etcd's authorization logic.
    * **Likelihood:** Low
    * **Impact:** High
    * **Effort:** High
    * **Skill Level:** Advanced
    * **Detection Difficulty:** Hard

## Attack Tree Path: [2.3.1 Incorrect Role Assignments](./attack_tree_paths/2_3_1_incorrect_role_assignments.md)

*   **Description:** Users or applications are granted roles with excessive permissions, allowing them to perform actions they shouldn't be able to.
    *   **Likelihood:** Medium
    *   **Impact:** Medium to High (Depends on the level of over-permissioning)
    *   **Effort:** Low
    *   **Skill Level:** Intermediate
    *   **Detection Difficulty:** Medium

## Attack Tree Path: [2.3.1.1 Overly Permissive Roles](./attack_tree_paths/2_3_1_1_overly_permissive_roles.md)

*   **Description:** A role is defined with overly broad permissions (e.g., read-write access to all keys) when more restrictive permissions would suffice. This is a common configuration error.
    *   **Likelihood:** Medium
    *   **Impact:** Medium to High (Depends on the specific permissions granted)
    *   **Effort:** Very Low
    *   **Skill Level:** Novice
    *   **Detection Difficulty:** Easy (Through configuration audits)

