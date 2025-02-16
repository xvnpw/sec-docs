# Attack Tree Analysis for pi-hole/pi-hole

Objective: Disrupt Network Availability, Integrity, or Confidentiality via Pi-hole [!]

## Attack Tree Visualization

```
                                     [Attacker's Goal] [!]
                                        /           \
                                       /             \
                  [1.2 Block Legitimate Domains]      [2.2 Modify Lists] [!]      [3.3 Pivot Attack] [!]
                         /                                   /
                        /                                   /
                      [C]                                 [I]

```

## Attack Tree Path: [[Attacker's Goal: Disrupt Network Availability, Integrity, or Confidentiality via Pi-hole] [!]](./attack_tree_paths/_attacker's_goal_disrupt_network_availability__integrity__or_confidentiality_via_pi-hole___!_.md)

*   **Description:** This is the overarching objective of the attacker. Any successful compromise of the Pi-hole that achieves one of these disruptions fulfills this goal.
*   **Criticality:** This is the root node and is inherently critical.

## Attack Tree Path: [[1.2 Block Legitimate Domains]](./attack_tree_paths/_1_2_block_legitimate_domains_.md)

*   **Description:** This attack aims to make the network partially or completely unusable by adding legitimate and essential domains to the Pi-hole's blocklist. This prevents users from accessing those services.
*   **Impact:** High - Can cause significant disruption to network users and services.
*   **Attack Vector:**
    *   **[C] Unauthorized List Modification:**
        *   **Description:** The attacker gains unauthorized access to either the Pi-hole's web interface or the underlying configuration files and adds legitimate domains to the blocklist.
        *   **Likelihood:** Medium - Depends on the strength of passwords, exposure of the web interface, and security of the system.
        *   **Impact:** High - Directly blocks access to targeted domains.
        *   **Effort:** Low - Brute-forcing weak passwords or exploiting exposed services is relatively easy.
        *   **Skill Level:** Beginner - Requires basic hacking tools and techniques.
        *   **Detection Difficulty:** Medium - Changes to blocklists are often logged, but detecting unauthorized changes requires active monitoring and comparison to a known good state.

## Attack Tree Path: [[2.2 Modify Lists] [!]](./attack_tree_paths/_2_2_modify_lists___!_.md)

*   **Description:** This is a broader category encompassing any unauthorized modification of Pi-hole's blocklists or whitelists. This can be used to block legitimate domains (as in 1.2), allow malicious domains, or otherwise disrupt DNS resolution.
*   **Criticality:** This is a critical node because it's a central point of attack with multiple access vectors and high impact.
*   **Impact:** High - Can disrupt network availability, redirect users to malicious sites, or bypass security measures.
*   **Attack Vector:**
    *   **[I] Unauthorized Web Access:**
        *   **Description:** The attacker gains unauthorized access to the Pi-hole's web interface, typically through weak passwords, exposed services, or vulnerabilities in the web application.
        *   **Likelihood:** Medium - Depends on password strength and network exposure.
        *   **Impact:** High - Allows direct manipulation of Pi-hole's core functionality.
        *   **Effort:** Low - Brute-forcing or guessing passwords is easy.
        *   **Skill Level:** Beginner - Basic hacking tools and techniques.
        *   **Detection Difficulty:** Medium - Failed login attempts are often logged, but successful logins may not be immediately suspicious.

## Attack Tree Path: [[3.3 Pivot Attack] [!]](./attack_tree_paths/_3_3_pivot_attack___!_.md)

*   **Description:** After compromising the Pi-hole, the attacker uses it as a base to launch further attacks against other devices on the local network. This leverages the Pi-hole's trusted position within the network.
*   **Criticality:** This is a critical node because it represents a significant escalation of the attack, potentially leading to a much wider compromise.
*   **Impact:** Very High - Can lead to the compromise of multiple devices and sensitive data.
*  **Attack Vectors (Not shown in the sub-tree, but relevant from the full tree):**
    *    **(Q) Network Scanning:**
        *   **Description:** The attacker uses the compromised Pi-hole to scan the local network for other vulnerable devices.
        *   **Likelihood:** Medium
        *   **Impact:** High (as a precursor to further attacks)
        *   **Effort:** Low
        *   **Skill Level:** Intermediate
        *   **Detection Difficulty:** Medium
    *    **(R) Launch Attacks:**
        *   **Description:** The attacker uses the compromised Pi-hole to launch direct attacks (e.g., exploit vulnerabilities, brute-force passwords) against other devices identified during scanning.
        *   **Likelihood:** Low (depends on vulnerabilities on other devices)
        *   **Impact:** Very High
        *   **Effort:** Medium
        *   **Skill Level:** Advanced
        *   **Detection Difficulty:** Medium

