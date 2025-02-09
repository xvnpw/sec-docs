# Attack Tree Analysis for ossrs/srs

Objective: Compromise SRS-based Application

## Attack Tree Visualization

```
                                     [Attacker's Goal: Compromise SRS-based Application]
                                                    |
        =========================================================================================
        ||                                              ||
[[Sub-Goal 1: Disrupt Service (DoS/DDoS)]]      [[Sub-Goal 2: Unauthorized Access/Control]]
        ||                                              ||
=========================               =================================================
||                      ||               ||                               ||
[[1.1 Resource Exhaust]]                 [[2.1 Authentication Bypass]]
        ||                                              ||
=================                               =================
||      ||      ||                              ||       ||
[[1.1.1]][[1.1.2]][[1.1.3]]                    [[2.1.1]][[2.1.2]]
  CPU     Mem    Conn                             Weak    Def.
  Flood   Flood  Flood                            Creds   Creds
```
And also critical node:
```
[[3.2.2]]
Client IPs
```

## Attack Tree Path: [Sub-Goal 1: Disrupt Service (DoS/DDoS)](./attack_tree_paths/sub-goal_1_disrupt_service__dosddos_.md)

*   **Description:** The attacker aims to make the SRS-based streaming service unavailable to legitimate users. This is a critical sub-goal because service disruption directly impacts the application's core functionality.
*   **High-Risk Path:** `=== [[1.1 Resource Exhaustion]] ===`
    *   **Description:** This path focuses on overwhelming the server's resources, making it unable to handle legitimate requests.
    *   **Critical Nodes:**
        *   **[[1.1.1 CPU Flood]]:**
            *   **Description:** The attacker sends a large number of computationally expensive requests to the SRS server. This could involve requesting multiple simultaneous transcodes, initiating many connections with complex handshakes, or exploiting any SRS feature that consumes significant CPU cycles.
            *   **Likelihood:** Medium
            *   **Impact:** High
            *   **Effort:** Low
            *   **Skill Level:** Novice
            *   **Detection Difficulty:** Easy
        *   **[[1.1.2 Memory Flood]]:**
            *   **Description:** The attacker attempts to consume all available memory on the SRS server. This could involve sending large amounts of data, creating numerous persistent connections, or exploiting memory leaks within SRS's handling of specific codecs or protocols.
            *   **Likelihood:** Medium
            *   **Impact:** High
            *   **Effort:** Medium
            *   **Skill Level:** Intermediate
            *   **Detection Difficulty:** Medium
        *   **[[1.1.3 Connection Flood]]:**
            *   **Description:** The attacker establishes a massive number of connections (valid or invalid) to the SRS server, exhausting its connection pool and preventing legitimate users from connecting.
            *   **Likelihood:** High
            *   **Impact:** High
            *   **Effort:** Low
            *   **Skill Level:** Script Kiddie
            *   **Detection Difficulty:** Very Easy

## Attack Tree Path: [Sub-Goal 2: Unauthorized Access/Control](./attack_tree_paths/sub-goal_2_unauthorized_accesscontrol.md)

*   **Description:** The attacker aims to gain access to streams or control over the SRS server without proper authorization. This is a critical sub-goal because it can lead to complete system compromise, data breaches, and unauthorized manipulation of the streaming service.
*   **High-Risk Path:** `=== [[2.1 Authentication Bypass]] ===`
    *   **Description:** This path focuses on circumventing the authentication mechanisms protecting the SRS server or its streams.
    *   **Critical Nodes:**
        *   **[[2.1.1 Weak Credentials]]:**
            *   **Description:** The attacker attempts to guess or brute-force weak usernames and passwords used for accessing the SRS control panel, protected streams, or administrative interfaces.
            *   **Likelihood:** High
            *   **Impact:** Very High
            *   **Effort:** Low
            *   **Skill Level:** Script Kiddie
            *   **Detection Difficulty:** Medium
        *   **[[2.1.2 Default Credentials]]:**
            *   **Description:** The attacker attempts to use default credentials (e.g., "admin/admin") that may have been left unchanged by the administrator. This is a surprisingly common vulnerability.
            *   **Likelihood:** High
            *   **Impact:** Very High
            *   **Effort:** Very Low
            *   **Skill Level:** Script Kiddie
            *   **Detection Difficulty:** Medium

## Attack Tree Path: [Critical Node outside of main sub-trees](./attack_tree_paths/critical_node_outside_of_main_sub-trees.md)

* **[[3.2.2 Client IPs]]**:
    * **Description:** The attacker obtains the IP addresses of clients connecting to the streams.
    * **Likelihood:** High
    * **Impact:** Medium
    * **Effort:** Low
    * **Skill Level:** Novice
    * **Detection Difficulty:** Easy
    * **Why it's critical:** While not as directly impactful as DoS or full control, IP leakage is a serious privacy violation.  It can enable targeted attacks against clients, deanonymization, and potentially reveal sensitive information about the users of the streaming service.  It's also relatively easy to achieve through misconfiguration or vulnerabilities in logging or stream metadata handling.

