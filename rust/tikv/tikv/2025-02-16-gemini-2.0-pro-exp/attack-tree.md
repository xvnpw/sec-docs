# Attack Tree Analysis for tikv/tikv

Objective: Compromise Application via TiKV (Focusing on High-Risk Paths)

## Attack Tree Visualization

Compromise Application via TiKV
├── [1] Data Exfiltration [*]
│   └── [OR] Gain Unauthorized Access to TiKV Cluster [!] [*]
│       ├── [+] Weak or Default Credentials [!] [*]
│       │   ├── [ ] Brute-force attack on TiKV credentials
│       │   └── [ ] Use of default/easily guessable credentials [!]
│       ├── [+] Network Misconfiguration [!] [*]
│       │   ├── [ ] TiKV ports exposed to untrusted networks [!]
│       │   ├── [ ] Firewall misconfiguration allowing unauthorized access [!]
│       │   └── [ ] Lack of network segmentation isolating TiKV [!]
│       └── [+] Compromise Placement Driver (PD) [*]
│           └── [ ] Gain unauthorized access to PD (weak credentials, network misconfiguration) [!]
├── [2] Data Corruption/Destruction [*]
│   └── [OR] (Same attack vectors as Data Exfiltration, but with the intent to modify/delete data)
├── [3] Denial of Service (DoS)
│   ├── [OR] Resource Exhaustion [!]
│   │   ├── [+] Overwhelm TiKV with Requests [!]
│   │   │   ├── [ ] Send a large number of read/write requests [!]
│   │   │   └── [ ] Send large, complex queries
│   └── [OR] Network-Based DoS [!]
│       ├── [ ] Flood TiKV ports with traffic [!]
│       └── [ ] Disrupt network connectivity to TiKV
└── [5] Code Execution on TiKV Nodes [*]
    └── [OR] Exploit TiKV Server Vulnerabilities (as in Data Exfiltration, but with a focus on RCE) [*]

## Attack Tree Path: [Data Exfiltration](./attack_tree_paths/data_exfiltration.md)

*   **Critical Node:** Represents the primary goal of stealing sensitive data.

    *   **Gain Unauthorized Access to TiKV Cluster [!] [*]**
        *   **High-Risk Path & Critical Node:** This is the most common and impactful entry point.
        *   **Weak or Default Credentials [!] [*]**
            *   **High-Risk Path & Critical Node:**  A major vulnerability due to ease of exploitation.
            *   **Brute-force attack on TiKV credentials:**
                *   **Description:**  Attempting to guess passwords by trying many combinations.
                *   **Likelihood:** Medium
                *   **Impact:** Very High
                *   **Effort:** Low
                *   **Skill Level:** Novice
                *   **Detection Difficulty:** Easy (with proper logging and monitoring)
            *   **Use of default/easily guessable credentials [!]:**
                *   **Description:**  Exploiting unchanged default passwords or easily predictable ones.
                *   **Likelihood:** High
                *   **Impact:** Very High
                *   **Effort:** Very Low
                *   **Skill Level:** Novice
                *   **Detection Difficulty:** Very Easy (if auditing for default credentials)
        *   **Network Misconfiguration [!] [*]**
            *   **High-Risk Path & Critical Node:** Exposing TiKV to unauthorized networks.
            *   **TiKV ports exposed to untrusted networks [!]:**
                *   **Description:**  TiKV services are directly accessible from the internet or other untrusted networks.
                *   **Likelihood:** Medium
                *   **Impact:** Very High
                *   **Effort:** Low
                *   **Skill Level:** Intermediate
                *   **Detection Difficulty:** Easy (with network scanning)
            *   **Firewall misconfiguration allowing unauthorized access [!]:**
                *   **Description:**  Firewall rules are too permissive, allowing unintended access to TiKV.
                *   **Likelihood:** Medium
                *   **Impact:** Very High
                *   **Effort:** Low
                *   **Skill Level:** Intermediate
                *   **Detection Difficulty:** Easy (with firewall rule review)
            *   **Lack of network segmentation isolating TiKV [!]:**
                *   **Description:**  TiKV is not isolated on a dedicated network, increasing the attack surface.
                *   **Likelihood:** Medium
                *   **Impact:** Very High
                *   **Effort:** Low
                *   **Skill Level:** Intermediate
                *   **Detection Difficulty:** Easy (with network architecture review)
        * **Compromise Placement Driver (PD) [*]**
            *   **Critical Node:** Gaining control of the PD allows manipulation of the entire cluster.
            *    **Gain unauthorized access to PD (weak credentials, network misconfiguration) [!]**: 
                *   **Description:** Similar vulnerabilities as accessing TiKV directly, but targeting the PD.
                *   **Likelihood:** Medium
                *   **Impact:** Very High
                *   **Effort:** Low
                *   **Skill Level:** Intermediate
                *   **Detection Difficulty:** Medium

## Attack Tree Path: [Data Corruption/Destruction](./attack_tree_paths/data_corruptiondestruction.md)

*   **Critical Node:** Represents the goal of damaging or deleting data.  Attack vectors are the same as Data Exfiltration, but with a different intent.

## Attack Tree Path: [Denial of Service (DoS)](./attack_tree_paths/denial_of_service__dos_.md)

    *   **Resource Exhaustion [!]**
        *   **High-Risk Path:**  Relatively easy to execute and can disrupt service.
        *   **Overwhelm TiKV with Requests [!]**
            *   **High-Risk Path:**  Sending a flood of requests to overload the system.
            *   **Send a large number of read/write requests [!]:**
                *   **Description:**  Flooding TiKV with legitimate-looking requests.
                *   **Likelihood:** Medium
                *   **Impact:** Medium
                *   **Effort:** Low
                *   **Skill Level:** Novice
                *   **Detection Difficulty:** Easy (with traffic monitoring)
            *   **Send large, complex queries:**
                *   **Description:**  Crafting queries that consume excessive resources.
                *   **Likelihood:** Medium
                *   **Impact:** Medium
                *   **Effort:** Medium
                *   **Skill Level:** Intermediate
                *   **Detection Difficulty:** Medium (with query analysis)
    *   **Network-Based DoS [!]**
        *   **High-Risk Path:**  Disrupting network connectivity to TiKV.
        *   **Flood TiKV ports with traffic [!]:**
            *   **Description:**  Sending a large volume of network traffic to overwhelm TiKV's network interfaces.
            *   **Likelihood:** High
            *   **Impact:** Medium
            *   **Effort:** Low
            *   **Skill Level:** Novice
            *   **Detection Difficulty:** Easy (with network traffic monitoring)
        *   **Disrupt network connectivity to TiKV:**
            *   **Description:**  Attacking network infrastructure (routers, switches) to isolate TiKV.
            *   **Likelihood:** Low
            *   **Impact:** High
            *   **Effort:** High
            *   **Skill Level:** Advanced
            *   **Detection Difficulty:** Medium

## Attack Tree Path: [Code Execution on TiKV Nodes](./attack_tree_paths/code_execution_on_tikv_nodes.md)

*   **Critical Node:** Represents the highest level of compromise.

    *   **Exploit TiKV Server Vulnerabilities (as in Data Exfiltration, but with a focus on RCE) [*]**
        *   **Critical Node:**  The most direct path to RCE.  This includes vulnerabilities like:
            *   Buffer overflows
            *   Format string vulnerabilities
            *   Deserialization vulnerabilities
            *   Code injection vulnerabilities
        * **Likelihood:** Very Low
        * **Impact:** Very High
        * **Effort:** Very High
        * **Skill Level:** Expert
        * **Detection Difficulty:** Very Hard

