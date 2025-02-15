# Attack Tree Analysis for fabric/fabric

Objective: Execute Arbitrary Code/Disrupt Service via Fabric (Impact: Very High)

## Attack Tree Visualization

```
                                     +-------------------------------------------------+
                                     |  Execute Arbitrary Code/Disrupt Service via Fabric |
                                     +-------------------------------------------------+
                                                     |
                                                     |
                                      +--------------------------+
                                      | ***Abuse Fabric Features***   |
                                      | ***(Misconfiguration)***      |
                                      +--------------------------+
                                                     |
                                      +--------+---------+
                                      | [!]***Weak***| [!]***Command***|
                                      | [!]***Auth***| [!]***Injection***|
                                      |        |         |
                                      +--------+---------+
```

## Attack Tree Path: [Abuse Fabric Features (Misconfiguration) (High-Risk Path)](./attack_tree_paths/abuse_fabric_features__misconfiguration___high-risk_path_.md)

*   **Overall Description:** This represents the most likely and often easiest attack vector. It leverages correctly functioning Fabric features but exploits insecure configurations or coding practices by the developers using Fabric.
*   **Likelihood:** Medium to High
*   **Impact:** High to Very High
*   **Effort:** Low to Medium
*   **Skill Level:** Novice to Intermediate
*   **Detection Difficulty:** Medium to Hard

## Attack Tree Path: [[!] Weak Authentication (Critical Node & High-Risk Path Component)](./attack_tree_paths/_!__weak_authentication__critical_node_&_high-risk_path_component_.md)

*   **Description:** This involves using weak or easily guessable SSH keys, reusing the same key across multiple servers, or (worst of all) using password-based authentication with Fabric.
*   **Attack Vector:**
    1.  Attacker attempts to connect to the target server via SSH.
    2.  If password authentication is enabled, the attacker attempts a brute-force or dictionary attack.
    3.  If weak or reused SSH keys are used, the attacker attempts to use a compromised key or guess the key.
    4.  If successful, the attacker gains SSH access to the server.
    5.  The attacker can then use Fabric to execute commands or manipulate the system.
*   **Likelihood:** Medium to High
*   **Impact:** High to Very High
*   **Effort:** Low
*   **Skill Level:** Novice
*   **Detection Difficulty:** Medium

## Attack Tree Path: [[!] Command Injection (Critical Node & High-Risk Path Component)](./attack_tree_paths/_!__command_injection__critical_node_&_high-risk_path_component_.md)

*   **Description:** This occurs when a Fabric task takes user-supplied input and incorporates it directly into a shell command without proper sanitization or escaping.
*   **Attack Vector:**
    1.  The attacker identifies a Fabric task that takes user input.
    2.  The attacker crafts malicious input that includes shell commands.  For example, if the task takes a filename, the attacker might provide a filename like `; rm -rf /;`.
    3.  The Fabric task executes the command, including the attacker's injected commands.
    4.  The attacker's commands are executed with the privileges of the user running the Fabric task (ideally *not* root).
*   **Likelihood:** Medium
*   **Impact:** Very High
*   **Effort:** Low to Medium
*   **Skill Level:** Intermediate
*   **Detection Difficulty:** Medium to Hard

