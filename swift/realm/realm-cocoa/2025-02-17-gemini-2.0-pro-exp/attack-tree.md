# Attack Tree Analysis for realm/realm-cocoa

Objective: Gain Unauthorized Access/Control/Disrupt Realm Data

## Attack Tree Visualization

                                     +-----------------------------------------------------+
                                     |  Gain Unauthorized Access/Control/Disrupt Realm Data |
                                     +-----------------------------------------------------+
                                                        |
                                                        |
                                          +---------------------+
                                          |  Local Data Access  |
                                          +---------------------+
                                                        |
                                          +---------+---------+
                                          | 1b. Root/Jailbreak|-> HIGH RISK ->
                                          |     Compromise   |
                                          +---------+---------+
                                          (L/H/M-H/I-A/M)   |
                                                        |
                    +---------------------------------------+-------------------------------------+
                    |                                       |                                     |
        -> HIGH RISK ->+---------+---------+     -> HIGH RISK ->+---------+---------+
                    | 1c. Unencrypted   | [CRITICAL]            | 1d. Weak Encryption| [CRITICAL]
                    |     Realm File    |                        |     Key           |
                    +---------+---------+                        +---------+---------+
                    (L-H/VH/VL/N/VH)   |                        (L-M/VH/L-H/N-A/VH)|
                                                        |
                                          +---------+---------+
                                          | 1f.  Debugging/    |
                                          |      Reverse Eng. |
                                          +---------+---------+
                                          (M/H/M-H/I-A/M-H)  |

## Attack Tree Path: [1b. Root/Jailbreak Compromise](./attack_tree_paths/1b__rootjailbreak_compromise.md)

*   **Description:** The attacker gains root (Android) or jailbreak (iOS) access to the device, bypassing many of the operating system's security controls. This allows them to access files and memory that would normally be protected.
*   **Likelihood:** Low (Requires user action or exploitation of a vulnerability)
*   **Impact:** High (Bypasses OS security)
*   **Effort:** Medium to High (Depends on the vulnerability)
*   **Skill Level:** Intermediate to Advanced
*   **Detection Difficulty:** Medium (Root/Jailbreak detection is possible, but can be bypassed)
*   **Mitigation:**
    *   Implement root/jailbreak detection.
    *   Consider terminating the application or wiping Realm data if detected (with user warnings).
    *   Strongly rely on encryption (see 1c and 1d).

## Attack Tree Path: [-> HIGH RISK -> 1c. Unencrypted Realm File [CRITICAL]](./attack_tree_paths/-_high_risk_-_1c__unencrypted_realm_file__critical_.md)

*   **Description:** The Realm database file is stored on the device without encryption.  This means that *any* access to the file (via root/jailbreak, physical access, etc.) grants immediate and complete access to the data.
*   **Likelihood:** Low (If developers follow best practices) / High (If developers neglect encryption)
*   **Impact:** Very High (Direct access to all data)
*   **Effort:** Very Low (Just need to access the file)
*   **Skill Level:** Novice
*   **Detection Difficulty:** Very Hard (No indication of access unless file system auditing is in place)
*   **Mitigation:**
    *   **Always encrypt Realm files containing sensitive data.** This is the single most important mitigation.

## Attack Tree Path: [-> HIGH RISK -> 1d. Weak Encryption Key [CRITICAL]](./attack_tree_paths/-_high_risk_-_1d__weak_encryption_key__critical_.md)

*   **Description:** The Realm file *is* encrypted, but the encryption key is weak, easily guessable, derived from a poor source, or stored insecurely. This effectively nullifies the protection provided by encryption.
*   **Likelihood:** Low to Medium (Depends on key generation and storage practices)
*   **Impact:** Very High (Renders encryption useless)
*   **Effort:** Low to High (Depends on the weakness - brute-forcing vs. finding a hardcoded key)
*   **Skill Level:** Novice to Advanced (Depends on the attack method)
*   **Detection Difficulty:** Very Hard (Unless key compromise is detected through other means)
*   **Mitigation:**
    *   Use a strong, randomly generated encryption key.
    *   Store the key securely using the platform's secure storage mechanisms (Keychain on iOS, Keystore on Android).
    *   *Never* hardcode the key.
    *   Consider key derivation functions (KDFs) like PBKDF2 or Argon2.

## Attack Tree Path: [-> HIGH RISK -> 1f. Debugging/Reverse Engineering](./attack_tree_paths/-_high_risk_-_1f__debuggingreverse_engineering.md)

*   **Description:** After gaining root/jailbreak access, the attacker uses debugging tools or reverse engineering techniques to inspect application memory or binary, potentially revealing the encryption key or decrypted data.
*   **Likelihood:** Medium (Requires access to the app binary and debugging tools)
*   **Impact:** High (Can reveal key or data in memory)
*   **Effort:** Medium to High
*   **Skill Level:** Intermediate to Advanced
*   **Detection Difficulty:** Medium to Hard (Requires monitoring for debugging activity)
* **Mitigation:**
        * Disable debugging features in production builds.
        * Use code obfuscation.
        * Consider white-box cryptography (complex and may not be fully effective).

