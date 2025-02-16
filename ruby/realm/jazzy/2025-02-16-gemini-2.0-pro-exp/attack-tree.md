# Attack Tree Analysis for realm/jazzy

Objective: To leak sensitive information (source code structure, internal API documentation, potentially private code snippets if misconfigured) from an application using Jazzy.

## Attack Tree Visualization

```
                                     +-----------------------------------------------------+
                                     |  Attacker's Goal: Leak Sensitive Information         |
                                     +-----------------------------------------------------+
                                                        |
                                                        |
                                        +---------------------+
                                        | 1.1 Insecure Config [HIGH-RISK] |
                                        +---------------------+
                                                  |
                                        +-------+-------+
                                        | 1.1.1 | 1.1.2 |
                                        +-------+-------+
                                            |         |
                                            |         +---------------------+
                                            |                             |
                                        +-------+                     +-------+
                                        |1.1.1  | [CRITICAL]            |1.1.2  | [CRITICAL]
                                        |`min_acl`|                     |Exposing|
                                        |Too     |                     |`source_|
                                        |Permissv|                     |directory`|
                                        +-------+                     +-------+
```

## Attack Tree Path: [1. Information Leakage](./attack_tree_paths/1__information_leakage.md)

*   **1.1 Insecure Configuration [HIGH-RISK]**: This is the primary attack vector, focusing on misconfigurations of Jazzy that can lead to unintended information disclosure.

    *   **Likelihood:** High. This encompasses common mistakes made during Jazzy setup and usage.
    *   **Impact:** High to Very High. The severity depends on the specific information leaked, ranging from internal API details to complete source code exposure.
    *   **Effort:** Very Low to Low. Exploiting these misconfigurations typically requires minimal effort.
    *   **Skill Level:** Novice to Intermediate. Basic understanding of Jazzy and web server configurations is sufficient.
    *   **Detection Difficulty:** Medium. Requires reviewing Jazzy configurations and the generated output, as well as web server configurations.

    *   **1.1.1 `min_acl` Too Permissive [CRITICAL]**: This specific misconfiguration involves setting the `--min_acl` option to a value that exposes more information than intended (e.g., `internal` or `private`).

        *   **Likelihood:** High. This is a very common mistake, often due to a lack of understanding of the `--min_acl` option or a failure to properly review the generated documentation.
        *   **Impact:** High to Very High. Exposing internal APIs and implementation details significantly increases the attack surface of the application. Exposing private code snippets is a critical security breach.
        *   **Effort:** Very Low. The attacker simply needs to access the generated documentation, which is often publicly available.
        *   **Skill Level:** Novice. No special skills are required.
        *   **Detection Difficulty:** Medium. Requires reviewing the Jazzy configuration and the generated documentation. Automated tools can help, but manual inspection is often necessary.

    *   **1.1.2 Exposing `source_directory` Contents [CRITICAL]**: This vulnerability occurs when the directory containing the source code (specified by `source_directory` in Jazzy's configuration) is accidentally made accessible via the web server.

        *   **Likelihood:** Medium. This requires a misconfiguration of the web server or a deployment error. It's less likely than a direct Jazzy misconfiguration but still a significant risk.
        *   **Impact:** Very High. Direct access to the source code represents a complete compromise of the application's intellectual property and allows attackers to analyze the code for vulnerabilities at their leisure.
        *   **Effort:** Low to Medium. The effort depends on the specific misconfiguration. It could be as simple as forgetting to set proper directory permissions or a more complex web server configuration error.
        *   **Skill Level:** Novice to Intermediate. Basic web server administration knowledge is required.
        *   **Detection Difficulty:** Easy to Medium. Can be detected through regular security audits, penetration testing, or by monitoring web server logs for unusual access patterns (requests to files within the source directory).

