# Attack Tree Analysis for jenkinsci/jenkins

Objective: [[Gain RCE on Application Server via Jenkins]]

## Attack Tree Visualization

```
                                     [[Gain RCE on Application Server via Jenkins]]
                                                    |
          =================================================================================================
          ||                                        ||                                                     ||
  [[Exploit Jenkins Core/Plugins]]        [[Abuse Jenkins Features/Configuration]]                [Compromise Jenkins Credentials]
          ||                                        ||                                                     |
  =====================               =====================================               -----------------
  ||                                   ||                   ||                                     |
[[CVE Exploitation]]                 [[Script Console]] [[Build Triggers]]                       [[Default/Common]]
  ||                                   ||                   ||
  ||                                   ||   =================
  ||                                   ||   ||
  ||                                   ||   ||
[[Known CVE]]                         [[Custom Script]] [[Unsafe Build Steps]]
  ||                                                     ||
  ||                                                     ||
[[Public Exploit]]                                     [[Shell Commands]]
```

## Attack Tree Path: [[[Exploit Jenkins Core/Plugins]]](./attack_tree_paths/__exploit_jenkins_coreplugins__.md)

*   **Description:** This attack vector focuses on leveraging vulnerabilities within the core Jenkins software or its installed plugins.  It's a critical area because vulnerabilities here can often lead directly to RCE.
*   **High-Risk Path:** `=== [[CVE Exploitation]] === [[Known CVE]] === [[Public Exploit]]`
    *   **[[CVE Exploitation]]**:
        *   **Description:** Exploiting known and documented vulnerabilities (Common Vulnerabilities and Exposures).
        *   **Why Critical:** CVEs are publicly known, making them easier targets for attackers.
    *   **[[Known CVE]]**:
        *   **Description:** A vulnerability with a specific CVE identifier, indicating it's been publicly disclosed.
        *   **Why Critical:** Public disclosure means information about the vulnerability is readily available.
    *   **[[Public Exploit]]**:
        *   **Description:**  A readily available exploit code or script that automates the exploitation of a specific CVE.
        *   **Why Critical:**  Public exploits drastically lower the skill and effort required for an attacker, making this the most dangerous path.
        *   **Likelihood:** High (if unpatched and exploit exists) / Low (if patched promptly)
        *   **Impact:** Very High (RCE)
        *   **Effort:** Very Low (if exploit is readily available)
        *   **Skill Level:** Novice (can use pre-built tools)
        *   **Detection Difficulty:** Medium (IDS/IPS might detect, but obfuscation is possible)

## Attack Tree Path: [[[Abuse Jenkins Features/Configuration]]](./attack_tree_paths/__abuse_jenkins_featuresconfiguration__.md)

*   **Description:** This attack vector involves misusing legitimate Jenkins features or exploiting misconfigurations to gain unauthorized access or execute malicious code.
*   **High-Risk Path 1:** `=== [[Script Console]] === [[Custom Script]]`
    *   **[[Script Console]]**:
        *   **Description:** The built-in Groovy script console in Jenkins, which allows administrators to execute arbitrary Groovy code.
        *   **Why Critical:** Provides a direct and powerful way to execute code on the Jenkins server.
    *   **[[Custom Script]]**:
        *   **Description:**  Running arbitrary, attacker-supplied Groovy code within the script console.
        *   **Why Critical:**  Allows for complete control over the Jenkins server and potentially the underlying host.
        *   **Likelihood:** Medium (requires admin access)
        *   **Impact:** Very High (RCE)
        *   **Effort:** Low (if admin access is obtained)
        *   **Skill Level:** Intermediate (requires Groovy knowledge)
        *   **Detection Difficulty:** Medium (audit logs might show script execution, but content might be obfuscated)

*   **High-Risk Path 2:** `=== [[Build Triggers]] === [[Unsafe Build Steps]] === [[Shell Commands]]`
    *   **[[Build Triggers]]**:
        *   **Description:**  Mechanisms that automatically start Jenkins builds based on certain events (e.g., code commits, time schedules, webhooks).
        *   **Why Critical:**  Misconfigured triggers can be abused to initiate malicious builds.
    *   **[[Unsafe Build Steps]]**:
        *   **Description:**  Build steps within a Jenkins job that are configured in a way that allows for the execution of arbitrary or malicious code.
        *   **Why Critical:**  A direct way to inject malicious code into the build process.
    *   **[[Shell Commands]]**:
        *   **Description:**  Using shell commands (e.g., `bash`, `cmd`) within build steps.
        *   **Why Critical:**  Shell commands provide a very powerful and flexible way to execute code, making them a high-risk if not carefully sanitized.  This is the most dangerous type of unsafe build step.
        *   **Likelihood:** High (common misconfiguration)
        *   **Impact:** Very High (RCE)
        *   **Effort:** Low
        *   **Skill Level:** Intermediate (basic scripting knowledge)
        *   **Detection Difficulty:** Medium (audit logs and build history can reveal suspicious commands)

## Attack Tree Path: [[Compromise Jenkins Credentials]](./attack_tree_paths/_compromise_jenkins_credentials_.md)

* **Description:** Gaining unauthorized access to Jenkins accounts, often through weak or compromised credentials.
    * **High-Risk Path:** (Brute Force === [[Default/Common]])
        *   **[[Default/Common]]**:
            *   **Description:**  Using default credentials (e.g., "admin/admin") or commonly used passwords.
            *   **Why Critical:**  Default credentials are often well-known and easily guessed, providing a simple entry point for attackers.
            *   **Likelihood:** High (if default credentials are not changed)
            *   **Impact:** High (access to Jenkins)
            *   **Effort:** Very Low
            *   **Skill Level:** Novice
            *   **Detection Difficulty:** Easy (if default credentials are known)

