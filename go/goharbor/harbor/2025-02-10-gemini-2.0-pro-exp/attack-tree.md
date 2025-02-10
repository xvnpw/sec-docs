# Attack Tree Analysis for goharbor/harbor

Objective: Gain unauthorized access to, exfiltrate, or manipulate container images and associated metadata.***

## Attack Tree Visualization

[Gain unauthorized access to, exfiltrate, or manipulate container images and associated metadata]***
                                |
        ---------------------------------------------------------------------------------
        |                                               |                               |
[Compromise Harbor Instance]***      [Exploit Vulnerabilities in Harbor]***   [Abuse Harbor Features]***
        |                                               |                               |
---------------------***                ---------------------***       ---------------------------------
|                   |                       |                               |               |
[Admin Account   [CVE Exploitation]***   [RBAC Bypass]***        [Image Manipulation]
 Takeover]***       |                               |                       |
    |            [Exploit known                  [Missing RBAC]***    [Malicious Image
    -----***        Harbor CVEs]***                 [Bypass AuthN/Z]***     Pushing]***
    |                   |
[Brute Force]*** [Phishing/
  Admin           Social Eng.]***
  Password]***

## Attack Tree Path: [1. Compromise Harbor Instance***](./attack_tree_paths/1__compromise_harbor_instance.md)

*   **Description:** Gaining full control over the Harbor registry instance, allowing the attacker to perform any action.
*   **High-Risk Path:** Admin Account Takeover -> Brute Force/Phishing
    *   **1.1 Admin Account Takeover***
        *   **Description:** Obtaining administrative credentials, granting complete control.
        *   *1.1.1 Brute Force Admin Password***
            *   **Description:**  Attempting to guess the administrator's password through automated means.
            *   **Likelihood:** Low (with strong passwords and rate limiting), Medium (otherwise)
            *   **Impact:** Very High
            *   **Effort:** Low
            *   **Skill Level:** Novice
            *   **Detection Difficulty:** Easy
        *   *1.1.2 Phishing/Social Engineering***
            *   **Description:** Tricking an administrator into revealing their credentials through deceptive emails or other social engineering tactics.
            *   **Likelihood:** Medium
            *   **Impact:** Very High
            *   **Effort:** Medium
            *   **Skill Level:** Intermediate
            *   **Detection Difficulty:** Medium

## Attack Tree Path: [2. Exploit Vulnerabilities in Harbor***](./attack_tree_paths/2__exploit_vulnerabilities_in_harbor.md)

*   **Description:** Leveraging flaws in Harbor's code or its dependencies to gain unauthorized access or control.
*   **High-Risk Path:** CVE Exploitation -> Exploit known Harbor CVEs
    *   **2.1 CVE Exploitation***
        *   **Description:** Utilizing publicly known and documented vulnerabilities (CVEs) to compromise the system.
        *   *2.1.1 Exploit known Harbor CVEs***
            *   **Description:** Specifically targeting vulnerabilities that have been publicly disclosed for Harbor.
            *   **Likelihood:** Medium
            *   **Impact:** Variable (potentially Very High)
            *   **Effort:** Low to Medium
            *   **Skill Level:** Intermediate to Advanced
            *   **Detection Difficulty:** Medium to Hard

## Attack Tree Path: [3. Abuse Harbor Features***](./attack_tree_paths/3__abuse_harbor_features.md)

*   **Description:** Misusing legitimate Harbor functionalities for malicious purposes, bypassing intended security controls.
*   **High-Risk Path 1:** RBAC Bypass -> Missing RBAC / Bypass AuthN/Z
    *   **3.1 RBAC Bypass***
        *   **Description:** Circumventing Harbor's Role-Based Access Control mechanisms to gain unauthorized access to resources.
        *   *3.1.1 Missing RBAC***
            *   **Description:**  Exploiting the absence of properly defined roles and permissions, allowing users to access resources they shouldn't.
            *   **Likelihood:** Low (if configured), Medium (if poorly configured)
            *   **Impact:** High
            *   **Effort:** Low
            *   **Skill Level:** Novice
            *   **Detection Difficulty:** Medium
        *   *3.1.2 Bypass AuthN/Z***
            *   **Description:** Finding ways to bypass authentication (proving identity) or authorization (checking permissions) checks.
            *   **Likelihood:** Low
            *   **Impact:** High
            *   **Effort:** High
            *   **Skill Level:** Advanced
            *   **Detection Difficulty:** Hard
*   **High-Risk Path 2:** Image Manipulation -> Malicious Image Pushing
    *   **3.2 Image Manipulation**
        *   **Description:** Modifying existing images or introducing malicious ones into the registry.
        *   *3.2.1 Malicious Image Pushing***
            *   **Description:**  Uploading a crafted malicious image to the registry, potentially compromising any system that pulls and runs it.
            *   **Likelihood:** Low (with controls), Medium (without)
            *   **Impact:** High
            *   **Effort:** Low to Medium
            *   **Skill Level:** Intermediate
            *   **Detection Difficulty:** Medium

