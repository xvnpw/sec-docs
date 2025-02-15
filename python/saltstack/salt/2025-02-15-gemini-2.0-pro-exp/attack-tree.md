# Attack Tree Analysis for saltstack/salt

Objective: Gain unauthorized root-level access to Salt Master and/or Minions, leading to complete control over the managed infrastructure and the application running on it.

## Attack Tree Visualization

Gain Unauthorized Root Access (Salt Master/Minions) [CRITICAL]
    |
    |--- 1. [HIGH RISK] Compromise Salt Master
    |       |
    |       |--- 1.1 [HIGH RISK] Exploit Vulnerabilities [CRITICAL]
    |
    |--- 2. Compromise Salt Minions Directly
            |
            |--- 2.2 Leverage Misconfigured Minion Auth
                    |
                    |--- 2.2.2 [HIGH RISK] Insecure File Perms. [CRITICAL]

## Attack Tree Path: [1. Compromise Salt Master [CRITICAL]](./attack_tree_paths/1__compromise_salt_master__critical_.md)

This is the primary, overarching critical node.  Compromise here grants complete control.

## Attack Tree Path: [1.1 [HIGH RISK] Exploit Vulnerabilities [CRITICAL]](./attack_tree_paths/1_1__high_risk__exploit_vulnerabilities__critical_.md)

**Description:** Exploiting known or zero-day vulnerabilities in the Salt Master software, its modules, or dependencies. This includes flaws that allow for remote code execution (RCE), authentication bypass, or privilege escalation.
        **Examples:**
            *   CVE-2020-11651 & CVE-2020-11652 (Authentication Bypass and Directory Traversal)
            *   CVE-2020-28243 (Command Injection in `ps` module)
            *   CVE-2021-25281, CVE-2021-25282, CVE-2021-25283 (Multiple Vulnerabilities)
            *   Zero-day vulnerabilities in custom or third-party Salt modules/states.
        **Likelihood:** Medium. New vulnerabilities are regularly discovered, and zero-days are a constant threat. Salt's popularity increases its attractiveness as a target.
        **Impact:** Very High. Full control over the entire Salt infrastructure and all managed systems.
        **Effort:** High. Requires significant skill to discover and exploit new vulnerabilities. Exploiting known vulnerabilities is easier if patching is delayed.
        **Skill Level:** Advanced to Expert. Deep understanding of Salt's internals, exploit development, and potentially reverse engineering are needed.
        **Detection Difficulty:** Medium to Hard. Sophisticated exploits may evade basic security measures. Requires advanced IDS/IPS, SIEM, and potentially specialized Salt monitoring.

## Attack Tree Path: [2. Compromise Salt Minions Directly](./attack_tree_paths/2__compromise_salt_minions_directly.md)

This is a broader category, but the specific high-risk path within it is detailed below.

## Attack Tree Path: [2.2 Leverage Misconfigured Minion Auth](./attack_tree_paths/2_2_leverage_misconfigured_minion_auth.md)

This is a stepping stone to full control, often easier than directly attacking the master.

## Attack Tree Path: [2.2.2 [HIGH RISK] Insecure File Permissions [CRITICAL]](./attack_tree_paths/2_2_2__high_risk__insecure_file_permissions__critical_.md)

**Description:** The Salt Minion's private key (`/etc/salt/pki/minion/minion.pem` by default) or configuration files have overly permissive read/write permissions.  This allows any local user (or a compromised low-privilege process) to read the key and impersonate the minion, or modify the minion's configuration to point it to a malicious master.
            **Examples:**
                *   `minion.pem` having permissions like `644` (world-readable) instead of `600` (owner-only read/write).
                *   `/etc/salt/minion` or `/etc/salt/minion.d/` being writable by non-root users.
            **Likelihood:** Medium. This is a common operational oversight, especially in environments without strict configuration management or regular audits.  It's a classic "low-hanging fruit" vulnerability.
            **Impact:** Very High.  Allows complete control over the compromised minion.  The attacker can then execute arbitrary Salt commands as that minion, potentially escalating privileges or moving laterally to other systems, including the Salt Master.
            **Effort:** Low.  Checking and modifying file permissions is a trivial task for anyone with shell access.  No specialized tools are required.
            **Skill Level:** Beginner to Intermediate. Basic Linux/Unix file permission knowledge is sufficient.
            **Detection Difficulty:** Easy.  File Integrity Monitoring (FIM) tools, configuration management systems (including Salt itself!), and routine security audits should detect this immediately.  This is a *very* high-priority item to monitor and remediate.

