# Attack Tree Analysis for alibaba/sentinel

Objective: Compromise Application via Sentinel Exploitation

## Attack Tree Visualization

* **[HIGH-RISK PATH] 1. Exploit Sentinel Control Plane (Dashboard/Console) [CRITICAL NODE]**
    * **[HIGH-RISK PATH] 1.1. Unauthorized Access to Dashboard [CRITICAL NODE]**
        * **[HIGH-RISK PATH] 1.1.1. Default Credentials [CRITICAL NODE]**
    * **[HIGH-RISK PATH] 1.2. Exploit Dashboard Vulnerabilities [CRITICAL NODE]**
        * **[HIGH-RISK PATH] 1.2.1. Web Application Vulnerabilities (XSS, CSRF, Injection, Deserialization) [CRITICAL NODE]**
* **[HIGH-RISK PATH] 2. Manipulate Sentinel Agent Configuration (Local) [CRITICAL NODE]**
    * **[HIGH-RISK PATH] 2.2.1. Configuration File Tampering [CRITICAL NODE]**
* **[HIGH-RISK PATH] 2.3. Exploit Vulnerabilities in Sentinel Client Library [CRITICAL NODE]**
    * **[HIGH-RISK PATH] 2.3.1. Code Injection/RCE [CRITICAL NODE]**
* **[HIGH-RISK PATH] 3. Manipulate Sentinel Configuration/Rules [CRITICAL NODE]**
    * **[HIGH-RISK PATH] 3.1. Rule Injection via Dashboard (Requires 1.1 or 1.2) [CRITICAL NODE]**
        * **[HIGH-RISK PATH] 3.1.1. DoS via Rule Manipulation [CRITICAL NODE]**
        * **[HIGH-RISK PATH] 3.1.3. Bypass Security Controls via Rule Modification [CRITICAL NODE]**
    * **[HIGH-RISK PATH] 3.2. Rule Injection via Configuration Channels (If applicable) [CRITICAL NODE]**
        * **[HIGH-RISK PATH] 3.2.1. Compromise Configuration Source [CRITICAL NODE]**
* **[HIGH-RISK PATH] 4. Exploit Sentinel Dependencies or Implementation Flaws [CRITICAL NODE]**
    * **[HIGH-RISK PATH] 4.1. Vulnerable Dependencies [CRITICAL NODE]**
        * **[HIGH-RISK PATH] 4.1.1. Dependency Vulnerability Exploitation [CRITICAL NODE]**

## Attack Tree Path: [1. Exploit Sentinel Control Plane (Dashboard/Console) [CRITICAL NODE]](./attack_tree_paths/1__exploit_sentinel_control_plane__dashboardconsole___critical_node_.md)

**1. Exploit Sentinel Control Plane (Dashboard/Console) [CRITICAL NODE]**

* **1.1. Unauthorized Access to Dashboard [CRITICAL NODE]**
    * **1.1.1. Default Credentials [CRITICAL NODE]**
        * **Attack Vector:** Attacker attempts to log in to the Sentinel Dashboard using default usernames and passwords that were not changed during initial setup.
        * **Likelihood:** Low (Should be changed, but sometimes overlooked)
        * **Impact:** Critical (Full control of Sentinel)
        * **Effort:** Low (Very easy if defaults exist)
        * **Skill Level:** Beginner
        * **Detection Difficulty:** Easy (Login attempts can be logged)

* **1.2. Exploit Dashboard Vulnerabilities [CRITICAL NODE]**
    * **1.2.1. Web Application Vulnerabilities (XSS, CSRF, Injection, Deserialization) [CRITICAL NODE]**
        * **Attack Vector:** Attacker identifies and exploits common web application vulnerabilities present in the Sentinel Dashboard application. This includes:
            * **Cross-Site Scripting (XSS):** Injecting malicious scripts into the dashboard to execute in other users' browsers, potentially leading to session hijacking or further attacks.
            * **Cross-Site Request Forgery (CSRF):** Forcing authenticated users to perform unintended actions on the dashboard, such as rule manipulation.
            * **Injection Flaws (SQL Injection, Command Injection, etc.):** Exploiting vulnerabilities in data handling to inject malicious code and gain unauthorized access or control.
            * **Insecure Deserialization:** Exploiting vulnerabilities in how the dashboard handles serialized data to execute arbitrary code.
        * **Likelihood:** Low/Medium (Depends on dashboard code quality and security practices)
        * **Impact:** High/Critical (Depending on vulnerability - XSS: session hijacking, CSRF: rule manipulation, Injection/Deserialization: RCE)
        * **Effort:** Medium/High (Requires vulnerability research, exploit development)
        * **Skill Level:** Intermediate/Advanced
        * **Detection Difficulty:** Medium/Hard (Depends on vulnerability type, WAF might help, but bypasses are possible)

## Attack Tree Path: [1.1. Unauthorized Access to Dashboard [CRITICAL NODE]](./attack_tree_paths/1_1__unauthorized_access_to_dashboard__critical_node_.md)

* **1.1. Unauthorized Access to Dashboard [CRITICAL NODE]**
    * **1.1.1. Default Credentials [CRITICAL NODE]**
        * **Attack Vector:** Attacker attempts to log in to the Sentinel Dashboard using default usernames and passwords that were not changed during initial setup.
        * **Likelihood:** Low (Should be changed, but sometimes overlooked)
        * **Impact:** Critical (Full control of Sentinel)
        * **Effort:** Low (Very easy if defaults exist)
        * **Skill Level:** Beginner
        * **Detection Difficulty:** Easy (Login attempts can be logged)

## Attack Tree Path: [1.1.1. Default Credentials [CRITICAL NODE]](./attack_tree_paths/1_1_1__default_credentials__critical_node_.md)

* **1.1.1. Default Credentials [CRITICAL NODE]**
        * **Attack Vector:** Attacker attempts to log in to the Sentinel Dashboard using default usernames and passwords that were not changed during initial setup.
        * **Likelihood:** Low (Should be changed, but sometimes overlooked)
        * **Impact:** Critical (Full control of Sentinel)
        * **Effort:** Low (Very easy if defaults exist)
        * **Skill Level:** Beginner
        * **Detection Difficulty:** Easy (Login attempts can be logged)

## Attack Tree Path: [1.2. Exploit Dashboard Vulnerabilities [CRITICAL NODE]](./attack_tree_paths/1_2__exploit_dashboard_vulnerabilities__critical_node_.md)

* **1.2. Exploit Dashboard Vulnerabilities [CRITICAL NODE]**
    * **1.2.1. Web Application Vulnerabilities (XSS, CSRF, Injection, Deserialization) [CRITICAL NODE]**
        * **Attack Vector:** Attacker identifies and exploits common web application vulnerabilities present in the Sentinel Dashboard application. This includes:
            * **Cross-Site Scripting (XSS):** Injecting malicious scripts into the dashboard to execute in other users' browsers, potentially leading to session hijacking or further attacks.
            * **Cross-Site Request Forgery (CSRF):** Forcing authenticated users to perform unintended actions on the dashboard, such as rule manipulation.
            * **Injection Flaws (SQL Injection, Command Injection, etc.):** Exploiting vulnerabilities in data handling to inject malicious code and gain unauthorized access or control.
            * **Insecure Deserialization:** Exploiting vulnerabilities in how the dashboard handles serialized data to execute arbitrary code.
        * **Likelihood:** Low/Medium (Depends on dashboard code quality and security practices)
        * **Impact:** High/Critical (Depending on vulnerability - XSS: session hijacking, CSRF: rule manipulation, Injection/Deserialization: RCE)
        * **Effort:** Medium/High (Requires vulnerability research, exploit development)
        * **Skill Level:** Intermediate/Advanced
        * **Detection Difficulty:** Medium/Hard (Depends on vulnerability type, WAF might help, but bypasses are possible)

## Attack Tree Path: [1.2.1. Web Application Vulnerabilities (XSS, CSRF, Injection, Deserialization) [CRITICAL NODE]](./attack_tree_paths/1_2_1__web_application_vulnerabilities__xss__csrf__injection__deserialization___critical_node_.md)

* **1.2.1. Web Application Vulnerabilities (XSS, CSRF, Injection, Deserialization) [CRITICAL NODE]**
        * **Attack Vector:** Attacker identifies and exploits common web application vulnerabilities present in the Sentinel Dashboard application. This includes:
            * **Cross-Site Scripting (XSS):** Injecting malicious scripts into the dashboard to execute in other users' browsers, potentially leading to session hijacking or further attacks.
            * **Cross-Site Request Forgery (CSRF):** Forcing authenticated users to perform unintended actions on the dashboard, such as rule manipulation.
            * **Injection Flaws (SQL Injection, Command Injection, etc.):** Exploiting vulnerabilities in data handling to inject malicious code and gain unauthorized access or control.
            * **Insecure Deserialization:** Exploiting vulnerabilities in how the dashboard handles serialized data to execute arbitrary code.
        * **Likelihood:** Low/Medium (Depends on dashboard code quality and security practices)
        * **Impact:** High/Critical (Depending on vulnerability - XSS: session hijacking, CSRF: rule manipulation, Injection/Deserialization: RCE)
        * **Effort:** Medium/High (Requires vulnerability research, exploit development)
        * **Skill Level:** Intermediate/Advanced
        * **Detection Difficulty:** Medium/Hard (Depends on vulnerability type, WAF might help, but bypasses are possible)

## Attack Tree Path: [2. Manipulate Sentinel Agent Configuration (Local) [CRITICAL NODE]](./attack_tree_paths/2__manipulate_sentinel_agent_configuration__local___critical_node_.md)

**2. Manipulate Sentinel Agent Configuration (Local) [CRITICAL NODE]**

* **2.2.1. Configuration File Tampering [CRITICAL NODE]**
    * **Attack Vector:**  If an attacker gains unauthorized access to the server or environment where the application and Sentinel agent are running, they might attempt to directly modify the Sentinel agent's configuration files. This could involve:
        * Disabling critical rules.
        * Changing rule thresholds to ineffective levels.
        * Altering other agent behaviors to bypass protections or cause disruptions.
    * **Likelihood:** Low (Requires compromised server access, proper file permissions should prevent this)
    * **Impact:** Critical (Disable rules, change thresholds, full control over agent behavior)
    * **Effort:** Medium (Requires server access, file modification)
    * **Skill Level:** Intermediate
    * **Detection Difficulty:** Medium (File integrity monitoring can detect changes)

## Attack Tree Path: [2.2.1. Configuration File Tampering [CRITICAL NODE]](./attack_tree_paths/2_2_1__configuration_file_tampering__critical_node_.md)

* **2.2.1. Configuration File Tampering [CRITICAL NODE]**
    * **Attack Vector:**  If an attacker gains unauthorized access to the server or environment where the application and Sentinel agent are running, they might attempt to directly modify the Sentinel agent's configuration files. This could involve:
        * Disabling critical rules.
        * Changing rule thresholds to ineffective levels.
        * Altering other agent behaviors to bypass protections or cause disruptions.
    * **Likelihood:** Low (Requires compromised server access, proper file permissions should prevent this)
    * **Impact:** Critical (Disable rules, change thresholds, full control over agent behavior)
    * **Effort:** Medium (Requires server access, file modification)
    * **Skill Level:** Intermediate
    * **Detection Difficulty:** Medium (File integrity monitoring can detect changes)

## Attack Tree Path: [2.3. Exploit Vulnerabilities in Sentinel Client Library [CRITICAL NODE]](./attack_tree_paths/2_3__exploit_vulnerabilities_in_sentinel_client_library__critical_node_.md)

**3. Exploit Vulnerabilities in Sentinel Client Library [CRITICAL NODE]**

* **2.3.1. Code Injection/RCE [CRITICAL NODE]**
    * **Attack Vector:** Attacker discovers and exploits a code injection or Remote Code Execution (RCE) vulnerability within the Sentinel client library itself. This is a serious vulnerability that could allow the attacker to execute arbitrary code on the application server.
    * **Likelihood:** Very Low (Sentinel is a mature project, RCE vulnerabilities are rare but possible in any software)
    * **Impact:** Critical (Full application compromise)
    * **Effort:** High (Requires finding and exploiting complex vulnerabilities)
    * **Skill Level:** Advanced
    * **Detection Difficulty:** Hard (Depends on vulnerability, might be subtle or trigger standard security alerts)

## Attack Tree Path: [2.3.1. Code Injection/RCE [CRITICAL NODE]](./attack_tree_paths/2_3_1__code_injectionrce__critical_node_.md)

* **2.3.1. Code Injection/RCE [CRITICAL NODE]**
    * **Attack Vector:** Attacker discovers and exploits a code injection or Remote Code Execution (RCE) vulnerability within the Sentinel client library itself. This is a serious vulnerability that could allow the attacker to execute arbitrary code on the application server.
    * **Likelihood:** Very Low (Sentinel is a mature project, RCE vulnerabilities are rare but possible in any software)
    * **Impact:** Critical (Full application compromise)
    * **Effort:** High (Requires finding and exploiting complex vulnerabilities)
    * **Skill Level:** Advanced
    * **Detection Difficulty:** Hard (Depends on vulnerability, might be subtle or trigger standard security alerts)

## Attack Tree Path: [3. Manipulate Sentinel Configuration/Rules [CRITICAL NODE]](./attack_tree_paths/3__manipulate_sentinel_configurationrules__critical_node_.md)

**4. Manipulate Sentinel Configuration/Rules [CRITICAL NODE]**

* **3.1. Rule Injection via Dashboard (Requires 1.1 or 1.2) [CRITICAL NODE]**
    * **3.1.1. DoS via Rule Manipulation [CRITICAL NODE]**
        * **Attack Vector:** If an attacker gains unauthorized access to the Sentinel Dashboard, they can inject malicious rules designed to cause a Denial of Service (DoS) attack. This could involve:
            * Creating rules that block all legitimate traffic.
            * Severely throttling request rates to make the application unusable.
            * Triggering circuit breakers unnecessarily to shut down critical services.
        * **Likelihood:** Medium (If dashboard access is compromised, this is a likely attack)
        * **Impact:** High (Application DoS)
        * **Effort:** Low (Easy to create blocking rules via dashboard)
        * **Skill Level:** Beginner
        * **Detection Difficulty:** Easy (Sudden drop in traffic, increased errors, rule changes in audit logs)
    * **3.1.3. Bypass Security Controls via Rule Modification [CRITICAL NODE]**
        * **Attack Vector:** An attacker with dashboard access might modify existing Sentinel rules to weaken security controls. This could involve:
            * Relaxing rate limits to allow malicious traffic to pass through.
            * Disabling circuit breakers that would normally protect against overload.
            * Modifying allowlists or denylists to permit malicious requests.
        * **Likelihood:** Medium (If dashboard access is compromised, attacker might try to weaken security rules)
        * **Impact:** Medium/High (Weakened security posture, potential for further attacks)
        * **Effort:** Low (Easy to modify existing rules via dashboard)
        * **Skill Level:** Beginner
        * **Detection Difficulty:** Medium (Rule changes can be audited, but impact might be subtle initially)

* **3.2. Rule Injection via Configuration Channels (If applicable) [CRITICAL NODE]**
    * **3.2.1. Compromise Configuration Source [CRITICAL NODE]**
        * **Attack Vector:** If Sentinel rules are loaded from an external configuration source (e.g., Git repository, database, configuration server), an attacker might target and compromise this source.  Successful compromise allows them to inject malicious rules that will be automatically loaded by Sentinel agents across the application infrastructure.
        * **Likelihood:** Low/Medium (Depends on security of config source - Git, DB, Config Server)
        * **Impact:** Critical (Full control over Sentinel rules, widespread impact)
        * **Effort:** Medium/High (Depends on config source security)
        * **Skill Level:** Intermediate/Advanced
        * **Detection Difficulty:** Medium/Hard (Depends on config source auditing and monitoring)

## Attack Tree Path: [3.1. Rule Injection via Dashboard (Requires 1.1 or 1.2) [CRITICAL NODE]](./attack_tree_paths/3_1__rule_injection_via_dashboard__requires_1_1_or_1_2___critical_node_.md)

* **3.1. Rule Injection via Dashboard (Requires 1.1 or 1.2) [CRITICAL NODE]**
    * **3.1.1. DoS via Rule Manipulation [CRITICAL NODE]**
        * **Attack Vector:** If an attacker gains unauthorized access to the Sentinel Dashboard, they can inject malicious rules designed to cause a Denial of Service (DoS) attack. This could involve:
            * Creating rules that block all legitimate traffic.
            * Severely throttling request rates to make the application unusable.
            * Triggering circuit breakers unnecessarily to shut down critical services.
        * **Likelihood:** Medium (If dashboard access is compromised, this is a likely attack)
        * **Impact:** High (Application DoS)
        * **Effort:** Low (Easy to create blocking rules via dashboard)
        * **Skill Level:** Beginner
        * **Detection Difficulty:** Easy (Sudden drop in traffic, increased errors, rule changes in audit logs)
    * **3.1.3. Bypass Security Controls via Rule Modification [CRITICAL NODE]**
        * **Attack Vector:** An attacker with dashboard access might modify existing Sentinel rules to weaken security controls. This could involve:
            * Relaxing rate limits to allow malicious traffic to pass through.
            * Disabling circuit breakers that would normally protect against overload.
            * Modifying allowlists or denylists to permit malicious requests.
        * **Likelihood:** Medium (If dashboard access is compromised, attacker might try to weaken security rules)
        * **Impact:** Medium/High (Weakened security posture, potential for further attacks)
        * **Effort:** Low (Easy to modify existing rules via dashboard)
        * **Skill Level:** Beginner
        * **Detection Difficulty:** Medium (Rule changes can be audited, but impact might be subtle initially)

## Attack Tree Path: [3.1.1. DoS via Rule Manipulation [CRITICAL NODE]](./attack_tree_paths/3_1_1__dos_via_rule_manipulation__critical_node_.md)

* **3.1.1. DoS via Rule Manipulation [CRITICAL NODE]**
        * **Attack Vector:** If an attacker gains unauthorized access to the Sentinel Dashboard, they can inject malicious rules designed to cause a Denial of Service (DoS) attack. This could involve:
            * Creating rules that block all legitimate traffic.
            * Severely throttling request rates to make the application unusable.
            * Triggering circuit breakers unnecessarily to shut down critical services.
        * **Likelihood:** Medium (If dashboard access is compromised, this is a likely attack)
        * **Impact:** High (Application DoS)
        * **Effort:** Low (Easy to create blocking rules via dashboard)
        * **Skill Level:** Beginner
        * **Detection Difficulty:** Easy (Sudden drop in traffic, increased errors, rule changes in audit logs)

## Attack Tree Path: [3.1.3. Bypass Security Controls via Rule Modification [CRITICAL NODE]](./attack_tree_paths/3_1_3__bypass_security_controls_via_rule_modification__critical_node_.md)

* **3.1.3. Bypass Security Controls via Rule Modification [CRITICAL NODE]**
        * **Attack Vector:** An attacker with dashboard access might modify existing Sentinel rules to weaken security controls. This could involve:
            * Relaxing rate limits to allow malicious traffic to pass through.
            * Disabling circuit breakers that would normally protect against overload.
            * Modifying allowlists or denylists to permit malicious requests.
        * **Likelihood:** Medium (If dashboard access is compromised, attacker might try to weaken security rules)
        * **Impact:** Medium/High (Weakened security posture, potential for further attacks)
        * **Effort:** Low (Easy to modify existing rules via dashboard)
        * **Skill Level:** Beginner
        * **Detection Difficulty:** Medium (Rule changes can be audited, but impact might be subtle initially)

## Attack Tree Path: [3.2. Rule Injection via Configuration Channels (If applicable) [CRITICAL NODE]](./attack_tree_paths/3_2__rule_injection_via_configuration_channels__if_applicable___critical_node_.md)

* **3.2. Rule Injection via Configuration Channels (If applicable) [CRITICAL NODE]**
    * **3.2.1. Compromise Configuration Source [CRITICAL NODE]**
        * **Attack Vector:** If Sentinel rules are loaded from an external configuration source (e.g., Git repository, database, configuration server), an attacker might target and compromise this source.  Successful compromise allows them to inject malicious rules that will be automatically loaded by Sentinel agents across the application infrastructure.
        * **Likelihood:** Low/Medium (Depends on security of config source - Git, DB, Config Server)
        * **Impact:** Critical (Full control over Sentinel rules, widespread impact)
        * **Effort:** Medium/High (Depends on config source security)
        * **Skill Level:** Intermediate/Advanced
        * **Detection Difficulty:** Medium/Hard (Depends on config source auditing and monitoring)

## Attack Tree Path: [3.2.1. Compromise Configuration Source [CRITICAL NODE]](./attack_tree_paths/3_2_1__compromise_configuration_source__critical_node_.md)

* **3.2.1. Compromise Configuration Source [CRITICAL NODE]**
        * **Attack Vector:** If Sentinel rules are loaded from an external configuration source (e.g., Git repository, database, configuration server), an attacker might target and compromise this source.  Successful compromise allows them to inject malicious rules that will be automatically loaded by Sentinel agents across the application infrastructure.
        * **Likelihood:** Low/Medium (Depends on security of config source - Git, DB, Config Server)
        * **Impact:** Critical (Full control over Sentinel rules, widespread impact)
        * **Effort:** Medium/High (Depends on config source security)
        * **Skill Level:** Intermediate/Advanced
        * **Detection Difficulty:** Medium/Hard (Depends on config source auditing and monitoring)

## Attack Tree Path: [4. Exploit Sentinel Dependencies or Implementation Flaws [CRITICAL NODE]](./attack_tree_paths/4__exploit_sentinel_dependencies_or_implementation_flaws__critical_node_.md)

**5. Exploit Sentinel Dependencies or Implementation Flaws [CRITICAL NODE]**

* **4.1. Vulnerable Dependencies [CRITICAL NODE]**
    * **4.1.1. Dependency Vulnerability Exploitation [CRITICAL NODE]**
        * **Attack Vector:** Sentinel, like most software, relies on external libraries and frameworks (dependencies). If any of these dependencies have known vulnerabilities, an attacker could exploit them to compromise Sentinel and, consequently, the application. This could involve exploiting vulnerabilities in libraries like Netty, Guava, or others used by Sentinel.
        * **Likelihood:** Low/Medium (Depends on Sentinel's dependency management and update practices, and vulnerability disclosure)
        * **Impact:** High/Critical (Depending on vulnerability - DoS, RCE, etc.)
        * **Effort:** Low/Medium (If known vulnerability exists, exploit might be readily available)
        * **Skill Level:** Beginner/Intermediate (If exploit is public), Advanced (for 0-day)
        * **Detection Difficulty:** Medium (Vulnerability scanners can detect known dependency vulnerabilities, exploit attempts might be detected by IDS/IPS)

## Attack Tree Path: [4.1. Vulnerable Dependencies [CRITICAL NODE]](./attack_tree_paths/4_1__vulnerable_dependencies__critical_node_.md)

* **4.1. Vulnerable Dependencies [CRITICAL NODE]**
    * **4.1.1. Dependency Vulnerability Exploitation [CRITICAL NODE]**
        * **Attack Vector:** Sentinel, like most software, relies on external libraries and frameworks (dependencies). If any of these dependencies have known vulnerabilities, an attacker could exploit them to compromise Sentinel and, consequently, the application. This could involve exploiting vulnerabilities in libraries like Netty, Guava, or others used by Sentinel.
        * **Likelihood:** Low/Medium (Depends on Sentinel's dependency management and update practices, and vulnerability disclosure)
        * **Impact:** High/Critical (Depending on vulnerability - DoS, RCE, etc.)
        * **Effort:** Low/Medium (If known vulnerability exists, exploit might be readily available)
        * **Skill Level:** Beginner/Intermediate (If exploit is public), Advanced (for 0-day)
        * **Detection Difficulty:** Medium (Vulnerability scanners can detect known dependency vulnerabilities, exploit attempts might be detected by IDS/IPS)

## Attack Tree Path: [4.1.1. Dependency Vulnerability Exploitation [CRITICAL NODE]](./attack_tree_paths/4_1_1__dependency_vulnerability_exploitation__critical_node_.md)

* **4.1.1. Dependency Vulnerability Exploitation [CRITICAL NODE]**
        * **Attack Vector:** Sentinel, like most software, relies on external libraries and frameworks (dependencies). If any of these dependencies have known vulnerabilities, an attacker could exploit them to compromise Sentinel and, consequently, the application. This could involve exploiting vulnerabilities in libraries like Netty, Guava, or others used by Sentinel.
        * **Likelihood:** Low/Medium (Depends on Sentinel's dependency management and update practices, and vulnerability disclosure)
        * **Impact:** High/Critical (Depending on vulnerability - DoS, RCE, etc.)
        * **Effort:** Low/Medium (If known vulnerability exists, exploit might be readily available)
        * **Skill Level:** Beginner/Intermediate (If exploit is public), Advanced (for 0-day)
        * **Detection Difficulty:** Medium (Vulnerability scanners can detect known dependency vulnerabilities, exploit attempts might be detected by IDS/IPS)

