# Attack Tree Analysis for pi-hole/pi-hole

Objective: Compromise Application via Pi-hole Exploitation

## Attack Tree Visualization

```
Root Goal: Compromise Application via Pi-hole Exploitation [CRITICAL NODE]
├───[1.0] Compromise Pi-hole System [CRITICAL NODE] [HIGH RISK]
│   ├───[1.1] Exploit Pi-hole Web Interface Vulnerabilities [CRITICAL NODE] [HIGH RISK]
│   │   ├───[1.1.1] Authentication Bypass [CRITICAL NODE] [HIGH RISK]
│   │   │   └───[1.1.1.a] Exploit Default Credentials (if not changed) [HIGH RISK]
│   │   ├───[1.1.2] Injection Vulnerabilities
│   │   │   ├───[1.1.2.c] Cross-Site Scripting (XSS) (to steal credentials, redirect users, or execute malicious scripts) [HIGH RISK]
│   │   │   ├───[1.1.2.d] Cross-Site Request Forgery (CSRF) (to perform actions on behalf of an authenticated admin) [HIGH RISK]
│   │   ├───[1.1.4] Denial of Service (DoS) via Web Interface
│   │   │   └───[1.1.4.a] Resource exhaustion (e.g., excessive requests, large file uploads) [HIGH RISK]
│   ├───[1.2] Exploit Pi-hole Core DNS/DHCP Service (FTL) Vulnerabilities
│   │   ├───[1.2.2] Vulnerabilities in DHCP Server (if enabled)
│   │   │   ├───[1.2.2.a] DHCP Starvation to cause DoS [HIGH RISK]
│   │   │   ├───[1.2.2.b] Rogue DHCP Server attack (if Pi-hole is not properly secured in the network) - *Less Pi-hole specific, more network config* [HIGH RISK]
│   ├───[1.3] Exploit Pi-hole Configuration and File System Weaknesses
│   │   ├───[1.3.1] Insecure File Permissions
│   │   │   └───[1.3.1.b] Modify blocklists or whitelist to allow malicious domains or block legitimate ones [HIGH RISK]
│   ├───[1.5] Exploit Dependencies of Pi-hole [CRITICAL NODE]
│   │   ├───[1.5.1] Vulnerabilities in Underlying OS (e.g., Raspberry Pi OS, Debian) [CRITICAL NODE]
│   │   ├───[1.5.2] Vulnerabilities in Web Server (lighttpd/nginx) or PHP [CRITICAL NODE]
├───[2.0] Leverage Compromised Pi-hole to Attack Application [CRITICAL NODE] [HIGH RISK]
│   ├───[2.1] DNS Manipulation to Redirect Application Traffic [CRITICAL NODE] [HIGH RISK]
│   │   ├───[2.1.1] Modify DNS Records Served by Pi-hole [HIGH RISK]
│   │   │   └───[2.1.1.a] Redirect application's domain to attacker-controlled server (phishing, data theft, malware injection) [HIGH RISK]
│   │   ├───[2.1.2] Modify Blocklists/Whitelists to Interfere with Application Functionality [HIGH RISK]
│   │   │   ├───[2.1.2.a] Block domains required by the application, causing DoS or malfunction [HIGH RISK]
│   │   │   ├───[2.1.2.b] Whitelist malicious domains to bypass Pi-hole's protection for attacker's infrastructure [HIGH RISK]
│   │   ├───[2.2] Network Interception and Monitoring (if Pi-hole is positioned in a critical network path) [HIGH RISK]
│   │   │   └───[2.2.1] Passive Monitoring of DNS Queries [HIGH RISK]
```

## Attack Tree Path: [Root Goal: Compromise Application via Pi-hole Exploitation [CRITICAL NODE]](./attack_tree_paths/root_goal_compromise_application_via_pi-hole_exploitation__critical_node_.md)

This is the ultimate objective of the attacker. Success here means the attacker has achieved their goal of compromising the application by exploiting the Pi-hole system.

## Attack Tree Path: [[1.0] Compromise Pi-hole System [CRITICAL NODE] [HIGH RISK]](./attack_tree_paths/_1_0__compromise_pi-hole_system__critical_node___high_risk_.md)

This is the primary critical node and a high-risk path because compromising the Pi-hole system is the necessary first step to leverage it for attacking the application.
*   **Attack Vectors:** All sub-nodes under [1.0] represent attack vectors to achieve this goal.

## Attack Tree Path: [[1.1] Exploit Pi-hole Web Interface Vulnerabilities [CRITICAL NODE] [HIGH RISK]](./attack_tree_paths/_1_1__exploit_pi-hole_web_interface_vulnerabilities__critical_node___high_risk_.md)

The web interface is a major attack surface due to its accessibility and potential for common web vulnerabilities. Compromising it grants administrative control.
*   **Attack Vectors:**
    *   **[1.1.1] Authentication Bypass [CRITICAL NODE] [HIGH RISK]:** Bypassing authentication is a direct route to gaining admin access.
        *   **[1.1.1.a] Exploit Default Credentials (if not changed) [HIGH RISK]:**  Using default credentials (if not changed during setup) is a trivial and highly effective way to bypass authentication.
    *   **[1.1.2] Injection Vulnerabilities:** Exploiting injection flaws in the web interface.
        *   **[1.1.2.c] Cross-Site Scripting (XSS) (to steal credentials, redirect users, or execute malicious scripts) [HIGH RISK]:** Injecting malicious scripts into the web interface to steal admin sessions, redirect admins to phishing sites, or perform actions on their behalf.
        *   **[1.1.2.d] Cross-Site Request Forgery (CSRF) (to perform actions on behalf of an authenticated admin) [HIGH RISK]:**  Tricking an authenticated admin into performing unintended actions by crafting malicious requests.
    *   **[1.1.4] Denial of Service (DoS) via Web Interface:** Overloading the web interface to disrupt admin access.
        *   **[1.1.4.a] Resource exhaustion (e.g., excessive requests, large file uploads) [HIGH RISK]:** Sending a large volume of requests or large files to overwhelm the web server and make it unavailable.

## Attack Tree Path: [[1.2] Exploit Pi-hole Core DNS/DHCP Service (FTL) Vulnerabilities](./attack_tree_paths/_1_2__exploit_pi-hole_core_dnsdhcp_service__ftl__vulnerabilities.md)

Attacking the core DNS/DHCP functionality of Pi-hole.
    *   **[1.2.2] Vulnerabilities in DHCP Server (if enabled):** If Pi-hole is used as a DHCP server, it becomes an attack vector.
        *   **[1.2.2.a] DHCP Starvation to cause DoS [HIGH RISK]:** Exhausting the DHCP address pool to prevent legitimate devices from obtaining IP addresses, causing network disruption.
        *   **[1.2.2.b] Rogue DHCP Server attack (if Pi-hole is not properly secured in the network) - *Less Pi-hole specific, more network config* [HIGH RISK]:** Introducing a malicious DHCP server on the network to intercept traffic or perform MitM attacks. While less Pi-hole specific, a compromised Pi-hole could be used to facilitate this.

## Attack Tree Path: [[1.3] Exploit Pi-hole Configuration and File System Weaknesses](./attack_tree_paths/_1_3__exploit_pi-hole_configuration_and_file_system_weaknesses.md)

Exploiting weaknesses in file permissions or configuration files.
    *   **[1.3.1] Insecure File Permissions:** Incorrect file permissions allowing unauthorized access.
        *   **[1.3.1.b] Modify blocklists or whitelist to allow malicious domains or block legitimate ones [HIGH RISK]:** Modifying blocklists or whitelists to bypass ad-blocking for malicious domains or block legitimate domains to cause application malfunction.

## Attack Tree Path: [[1.5] Exploit Dependencies of Pi-hole [CRITICAL NODE]](./attack_tree_paths/_1_5__exploit_dependencies_of_pi-hole__critical_node_.md)

Exploiting vulnerabilities in software that Pi-hole depends on.
    *   **[1.5.1] Vulnerabilities in Underlying OS (e.g., Raspberry Pi OS, Debian) [CRITICAL NODE]:** Exploiting known vulnerabilities in the operating system on which Pi-hole is running. OS compromise often leads to full system control.
    *   **[1.5.2] Vulnerabilities in Web Server (lighttpd/nginx) or PHP [CRITICAL NODE]:** Exploiting vulnerabilities in the web server or PHP versions used by Pi-hole. Web server compromise can lead to system compromise.

## Attack Tree Path: [[2.0] Leverage Compromised Pi-hole to Attack Application [CRITICAL NODE] [HIGH RISK]](./attack_tree_paths/_2_0__leverage_compromised_pi-hole_to_attack_application__critical_node___high_risk_.md)

This is the stage where the attacker uses the compromised Pi-hole to directly attack the target application.
    *   **Attack Vectors:**

## Attack Tree Path: [[2.1] DNS Manipulation to Redirect Application Traffic [CRITICAL NODE] [HIGH RISK]](./attack_tree_paths/_2_1__dns_manipulation_to_redirect_application_traffic__critical_node___high_risk_.md)

Using Pi-hole's DNS control to manipulate application traffic.
    *   **[2.1.1] Modify DNS Records Served by Pi-hole [HIGH RISK]:** Changing DNS records served by Pi-hole to redirect application traffic to attacker-controlled servers.
        *   **[2.1.1.a] Redirect application's domain to attacker-controlled server (phishing, data theft, malware injection) [HIGH RISK]:** Redirecting the application's domain to a malicious server for phishing, data theft, or malware distribution to application users.
    *   **[2.1.2] Modify Blocklists/Whitelists to Interfere with Application Functionality [HIGH RISK]:** Modifying blocklists or whitelists to disrupt application functionality.
        *   **[2.1.2.a] Block domains required by the application, causing DoS or malfunction [HIGH RISK]:** Blocking domains that are essential for the application to function correctly, leading to denial of service or malfunction.
        *   **[2.1.2.b] Whitelist malicious domains to bypass Pi-hole's protection for attacker's infrastructure [HIGH RISK]:** Whitelisting malicious domains to allow attacker infrastructure to bypass Pi-hole's ad-blocking and potentially deliver malicious content.
    *   **[2.2] Network Interception and Monitoring (if Pi-hole is positioned in a critical network path) [HIGH RISK]:** Using the compromised Pi-hole for network monitoring and interception.
        *   **[2.2.1] Passive Monitoring of DNS Queries [HIGH RISK]:** Monitoring DNS queries passing through the compromised Pi-hole to gather information about application usage patterns and accessed domains.

