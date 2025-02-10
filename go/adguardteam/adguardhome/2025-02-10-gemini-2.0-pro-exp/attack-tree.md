# Attack Tree Analysis for adguardteam/adguardhome

Objective: Gain Unauthorized Control/Disrupt DNS Resolution [!]

## Attack Tree Visualization

+-----------------------------------------------------+
|  Gain Unauthorized Control/Disrupt DNS Resolution [!] |
+-----------------------------------------------------+
                 |                         \
                 |                          \
       +---------------------+       +---------------------+
       |  Compromise AdGuard  |       |  Bypass AdGuard    |
       |  Home Configuration |       |  Filtering         |
       +---------------------+       +---------------------+
                 |                          |
                 |                          |
       +-----+                               +-----+
       |Weak |                               |Direct|
       |Creds|                               |DNS   |
       +-----+                               |Req.  |
         [!]                                 +-----+
                                               [!]

## Attack Tree Path: [Compromise AdGuard Home Configuration via Weak Credentials [!]](./attack_tree_paths/compromise_adguard_home_configuration_via_weak_credentials__!_.md)

*   **Description:** The attacker gains access to the AdGuard Home web interface by using default, easily guessable, or previously compromised credentials. This grants them full control over the AdGuard Home configuration.
*   **Likelihood:** Medium. This relies on users not changing default passwords or using weak, easily guessable passwords.
*   **Impact:** High. Complete control over AdGuard Home's settings allows the attacker to redirect DNS queries, disable filtering, inject malicious rules, and generally manipulate the DNS resolution process for all connected clients.
*   **Effort:** Very Low. If default credentials are in use, the effort is trivial. Even weak passwords can be cracked with minimal effort.
*   **Skill Level:** Novice. No specialized skills are required, especially if default credentials are used. Basic password guessing techniques are sufficient.
*   **Detection Difficulty:** Easy. Failed login attempts can be logged. Successful logins from unexpected IP addresses or at unusual times can be flagged. However, if the attacker uses the correct credentials on the first try, detection becomes more reliant on monitoring for configuration changes.
* **Mitigation Steps:**
    *   Enforce strong password policies during AdGuard Home setup.
    *   Require users to change the default password upon initial login.
    *   Implement account lockout after a certain number of failed login attempts.
    *   Consider offering or requiring multi-factor authentication (MFA).
    *   Educate users about the importance of strong, unique passwords.
    *   Log all successful and failed login attempts.
    *   Monitor for configuration changes and alert on unauthorized modifications.

## Attack Tree Path: [Bypass AdGuard Filtering via Direct DNS Requests [!]](./attack_tree_paths/bypass_adguard_filtering_via_direct_dns_requests__!_.md)

*   **Description:** Clients are configured to use DNS servers other than the AdGuard Home instance, completely circumventing the filtering and security measures provided by AdGuard Home. This can happen if clients are manually configured with different DNS servers, or if the network configuration allows clients to bypass the designated DNS server.
*   **Likelihood:** Medium. This depends heavily on the network configuration and the ability of users to modify their DNS settings. In a tightly controlled environment, this is less likely. In a home or less restrictive environment, it's more likely.
*   **Impact:** High. Complete bypass of AdGuard Home's filtering renders it ineffective. Clients are exposed to all unfiltered content, including potentially malicious websites and trackers.
*   **Effort:** Low. Changing DNS settings on most devices is a straightforward process.
*   **Skill Level:** Novice. Requires only basic knowledge of network settings on the client device.
*   **Detection Difficulty:** Medium. Requires network monitoring to identify DNS traffic going to unauthorized DNS servers. This can be achieved through firewall logs, network traffic analysis tools, or by configuring AdGuard Home to log queries from unexpected sources (if possible).
* **Mitigation Steps:**
    *   **Network-Level Enforcement:** Configure the router/firewall to *force* all DNS traffic (port 53) to go through the AdGuard Home instance. Block outgoing connections to other DNS servers.
    *   **DHCP Configuration:** Ensure the DHCP server provides *only* the AdGuard Home IP address as the DNS server to clients.
    *   **Client-Side Configuration (where possible):** Use Group Policy (in corporate environments) or other management tools to lock down DNS settings on client devices.
    *   **Monitor for Bypassing:** Use network monitoring tools to detect DNS queries going to external DNS servers.
    *   **Educate Users:** Inform users about the importance of using the designated DNS server and the risks of bypassing it.
    *   **Block Known Public DNS Servers:** If possible, block access to well-known public DNS servers (e.g., 8.8.8.8, 1.1.1.1) at the firewall level, *except* for the AdGuard Home instance itself (which may need to use them as upstream resolvers).
    * **Disable DoH/DoT/TRR on clients:** If clients are using encrypted DNS protocols directly to public resolvers, this will bypass AdGuard Home. Ensure these are disabled on clients, or that they are configured to use AdGuard Home as the DoH/DoT/TRR resolver.

