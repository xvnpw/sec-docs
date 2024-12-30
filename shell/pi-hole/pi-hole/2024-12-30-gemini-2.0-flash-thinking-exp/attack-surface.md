### Key Attack Surface List Introduced by Pi-hole (High & Critical, Pi-hole Specific)

Here's an updated list of key attack surfaces directly involving Pi-hole, focusing on those with High and Critical risk severity:

*   **Attack Surface: DNS Query Manipulation/Spoofing**
    *   **Description:** An attacker intercepts or manipulates DNS queries and responses, redirecting the application to malicious servers.
    *   **How Pi-hole Contributes:** Pi-hole acts as the DNS resolver for the application. If compromised, it can be forced to return attacker-controlled IP addresses for legitimate domains.
    *   **Example:** An attacker gains control of the Pi-hole server and modifies DNS records for the application's backend API domain, redirecting API calls to a fake server that steals credentials.
    *   **Impact:** Data breaches, credential theft, serving malicious content, application malfunction.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developers:**
            *   Implement certificate pinning or TLS verification to ensure the application only connects to trusted servers.
        *   **Users/Administrators:**
            *   Secure the Pi-hole server with strong passwords and regular security updates.
            *   Restrict access to the Pi-hole administrative interface.
            *   Monitor Pi-hole logs for suspicious DNS queries or changes.

*   **Attack Surface: DNS Cache Poisoning**
    *   **Description:** An attacker injects false DNS records into the Pi-hole's cache, causing it to return incorrect IP addresses for legitimate domains to other clients using the same Pi-hole instance.
    *   **How Pi-hole Contributes:** Pi-hole caches DNS responses to improve performance. If this cache is poisoned, the application will receive incorrect DNS information.
    *   **Example:** An attacker exploits a vulnerability in `dnsmasq` (or `unbound`) used by Pi-hole to inject a false record for a banking website, redirecting users to a phishing site.
    *   **Impact:** Redirection to malicious websites, phishing attacks, potential for man-in-the-middle attacks.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Users/Administrators:**
            *   Keep Pi-hole and its underlying DNS resolver (`dnsmasq` or `unbound`) updated to the latest versions to patch known vulnerabilities.
            *   Configure Pi-hole to use DNSSEC for upstream resolvers if supported.
            *   Monitor Pi-hole logs for unusual DNS cache entries.

*   **Attack Surface: Web Interface Authentication Bypass/Authorization Issues**
    *   **Description:** An attacker bypasses the authentication mechanism or exploits authorization flaws in the Pi-hole web interface to gain unauthorized access and control.
    *   **How Pi-hole Contributes:** The web interface allows configuration and management of Pi-hole. If compromised, an attacker can modify settings affecting the application's DNS resolution.
    *   **Example:** An attacker exploits a known vulnerability in the Pi-hole web interface to log in without valid credentials and then disables blocklists, allowing the application to connect to malicious domains.
    *   **Impact:** Complete control over Pi-hole settings, potential for DNS manipulation, information disclosure.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Users/Administrators:**
            *   Use strong, unique passwords for the Pi-hole web interface.
            *   Keep Pi-hole updated to patch known web interface vulnerabilities.
            *   Restrict network access to the Pi-hole web interface to trusted IP addresses or networks.
            *   Disable the web interface if it's not required.

*   **Attack Surface: Compromised Configuration Files**
    *   **Description:** An attacker gains access to the Pi-hole server's filesystem and modifies configuration files to alter DNS settings or disable blocking.
    *   **How Pi-hole Contributes:** Pi-hole relies on configuration files to define its behavior. Modifying these files can directly impact the application's DNS resolution.
    *   **Example:** An attacker gains root access to the Pi-hole server and modifies `pihole-FTL.conf` to disable blocking or redirect specific domains.
    *   **Impact:** Complete control over Pi-hole's functionality, potential for DNS manipulation, bypassing security measures.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Users/Administrators:**
            *   Secure the Pi-hole server operating system with strong passwords, regular updates, and appropriate firewall rules.
            *   Implement file integrity monitoring to detect unauthorized changes to configuration files.
            *   Restrict access to the Pi-hole server's filesystem.