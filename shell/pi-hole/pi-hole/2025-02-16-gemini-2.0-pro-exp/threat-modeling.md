# Threat Model Analysis for pi-hole/pi-hole

## Threat: [DNS Cache Poisoning / Spoofing](./threats/dns_cache_poisoning__spoofing.md)

*   **Description:** An attacker injects forged DNS records into Pi-hole's cache. This is done by exploiting weaknesses in the DNS protocol (if DNSSEC is not used) or by sending crafted DNS responses directly to the Pi-hole. The attacker might be on the local network or could be leveraging a compromised upstream DNS server.
    *   **Impact:** Users are redirected to malicious websites (phishing, malware distribution), bypassing security controls. Sensitive data theft and malware installation are likely. Legitimate services become inaccessible.
    *   **Affected Component:** `FTL` (Faster Than Light) DNS resolver (specifically the caching mechanism).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Enable DNSSEC:** Use DNSSEC validation in Pi-hole (if supported by upstream and clients).
        *   **Use Reputable Upstream DNS:** Select trusted, security-focused upstream DNS providers.
        *   **Monitor for Anomalies:** Implement monitoring to detect unusual DNS responses.
        *   **Firewall Rules:** Restrict inbound DNS traffic to trusted sources (if possible).

## Threat: [Denial of Service (DoS) against Pi-hole](./threats/denial_of_service__dos__against_pi-hole.md)

*   **Description:** An attacker floods the Pi-hole with DNS requests, overwhelming its resources (CPU, memory, network). This prevents Pi-hole from responding to legitimate DNS queries. The attack could be targeted or a side effect of a larger DDoS.
    *   **Impact:** Complete network outage for all devices relying on the Pi-hole for DNS. Users cannot access internet services.
    *   **Affected Component:** `FTL` DNS resolver (resource handling), network interface.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Rate Limiting:** Configure `FTL`'s rate limiting.
        *   **Firewall:** Use a firewall to block excessive traffic (UDP port 53).
        *   **Resource Allocation:** Ensure sufficient CPU, memory, and network bandwidth.
        *   **Monitoring:** Monitor resource usage to detect DoS attempts.
        *   **Upstream DoS Protection:** Choose an upstream DNS provider with DoS protection.

## Threat: [Unauthorized Access and Configuration Modification](./threats/unauthorized_access_and_configuration_modification.md)

*   **Description:** An attacker gains access to the Pi-hole's web administrative interface. This could be through brute-force attacks, exploiting web interface vulnerabilities, or using stolen credentials. The attacker then modifies settings, whitelists, blacklists, or adds malicious DNS entries.
    *   **Impact:** Bypassing of blocking rules, redirection of traffic, disabling of security features, potential sensitive information exposure, complete control over DNS resolution.
    *   **Affected Component:** Web interface (`lighttpd` web server, PHP scripts in `/var/www/html/admin`), `FTL` (configuration is used by FTL).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Strong Password:** Use a strong, unique password.
        *   **Two-Factor Authentication (2FA):** Enable 2FA if available.
        *   **Access Control:** Restrict web interface access to specific IPs or trusted networks.
        *   **Regular Auditing:** Review the configuration for unauthorized changes.
        *   **Disable Unnecessary Features:** Disable unneeded features (e.g., remote access).
        *   **Keep Software Updated:** Regularly update Pi-hole.

## Threat: [Exploitation of Pi-hole Software Vulnerabilities](./threats/exploitation_of_pi-hole_software_vulnerabilities.md)

*   **Description:** An attacker exploits a vulnerability in the Pi-hole software (e.g., a buffer overflow in `FTL`, an XSS vulnerability in the web interface, or command injection). This could be a known or zero-day vulnerability.
    *   **Impact:** Varies; could range from denial of service to remote code execution (RCE) with root privileges, giving the attacker complete control.
    *   **Affected Component:** Potentially any: `FTL`, web interface (`lighttpd` and PHP scripts), `pihole-FTL` service, gravity database.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Keep Pi-hole Updated:** Regularly update to the latest version.
        *   **Security Audits:** Periodically review the codebase and configuration (if you have the expertise).
        *   **Vulnerability Scanning:** Use vulnerability scanners.
        *   **Principle of Least Privilege:** Run services with least necessary privileges.

## Threat: [Physical Access Compromise](./threats/physical_access_compromise.md)

* **Description:** An attacker gains physical access to the device running Pi-hole. They could steal the SD card, connect peripherals, or directly interact with the hardware.
    * **Impact:** Complete compromise of the Pi-hole. Access to all data, configuration modification, malware installation, or use of the device for malicious purposes.
    * **Affected Component:** All components.
    * **Risk Severity:** Critical
    * **Mitigation Strategies:**
        * **Physical Security:** Place the device in a secure location.
        * **Full Disk Encryption:** Encrypt the entire filesystem.
        * **Disable Unused Interfaces:** Disable unnecessary physical interfaces (e.g., USB ports).
        * **Bootloader Protection:** Configure the bootloader to require a password.
        * **Tamper-Evident Seals:** Use tamper-evident seals.

