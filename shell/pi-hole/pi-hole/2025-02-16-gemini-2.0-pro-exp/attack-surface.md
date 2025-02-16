# Attack Surface Analysis for pi-hole/pi-hole

## Attack Surface: [DNS Resolution Manipulation (Upstream)](./attack_surfaces/dns_resolution_manipulation__upstream_.md)

*   **Description:** Attacks targeting the integrity of DNS resolution by compromising or manipulating the upstream DNS servers that Pi-hole uses.
    *   **How Pi-hole Contributes:** Pi-hole relies on external DNS servers for resolution, making it a conduit for potentially malicious responses. It acts as the intermediary, directly handling the potentially compromised responses.
    *   **Example:** An attacker compromises a public DNS server used by Pi-hole and redirects `bank.com` to a phishing site. Users accessing `bank.com` through Pi-hole are sent to the fake site.
    *   **Impact:** Users are redirected to malicious sites, leading to credential theft, malware infection, or data breaches.
    *   **Risk Severity:** **Critical**
    *   **Mitigation Strategies:**
        *   **Developers:**
            *   Implement robust DNSSEC validation.
            *   Provide curated lists of trusted upstream DNS providers.
            *   Offer options for DoH/DoT with pre-configured, trusted providers.
            *   Implement monitoring for anomalous DNS responses.
        *   **Users:**
            *   Choose reputable, well-maintained upstream DNS servers (e.g., Cloudflare, Google, Quad9).
            *   Enable DNSSEC validation in Pi-hole settings.
            *   Consider using DoH/DoT within Pi-hole.
            *   Monitor Pi-hole logs for unusual DNS queries.

## Attack Surface: [DNS Spoofing/Cache Poisoning (Local Network)](./attack_surfaces/dns_spoofingcache_poisoning__local_network_.md)

*   **Description:** Attacks where an adversary on the local network intercepts and modifies DNS requests *before* they reach the Pi-hole.
    *   **How Pi-hole Contributes:** Pi-hole acts as the primary DNS server for the local network, making it the *direct target* for local DNS spoofing attempts.  It's the intended recipient of the spoofed requests.
    *   **Example:** An attacker on the same Wi-Fi network uses ARP spoofing to intercept DNS traffic and redirect users to malicious sites.
    *   **Impact:** Users are redirected to malicious sites, bypassing Pi-hole's blocking.
    *   **Risk Severity:** **High**
    *   **Mitigation Strategies:**
        *   **Developers:**
            *   Strengthen built-in DNS rebinding protection.
            *   Consider offering features to detect ARP spoofing on the network (though this is outside Pi-hole's core function).
        *   **Users:**
            *   Secure the local network (strong Wi-Fi password, WPA3 if possible).
            *   Use a wired connection for the Pi-hole device if possible.
            *   Implement network segmentation to isolate sensitive devices.
            *   Use a VPN on untrusted networks.
            *   Enable DoH/DoT within Pi-hole (this shifts the trust to the DoH/DoT provider but mitigates local spoofing).

## Attack Surface: [Malicious Blocklists/Whitelists](./attack_surfaces/malicious_blocklistswhitelists.md)

*   **Description:** Attacks that involve compromising blocklist providers or tricking administrators into adding malicious lists.
    *   **How Pi-hole Contributes:** Pi-hole's core functionality *directly relies* on blocklists and whitelists, making them a direct attack vector.  The malicious lists are *directly ingested and used* by Pi-hole.
    *   **Example:** An attacker compromises a popular blocklist provider and adds `legitimate-update-server.com` to the blocklist, preventing devices from receiving updates. Or, an attacker convinces an admin to add a whitelist entry for `malware-download.com`.
    *   **Impact:** Denial of service for legitimate services, or bypassing of Pi-hole's blocking, allowing access to malicious sites.
    *   **Risk Severity:** **High**
    *   **Mitigation Strategies:**
        *   **Developers:**
            *   Provide a mechanism for verifying the integrity of downloaded blocklists (e.g., checksums, digital signatures).
            *   Maintain a list of known-good blocklist providers.
            *   Implement warnings for unusually large or frequently changing blocklists.
        *   **Users:**
            *   Use only reputable blocklist providers.
            *   Carefully review any custom blocklists or whitelists before adding them.
            *   Regularly audit the configured lists.

## Attack Surface: [Web Interface (Admin Panel) Weak Authentication](./attack_surfaces/web_interface__admin_panel__weak_authentication.md)

*   **Description:** Using weak or default credentials to access the Pi-hole's administrative web interface.
    *   **How Pi-hole Contributes:** The web interface is a *direct component* of Pi-hole, providing administrative access. Weak authentication on this interface is a direct vulnerability of the Pi-hole application itself.
    *   **Example:** An attacker uses the default Pi-hole password (which is often easily found online) to gain access to the web interface.
    *   **Impact:** Full control of the Pi-hole, allowing modification of settings, blocklists, and potential lateral movement on the network.
    *   **Risk Severity:** **Critical**
    *   **Mitigation Strategies:**
        *   **Developers:**
            *   Enforce strong password policies during setup.
            *   Consider implementing two-factor authentication (2FA).
            *   Provide clear warnings about the risks of using default credentials.
        *   **Users:**
            *   Change the default password immediately after installation.
            *   Use a strong, unique password.
            *   Consider using a password manager.

