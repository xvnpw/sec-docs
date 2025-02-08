# Threat Model Analysis for coturn/coturn

## Threat: [Resource Exhaustion (Denial of Service) via Allocation Flooding](./threats/resource_exhaustion__denial_of_service__via_allocation_flooding.md)

*   **Description:** An attacker sends a large number of `Allocate` requests to the coturn server, attempting to consume all available ports, memory, or CPU cycles.  They may not even complete the allocation process, just repeatedly request new allocations. This can be done from a single IP or distributed across multiple IPs (DDoS). This directly exploits coturn's allocation handling.
    *   **Impact:** The server becomes unresponsive to legitimate clients, preventing them from establishing connections.  Service is disrupted, potentially causing financial loss or reputational damage.
    *   **Affected Component:**  `turn_server_main_loop` (main server loop handling requests), `turn_server_add_allocation` (allocation creation), memory management functions, network socket handling.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Implement strict rate limiting using `total-quota`, `user-quota`, and `ip-limit` configuration options.  These limit the number of allocations and bandwidth per user and IP address.
        *   Set appropriate resource limits using `max-bps` (maximum bandwidth per user) and `max-ports-per-user`.
        *   Monitor server resource usage (CPU, memory, network) and set alerts for high utilization.
        *   Use a firewall to limit the number of connections from a single IP address.
        *   Consider using a DDoS mitigation service.

## Threat: [Unauthorized Relay (Traffic Hijacking)](./threats/unauthorized_relay__traffic_hijacking_.md)

*   **Description:** An attacker successfully authenticates (or bypasses authentication) and uses the TURN server to relay traffic to arbitrary destinations, masking their true IP address.  This could be used for spamming, launching attacks against other systems, or accessing resources that are restricted based on IP address. This directly exploits coturn's relay functionality.
    *   **Impact:** The TURN server is used for malicious activities, potentially leading to legal liability, blacklisting of the server's IP address, and reputational damage.  The attacker can bypass network security controls.
    *   **Affected Component:** `turn_server_relay_message` (handles relaying of data), `turn_server_check_relay_endpoint` (checks relay endpoint validity - *if misconfigured*), authentication modules (if bypassed).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Implement strong authentication using long-term credentials, TLS client certificates, or a robust authentication backend (e.g., database, RADIUS).
        *   Strictly control relay destinations using `allowed-peer-ip` and `denied-peer-ip` configuration options.  Only allow relaying to known and trusted networks.
        *   Regularly review and update the allowed/denied peer IP lists.
        *   Monitor relay traffic for suspicious patterns.

## Threat: [Authentication Bypass (Credential Stuffing/Brute Force)](./threats/authentication_bypass__credential_stuffingbrute_force_.md)

*   **Description:** An attacker attempts to gain unauthorized access by trying many username/password combinations (credential stuffing) or systematically trying all possible passwords (brute force).  They may target the long-term credential database or the shared secret mechanism, directly attacking coturn's authentication mechanisms.
    *   **Impact:** The attacker gains unauthorized access to the TURN server, allowing them to use it for relaying traffic or potentially accessing other resources if the same credentials are used elsewhere.
    *   **Affected Component:** Authentication modules: `turn_server_check_credentials`, `turn_server_check_oauth`, database interaction functions (if using a database for credentials).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Use strong, unique passwords for all user accounts.
        *   Implement account lockout policies after a certain number of failed login attempts (e.g., using `lt-cred-mech` and related options).
        *   Use a strong hashing algorithm for storing passwords (coturn uses HMAC-SHA1 by default, which is generally considered secure *for this purpose*, but ensure it's configured correctly).
        *   Consider using multi-factor authentication (MFA) if supported by your authentication backend.
        *   Monitor authentication logs for suspicious activity.

## Threat: [Traffic Eavesdropping (Man-in-the-Middle)](./threats/traffic_eavesdropping__man-in-the-middle_.md)

*   **Description:** An attacker intercepts the communication between a client and the TURN server, potentially capturing sensitive data like usernames, passwords (if not using TLS), or the relayed data itself. This is most likely if TLS is not used or is improperly configured *within coturn*.
    *   **Impact:** Loss of confidentiality of client data and relayed traffic.  The attacker may be able to impersonate the client or the server.
    *   **Affected Component:** Network communication layer, TLS implementation (`turn_server_accept_connection`, `handle_turn_message`, and related functions handling encrypted traffic).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Enforce TLS for all TURN connections (use the `-L` or `--listening-port` option with TLS, and the `--tls-listening-port` option).
        *   Use strong TLS ciphers and protocols (configure using `--cipher-list`).
        *   Ensure clients are configured to use TLS and to validate the server's certificate.
        *   Use a valid, trusted TLS certificate (not a self-signed certificate in production).
        *   Regularly update the TLS certificate.

## Threat: [Software Vulnerability Exploitation](./threats/software_vulnerability_exploitation.md)

*   **Description:** An attacker exploits a known or zero-day vulnerability in the coturn software itself.  This could allow them to execute arbitrary code, gain unauthorized access, or cause a denial of service. This is a direct threat to the coturn application.
    *   **Impact:**  Complete compromise of the TURN server.  The attacker could gain full control of the server and use it for any purpose.
    *   **Affected Component:**  Potentially any component of coturn, depending on the specific vulnerability.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Regularly update coturn to the latest stable version.
        *   Monitor security advisories and mailing lists related to coturn.
        *   Use a vulnerability scanner to identify potential vulnerabilities.
        *   Consider using a web application firewall (WAF) to protect against known exploits.

## Threat: [UDP Amplification Attack](./threats/udp_amplification_attack.md)

*   **Description:** An attacker sends small requests to the coturn server over UDP, spoofing the source IP address to be the victim's IP address.  The coturn server responds with a larger response to the victim, amplifying the attacker's traffic and causing a denial-of-service attack against the victim. This directly leverages coturn's UDP relay capabilities.
    *   **Impact:** The victim's network is flooded with traffic, making their services unavailable.  The coturn server is used as an unwitting participant in a DDoS attack.
    *   **Affected Component:** UDP relay handling (`turn_server_relay_message` for UDP), network socket handling.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Disable UDP relaying if it is not absolutely necessary.
        *   If UDP relaying is required, implement strict rate limiting and filtering.
        *   Use `denied-peer-ip` to block known malicious networks.
        *   Monitor network traffic for signs of amplification attacks.
        *   Consider using a DDoS mitigation service.

