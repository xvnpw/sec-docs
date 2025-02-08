# Attack Surface Analysis for coturn/coturn

## Attack Surface: [1. UDP Amplification DDoS Attack](./attack_surfaces/1__udp_amplification_ddos_attack.md)

    *   **Description:** Attackers exploit coturn's UDP handling to amplify traffic directed at a victim. Small requests to coturn result in large responses, overwhelming the target.
    *   **How coturn Contributes:** coturn's core function involves handling UDP traffic for STUN and TURN, making it a *direct* participant in the amplification.
    *   **Example:** An attacker sends a small STUN binding request to coturn, spoofing the source IP as the victim's. coturn sends a larger response to the victim.
    *   **Impact:** Denial of service for the targeted victim; potential service disruption for legitimate coturn users.
    *   **Risk Severity:** **Critical**
    *   **Mitigation Strategies:**
        *   Implement strict rate limiting on incoming UDP requests (`--max-bps`, `--user-quota`).
        *   Configure firewall rules to block/limit traffic from known malicious sources.
        *   Monitor for unusual UDP spikes.
        *   Use a DDoS mitigation service.
        *   Ensure coturn is updated.

## Attack Surface: [2. Resource Exhaustion (DoS)](./attack_surfaces/2__resource_exhaustion__dos_.md)

    *   **Description:** Attackers flood coturn with requests to consume server resources (CPU, memory, bandwidth), making it unavailable.
    *   **How coturn Contributes:** coturn manages connections and relay sessions, *directly* consuming resources.
    *   **Example:** Thousands of simultaneous TURN allocation requests exhaust memory.
    *   **Impact:** Denial of service; potential server instability.
    *   **Risk Severity:** **High**
    *   **Mitigation Strategies:**
        *   Configure coturn's resource limits: `--max-bps`, `--max-users`, `--total-quota`, `--user-quota`, `--max-port`, `--min-port`.
        *   Implement connection rate limiting (`--conn-per-ip-limit`).
        *   Monitor server resource usage and set alerts.
        *   Consider horizontal scaling.

## Attack Surface: [3. Unauthorized Relay Usage (Open Relay)](./attack_surfaces/3__unauthorized_relay_usage__open_relay_.md)

    *   **Description:** Attackers exploit a misconfigured coturn (no authentication) to relay their traffic, hiding their origin.
    *   **How coturn Contributes:** coturn's *primary function* is to relay; without authentication, it's an open relay.
    *   **Example:** An attacker uses an unauthenticated coturn to relay spam.
    *   **Impact:** Abuse of resources; potential legal/reputational damage; facilitation of malicious activities.
    *   **Risk Severity:** **Critical**
    *   **Mitigation Strategies:**
        *   *Always* require authentication for TURN relay usage.
        *   Never configure as an open relay without extreme caution and additional security.
        *   Regularly audit the configuration.

## Attack Surface: [4. Credential Brute-Force / Stuffing Attacks](./attack_surfaces/4__credential_brute-force__stuffing_attacks.md)

    *   **Description:** Attackers guess usernames/passwords to gain unauthorized TURN relay access.
    *   **How coturn Contributes:** coturn *directly* uses username/password authentication for TURN.
    *   **Example:** An attacker uses a password list to try to log in.
    *   **Impact:** Unauthorized relay access.
    *   **Risk Severity:** **High**
    *   **Mitigation Strategies:**
        *   Strong password policies.
        *   Account lockout (`--denied-peer-ip`).
        *   Monitor for failed logins.
        *   Consider MFA (requires custom integration).
        * Use long-term, randomly generated credentials.

## Attack Surface: [5. Traffic Interception (MitM) - Without TLS](./attack_surfaces/5__traffic_interception__mitm__-_without_tls.md)

    *   **Description:** If TLS is not used/misconfigured, attackers intercept/modify relayed traffic.
    *   **How coturn Contributes:** coturn *directly* relays the traffic; without TLS, it's in plain text.
    *   **Example:** Interception of TURN traffic on the same network.
    *   **Impact:** Loss of confidentiality/integrity of relayed data.
    *   **Risk Severity:** **Critical**
    *   **Mitigation Strategies:**
        *   *Always* use TLS for TURN (`--tls-listening-port`).
        *   Strong, up-to-date TLS ciphers/protocols.
        *   Valid, trusted CA certificates.
        *   Regular TLS configuration review.

## Attack Surface: [6. Software Vulnerabilities (RCE, DoS, Info Disclosure)](./attack_surfaces/6__software_vulnerabilities__rce__dos__info_disclosure_.md)

    *   **Description:** coturn may have vulnerabilities exploitable for server control, DoS, or information leaks.
    *   **How coturn Contributes:** The vulnerability exists *within* the coturn codebase.
    *   **Example:** A buffer overflow allows arbitrary code execution.
    *   **Impact:** Varies; could be DoS to complete compromise.
    *   **Risk Severity:** **Critical** to **High**
    *   **Mitigation Strategies:**
        *   *Keep coturn updated.*
        *   Monitor security advisories.
        *   Use a vulnerability scanner.
        *   Regular security audits.

## Attack Surface: [7. Configuration Errors (General - Directly Affecting Security)](./attack_surfaces/7__configuration_errors__general_-_directly_affecting_security_.md)

    *   **Description:** Misconfigurations like incorrect realm, overly permissive IP lists, or disabled security features.  Focus here is on errors *directly* impacting coturn's security mechanisms.
    *   **How coturn Contributes:** coturn's behavior is *directly* controlled by its configuration.
    *   **Example:**  A broad `--allowed-peer-ip` allows unauthorized access.  Disabling rate limiting.
    *   **Impact:** Varies; can lead to significant breaches.
    *   **Risk Severity:** **High**
    *   **Mitigation Strategies:**
        *   Review coturn documentation.
        *   Use configuration management.
        *   Regularly audit `turnserver.conf`.
        *   Test changes in a non-production environment.
        *   Principle of least privilege.

