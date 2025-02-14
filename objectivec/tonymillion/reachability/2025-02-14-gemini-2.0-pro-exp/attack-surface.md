# Attack Surface Analysis for tonymillion/reachability

## Attack Surface: [1. Network Topology Discovery](./attack_surfaces/1__network_topology_discovery.md)

*   **Description:** An attacker attempts to learn about the internal network structure by observing the application's behavior related to reachability checks.
    *   **How Reachability Contributes:** The library's core function is to test reachability to specific hosts, making it a direct tool for network probing if misused.
    *   **Example:** An attacker observes that the application's UI shows "Offline" when they try to access a feature, and the error message (or timing) reveals that the application is attempting to reach `internal-db.example.com`.
    *   **Impact:** Leaked information about internal network structure can be used to plan further attacks, identify vulnerable services, and bypass perimeter defenses.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Abstraction:** Do not expose raw reachability results or target hostnames to the user. Use generic status indicators (e.g., "Service Unavailable").
        *   **Rate Limiting:** Implement strict rate limiting on any user-facing features that trigger reachability checks.
        *   **Generic Targets:** Use generic hostnames or IP addresses for reachability checks when possible (e.g., a gateway address instead of a specific database server).
        *   **Logging and Monitoring:** Log all reachability check targets and results, and monitor for unusual patterns or probes.

## Attack Surface: [2. DNS Spoofing/Hijacking Amplification](./attack_surfaces/2__dns_spoofinghijacking_amplification.md)

*   **Description:** An attacker manipulates DNS resolution to redirect reachability checks to a malicious host, potentially leading to data exfiltration or further compromise.
    *   **How Reachability Contributes:** If the library uses hostnames, it relies on DNS.  The application's *reaction* to the (spoofed) reachability result is the key vulnerability.
    *   **Example:** An attacker poisons the DNS cache to point `api.example.com` to their server. The application, believing the API is "reachable" (because the attacker's server responds), sends sensitive data to the attacker.
    *   **Impact:** Data breaches, man-in-the-middle attacks, and potential compromise of the application or connected services.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **IP Addresses:** Use IP addresses instead of hostnames for critical reachability checks whenever feasible.
        *   **DNSSEC:** Implement DNSSEC to validate DNS responses and prevent spoofing.
        *   **Trusted Resolver:** Use a dedicated, trusted DNS resolver for reachability checks.
        *   **Certificate Pinning (if applicable):** If the application communicates with a specific service after the reachability check, use certificate pinning to ensure it's talking to the legitimate server, even if DNS is compromised.
        *   **Monitor DNS Resolution:** Monitor DNS resolution times and failures for anomalies.

