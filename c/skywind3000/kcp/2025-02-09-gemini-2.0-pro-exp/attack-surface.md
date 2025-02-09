# Attack Surface Analysis for skywind3000/kcp

## Attack Surface: [Source IP Spoofing (Due to UDP)](./attack_surfaces/source_ip_spoofing__due_to_udp_.md)

*   **Description:** An attacker forges the source IP address of KCP packets.
    *   **KCP Contribution:** KCP is built on top of UDP, which is inherently connectionless and vulnerable to source IP spoofing. KCP's `conv` ID does not provide authentication.
    *   **Example:** An attacker spoofs a trusted server's IP to send malicious KCP packets to clients.
    *   **Impact:** Data breaches, unauthorized access, man-in-the-middle attacks, denial of service.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Application-Layer Authentication is Mandatory:** KCP *cannot* mitigate this on its own. The application *must* implement strong cryptographic authentication (PSK or public-key based) and associate the KCP `conv` ID with an authenticated session.  This is not a KCP-level mitigation, but it's the *only* way to address this inherent UDP vulnerability.

## Attack Surface: [Denial of Service (DoS) via Packet Flooding](./attack_surfaces/denial_of_service__dos__via_packet_flooding.md)

*   **Description:** An attacker sends a large volume of KCP packets (valid or invalid, but conforming to the basic KCP packet structure) to overwhelm resources.
    *   **KCP Contribution:** KCP's reliability and congestion control mechanisms, while designed for performance, can be abused by a flood of packets, even if those packets are ultimately rejected by the application layer.  The KCP library itself must still process these packets to some extent.
    *   **Example:** An attacker floods the server with KCP SYN packets or data packets with invalid application-layer data, consuming CPU and memory within the KCP library's processing routines.
    *   **Impact:** Service unavailability, performance degradation.
    *   **Risk Severity:** High to Critical
    *   **Mitigation Strategies:**
        *   **KCP Configuration:** Configure KCP with reasonable limits on buffer sizes, maximum connections, and other relevant parameters. This limits the resources KCP itself can consume.
        *   **Application-Layer Rate Limiting (Pre-KCP):** Implement strict rate limiting *before* packets reach the KCP processing logic. This is crucial to prevent KCP's internal mechanisms from being overwhelmed. This is technically an application-layer mitigation, but it's essential for protecting KCP.
        *   **Firewalling:** If possible, use firewall rules to restrict UDP traffic to known/trusted sources.

## Attack Surface: [Fragmentation/Reassembly Attacks (Targeting KCP Implementation)](./attack_surfaces/fragmentationreassembly_attacks__targeting_kcp_implementation_.md)

*   **Description:** An attacker sends malformed or overlapping KCP fragments specifically crafted to exploit vulnerabilities *within KCP's fragmentation and reassembly logic*.
    *   **KCP Contribution:** This attack directly targets the internal implementation of KCP's fragmentation and reassembly handling.
    *   **Example:** An attacker sends overlapping fragments with carefully crafted header values designed to trigger a buffer overflow or other memory corruption vulnerability *within the KCP library code itself*.
    *   **Impact:** Potential code execution within the context of the application (if a vulnerability exists in KCP), denial of service, data corruption.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Keep KCP Updated:** This is the *primary* mitigation.  Regularly update to the latest version of the KCP library to receive security patches that address any discovered vulnerabilities in its fragmentation handling.
        *   **Contribute to KCP Security Audits:** If possible, participate in or contribute to security audits and code reviews of the KCP library, focusing on the fragmentation and reassembly code.
        *   **Fuzzing (of KCP itself):** Ideally, the KCP library itself should be fuzzed to identify potential vulnerabilities in its handling of malformed fragments. This is a mitigation for the KCP *developers*, but benefits all users.

## Attack Surface: [Replay Attacks](./attack_surfaces/replay_attacks.md)

*   **Description:** An attacker captures and re-sends valid KCP packets to cause unintended actions.
    *   **KCP Contribution:** KCP provides reliable, ordered delivery *but does not inherently prevent replay attacks*. It's the application's responsibility to handle this.
    *   **Example:** Capturing a valid data packet and replaying it multiple times.
    *   **Impact:** Data corruption, unintended state changes, potential denial of service.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Application-Layer Protections are Mandatory:** KCP cannot mitigate this. The application *must* implement sequence numbers, timestamps, and/or cryptographic nonces *within the application data* to detect and reject replayed packets.

