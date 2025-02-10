# Attack Surface Analysis for egametang/et

## Attack Surface: [Spoofed KCP Packets](./attack_surfaces/spoofed_kcp_packets.md)

*   **Description:** Attackers can forge UDP packets with fake source IP addresses to impersonate legitimate clients or servers.
*   **How `et` Contributes:** `et` uses UDP, which is inherently connectionless and susceptible to source IP spoofing. `et`'s KCP implementation provides reliability *on top of* UDP, but doesn't inherently prevent spoofing at the IP layer.
*   **Example:** An attacker sends KCP connection initiation packets with a spoofed source IP address, pretending to be a legitimate client. This could lead to resource exhaustion on the server or potentially disrupt existing connections.
*   **Impact:** Resource exhaustion, connection disruption, potential data corruption (if application-level validation is weak).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Application-Level Session Management:** Implement strong, cryptographically secure session management *above* the `et` layer. This should involve unique session identifiers (nonces, tokens) that are independent of the IP address and KCP session ID.
    *   **Rate Limiting:** Limit the rate of new connection attempts from individual IP addresses, especially during the initial handshake.
    *   **IP Allowlisting/Denylisting:** If the application's communication patterns are predictable, use IP address filtering to restrict connections to known good sources.
    *   **Input Validation:** Validate all data received from `et`, even if it appears to be from a valid KCP session.

## Attack Surface: [Replay Attacks (within KCP Window)](./attack_surfaces/replay_attacks__within_kcp_window_.md)

*   **Description:** Attackers capture and retransmit valid KCP packets within the allowed sequence number window.
*   **How `et` Contributes:** While KCP uses sequence numbers to ensure ordered delivery, it has a window of acceptable sequence numbers. An attacker can replay packets within this window. `et`'s implementation of KCP *allows* for this by design (for reliability).
*   **Example:** An attacker captures a valid "request" packet and replays it multiple times. If the application doesn't have its own replay protection, this could lead to duplicate actions (e.g., multiple orders being placed, multiple login attempts).
*   **Impact:** Duplicate actions, data corruption, potential denial of service (if replayed packets trigger resource-intensive operations).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Application-Level Nonces/Timestamps:** Include a unique, non-repeating value (nonce) or a timestamp in *every* application-level message sent over `et`. The receiver must validate these to ensure freshness and reject replays.
    *   **Short KCP Window:** If the application can tolerate it, use a smaller KCP window size. This reduces the time window for successful replay attacks. This must be balanced against potential performance impacts.
    *   **Idempotency:** Design application-level operations to be idempotent (i.e., executing them multiple times has the same effect as executing them once).

## Attack Surface: [Lack of Encryption (Man-in-the-Middle)](./attack_surfaces/lack_of_encryption__man-in-the-middle_.md)

*   **Description:** Data transmitted over `et` is not encrypted by default, making it vulnerable to interception and modification by a man-in-the-middle attacker.
*   **How `et` Contributes:** `et` itself does *not* provide encryption. It's a transport layer protocol. It's the application's responsibility to implement encryption *on top of* `et`.
*   **Example:** An attacker intercepts the communication between two parties using `et` and reads sensitive data (e.g., credentials, financial information) or modifies messages to cause harm.
*   **Impact:** Data breach, data modification, loss of confidentiality and integrity.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Mandatory Encryption:** **Always** implement strong encryption (e.g., TLS, DTLS, or a well-vetted custom encryption scheme) *on top of* the `et` connection. Treat the `et` connection as an untrusted transport.
    *   **Certificate Validation:** If using TLS/DTLS, ensure proper certificate validation to prevent MitM attacks using forged certificates.
    *   **Key Management:** Securely manage cryptographic keys.

## Attack Surface: [Denial-of-Service (DoS/DDoS) via Packet Flooding](./attack_surfaces/denial-of-service__dosddos__via_packet_flooding.md)

*   **Description:** Attackers flood the application with a large number of KCP packets (valid or invalid), overwhelming the `et` library or the application itself.
*   **How `et` Contributes:** While KCP is designed for efficiency, `et`'s implementation might have limitations in handling extremely high packet rates. The underlying UDP transport is also susceptible to flooding.
*   **Example:** An attacker sends a massive number of KCP connection requests or data packets, consuming all available bandwidth, CPU, or memory resources on the server.
*   **Impact:** Denial of service, application unavailability.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Rate Limiting:** Implement strict rate limiting at multiple levels (IP address, KCP session, application-level requests).
    *   **Connection Limiting:** Limit the maximum number of concurrent KCP connections.
    *   **Resource Allocation:** Ensure the application has sufficient resources (CPU, memory, network bandwidth) to handle expected traffic loads, and consider using a load balancer.
    *   **Firewall Rules:** Use firewall rules to block traffic from known malicious sources.
    *   **DDoS Mitigation Services:** Consider using a DDoS mitigation service (e.g., Cloudflare, AWS Shield) to protect against large-scale attacks.

## Attack Surface: [Code-Level Vulnerabilities (in `et` itself)](./attack_surfaces/code-level_vulnerabilities__in__et__itself_.md)

*   **Description:** Bugs in `et`'s code (e.g., buffer overflows, integer overflows, logic errors) could be exploited by attackers.
*   **How `et` Contributes:** This is inherent to any software. `et`, as a network library handling potentially untrusted input, is a prime target for these types of vulnerabilities.
*   **Example:** An attacker sends a specially crafted KCP packet that triggers a buffer overflow in `et`'s parsing logic, allowing the attacker to execute arbitrary code.
*   **Impact:** Remote code execution, denial of service, data corruption, privilege escalation.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Code Review:** Thoroughly review the `et` codebase, focusing on areas that handle packet data, memory allocation, and error handling.
    *   **Static Analysis:** Use static analysis tools (e.g., linters, security scanners) to identify potential vulnerabilities.
    *   **Fuzz Testing:** Use fuzz testing to send a wide range of malformed and unexpected inputs to `et` to uncover potential bugs.
    *   **Memory Safety Tools:** Use memory safety tools (e.g., AddressSanitizer) during testing.
    *   **Keep `et` Updated:** Regularly update to the latest version of the `et` library to benefit from any security patches.
    *   **Dependency Management:** Regularly audit and update `et`'s dependencies.

