# Attack Surface Analysis for nsqio/nsq

## Attack Surface: [Network Exposure of `nsqd` TCP Ports](./attack_surfaces/network_exposure_of__nsqd__tcp_ports.md)

*   **Description:** `nsqd` listens on configurable TCP ports to accept connections from producers and consumers.
    *   **How NSQ Contributes:** This is fundamental to NSQ's operation, enabling message exchange over the network.
    *   **Example:** An attacker on the network gains access to the `nsqd` port and publishes a large volume of garbage messages, overwhelming consumers or filling up disk space.
    *   **Impact:** Denial of Service (DoS), resource exhaustion, potential for injecting malicious data into the message stream.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Implement network segmentation and firewalls to restrict access to `nsqd` ports to only trusted hosts.
        *   Utilize access control lists (ACLs) if supported by the network infrastructure.
        *   Consider running `nsqd` within a private network.

## Attack Surface: [Unsecured `nsqd` HTTP API](./attack_surfaces/unsecured__nsqd__http_api.md)

*   **Description:** `nsqd` exposes an HTTP API for administrative tasks, health checks, and statistics.
    *   **How NSQ Contributes:** This API is a core component for managing and monitoring `nsqd`.
    *   **Example:** An attacker gains access to the `nsqd` HTTP API and uses it to delete critical topics or pause message processing, causing application disruption.
    *   **Impact:** Denial of Service (DoS), data loss (topic deletion), information disclosure (statistics).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Restrict access to the `nsqd` HTTP API to trusted networks or specific IP addresses.
        *   Implement authentication and authorization mechanisms for the HTTP API if possible (consider using a reverse proxy with authentication).
        *   Disable or restrict access to non-essential API endpoints.

## Attack Surface: [Network Exposure of `nsqlookupd` TCP Ports](./attack_surfaces/network_exposure_of__nsqlookupd__tcp_ports.md)

*   **Description:** `nsqlookupd` listens on configurable TCP ports for `nsqd` instances to register and for clients to query for `nsqd` locations.
    *   **How NSQ Contributes:** This is essential for NSQ's distributed nature, allowing producers and consumers to discover available `nsqd` instances.
    *   **Example:** An attacker gains access to the `nsqlookupd` port and registers a rogue `nsqd` instance, potentially redirecting message traffic to a malicious server.
    *   **Impact:** Message redirection, potential for data interception or manipulation, disruption of message flow.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Implement network segmentation and firewalls to restrict access to `nsqlookupd` ports to only trusted hosts.
        *   Utilize access control lists (ACLs) if supported by the network infrastructure.
        *   Consider running `nsqlookupd` within a private network.

