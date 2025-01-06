# Attack Surface Analysis for v2ray/v2ray-core

## Attack Surface: [Insecure Protocol Configuration (VMess, Shadowsocks, etc.)](./attack_surfaces/insecure_protocol_configuration__vmess__shadowsocks__etc__.md)

*   **Description:**  Using weak or outdated encryption algorithms, insecure authentication methods, or improper protocol settings *within v2ray-core's configuration*.
    *   **How v2ray-core Contributes:** v2ray-core's design allows configuration of various protocols with different security levels, and the responsibility for choosing secure options lies with the user. Incorrect choices directly expose vulnerabilities handled by v2ray-core.
    *   **Example:** Configuring VMess within v2ray-core with `aes-128-cfb` instead of `aes-128-gcm`, or using a weak `alterId` setting in the v2ray-core configuration.
    *   **Impact:**  Traffic interception, decryption, and potential manipulation by attackers due to weaknesses in the configured protocol within v2ray-core. Authentication bypass leading to unauthorized access through the v2ray-core proxy.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Configure v2ray-core to utilize strong, recommended ciphers and authentication methods for the chosen protocol (e.g., `aes-128-gcm` or `chacha20-poly1305` for VMess) within v2ray-core's configuration.
        *   Avoid using deprecated or known-vulnerable protocol settings available within v2ray-core.
        *   Regularly review and update the v2ray-core configuration file to adhere to security best practices for the selected protocols.
        *   For VMess, configure a sufficiently large and random `alterId` within v2ray-core.

## Attack Surface: [Exposed or Unsecured Control Plane (API)](./attack_surfaces/exposed_or_unsecured_control_plane__api_.md)

*   **Description:**  The v2ray-core API (typically gRPC or HTTP) is accessible without proper authentication or authorization, allowing unauthorized control *of the v2ray instance itself*.
    *   **How v2ray-core Contributes:** v2ray-core provides an API for management, and the responsibility for securing this API (through configuration) falls on the user. Failure to do so directly exposes v2ray-core's control mechanisms.
    *   **Example:**  Leaving the gRPC API endpoint configured in v2ray-core accessible on a public interface without TLS and client authentication configured within v2ray-core.
    *   **Impact:**  Complete compromise of the v2ray instance, allowing attackers to manipulate v2ray-core's routing, disable services managed by v2ray-core, or potentially gain access to the underlying system through actions initiated by the compromised v2ray-core.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Secure the v2ray-core API using TLS/HTTPS with strong certificates, configured within v2ray-core.
        *   Implement robust client authentication (e.g., mutual TLS, API keys) for accessing the v2ray-core API.
        *   Restrict network access to the v2ray-core API to trusted networks or clients only through firewall rules and v2ray-core's listening configuration.
        *   Avoid exposing the v2ray-core API on public interfaces if not absolutely necessary.

## Attack Surface: [Incorrect Routing or Proxying Logic within v2ray-core](./attack_surfaces/incorrect_routing_or_proxying_logic_within_v2ray-core.md)

*   **Description:**  Misconfigured routing rules *within v2ray-core* leading to unintended access to internal resources or the ability to bypass security controls enforced by v2ray-core.
    *   **How v2ray-core Contributes:** v2ray-core's core functionality is routing and proxying traffic. Incorrectly defined rules within its configuration directly lead to exploitable pathways.
    *   **Example:**  A routing rule in v2ray-core's configuration that inadvertently allows traffic destined for an internal database server to bypass authentication checks enforced by v2ray-core.
    *   **Impact:**  Exposure of sensitive internal resources through v2ray-core, potential data breaches facilitated by v2ray-core's misrouting, and the ability to launch attacks from within the network using v2ray-core as a pivot.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Carefully design and review routing configurations within v2ray-core, adhering to the principle of least privilege for traffic flow managed by v2ray-core.
        *   Implement strict access controls and authentication for resources accessible through v2ray-core's routing.
        *   Regularly audit v2ray-core's routing rules to identify and correct any misconfigurations that could create security loopholes.

