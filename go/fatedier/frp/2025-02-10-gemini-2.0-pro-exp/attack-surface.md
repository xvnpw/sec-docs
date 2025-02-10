# Attack Surface Analysis for fatedier/frp

## Attack Surface: [Exposed `frps` Listening Port(s)](./attack_surfaces/exposed__frps__listening_port_s_.md)

*   *Description:* The primary entry point for attackers targeting the `frps` server. This is the `bind_port` and any other ports `frps` listens on.
    *   *How `frp` Contributes:* `frp` *requires* opening a port on the `frps` server to function. This is fundamental to its operation.
    *   *Example:* An attacker scans for open ports and finds the `frps` port exposed.
    *   *Impact:* Unauthorized access to `frps`, potentially leading to exposure of internal services, data breaches, or server compromise.
    *   *Risk Severity:* **Critical**
    *   *Mitigation Strategies:*
        *   **Firewall:** *Strictly* limit access to the `frps` port(s) using a firewall (iptables, cloud provider firewall) to only authorized IP addresses/networks. This is the *most critical* mitigation.
        *   **Port Knocking/SPA:** Implement port knocking or Single Packet Authorization to hide the open port.
        *   **Minimize Open Ports:** Disable unused `frp` features that require additional ports.

## Attack Surface: [Weak or Default Authentication](./attack_surfaces/weak_or_default_authentication.md)

*   *Description:* Using a weak, easily guessable, or default `token` for `frpc`-`frps` authentication.
    *   *How `frp` Contributes:* `frp`'s built-in authentication mechanism relies on a shared secret (`token`). The security of this mechanism depends entirely on the strength of the token.
    *   *Example:* An attacker brute-forces or guesses the `token` and connects to `frps`.
    *   *Impact:* Unauthorized access to `frps` and any services exposed through it.
    *   *Risk Severity:* **Critical**
    *   *Mitigation Strategies:*
        *   **Strong, Random Token:** Use a long, randomly generated, cryptographically secure token. Avoid predictable patterns. Use a password manager.
        *   **TLS Encryption:** *Always* enable TLS encryption (`tls_enable = true`) in both `frps.ini` and `frpc.ini` to protect the token during transmission.

## Attack Surface: [`frps` Dashboard Exposure (Without Authentication)](./attack_surfaces/_frps__dashboard_exposure__without_authentication_.md)

*   *Description:* The `frps` dashboard, if enabled and accessible without authentication, reveals sensitive information.
    *   *How `frp` Contributes:* `frp` provides an optional dashboard, and its security is entirely dependent on proper configuration.
    *   *Example:* An attacker finds the dashboard exposed on the default port without a password.
    *   *Impact:* Information disclosure (client IPs, configurations), potential for further attacks.
    *   *Risk Severity:* **High**
    *   *Mitigation Strategies:*
        *   **Disable in Production:** Strongly consider disabling the dashboard in production.
        *   **Strong Authentication:** If enabled, *require* strong username/password authentication.
        *   **Network Segmentation:** Restrict access to a separate management network via firewall rules.
        * **TLS Encryption:** Use TLS for dashboard.

## Attack Surface: [Unpatched `frp` Vulnerabilities (RCE)](./attack_surfaces/unpatched__frp__vulnerabilities__rce_.md)

*   *Description:* Exploitable remote code execution (RCE) vulnerabilities in the `frp` software.
    *   *How `frp` Contributes:* This is a direct vulnerability *within* the `frp` codebase itself.
    *   *Example:* A zero-day RCE vulnerability in `frp` is exploited.
    *   *Impact:* Complete server compromise.
    *   *Risk Severity:* **Critical**
    *   *Mitigation Strategies:*
        *   **Regular Updates:** Keep `frp` updated to the latest stable version. Monitor for security advisories.
        *   **Minimal Installation:** Run `frps` with minimal privileges (not as root).
        *   **Containerization:** Run `frps` within a container to isolate it.

## Attack Surface: [Man-in-the-Middle (MitM) Attack (without TLS)](./attack_surfaces/man-in-the-middle__mitm__attack__without_tls_.md)

*   *Description:* Interception of `frpc`-`frps` communication when TLS is disabled.
    *   *How `frp` Contributes:* `frp`'s communication is vulnerable to MitM *if* TLS is not explicitly enabled.  The protocol itself doesn't inherently prevent MitM without TLS.
    *   *Example:* An attacker intercepts traffic and steals the `token` because TLS is not used.
    *   *Impact:* Credential theft, data interception, potential for malicious data injection.
    *   *Risk Severity:* **Critical**
    *   *Mitigation Strategies:*
        *   **Always Use TLS:** Enable TLS encryption (`tls_enable = true`) in both `frps.ini` and `frpc.ini`. Use valid certificates. This is mandatory.

