# Threat Model Analysis for fatedier/frp

## Threat: [frps Authentication Bypass](./threats/frps_authentication_bypass.md)

*   **Threat:** `frps` Authentication Bypass

    *   **Description:** An attacker bypasses the authentication mechanism of the `frps` server. This could be achieved through exploiting a vulnerability in the authentication logic, guessing weak credentials, or leveraging leaked credentials. The attacker might use brute-force attacks, dictionary attacks, or exploit vulnerabilities like improper handling of authentication tokens.
    *   **Impact:** The attacker gains full control over the `frps` server, allowing them to view all connected clients, intercept/modify/redirect traffic, and potentially use the server as a pivot point for further attacks.  This is a complete compromise of the `frp` infrastructure.
    *   **Affected frp Component:** `frps` server, specifically the authentication handling within the `control.go` and related files (handling user login and token validation).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Strong Passwords/Tokens:** Enforce strong, unique passwords or use token-based authentication with long, randomly generated tokens.  Disable default credentials.
        *   **Rate Limiting:** Implement rate limiting on authentication attempts to prevent brute-force attacks.  `frp`'s configuration can help with this.
        *   **Account Lockout:** Implement account lockout policies after a certain number of failed login attempts.
        *   **Multi-Factor Authentication (MFA):** While `frp` doesn't natively support MFA, consider implementing it at the network or system level (e.g., SSH with MFA for server access).
        *   **Regular Security Audits:** Regularly audit the `frps` configuration and authentication logs.
        *   **Vulnerability Scanning and Patching:** Regularly scan for vulnerabilities and apply security updates to `frps`.

## Threat: [frps Denial of Service (DoS)](./threats/frps_denial_of_service__dos_.md)

*   **Threat:** `frps` Denial of Service (DoS)

    *   **Description:** An attacker floods the `frps` server with a large number of connection requests, exceeding its capacity to handle legitimate traffic.  This could involve SYN floods, UDP floods, or application-layer attacks targeting `frp`'s specific protocols.
    *   **Impact:**  All services exposed through the `frps` server become unavailable to legitimate users.  This disrupts business operations and can cause significant downtime.
    *   **Affected frp Component:** `frps` server, specifically the network handling and connection management components (likely within `server.go` and related networking code).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Rate Limiting (Connection Level):** Configure `frps` to limit the number of connections per client IP address or globally using `max_pool_count` and related settings.
        *   **Resource Limits (OS Level):** Configure operating system-level resource limits (e.g., `ulimit` on Linux) to prevent `frps` from consuming excessive CPU, memory, or file descriptors.
        *   **Firewall Rules:** Implement firewall rules to block or rate-limit traffic from known malicious sources or suspicious IP ranges.
        *   **DDoS Protection Services:** Utilize cloud-based DDoS protection services to mitigate large-scale, distributed attacks.
        *   **Monitoring and Alerting:** Implement monitoring to detect and alert on high connection rates or resource utilization.

## Threat: [Man-in-the-Middle (MitM) Attack (without TLS)](./threats/man-in-the-middle__mitm__attack__without_tls_.md)

*   **Threat:** Man-in-the-Middle (MitM) Attack (without TLS)

    *   **Description:** An attacker intercepts the communication between `frpc` and `frps`.  If TLS is not properly configured or is disabled, the attacker can eavesdrop on the traffic, modify data in transit, and potentially inject malicious commands.  This requires the attacker to be positioned on the network path between the client and server.
    *   **Impact:**  Complete compromise of the confidentiality and integrity of the communication.  The attacker can steal sensitive data, inject malicious code, or redirect traffic to malicious servers.
    *   **Affected frp Component:**  Communication channel between `frpc` and `frps`, specifically the network transport layer.
    *   **Risk Severity:** Critical (if TLS is not used)
    *   **Mitigation Strategies:**
        *   **Mandatory TLS Encryption:**  **Always** use TLS encryption for all communication between `frpc` and `frps`.  Configure `tls_enable = true` in both `frps.ini` and `frpc.ini`.
        *   **Valid Certificates:** Use valid TLS certificates issued by a trusted Certificate Authority (CA) or properly configured self-signed certificates with appropriate trust established.
        *   **Certificate Pinning:** Implement certificate pinning (using `tls_trusted_ca_file` or similar) to prevent attackers from using forged certificates.
        *   **Strong Cipher Suites:** Configure `frp` to use strong TLS cipher suites and protocols.

## Threat: [frpc Client Compromise](./threats/frpc_client_compromise.md)

* **Threat:** `frpc` Client Compromise

    *   **Description:** An attacker gains control of a machine running the `frpc` client.  This could occur through malware infection, social engineering, exploiting vulnerabilities in the operating system or other software on the client machine, or physical access.
    *   **Impact:** The attacker gains access to all internal services exposed by *that specific* `frpc` client.  They could potentially modify the `frpc.ini` to expose additional services or redirect traffic to malicious destinations.  The compromised client could be used as a pivot point to attack other systems on the internal network.
    *   **Affected frp Component:** `frpc` client, including the `frpc.ini` configuration file and the running `frpc` process.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Endpoint Protection:** Deploy robust endpoint security software (antivirus, EDR, HIDS) on all machines running `frpc`.
        *   **Least Privilege:** Run `frpc` with a non-privileged user account.  Avoid running it as root or administrator.
        *   **Configuration File Protection:** Protect the `frpc.ini` file from unauthorized modification using file permissions and integrity monitoring.
        *   **Regular Security Updates:** Keep the operating system and all software on the client machine up-to-date with security patches.
        *   **User Education:** Train users about phishing, social engineering, and safe computing practices.
        *   **Network Segmentation (Internal):** Implement network segmentation *within* the internal network to limit the blast radius of a compromised client.

