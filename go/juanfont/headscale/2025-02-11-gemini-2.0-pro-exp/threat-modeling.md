# Threat Model Analysis for juanfont/headscale

## Threat: [Rogue Node Registration via Compromised Pre-Auth Key](./threats/rogue_node_registration_via_compromised_pre-auth_key.md)

*   **Description:** An attacker obtains a valid, unexpired pre-auth key through theft, social engineering, or by finding it exposed. The attacker then uses this key to register a malicious node with the Headscale server.  While the *compromise* might be external, the *use* of the key directly involves Headscale's registration process.
*   **Impact:** The attacker gains unauthorized access to the WireGuard network. They can intercept, modify, or drop traffic, potentially exfiltrating sensitive data or launching further attacks.
*   **Affected Component:** `PreAuthKey` handling in `handler.go` (functions related to key validation and node registration, like `RegisterNode`), database interactions related to storing and validating pre-auth keys.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Developer:** Implement strict key validation (expiry, one-time use). Add rate limiting to registration attempts. Improve error handling to avoid leaking key information.
    *   **User:** Use strong, random pre-auth keys. Treat keys as highly sensitive. Use secure channels for key distribution. Implement short key lifetimes. Use one-time keys. Regularly audit and revoke unused/expired keys.

## Threat: [Rogue Node Registration via Headscale Server Vulnerability](./threats/rogue_node_registration_via_headscale_server_vulnerability.md)

*   **Description:** An attacker exploits a vulnerability in the Headscale server's code (e.g., buffer overflow, injection, logic error) to bypass pre-auth key validation or other security checks, registering a malicious node without a valid key. This is a *direct* vulnerability in Headscale.
*   **Impact:** Unauthorized network access, traffic interception, data exfiltration, potential for further attacks.
*   **Affected Component:** Any part of the Headscale server code involved in node registration and key validation: `handler.go`, `v1.go` (API endpoints), database interaction code. Functions like `RegisterNode`, `handleRegister`, and related database queries.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Developer:** Thorough security audits and code reviews (focus on input validation, authentication, authorization). Secure coding practices. Robust error handling. Regular penetration testing. Keep dependencies up-to-date.
    *   **User:** Keep Headscale updated. Run with least necessary privileges (avoid root).

## Threat: [Headscale Configuration Tampering via Unauthorized Access](./threats/headscale_configuration_tampering_via_unauthorized_access.md)

*   **Description:** An attacker gains unauthorized access to the Headscale *server* (compromised credentials, SSH key theft, exploiting *another* service) and modifies the Headscale configuration file or database *directly*.  The vulnerability exploited might be *external*, but the *tampering* directly affects Headscale.
*   **Impact:** Altered routing rules, ACLs, user permissions. Network disruption, unauthorized access, attacker gaining elevated privileges within the Headscale network.
*   **Affected Component:** Configuration file (`config.yaml`), database, code that reads/writes to these: `config.go`, database interaction functions.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developer:** Robust access controls on the server. Strong passwords/SSH keys. MFA for admin access. Consider a configuration management system.
    *   **User:** Secure the server's OS. Strong passwords/SSH keys. MFA. Regularly back up configuration/database. File integrity monitoring (FIM) on the configuration file. Restrict network access to the server.

## Threat: [Elevation of Privilege via Headscale Vulnerability](./threats/elevation_of_privilege_via_headscale_vulnerability.md)

*   **Description:** An attacker exploits a vulnerability *within* the Headscale server code (e.g., buffer overflow, code injection) to gain elevated privileges on the server, potentially achieving root access. This is a *direct* vulnerability in Headscale.
*   **Impact:** Complete control of the Headscale server and potentially the underlying OS, compromising the entire network and other systems on the same machine.
*   **Affected Component:** Potentially any part of the Headscale codebase, especially code handling external input or interacting with the OS.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Developer:** Thorough security audits and code reviews. Secure coding practices (avoid unsafe functions, validate input). Regular penetration testing. Keep dependencies up-to-date. Run Headscale with least necessary privileges (container, dedicated user).
    *   **User:** Keep Headscale updated. Run with least necessary privileges. Security hardening on the server's OS.

