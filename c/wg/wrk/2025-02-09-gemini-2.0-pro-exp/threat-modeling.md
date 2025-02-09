# Threat Model Analysis for wg/wrk

## Threat: [Intentional Denial of Service (DoS)](./threats/intentional_denial_of_service__dos_.md)

*   **Description:** A malicious actor (internal or external) uses `wrk` to deliberately flood a target server with requests, aiming to disrupt service. The attacker leverages `wrk`'s ability to generate high-volume HTTP traffic. The attacker might have obtained access to a system where `wrk` is installed or be able to execute it remotely.
    *   **Impact:** The target server becomes unavailable, causing significant disruption to services, potential financial losses, and reputational damage.
    *   **Affected Component:** `wrk`'s core engine (responsible for generating and managing HTTP requests), specifically the thread management (`-t`), connection management (`-c`), and duration (`-d`) parameters. The network stack of both the `wrk` host and the target server are also heavily involved.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Strict Access Control:** Restrict access to `wrk` execution to authorized personnel only. Use operating system permissions and `sudo` controls.  This is the *primary* mitigation.
        *   **Network Segmentation:** Isolate the network where `wrk` is run from production networks.  Use firewalls to prevent unauthorized traffic.
        *   **Intrusion Detection/Prevention Systems (IDS/IPS):** Deploy IDS/IPS to detect and potentially block malicious `wrk` traffic patterns (though this is more of a defense-in-depth measure, as `wrk` traffic can resemble legitimate high load).
        *   **Rate Limiting (on Target):** Implement robust rate limiting and other DoS protection mechanisms on the *target* server. This is crucial, but it's a mitigation for the *target*, not `wrk` itself.
        *   **Incident Response Plan:** Have a well-defined incident response plan to quickly address and mitigate DoS attacks.

## Threat: [Sensitive Data Exposure via Lua Script](./threats/sensitive_data_exposure_via_lua_script.md)

*   **Description:** A custom Lua script used with `wrk` is maliciously crafted to log or transmit sensitive data obtained from HTTP responses.  This is a deliberate attack where the attacker writes or modifies the Lua script to exfiltrate data.  The script might print this data to the console, write it to a file, or send it to an external server controlled by the attacker.
    *   **Impact:** Exposure of confidential information, leading to potential data breaches, regulatory violations (e.g., GDPR, CCPA), reputational damage, and financial losses.
    *   **Affected Component:** `wrk`'s Lua scripting engine (specifically, the `request`, `response`, and any custom functions within the Lua script that handle data). The attacker is exploiting the scripting capabilities of `wrk`.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Mandatory Code Review:** Require thorough code review of *all* Lua scripts by security experts, focusing on data handling and logging practices. This is the *primary* mitigation.
        *   **Input Sanitization:** Sanitize all inputs to the Lua script to prevent injection attacks (though this is less of a direct `wrk` threat and more general Lua security).
        *   **Secure Coding Practices:** Enforce secure coding guidelines for Lua scripts, including avoiding hardcoded secrets and minimizing data logging.
        *   **Secrets Management:** Use a secure secrets management system to inject sensitive data into the script's environment, rather than hardcoding it.
        *   **Secure Logging:** If logging is necessary, use a secure logging mechanism that redacts or encrypts sensitive data. Avoid logging to the console.
        *   **Data Minimization:** Design scripts to only retrieve and process the minimum necessary data.

## Threat: [`wrk` Binary Tampering](./threats/_wrk__binary_tampering.md)

*   **Description:** An attacker gains access to the system where `wrk` is installed and modifies the `wrk` binary itself. This could be done to alter its behavior, inject malicious code (e.g., to send requests to a different server, exfiltrate data, or create a backdoor), or to make the DoS capabilities even more potent.
    *   **Impact:** The compromised `wrk` binary could be used to launch more sophisticated attacks, exfiltrate data, or provide the attacker with persistent access to the system.  The attacker could use the modified `wrk` to attack any target, not just the originally intended one.
    *   **Affected Component:** The `wrk` executable binary itself.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **File Integrity Monitoring (FIM):** Use a FIM tool to monitor the `wrk` binary for unauthorized changes. This is the *primary* mitigation.
        *   **Code Signing:** Digitally sign the `wrk` binary to verify its authenticity and integrity.  This helps detect tampering.
        *   **Least Privilege:** Run `wrk` as a non-root user with limited permissions (though this is more about limiting the damage an attacker can do if they *do* compromise the system).
        *   **Secure Software Supply Chain:** Obtain `wrk` from a trusted source (e.g., the official GitHub repository) and verify its integrity using checksums.

## Threat: [Lua Script Tampering](./threats/lua_script_tampering.md)

*   **Description:** An attacker modifies a Lua script used by `wrk` to inject malicious code or alter its behavior.  This is similar to the "Sensitive Data Exposure" threat, but the attacker's goal might be broader than just data exfiltration. They could use the modified script to launch attacks against the target server (e.g., sending malicious payloads), perform other unauthorized actions, or even use the script as a stepping stone to attack other systems.
    *   **Impact:** A compromised Lua script can lead to a variety of attacks, depending on the attacker's goals, including data breaches, system compromise, and further propagation of the attack.
    *   **Affected Component:** The Lua script file(s) used by `wrk`.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **File Integrity Monitoring (FIM):** Monitor Lua script files for unauthorized changes. This is a *primary* mitigation.
        *   **Code Signing:** Digitally sign Lua scripts to verify their authenticity.
        *   **Secure Storage:** Store Lua scripts in a secure location with restricted access.
        *   **Code Review:** Thoroughly review any changes to Lua scripts before deployment, with a focus on security implications.

