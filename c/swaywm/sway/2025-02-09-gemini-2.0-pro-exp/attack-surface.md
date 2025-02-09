# Attack Surface Analysis for swaywm/sway

## Attack Surface: [IPC Socket Abuse](./attack_surfaces/ipc_socket_abuse.md)

*   **Description:** Sway's Unix domain socket allows external control and information retrieval, making it a prime target for attackers.
    *   **Sway's Contribution:** Sway creates, manages, and defines the functionality of this socket.  The security of the IPC mechanism is entirely Sway's responsibility.
    *   **Example:** An attacker with access to the socket sends a command to execute a malicious script configured within Sway, or to manipulate window properties to facilitate a phishing attack.
    *   **Impact:** Complete control of the Sway session, potential execution of arbitrary code, data exfiltration, denial of service.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Developers:**
            *   Implement *strict* input validation and sanitization on *all* IPC commands.  Reject any unexpected input.
            *   Enforce a *minimal* command whitelist, allowing only essential operations.
            *   Strongly consider adding authentication/authorization (e.g., capabilities or a secure cookie mechanism) to the IPC socket.
            *   Implement robust rate limiting to prevent DoS attacks.
            *   Conduct frequent security audits of the IPC code, including fuzzing.
        *   **Users:**
            *   *Verify* and *maintain* correct socket permissions (`srw-------`).  Automate this check if possible.
            *   Run *all* untrusted applications in sandboxed environments (Flatpak, Snap, Firejail, etc.).  This is crucial.
            *   Monitor the socket for unusual activity (e.g., using `lsof`, `auditd`, or custom scripts).

## Attack Surface: [Wayland Protocol Implementation Vulnerabilities](./attack_surfaces/wayland_protocol_implementation_vulnerabilities.md)

*   **Description:** Flaws in Sway's handling of the Wayland protocol messages can be exploited by malicious Wayland clients.
    *   **Sway's Contribution:** Sway is *directly* responsible for the correct and secure implementation of the Wayland protocol.  Any bugs here are Sway's responsibility.
    *   **Example:** A malicious Wayland client sends a specially crafted message that triggers a buffer overflow or use-after-free vulnerability in Sway's Wayland handling code, leading to code execution.
    *   **Impact:** Compromise of the Sway compositor, potential privilege escalation, client isolation bypass, denial of service.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developers:**
            *   Perform *extensive* fuzzing of the *entire* Wayland protocol implementation, including all supported extensions.
            *   Conduct regular, in-depth security audits of the Wayland-related code, focusing on memory safety and input validation.
            *   Use memory-safe languages or techniques (e.g., Rust, bounds checking, AddressSanitizer) whenever possible.
            *   Stay *proactively* informed about security advisories related to Wayland, wlroots, and related libraries.
        *   **Users:**
            *   Keep Sway and its *critical* dependencies (wlroots, libwayland) *constantly* updated.  Use a distribution with rapid security updates.
            *   Run *all* untrusted applications in sandboxed environments. This is a crucial defense-in-depth measure.

## Attack Surface: [Malicious Configuration and Scripting](./attack_surfaces/malicious_configuration_and_scripting.md)

*   **Description:** Attackers modifying the Sway configuration file to inject malicious commands or scripts that Sway will execute.
    *   **Sway's Contribution:** Sway directly interprets and executes commands and scripts defined in its configuration file.
    *   **Example:** An attacker gains write access to the configuration file and adds a command to download and execute a malicious payload when Sway starts or when a specific keybinding is pressed.
    *   **Impact:** Execution of arbitrary code with the user's privileges, persistence, system compromise.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developers:**
            *   Provide *very clear* and *concise* documentation on secure configuration practices, emphasizing the risks of arbitrary command execution.
            *   Consider a more structured and less error-prone configuration format (e.g., TOML with schema validation) to minimize the risk of misconfiguration leading to vulnerabilities.
            *   *Strongly* discourage or limit the execution of arbitrary user-provided commands within the configuration.  If necessary, provide a highly restricted and sandboxed environment for such commands.
        *   **Users:**
            *   *Strictly* protect the configuration file with correct permissions (`rw-------`).  Automate this check.
            *   *Regularly* review the configuration file for *any* suspicious or unfamiliar entries.
            *   *Never* use untrusted configuration snippets from the internet without *thorough* understanding and verification.
            *   Use a version control system (e.g., Git) to track changes and facilitate rollbacks.

