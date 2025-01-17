# Attack Surface Analysis for swaywm/sway

## Attack Surface: [Unauthorized Access and Manipulation via Sway IPC Socket](./attack_surfaces/unauthorized_access_and_manipulation_via_sway_ipc_socket.md)

*   **Attack Surface:** Unauthorized Access and Manipulation via Sway IPC Socket
    *   **Description:** A malicious process running under the same user can connect to Sway's IPC socket and send commands.
    *   **How Sway Contributes:** Sway's design relies on an unauthenticated Unix socket for IPC, allowing any process with the correct permissions to interact with it.
    *   **Example:** A rogue application could connect to the Sway socket and send commands to close all other windows, change the layout, or even execute commands configured in Sway's `exec` bindings.
    *   **Impact:**  Loss of productivity, denial of service for other applications, potential execution of arbitrary commands if Sway is configured with `exec` bindings.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developers:**  Avoid relying on the assumption that only trusted applications can access the Sway socket. If your application interacts with Sway, implement robust input validation and error handling for IPC messages.
        *   **Users:** Be cautious about running untrusted applications. Consider using containerization or virtualization to isolate potentially malicious processes. Review Sway configuration for potentially dangerous `exec` bindings.

## Attack Surface: [Malicious Configuration Injection](./attack_surfaces/malicious_configuration_injection.md)

*   **Attack Surface:** Malicious Configuration Injection
    *   **Description:** An attacker gains write access to the user's Sway configuration file (`~/.config/sway/config`) and injects malicious commands.
    *   **How Sway Contributes:** Sway executes commands specified in the configuration file during startup and when the configuration is reloaded.
    *   **Example:** An attacker could add an `exec` command to the configuration that runs a reverse shell upon Sway startup, granting them remote access to the user's session.
    *   **Impact:** Full system compromise, arbitrary code execution with user privileges.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Developers:**  This is primarily a user responsibility, but developers can educate users about the importance of securing their configuration files.
        *   **Users:** Protect the Sway configuration directory and file with appropriate permissions (read/write only for the user). Regularly review the configuration file for unexpected entries. Use a version control system for the configuration file to track changes.

