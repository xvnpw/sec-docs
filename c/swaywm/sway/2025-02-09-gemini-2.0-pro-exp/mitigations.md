# Mitigation Strategies Analysis for swaywm/sway

## Mitigation Strategy: [Restrict IPC Socket Permissions (Sway-Related Aspects)](./mitigation_strategies/restrict_ipc_socket_permissions__sway-related_aspects_.md)

*   **Description:**
    1.  **Understand Sway's Default:** Be aware that Sway *does* create its IPC socket with user-only permissions (`600`) by default. This is a good starting point.
    2.  **Systemd Integration (If Applicable):** If Sway is launched via systemd, review the service file (`/etc/systemd/system/` or `/usr/lib/systemd/system/`) for Sway.  Ensure that the `SocketMode=` option is set to `0600` (or `0660` if using a dedicated group).  If it's not, modify the service file and reload systemd (`systemctl daemon-reload`). This is *directly* related to how Sway is launched and managed.
    3. **Audit:** Regularly check `$SWAYSOCK` permissions.

*   **Threats Mitigated:**
    *   **Unauthorized Control of Sway (Severity: High):** Prevents unauthorized applications or users from controlling Sway via IPC.
    *   **Information Disclosure (Severity: Medium):** Limits access to Sway's internal state.
    *   **Denial of Service (Severity: Medium):** Reduces the attack surface for DoS attacks against the IPC socket.

*   **Impact:**
    *   **Unauthorized Control/Information Disclosure:** Significantly reduces risk.
    *   **Denial of Service:** Moderately reduces risk.

*   **Currently Implemented:**
    *   Sway creates the socket with `600` permissions by default.

*   **Missing Implementation:**
    *   No built-in auditing of socket permissions within Sway.
    *   Systemd service file configuration is distribution-dependent and may not always be optimal.

## Mitigation Strategy: [Validate IPC Messages (Hypothetical Sway Feature)](./mitigation_strategies/validate_ipc_messages__hypothetical_sway_feature_.md)

*   **Description:**
    *   *This strategy describes a feature that does NOT currently exist in Sway but would be a direct improvement to Sway's internal security.*
    1.  **Configuration Option:** Imagine a new configuration option in `sway/config`, such as `ipc_allowed_commands` or `ipc_command_policy`.
    2.  **Allowlist/Denylist:** This option would allow users to specify an allowlist or denylist of IPC commands.  For example:
        ```
        ipc_allowed_commands = ["get_workspaces", "get_outputs", "focus"]
        ```
        or
        ```
        ipc_denied_commands = ["exec", "reload", "exit"]
        ```
    3.  **Internal Enforcement:** Sway's internal IPC handling code would enforce this policy, rejecting any commands that are not allowed.
    4. **Default Policy:** A secure default policy should be in place.

*   **Threats Mitigated:**
    *   **Unauthorized Configuration Changes (Severity: High):** Prevents attackers from using IPC to modify Sway's configuration.
    *   **Arbitrary Code Execution (Severity: High):** Prevents the use of `exec` via IPC.
    *   **Privilege Escalation (Severity: High):** Reduces the attack surface for privilege escalation through IPC.

*   **Impact:**
    *   **All Threats:** Significantly reduces risk if implemented correctly.

*   **Currently Implemented:**
    *   **None.** This is a hypothetical feature.

*   **Missing Implementation:**
    *   **Entirely missing.** This would require significant changes to Sway's codebase.

## Mitigation Strategy: [Restrict Configuration File Permissions (Sway-Related Aspects)](./mitigation_strategies/restrict_configuration_file_permissions__sway-related_aspects_.md)

*   **Description:**
    1.  **User Responsibility:** Understand that Sway *expects* the user to manage the permissions of their configuration file (`~/.config/sway/config`).
    2.  **Documentation:** Sway's documentation *should* clearly emphasize the importance of setting the configuration file permissions to `600` (`chmod 600 ~/.config/sway/config`). This is a direct responsibility of the Sway project (documentation).
    3. **Check during startup (Hypothetical):** Sway *could* include a check during startup to verify that the configuration file has secure permissions and issue a warning if it doesn't. This would be a direct change to Sway.

*   **Threats Mitigated:**
    *   **Unauthorized Configuration Changes (Severity: High):** Prevents unauthorized modification of the Sway configuration.
    *   **Persistence (Severity: High):** Makes it harder for attackers to establish persistence via the configuration file.

*   **Impact:**
    *   **All Threats:** Significantly reduces risk if the user follows the recommended practice.

*   **Currently Implemented:**
    *   Sway relies on the user to set correct permissions.

*   **Missing Implementation:**
    *   No explicit warning or check within Sway if the configuration file has insecure permissions.
    *   Documentation could be more explicit about the required permissions.

## Mitigation Strategy: [Minimize `exec` in Configuration (Direct Sway Usage)](./mitigation_strategies/minimize__exec__in_configuration__direct_sway_usage_.md)

*   **Description:**
    1.  **Conscious Choice:** When writing your Sway configuration file, make a conscious effort to minimize the use of the `exec` command.
    2.  **Alternatives:** Actively seek alternatives to `exec`:
        *   Use Sway's built-in commands for window management, workspace switching, etc.
        *   Use `.desktop` files for launching applications.
        *   Use dedicated launchers (rofi, dmenu, wofi) *called* via Sway's built-in commands or keybindings, rather than directly using `exec`.
    3. **Review and Refactor:** Regularly review your configuration file and refactor it to reduce the reliance on `exec`.

*   **Threats Mitigated:**
    *   **Arbitrary Code Execution (Severity: High):** Reduces the risk of malicious code injection through the configuration file.
    *   **Privilege Escalation (Severity: High):** Limits the potential for privilege escalation via `exec`.

*   **Impact:**
    *   **All Threats:** Significantly reduces risk, depending on how effectively `exec` is minimized.

*   **Currently Implemented:**
    *   Sway *allows* `exec`, but the user has full control over its usage.

*   **Missing Implementation:**
    *   No built-in restrictions or warnings about `exec` usage within Sway itself.

## Mitigation Strategy: [Configuration Validation (Hypothetical Sway Feature)](./mitigation_strategies/configuration_validation__hypothetical_sway_feature_.md)

* **Description:**
    * *This strategy describes a feature that does NOT currently exist in Sway but would be a direct improvement.*
    1. **Built-in Linter:** Sway *could* include a built-in linter or validator for its configuration file.
    2. **Checks:** This validator would check for:
        *   Potentially dangerous `exec` commands (e.g., those running with elevated privileges or using untrusted input).
        *   Insecure keybindings (e.g., binding sensitive actions to easily triggered keys).
        *   Deprecated or unsupported configuration options.
        *   Syntax errors.
    3. **Warnings/Errors:** The validator would issue warnings or errors during startup if it detects any issues.
    4. **Configuration Option:** A configuration option could control the strictness of the validator (e.g., `config_validation_level = [strict|moderate|none]`).

* **Threats Mitigated:**
     * **Arbitrary Code Execution (Severity: High):** By checking `exec` commands.
     * **Unauthorized Configuration Changes (Severity: High):** By detecting insecure keybindings and other problematic settings.
     * **Use of Deprecated Features (Severity: Low-Medium):** By warning about deprecated options.

* **Impact:**
    * Significantly reduces risk, depending on the comprehensiveness of the validator.

* **Currently Implemented:**
    * **None.** This is a hypothetical feature.

* **Missing Implementation:**
    * **Entirely missing.** This would require significant development effort.

