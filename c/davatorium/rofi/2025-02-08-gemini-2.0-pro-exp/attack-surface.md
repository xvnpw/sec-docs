# Attack Surface Analysis for davatorium/rofi

## Attack Surface: [Command Injection](./attack_surfaces/command_injection.md)

*   **Description:**  Execution of arbitrary commands by an attacker through manipulated input passed to `rofi`. This is the most significant risk.
*   **How Rofi Contributes:** `rofi`'s core functionality of executing commands and scripts based on user input or configured actions creates the direct potential for injection if input is not properly handled.  Features like `-run`, `-drun`, `-ssh`, and custom script modes are primary vectors.
*   **Example:**
    *   Application code: `rofi -show run -run-command "echo $(userInput)"`
    *   Attacker input: `userInput = "; rm -rf /; #"`
    *   Result: The attacker's command (`rm -rf /`) is executed.
*   **Impact:**  Complete system compromise, data loss, data exfiltration, installation of malware, denial of service.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Developer:**
        *   **Strict Input Validation and Sanitization:** Implement rigorous whitelisting of allowed characters and commands.  Reject *any* input that doesn't strictly conform to the expected format.  Use parameterized commands or escaping functions provided by your programming language to prevent shell metacharacter interpretation.
        *   **Avoid Shell Interpolation:** Do not use shell features like backticks or `$()` to build commands.  If absolutely necessary, use extreme caution and thorough escaping.
        *   **Use Rofi's Built-in Modes:** Prefer `rofi`'s built-in modes (like `-drun` for application launching) over custom shell scripts whenever possible.  These modes are generally safer.
        *   **Principle of Least Privilege:** Ensure the application (and `rofi`) runs with the *absolute minimum* necessary privileges.  Never run as root.
    *   **User:**
        *   Be extremely cautious about the source of any scripts or configurations used with `rofi`.  Only use trusted sources.
        *   Regularly update `rofi` and your system to get the latest security patches.

## Attack Surface: [Script Execution (Malicious Scripts)](./attack_surfaces/script_execution__malicious_scripts_.md)

*   **Description:** Execution of attacker-controlled scripts through `rofi`.
*   **How Rofi Contributes:** `rofi`'s ability to execute custom scripts (via custom modes or `-run-command`) creates a direct vulnerability if an attacker can modify or replace those scripts.
*   **Example:**
    *   Application uses a custom script at `/home/user/.config/rofi/my-script.sh`.
    *   Attacker gains write access to this file and replaces it with a malicious script.
    *   When the user triggers the script through `rofi`, the malicious code is executed.
*   **Impact:**  Similar to command injection: system compromise, data loss, data exfiltration, malware installation.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Developer:**
        *   **Secure Script Storage:** Store custom scripts in a directory that is *not* writable by the user running `rofi` or any unprivileged user.  Use restrictive file permissions (e.g., `chmod 755` or more restrictive).
        *   **Script Integrity Verification:** Implement a mechanism (e.g., checksums, digital signatures) to verify the integrity of custom scripts before execution.
        *   **Avoid Custom Scripts:**  Rely on `rofi`'s built-in modes whenever possible.
    *   **User:**
        *   Protect your `~/.config/rofi` directory and any other directories containing `rofi` scripts with strong file permissions.
        *   Be wary of downloading or using `rofi` scripts from untrusted sources.

