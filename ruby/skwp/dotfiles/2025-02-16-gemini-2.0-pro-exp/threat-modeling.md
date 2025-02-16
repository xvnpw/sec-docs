# Threat Model Analysis for skwp/dotfiles

## Threat: [Threat 1: Malicious Code Execution via `install.sh`](./threats/threat_1_malicious_code_execution_via__install_sh_.md)

*   **Description:** An attacker compromises the `skwp/dotfiles` repository (or a fork used by the application) and modifies the `install.sh` script to include malicious commands. These commands are executed during the initial setup or when dotfiles are updated.  The attacker might download and execute a reverse shell, install a rootkit, steal credentials, or perform other malicious actions. This is a direct injection of malicious code.
    *   **Impact:** Complete system compromise, data exfiltration, persistence, lateral movement within the network.
    *   **Affected Component:** `install.sh`
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **M1.1: Never Directly Execute `install.sh`:** Do *not* run `curl ... | sh` or similar. Download the script, *thoroughly* review it, and *then* execute it locally *only* if it's deemed safe.
        *   **M1.2: Pin to a Specific Commit:** Use a specific, reviewed commit hash instead of `main` or `master`. Example: `git clone --branch <commit_hash> ...`
        *   **M1.3: Manual Installation:** Perform installation steps manually, reviewing each command and change.
        *   **M1.4: Sandboxing:** Run the installation in a container or VM for isolation.
        *   **M1.5: Static Analysis:** Use a shell script analysis tool (e.g., `shellcheck`).

## Threat: [Threat 2: Malicious Alias/Function Overriding](./threats/threat_2_malicious_aliasfunction_overriding.md)

*   **Description:** An attacker modifies `.zshrc`, `.bashrc`, or other shell configuration files to define malicious aliases or functions that override common commands (e.g., `ls`, `cd`, `git`, `ssh`). When the user executes these commands, the malicious code runs. The attacker might exfiltrate data, modify files, or escalate privileges. This is a direct attack through shell configuration.
    *   **Impact:** Data exfiltration, file modification, privilege escalation, command hijacking.
    *   **Affected Component:** `.zshrc`, `.bashrc`, `.profile`, any file sourced by the shell.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **M2.1: Selective Sourcing:** Do *not* blindly source the entire dotfiles. Review each section of `.zshrc`, `.bashrc`, etc., and include only necessary parts.
        *   **M2.2: Code Review (Aliases/Functions):** Carefully review all aliases and functions. Understand what they do before including them.
        *   **M2.3: Avoid Overriding Core Commands:** Be very cautious about overriding core system commands. Use different names if necessary.
        *   **M2.4: Dedicated User:** Run the application with a dedicated, limited-privilege user account.
        *   **M2.5: Shell Auditing:** Enable shell history auditing and review it regularly.

## Threat: [Threat 3: Environment Variable Manipulation](./threats/threat_3_environment_variable_manipulation.md)

*   **Description:** An attacker modifies shell configuration files to set environment variables to malicious values, altering application or tool behavior. Examples:
        *   Modifying `PATH` to include a directory with malicious executables.
        *   Setting `LD_PRELOAD` to load a malicious library.
        *   Changing `http_proxy` or `https_proxy` to redirect traffic. This is a direct attack through environment manipulation within the dotfiles.
    *   **Impact:** Code execution, data interception, application misbehavior, privilege escalation.
    *   **Affected Component:** `.zshrc`, `.bashrc`, `.profile`, any file setting environment variables.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **M3.1: Environment Variable Whitelisting:** Define a whitelist of allowed environment variables and expected values.
        *   **M3.2: Review Environment Variable Settings:** Carefully review all environment variable settings in the dotfiles.
        *   **M3.3: Avoid Sensitive Variables in Dotfiles:** Do *not* store sensitive information (API keys, passwords) in dotfiles. Use a secure credential manager.
        *   **M3.4: Containerization:** Containers provide a more isolated environment.

## Threat: [Threat 4: Malicious `git` Configuration](./threats/threat_4_malicious__git__configuration.md)

*   **Description:** An attacker modifies the `.gitconfig` file to introduce malicious settings. Examples:
        *   Setting `core.sshCommand` to execute a malicious script.
        *   Configuring `credential.helper` to store credentials insecurely or send them to a malicious server.
        *   Disabling SSL verification. This is a direct attack through Git configuration.
    *   **Impact:** Code exfiltration, credential theft, man-in-the-middle attacks, supply chain compromise.
    *   **Affected Component:** `.gitconfig`
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **M4.1: Review `.gitconfig`:** Carefully review the `.gitconfig` file and understand all settings.
        *   **M4.2: Use System-Wide `gitconfig`:** Prefer the system-wide `gitconfig` and only override specific settings if necessary.
        *   **M4.3: Enable SSL Verification:** Ensure SSL verification is enabled for remote Git repositories.
        *   **M4.4: Use SSH Keys:** Use SSH keys for authentication and protect private keys.
        *   **M4.5: Git Hooks Review:** If using Git hooks from the dotfiles, review them thoroughly.

## Threat: [Threat 5: Malicious `ssh` Configuration](./threats/threat_5_malicious__ssh__configuration.md)

*   **Description:** An attacker modifies `~/.ssh/config` to introduce malicious settings. Examples:
        *   Adding a `ProxyCommand` to redirect connections through a malicious server.
        *   Disabling `HostKeyChecking`.
        *   Using weak ciphers. This is a direct attack through SSH configuration.
    *   **Impact:** Man-in-the-middle attacks, credential theft, data interception, unauthorized remote access.
    *   **Affected Component:** `~/.ssh/config`, `~/.ssh/known_hosts`
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **M5.1: Review `~/.ssh/config`:** Carefully review the `~/.ssh/config` file.
        *   **M5.2: Enable `HostKeyChecking`:** Ensure `HostKeyChecking` is enabled.
        *   **M5.3: Use Strong Ciphers:** Configure SSH to use strong ciphers and key exchange algorithms.
        *   **M5.4: Limit `ProxyCommand` Usage:** Avoid `ProxyCommand` unless necessary, and review settings carefully.
        *   **M5.5: Regularly Update `known_hosts`:** Keep `~/.ssh/known_hosts` up-to-date.

