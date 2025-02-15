# Threat Model Analysis for paramiko/paramiko

## Threat: [Authentication Bypass via Weak Cipher/MAC Negotiation](./threats/authentication_bypass_via_weak_ciphermac_negotiation.md)

*   **Threat:** Authentication Bypass via Weak Cipher/MAC Negotiation

    *   **Description:** An attacker forces the Paramiko client or server (if you're using Paramiko to implement an SSH server) to negotiate weak cryptographic algorithms (ciphers or MACs) during the SSH handshake. If vulnerabilities exist in these weaker algorithms, the attacker might decrypt traffic or forge messages, bypassing authentication.
    *   **Impact:** Unauthorized access to the remote system (or your server), data interception, potential for command injection.
    *   **Affected Paramiko Component:** `paramiko.Transport`, specifically the key exchange and negotiation process within the `_negotiate_keys` and related methods. This affects both client and server implementations.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Explicitly configure Paramiko to use *only* strong ciphers and MACs. Use `Transport.get_security_options().ciphers` and `Transport.get_security_options().macs` to set allowed algorithms. Prioritize modern, authenticated encryption algorithms (e.g., `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`).
        *   Regularly review and update the allowed algorithms based on current security best practices and known vulnerabilities.
        *   Disable support for known weak algorithms (e.g., `arcfour`, `hmac-md5`, `cbc` ciphers).

## Threat: [Host Key Spoofing (MITM)](./threats/host_key_spoofing__mitm_.md)

*   **Threat:** Host Key Spoofing (MITM)

    *   **Description:** An attacker intercepts the SSH connection and presents a forged host key to the Paramiko client. If the client doesn't properly verify the host key, the attacker can decrypt and modify the traffic, acting as a man-in-the-middle.
    *   **Impact:** Complete session compromise; credential theft, command injection, data exfiltration.
    *   **Affected Paramiko Component:** `paramiko.SSHClient`, specifically the `connect` method and the `missing_host_key` policy. Also affects custom host key verification callbacks if implemented incorrectly.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Never** use `paramiko.AutoAddPolicy()` in production.
        *   Use `paramiko.RejectPolicy()` and load known hosts from a trusted, tamper-proof source (e.g., a signed configuration file, a secure configuration management system).
        *   Implement a custom host key verification callback using `paramiko.client.WarningPolicy` or a custom subclass, and verify the host key fingerprint against a trusted database or use a certificate authority (CA).
        *   Consider using SSH certificates for host key verification.

## Threat: [Command Injection via `exec_command`](./threats/command_injection_via__exec_command_.md)

*   **Threat:** Command Injection via `exec_command`

    *   **Description:** An attacker injects malicious shell commands into the input passed to `paramiko.SSHClient.exec_command()`. If the application doesn't properly sanitize or escape user-provided input, the injected commands will be executed on the remote server. This is a direct misuse of a Paramiko API.
    *   **Impact:** Remote code execution on the remote server, leading to complete system compromise.
    *   **Affected Paramiko Component:** `paramiko.SSHClient.exec_command()`
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Strongly prefer SFTP for file transfers instead of constructing shell commands.**
        *   If `exec_command` is unavoidable, *never* directly concatenate user input into the command string.
        *   Use a robust sanitization and escaping library specifically designed for shell commands. Consider using `shlex.quote()` (with caution, understanding its limitations) or a more specialized library.
        *   Implement strict input validation to allow only expected characters and patterns.
        *   Use parameterized commands if the remote system and command structure support it.

## Threat: [Command Injection via `invoke_shell`](./threats/command_injection_via__invoke_shell_.md)

*   **Threat:** Command Injection via `invoke_shell`

    *   **Description:** Similar to `exec_command` injection, but targets the interactive shell provided by `paramiko.SSHClient.invoke_shell()`. An attacker sends malicious commands to the shell through the established channel. This is a direct misuse of a Paramiko API.
    *   **Impact:** Remote code execution on the remote server.
    *   **Affected Paramiko Component:** `paramiko.SSHClient.invoke_shell()`, and the associated `paramiko.Channel` object used for interaction.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Avoid `invoke_shell` whenever possible.** Use `exec_command` (with proper sanitization) for specific commands or SFTP for file transfers.
        *   If `invoke_shell` is absolutely necessary, *never* send unsanitized user input to the shell.
        *   Implement extremely strict input validation and escaping, even more rigorous than for `exec_command`.
        *   Consider using a terminal emulator library that provides built-in security features to mitigate injection risks.

## Threat: [SFTP Path Traversal](./threats/sftp_path_traversal.md)

*   **Threat:** SFTP Path Traversal

    *   **Description:** An attacker provides a malicious file path (e.g., containing `../`) to an SFTP operation (e.g., `paramiko.SFTPClient.open`, `get`, `put`, `listdir`). If the application doesn't validate the path *before* passing it to Paramiko, the attacker can access files outside the intended directory.
    *   **Impact:** Unauthorized file access (read or write), data leakage, potential for system compromise if sensitive files are overwritten.
    *   **Affected Paramiko Component:** `paramiko.SFTPClient` and its methods for file operations.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Always sanitize and validate file paths *before* passing them to Paramiko's SFTP methods.
        *   Normalize paths to remove `..` and other special characters. Use `os.path.normpath` and `os.path.abspath` (on the *client* side, before sending the path to the server).
        *   Implement a whitelist of allowed directories and files, rejecting any paths that don't match.
        *   Enforce a chroot jail or similar confinement mechanism on the *server* side to restrict the SFTP user's access (this is a server-side mitigation, but important to mention in conjunction with client-side validation).

## Threat: [Paramiko Vulnerability Exploitation (High/Critical Vulnerabilities)](./threats/paramiko_vulnerability_exploitation__highcritical_vulnerabilities_.md)

* **Threat:** Paramiko Vulnerability Exploitation (High/Critical Vulnerabilities)

    * **Description:**  An attacker exploits a *known or zero-day* vulnerability in the Paramiko library itself, specifically a vulnerability classified as High or Critical severity.
    * **Impact:** Varies depending on the specific vulnerability, but could range from denial of service to remote code execution *within the context of the application using Paramiko*.
    * **Affected Paramiko Component:** Any part of the Paramiko library.
    * **Risk Severity:** High/Critical (depending on the specific CVE)
    * **Mitigation Strategies:**
        *   Keep Paramiko up to date. Regularly check for and apply security updates, paying close attention to releases that address High or Critical vulnerabilities.
        *   Monitor security advisories related to Paramiko and its dependencies (e.g., `cryptography`). Subscribe to relevant mailing lists or security feeds.
        *   Use a software composition analysis (SCA) tool to identify known vulnerabilities in your application's dependencies, and configure it to alert on High/Critical issues.
        *   Implement a robust and rapid software update process to quickly deploy patches for critical vulnerabilities.

