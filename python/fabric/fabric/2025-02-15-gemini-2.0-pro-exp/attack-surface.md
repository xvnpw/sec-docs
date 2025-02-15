# Attack Surface Analysis for fabric/fabric

## Attack Surface: [SSH Key Compromise (Fabric-Managed Connections)](./attack_surfaces/ssh_key_compromise__fabric-managed_connections_.md)

*   *Description:* Unauthorized access to SSH private keys used *by Fabric* for automated connections. This focuses on keys specifically used within the Fabric context, not general SSH access.
    *   *Fabric Contribution:* Fabric *directly* uses SSH keys to establish connections and authenticate to remote servers. Its core operation depends on the security of these keys.
    *   *Example:* An attacker gains access to a server where Fabric scripts are run and finds an unencrypted private key file used exclusively by a Fabric task to connect to other servers.
    *   *Impact:* Complete control over the target servers accessible *via Fabric* with the privileges of the compromised user account. Potential for data breaches, system compromise, and lateral movement *through Fabric-managed connections*.
    *   *Risk Severity:* **Critical**
    *   *Mitigation Strategies:*
        *   Use strong, unique passphrases for all SSH private keys used by Fabric.
        *   Store private keys used by Fabric *securely* and separately from general-purpose keys (e.g., dedicated hardware security modules, encrypted key stores, secrets management systems, *never* in code repositories).
        *   Regularly rotate SSH keys used specifically for Fabric operations.
        *   Implement multi-factor authentication (MFA) for SSH access, even for automated Fabric connections, if possible (this may require more complex setup).
        *   Use SSH certificates instead of raw keys for improved manageability and security, especially for Fabric-managed connections.
        *   Use a dedicated, *restricted* user account on target servers *specifically for Fabric operations*, minimizing the impact of a key compromise. This account should have the absolute minimum necessary privileges.

## Attack Surface: [Command Injection (via `run`/`sudo`/`local`)](./attack_surfaces/command_injection__via__run__sudo__local__.md)

*   *Description:* User-supplied data is unsafely incorporated into shell commands executed by Fabric's `run`, `sudo`, or `local` functions. This is a direct consequence of how these Fabric functions operate.
    *   *Fabric Contribution:* Fabric *provides* the `run`, `sudo`, and `local` functions, which are the *direct mechanism* for executing shell commands. The vulnerability arises from *how these functions are used* within the application's code.
    *   *Example:* A web application uses Fabric to execute a command on a remote server, and the command string is built by concatenating user input: `run("command " + user_input)`. An attacker provides malicious input to execute arbitrary commands.
    *   *Impact:* Execution of arbitrary commands on the target server (or locally, if using `local`) with the privileges of the Fabric user (or the `sudo` user). This can lead to complete system compromise.
    *   *Risk Severity:* **Critical**
    *   *Mitigation Strategies:*
        *   *Absolutely never* directly concatenate user input into shell commands executed via Fabric.
        *   Favor built-in Fabric functions (like `put`, `get`, `files.exists`, `files.append`) over raw shell commands whenever possible. These functions are designed to handle data more safely.
        *   If shell commands are unavoidable, use extreme caution.  While Fabric doesn't have direct parameterized command support like database libraries, strive to structure commands where arguments are treated as data, not code, by the shell.
        *   Implement *strict* input validation and sanitization on *all* user-supplied data *before* it interacts with Fabric in any way. This is a crucial defense-in-depth measure.

## Attack Surface: [Privilege Escalation (via Fabric's `sudo`)](./attack_surfaces/privilege_escalation__via_fabric's__sudo__.md)

*   *Description:* Misconfigured `sudo` on target servers, combined with Fabric's `sudo` function, allows the Fabric user to gain excessive privileges.
    *   *Fabric Contribution:* Fabric's `sudo` function is the *direct mechanism* used to execute commands with elevated privileges. The vulnerability stems from the interaction between Fabric's `sudo` and the server's `sudo` configuration.
    *   *Example:* The Fabric user is allowed to run `sudo command` without a password for a wide range of commands, and the application uses `sudo` extensively via Fabric.
    *   *Impact:* An attacker who compromises the Fabric user account (or injects commands) can gain full root access to the target server *through Fabric*.
    *   *Risk Severity:* **High**
    *   *Mitigation Strategies:*
        *   Configure `sudo` on target servers with the principle of *least privilege*. Only allow the Fabric user to run the *specific* commands necessary for its tasks, and *nothing more*.
        *   *Always* require a password for `sudo` operations, even for the Fabric user.
        *   Regularly audit `sudoers` files for overly permissive rules, specifically focusing on the privileges granted to the account used by Fabric.
        *   Strongly consider using separate, *highly restricted* user accounts for *different* Fabric tasks, rather than a single account with broad `sudo` access. Each account should have the absolute minimum privileges required for its specific task.

## Attack Surface: [Man-in-the-Middle (MITM) Attacks (Fabric's SSH Connection Handling)](./attack_surfaces/man-in-the-middle__mitm__attacks__fabric's_ssh_connection_handling_.md)

*   *Description:* Fabric is configured (or misconfigured) in a way that bypasses or weakens SSH host key verification, allowing an attacker to intercept the connection.
    *   *Fabric Contribution:* Fabric *handles* the SSH connection establishment and relies on proper host key verification for security. Incorrect configuration *within Fabric* can create this vulnerability.
    *   *Example:* `env.disable_known_hosts = True` is set in the Fabric configuration, or the `known_hosts` file is not properly managed, leading to Fabric accepting connections from any host.
    *   *Impact:* An attacker can intercept the SSH connection established *by Fabric*, potentially injecting malicious commands or stealing data transmitted during the Fabric session.
    *   *Risk Severity:* **High**
    *   *Mitigation Strategies:*
        *   *Never* disable host key verification in production environments (i.e., never set `env.disable_known_hosts = True` or equivalent bypasses).
        *   Ensure that the `known_hosts` file is properly managed and populated with the correct host keys for all target servers.
        *   Use Fabric's features to verify host keys (or pre-populate the `known_hosts` file) before establishing connections.
        *   Strongly consider using SSH certificates for more robust and manageable host key verification, especially in environments managed by Fabric.

