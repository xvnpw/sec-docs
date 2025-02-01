# Mitigation Strategies Analysis for basecamp/kamal

## Mitigation Strategy: [Implement Strong SSH Key Management for Kamal](./mitigation_strategies/implement_strong_ssh_key_management_for_kamal.md)

### Mitigation Strategy: Implement Strong SSH Key Management for Kamal

*   **Description:**
    1.  **Generate a dedicated SSH key pair for Kamal deployments.** Use `ssh-keygen -t ed25519 -b 521 -N "" -f ~/.ssh/kamal_deploy_key` on the machine running Kamal to create a strong EdDSA key without a passphrase. This key will be exclusively used by Kamal.
    2.  **Distribute the *public* key (`~/.ssh/kamal_deploy_key.pub`) to the `authorized_keys` file of the designated user on each target server.**  Use `ssh-copy-id -i ~/.ssh/kamal_deploy_key.pub user@server_ip` for each server Kamal will manage. This allows Kamal to authenticate without passwords.
    3.  **Configure Kamal's `deploy.yml` to explicitly use the *private* key (`~/.ssh/kamal_deploy_key`).**  Within your `deploy.yml` file, ensure you have the line `ssh_key: ~/.ssh/kamal_deploy_key`. This tells Kamal which key to use for SSH connections.
    4.  **Disable password-based SSH authentication on all target servers managed by Kamal.**  Edit `/etc/ssh/sshd_config` on each server and set `PasswordAuthentication no`.  Restart the SSH service (`sudo systemctl restart sshd`) to apply the change. This prevents password-based brute-force attacks against the servers Kamal manages.
    5.  **Optionally, restrict SSH access by IP address or network range in server firewalls and SSH configuration (`/etc/ssh/sshd_config` - `AllowUsers` or `AllowGroups`).** Limit SSH access to the servers *only* from the known IP address of the machine running Kamal or the network it resides in. This further restricts the attack surface.
    6.  **Implement SSH key rotation for the Kamal deployment key.**  Establish a process to periodically (e.g., quarterly) regenerate the `kamal_deploy_key` pair and update the public key on all target servers and the private key configuration in `deploy.yml`. This minimizes the impact if the key is ever compromised.

*   **Threats Mitigated:**
    *   **Brute-force SSH attacks targeting servers managed by Kamal (High Severity):** Disabling password authentication eliminates password guessing attacks.
    *   **Compromised passwords for SSH access used by Kamal (High Severity):**  Key-based authentication removes the reliance on passwords, preventing exploitation of weak or leaked passwords.
    *   **Unauthorized access to servers via SSH if Kamal's credentials are stolen (Medium Severity):** Key rotation limits the window of opportunity if the Kamal deployment key is compromised.
    *   **Lateral movement from compromised deployment machine (Medium Severity):** IP-based restrictions limit the sources that can SSH to the servers, reducing lateral movement possibilities.

*   **Impact:**
    *   **Brute-force SSH attacks:** Risk reduced to negligible as password authentication is disabled for Kamal's access.
    *   **Compromised passwords:** Risk eliminated for Kamal's SSH access as passwords are not used.
    *   **Stolen credentials:** Risk significantly reduced with key rotation, limiting the lifespan of a compromised key.
    *   **Lateral movement:** Risk reduced by limiting SSH access sources, making it harder to exploit a compromised deployment machine to access servers.

*   **Currently Implemented:** Partially implemented. Key-based authentication is likely used for initial server setup, but a *dedicated* Kamal deployment key, enforced password authentication disabling, and IP restrictions are not consistently applied across all environments where Kamal is used.

*   **Missing Implementation:**
    *   Creation and consistent use of a dedicated `kamal_deploy_key` specifically for Kamal deployments.
    *   Automated or documented process for distributing `kamal_deploy_key.pub` to all servers managed by Kamal.
    *   Enforcement and verification of `PasswordAuthentication no` on all production and staging servers managed by Kamal.
    *   Implementation of a documented and scheduled SSH key rotation process for the Kamal deployment key.
    *   Configuration of IP-based access restrictions for SSH in server firewalls and SSH configuration, specifically for Kamal's access.

## Mitigation Strategy: [Regularly Audit Kamal Configuration (`deploy.yml`) and Deployment Scripts](./mitigation_strategies/regularly_audit_kamal_configuration___deploy_yml___and_deployment_scripts.md)

### Mitigation Strategy: Regularly Audit Kamal Configuration (`deploy.yml`) and Deployment Scripts

*   **Description:**
    1.  **Establish a schedule for regular security audits of the `deploy.yml` file and any custom scripts used within Kamal deployments (e.g., `before_deploy`, `after_deploy`, custom healthcheck scripts).** Conduct these audits at least quarterly or whenever significant changes are made to the deployment process or `deploy.yml`.
    2.  **Systematically review `deploy.yml` for potential security misconfigurations specific to Kamal.**  Focus on:
        *   **Exposure of secrets or sensitive information within `deploy.yml`.** Ensure secrets are not hardcoded and are managed via secure methods (ideally external secret management, but at minimum environment variables).
        *   **Insecure container configurations defined in `deploy.yml` (within the `docker` section).** Check for containers running as root unnecessarily, exposed ports that should be internal, or missing resource limits.
        *   **Weak or default configurations in Kamal settings.** Review settings like `docker.args` or `traefik.options` for any insecure defaults or configurations.
        *   **Unnecessary privileges granted to containers or services through Kamal configurations.**  Ensure containers are running with the least necessary privileges.
    3.  **Thoroughly review custom deployment scripts used by Kamal for security vulnerabilities.**  Specifically examine scripts in `before_deploy`, `after_deploy`, and healthcheck paths for:
        *   **Command injection vulnerabilities.**  Ensure any user input or external data used in scripts is properly sanitized and escaped to prevent command injection.
        *   **Path traversal vulnerabilities.**  Verify that scripts correctly handle file paths and prevent access to unauthorized files or directories.
        *   **Insecure handling of environment variables or secrets within scripts.** Ensure scripts do not inadvertently log or expose secrets.
        *   **Unnecessary system commands or excessive privileges used in scripts.**  Minimize the use of system commands and ensure scripts run with the least necessary privileges.
    4.  **Implement code review processes specifically for *all* changes to `deploy.yml` and any deployment scripts used by Kamal.**  Ensure that security is a primary consideration during these code reviews.  Use a checklist of common Kamal security misconfigurations during reviews.
    5.  **Document the intended purpose and security implications of each configuration setting within `deploy.yml`.**  This improves understanding, maintainability, and facilitates more effective security audits in the future.  Use comments within `deploy.yml` to explain security-relevant choices.

*   **Threats Mitigated:**
    *   **Security misconfigurations in Kamal deployment leading to vulnerabilities (Medium Severity):** Regular audits identify and allow remediation of misconfigurations in `deploy.yml` and related scripts.
    *   **Vulnerabilities in custom deployment scripts used by Kamal (Medium Severity):** Code review and focused audits reduce the risk of vulnerabilities in custom scripts that could be exploited post-deployment.
    *   **Configuration drift and undocumented changes in Kamal setup leading to unforeseen security issues (Low to Medium Severity):** Regular audits and documentation ensure configurations are understood and reviewed, reducing the risk of unintended security consequences from configuration changes over time.

*   **Impact:**
    *   **Security misconfigurations:** Risk reduced by proactive identification and remediation of misconfigurations in Kamal's configuration.
    *   **Script vulnerabilities:** Risk reduced through code review and security-focused audits of deployment scripts used by Kamal.
    *   **Configuration drift:** Risk reduced by regular audits and documentation, maintaining a secure and understandable Kamal deployment setup over time.

*   **Currently Implemented:** Partially implemented. Code reviews are generally conducted for changes, but *specific* security audits focused on Kamal configurations and deployment scripts are not regularly scheduled or formalized. Documentation of `deploy.yml` settings from a security perspective is likely lacking.

*   **Missing Implementation:**
    *   Establishment of a *regular, scheduled* process for security audits of `deploy.yml` and custom Kamal deployment scripts.
    *   Development of a security audit checklist or guidelines specifically tailored for reviewing Kamal configurations and scripts.
    *   Formal documentation of the security implications of various settings within `deploy.yml`.
    *   Integration of *specific security considerations* into the code review process for changes to `deploy.yml` and deployment scripts, beyond general code quality.

