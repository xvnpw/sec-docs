# Attack Surface Analysis for ansible/ansible

## Attack Surface: [Compromised Control Node](./attack_surfaces/compromised_control_node.md)

*   **Description:**  The machine running Ansible (the control node) is compromised, giving the attacker Ansible's access to all managed hosts.
    *   **How Ansible Contributes:** Ansible's centralized control model creates a single, high-value target.  The control node holds the credentials (SSH keys, etc.) needed to manage all connected systems. This is *inherent* to Ansible's design.
    *   **Example:** An attacker gains access to the control node via a phishing attack and uses the stored SSH keys to connect to all managed servers as root.
    *   **Impact:** Complete compromise of all systems managed by Ansible. Data breaches, system destruction, lateral movement.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Dedicated, Hardened Control Node:** Use a dedicated, minimal system (physical or virtual) *solely* for Ansible. Avoid using it for other tasks.
        *   **Multi-Factor Authentication (MFA):** Enforce MFA for *all* access to the control node.
        *   **Least Privilege (Control Node User):** The user running Ansible on the control node should have minimal permissions *on the control node itself*.
        *   **Secure Key Management:** Use HSMs, encrypted key storage, or a secrets management solution for SSH keys.  Never store keys in easily accessible locations.
        *   **Endpoint Detection and Response (EDR):** Deploy EDR on the control node.
        *   **Regular Patching:** Keep the control node's OS and all software (including Ansible) fully patched.
        *   **Auditing:** Regularly audit all activity on the control node.

## Attack Surface: [Malicious Playbooks/Roles/Modules](./attack_surfaces/malicious_playbooksrolesmodules.md)

*   **Description:**  An attacker injects malicious code into Ansible playbooks, roles, or modules, which is then executed on managed hosts.
    *   **How Ansible Contributes:** Ansible's core function is to execute code on remote systems.  This inherent capability is abused if the code is malicious.  The use of external roles/modules (e.g., from Ansible Galaxy) increases this risk.
    *   **Example:** An attacker compromises a popular Ansible role on Ansible Galaxy and adds a backdoor. Users who download and use this role unknowingly install the backdoor.
    *   **Impact:**  Compromise of managed hosts, data breaches, system destruction, persistent backdoors.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Strict Code Review:** Implement a rigorous code review process for *all* Ansible code, including internally developed and externally sourced content.
        *   **Vetting Third-Party Content:** *Thoroughly* vet all third-party roles/modules before use. Check author reputation, review code, look for red flags.
        *   **Version Control (Git):** Track all changes to Ansible code and facilitate rollbacks.
        *   **Private Repository:** Maintain a private repository for trusted roles and modules.
        *   **Checksum Verification:** Verify the integrity of downloaded roles/modules using checksums or digital signatures.
        *   **Regular Audits:** Conduct regular audits of playbooks and roles for unauthorized modifications.

## Attack Surface: [Compromised Ansible Vault](./attack_surfaces/compromised_ansible_vault.md)

*   **Description:**  An attacker gains access to the Ansible Vault password, decrypting sensitive data.
    *   **How Ansible Contributes:** Ansible Vault is *specifically* designed to store secrets.  Its security is entirely dependent on the Vault password's secrecy. This is a direct Ansible feature.
    *   **Example:** An attacker uses a weak Vault password or obtains it via social engineering, decrypting API keys and database credentials.
    *   **Impact:**  Exposure of sensitive data (passwords, API keys, etc.), leading to compromises of other systems.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Strong, Unique Vault Password:** Use a strong, unique, randomly generated password.
        *   **Secure Password Storage:** Store the Vault password in a password manager or HSM. *Never* in plain text.
        *   **Secrets Management Solution:** Consider using a dedicated secrets management solution (HashiCorp Vault, AWS Secrets Manager) *instead of* or *with* Ansible Vault.
        *   **Limit Vault Usage:** Only store *truly* sensitive data in the vault.
        * **Regular Password Rotation:** Rotate the Ansible Vault password periodically.

## Attack Surface: [Privilege Escalation via Ansible](./attack_surfaces/privilege_escalation_via_ansible.md)

*   **Description:** An attacker leverages Ansible's `become` functionality (e.g., `sudo`) to gain elevated privileges on a managed host.
    *   **How Ansible Contributes:** Ansible often *needs* elevated privileges to perform configuration tasks.  The `become` feature is a *direct* Ansible mechanism for achieving this. Misconfigurations can lead to unintended escalation.
    *   **Example:** An attacker compromises a low-privileged account and exploits a vulnerability in an Ansible module run with `become: yes` to gain root.
    *   **Impact:**  An attacker with limited access gains full control of the system.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Use `become` Sparingly:** Only use `become` when *absolutely* necessary.
        *   **Restrict `become` Methods:** Carefully configure `become_method` and `become_user` to limit the scope.
        *   **Least Privilege (Managed Hosts):** The Ansible user on managed hosts should have minimal permissions.
        *   **Sudoers Configuration:** If using `sudo`, carefully configure the `sudoers` file to restrict Ansible's elevated commands.
        *   **Auditing:** Regularly audit `become` configurations and usage.

## Attack Surface: [Man-in-the-Middle (MITM) Attacks (with Ansible Misconfiguration)](./attack_surfaces/man-in-the-middle__mitm__attacks__with_ansible_misconfiguration_.md)

*   **Description:**  An attacker intercepts and modifies communication between the Ansible control node and managed hosts.
    *   **How Ansible Contributes:** While Ansible uses SSH by default, *disabling host key verification* (a direct Ansible configuration option) makes MITM attacks trivial. This is a direct consequence of misusing an Ansible feature.
    *   **Example:** An attacker uses ARP spoofing, and because `host_key_checking = False` is set in `ansible.cfg`, the attack succeeds, injecting malicious commands.
    *   **Impact:** Compromise of managed hosts, data theft, configuration modification.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
      *   **SSH Host Key Verification:**  Ensure that SSH host key verification is *enabled* (this is the default, so do *not* disable it).  Manage host keys properly.
      * **Secure Network:** Use a secure network (VPN or physically secure network) for Ansible communication.
      * **Network Segmentation:** Limit the impact of a potential MITM attack.
      * **Network Monitoring:** Monitor for suspicious activity (ARP spoofing, DNS spoofing).

