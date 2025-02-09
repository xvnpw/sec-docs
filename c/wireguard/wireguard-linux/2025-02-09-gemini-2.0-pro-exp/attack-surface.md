# Attack Surface Analysis for wireguard/wireguard-linux

## Attack Surface: [1. Kernel Module Exploitation](./attack_surfaces/1__kernel_module_exploitation.md)

*   *Description:* Vulnerabilities within the `wireguard-linux` kernel module code itself (e.g., buffer overflows, use-after-free, race conditions).
    *   *How `wireguard-linux` Contributes:* The kernel module is the core component; any flaws in its code directly expose the system.  This is a *direct* involvement.
    *   *Example:* A buffer overflow in the packet processing logic could allow an attacker to inject arbitrary code into the kernel.
    *   *Impact:*        
        *   Denial of Service (DoS)
        *   Privilege Escalation (potentially to root)
        *   Information Disclosure (kernel memory, keys)
    *   *Risk Severity:* **Critical**
    *   *Mitigation Strategies:*
        *   **Keep Updated:** Always run the latest stable kernel and WireGuard module versions.
        *   **Kernel Hardening:** Employ kernel hardening techniques (SELinux, AppArmor, etc.).
        *   **Code Auditing:** (For developers) Conduct thorough code reviews and security audits of the WireGuard codebase.
        *   **Fuzzing:** (For developers) Utilize fuzzing techniques to identify potential vulnerabilities.
        *   **Userspace Implementation:** Consider a userspace implementation (e.g., `wireguard-go`) if kernel-level risks are unacceptable (trade-off: performance).

## Attack Surface: [2. Netlink Interface Manipulation](./attack_surfaces/2__netlink_interface_manipulation.md)

*   *Description:* Unauthorized access or manipulation of the Netlink interface used to configure WireGuard.
    *   *How `wireguard-linux` Contributes:* `wireguard-linux` *directly* uses the Netlink interface for all configuration and control.  This is its primary management interface.
    *   *Example:* A compromised process with `CAP_NET_ADMIN` could add a malicious peer to the WireGuard configuration, granting unauthorized access.
    *   *Impact:*
        *   Configuration Modification (unauthorized peers, altered routes)
        *   Information Disclosure (peer keys, allowed IPs)
        *   Denial of Service (disrupting connectivity)
    *   *Risk Severity:* **High**
    *   *Mitigation Strategies:*
        *   **Capability Restriction:** Strictly limit the use of the `CAP_NET_ADMIN` capability.
        *   **Dedicated User:** Run WireGuard management tools with a dedicated, non-root user account.
        *   **Monitoring:** Monitor Netlink messages for suspicious activity.
        *   **Access Control Lists (ACLs):** If possible, implement ACLs to restrict which processes can interact with the WireGuard Netlink interface.

## Attack Surface: [3. Private Key Compromise](./attack_surfaces/3__private_key_compromise.md)

*   *Description:* An attacker gains access to a WireGuard private key.
    *   *How `wireguard-linux` Contributes:* While `wireguard-linux` itself doesn't *store* the keys, its entire security model *depends* on the confidentiality of these keys. This is an indirect, but *critical* dependency. The *use* of the keys is directly within `wireguard-linux`.
    *   *Example:* An attacker compromises a server and steals the WireGuard private key file.
    *   *Impact:*
        *   Impersonation of a legitimate peer.
        *   Decryption of past and future traffic (depending on key exchange).
    *   *Risk Severity:* **Critical**
    *   *Mitigation Strategies:*
        *   **Secure Storage:** Store private keys securely, using strong password protection and/or hardware security modules (HSMs).
        *   **Access Control:** Implement strict access controls to prevent unauthorized access to key files.
        *   **Key Rotation:** Regularly rotate private keys.
        *   **Least Privilege:** Ensure the process using the key has the minimum necessary privileges.

