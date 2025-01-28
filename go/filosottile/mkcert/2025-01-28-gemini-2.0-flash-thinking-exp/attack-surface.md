# Attack Surface Analysis for filosottile/mkcert

## Attack Surface: [Compromise of Local CA Private Key](./attack_surfaces/compromise_of_local_ca_private_key.md)

*   **Description:**  The private key of the local Certificate Authority (CA) created by `mkcert` is compromised.
*   **How mkcert contributes to the attack surface:** `mkcert`'s primary function is to generate and store this local CA private key on the developer's machine, making it a central point of risk.
*   **Example:** Malware on a developer's laptop scans for and exfiltrates the `mkcert` CA private key. An attacker uses this key to issue a valid certificate for `evil.example.com`. When the developer visits `https://evil.example.com`, their browser trusts the certificate, enabling a Man-in-the-Middle (MITM) attack.
*   **Impact:**  Full compromise of locally trusted certificates, enabling MITM attacks, phishing, and impersonation of any website on systems trusting the compromised CA.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Secure Developer Machines:** Implement robust endpoint security measures like EDR, anti-malware, and host-based intrusion prevention systems (HIPS).
    *   **Principle of Least Privilege:** Restrict access to developer machines and the CA private key storage location to authorized personnel.
    *   **Secure Key Storage:** Utilize operating system-level security features to protect the CA private key file (e.g., file system permissions, encryption).
    *   **Regular Security Audits:** Conduct periodic security audits of developer machines and development environments.
    *   **Educate Developers:** Train developers on the importance of private key protection.

## Attack Surface: [Supply Chain Attacks Targeting mkcert Binaries](./attack_surfaces/supply_chain_attacks_targeting_mkcert_binaries.md)

*   **Description:** The `mkcert` binaries or installation process are compromised, leading to the distribution of a malicious version.
*   **How mkcert contributes to the attack surface:** Developers rely on downloading and installing `mkcert` binaries. Compromise of the distribution source directly impacts the security of `mkcert` installations.
*   **Example:** An attacker compromises the GitHub repository or a package manager distribution channel for `mkcert`. They replace the legitimate binary with a backdoored version. Developers unknowingly install this malicious `mkcert`. The backdoored version could steal the CA private key, install a rogue CA, or execute other malicious code.
*   **Impact:**  Compromise of developer machines, potential data breaches, and introduction of vulnerabilities into development environments through a trusted tool.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Verify Download Integrity:** Always verify the SHA256 checksum of downloaded `mkcert` binaries against the official checksum provided on the `mkcert` GitHub releases page.
    *   **Use Reputable Installation Methods:** Install `mkcert` from trusted sources like official GitHub releases or well-established package managers.
    *   **Software Composition Analysis (SCA) for Source Builds:** If building `mkcert` from source, use SCA tools to analyze dependencies for vulnerabilities.
    *   **Regularly Update mkcert:** Keep `mkcert` updated to the latest version for security patches.

