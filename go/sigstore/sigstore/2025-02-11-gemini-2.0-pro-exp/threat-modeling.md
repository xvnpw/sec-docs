# Threat Model Analysis for sigstore/sigstore

## Threat: [OIDC Identity Provider Account Takeover](./threats/oidc_identity_provider_account_takeover.md)

*   **Threat:** OIDC Identity Provider Account Takeover

    *   **Description:** An attacker gains control of a developer's account at an OIDC provider (e.g., Google, GitHub, Microsoft) through phishing, credential stuffing, or session hijacking. The attacker then uses this compromised identity to request signing certificates from Fulcio.

    *   **Impact:** The attacker can sign malicious artifacts using the compromised developer's identity, making them appear legitimate. This bypasses the intended identity checks.

    *   **Affected Component:** Fulcio (certificate issuance), Cosign (verification - relies on the validity of the certificate).

    *   **Risk Severity:** High

    *   **Mitigation Strategies:**
        *   **Strong Authentication:** Enforce strong, unique passwords and mandatory multi-factor authentication (MFA) on all OIDC provider accounts used for signing. Prefer phishing-resistant MFA methods like hardware security keys.
        *   **Account Monitoring:** Regularly monitor OIDC provider account activity for suspicious logins or changes.
        *   **Principle of Least Privilege:** Grant developers only the necessary permissions within the OIDC provider and the application.
        *   **Session Management:** Implement short session timeouts and robust session invalidation mechanisms.
        *   **Education:** Train developers on phishing awareness and secure credential handling.

## Threat: [Fulcio Root CA Key Compromise](./threats/fulcio_root_ca_key_compromise.md)

*   **Threat:** Fulcio Root CA Key Compromise

    *   **Description:** An attacker gains unauthorized access to the private key(s) associated with the Fulcio Root Certificate Authority. This could involve physical access to an HSM, a sophisticated software exploit, or insider threat.

    *   **Impact:** Catastrophic. The attacker can issue valid signing certificates for *any* identity, completely undermining the trust model of Sigstore.  All artifacts signed with certificates issued by the compromised CA are suspect.

    *   **Affected Component:** Fulcio (Root CA).

    *   **Risk Severity:** Critical

    *   **Mitigation Strategies:** (Primarily the responsibility of the Sigstore *operators* for the public good instance, but crucial for private instances):
        *   **Hardware Security Modules (HSMs):** Store root keys in FIPS 140-2 Level 3 (or higher) certified HSMs.
        *   **Offline Storage:** Keep the root CA offline and physically secured.
        *   **Key Sharding/Multi-Person Control:** Require multiple trusted individuals to cooperate to perform any operation with the root key.
        *   **Strict Access Control:** Implement rigorous access control policies and auditing for any interaction with the root CA.
        *   **Regular Audits:** Conduct regular security audits of the root CA infrastructure and procedures.
        *   **Incident Response Plan:** Have a well-defined and tested incident response plan for root CA compromise.

## Threat: [Rekor Transparency Log Tampering](./threats/rekor_transparency_log_tampering.md)

*   **Threat:** Rekor Transparency Log Tampering

    *   **Description:** An attacker attempts to modify or delete entries in the Rekor transparency log.  This could involve exploiting a vulnerability in Rekor, gaining unauthorized access to the underlying storage, or a denial-of-service attack followed by data manipulation.

    *   **Impact:** Loss of auditability and integrity of the signing record.  The attacker could potentially hide evidence of malicious signatures or make it difficult to verify the history of an artifact.

    *   **Affected Component:** Rekor (transparency log).

    *   **Risk Severity:** High

    *   **Mitigation Strategies:**
        *   **Merkle Tree Integrity:** Rekor's use of a Merkle Tree makes unauthorized modification detectable. This is inherent to Rekor's design.
        *   **Data Replication:** Use multiple, geographically distributed Rekor instances for redundancy and resilience.
        *   **Access Control:** Implement strict access control and authentication for Rekor's API and storage.
        *   **Monitoring:** Continuously monitor Rekor's integrity and availability.  Alert on any inconsistencies or unexpected behavior.
        *   **Regular Backups:** Maintain secure backups of the Rekor data.
        *   **Immutable Storage:** Consider using immutable storage solutions to prevent data modification or deletion.

## Threat: [Cosign Verification Policy Bypass](./threats/cosign_verification_policy_bypass.md)

*   **Threat:** Cosign Verification Policy Bypass

    *   **Description:** An attacker deploys a malicious artifact without performing proper signature verification, or they manipulate the verification policy to accept an invalid signature. This could involve exploiting a vulnerability in the deployment pipeline, disabling verification checks, or modifying the policy configuration.

    *   **Impact:** Malicious artifacts are deployed and executed, bypassing the security benefits of Sigstore.

    *   **Affected Component:** Cosign (verification process), Deployment Pipeline.

    *   **Risk Severity:** High

    *   **Mitigation Strategies:**
        *   **Mandatory Verification:** Integrate signature verification into the deployment pipeline and make it a *mandatory* step.
        *   **Policy-as-Code:** Define verification policies as code and manage them in a version control system.
        *   **Admission Controllers:** Use admission controllers (e.g., in Kubernetes) to enforce signature verification before deploying containers.
        *   **Least Privilege:** Grant deployment tools only the necessary permissions.
        *   **Auditing:** Regularly audit deployment processes and configurations to ensure verification is not bypassed.
        *   **Immutable Artifacts:** Use immutable artifact identifiers (e.g., content-addressable hashes) to prevent substitution after verification.

## Threat: [Malicious Dependency in Sigstore Tooling](./threats/malicious_dependency_in_sigstore_tooling.md)

*   **Threat:** Malicious Dependency in Sigstore Tooling

    *   **Description:** An attacker compromises a dependency used by a Sigstore component (e.g., Cosign, Fulcio, Rekor). This compromised dependency could contain malicious code that subverts the signing or verification process.

    *   **Impact:** The attacker could potentially gain control of the signing process, forge signatures, or bypass verification checks. The specific impact depends on the compromised dependency and its role.

    *   **Affected Component:** Any Sigstore component (Cosign, Fulcio, Rekor, etc.) that uses the compromised dependency.

    *   **Risk Severity:** High

    *   **Mitigation Strategies:**
        *   **Software Composition Analysis (SCA):** Use SCA tools to identify and track all dependencies.
        *   **Dependency Pinning:** Pin dependencies to specific, known-good versions.
        *   **Vulnerability Scanning:** Regularly scan dependencies for known vulnerabilities.
        *   **Dependency Updates:** Keep dependencies up-to-date to address security vulnerabilities.
        *   **Software Bill of Materials (SBOM):** Generate and maintain an SBOM to track all software components.
        *   **Vendor Security Assessments:** Evaluate the security practices of dependency providers.

## Threat: [Misconfigured OIDC Trust in Cosign/Client](./threats/misconfigured_oidc_trust_in_cosignclient.md)

*   **Threat:** Misconfigured OIDC Trust in Cosign/Client

    *   **Description:** The Sigstore client (e.g., Cosign) is configured to trust an unintended or malicious OIDC provider. This could be due to a configuration error, a compromised configuration file, or a social engineering attack.

    *   **Impact:** The client accepts signatures from unauthorized identities, potentially allowing malicious artifacts to be deployed.

    *   **Affected Component:** Cosign (verification), Client Configuration.

    *   **Risk Severity:** High

    *   **Mitigation Strategies:**
        *   **Configuration Validation:** Carefully review and validate all OIDC configuration settings.
        *   **Infrastructure-as-Code:** Manage client configuration using infrastructure-as-code to ensure consistency and prevent manual errors.
        *   **Least Privilege:** Configure the client to trust only the necessary OIDC providers.
        *   **Regular Audits:** Regularly audit client configurations.
        *   **Documentation:** Clearly document the expected OIDC configuration.

## Threat: [TUF Repository Rollback Attack](./threats/tuf_repository_rollback_attack.md)

* **Threat:** TUF Repository Rollback Attack

    * **Description:** An attacker reverts the TUF metadata to an older, potentially vulnerable version. This could allow them to serve outdated or compromised keys to clients.

    * **Impact:** Clients may trust outdated or compromised keys, leading to the acceptance of invalid signatures or the use of vulnerable Sigstore components.

    * **Affected Component:** TUF Repository, Sigstore Clients (relying on TUF for root of trust).

    * **Risk Severity:** High

    * **Mitigation Strategies:**
        * **TUF Design:** TUF's inherent design, with versioning and threshold signatures, mitigates rollback attacks. This is a core feature of TUF.
        * **Client-Side Verification:** Sigstore clients *must* verify the version numbers of TUF metadata to ensure they are not being rolled back. This is a client-side responsibility.
        * **Monitoring:** Monitor the TUF repository for unexpected changes or rollbacks.

