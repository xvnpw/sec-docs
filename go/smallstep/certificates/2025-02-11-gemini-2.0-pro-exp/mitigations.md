# Mitigation Strategies Analysis for smallstep/certificates

## Mitigation Strategy: [Short Certificate Lifetimes](./mitigation_strategies/short_certificate_lifetimes.md)

*   **Mitigation Strategy:** Issue end-entity certificates with short validity periods.

*   **Description:**
    1.  **Configuration:** When configuring `step-ca` (or using the `step` CLI for one-off certificates), set the default and maximum validity periods for issued certificates to a short duration.  This is typically done in the `ca.json` configuration file. Examples include hours, days, or a few weeks.  The exact duration depends on your operational needs and risk tolerance.
    2.  **Enforcement:**  Ensure that all certificate issuance requests adhere to these limits.  `step-ca` will enforce these limits based on its configuration.
    3. **Justification:** Short lifetimes minimize the impact of a compromised certificate. If an attacker obtains a certificate, it will only be valid for a limited time.

*   **Threats Mitigated:**
    *   **Long-Term Key Compromise (Severity: Medium):** Reduces the window of opportunity for an attacker to misuse a compromised certificate.
    *   **Certificate Misuse (Severity: High):** Limits the damage if a certificate is used for unauthorized purposes.

*   **Impact:**
    *   **Key Compromise:** Significantly reduces the time a compromised key can be used.
    *   **Misuse:** Limits the duration of any unauthorized certificate use.

*   **Currently Implemented:**
    *   `smallstep/certificates` is designed for short-lived certificates.  The `step ca init` and `step certificate create` commands, as well as the `ca.json` configuration, allow specifying validity periods.

*   **Missing Implementation:**
    *   This is often missed by not setting appropriately short default and maximum validity periods in the `step-ca` configuration.  Users might default to longer lifetimes (e.g., 1 year) for convenience, negating the benefits.

## Mitigation Strategy: [Certificate Revocation (CRL and OCSP)](./mitigation_strategies/certificate_revocation__crl_and_ocsp_.md)

*   **Mitigation Strategy:** Implement and enforce certificate revocation using CRLs and OCSP.

*   **Description:**
    1.  **CRL Generation:** Configure `step-ca` to automatically generate Certificate Revocation Lists (CRLs) at regular intervals.  This is typically done in the `ca.json` configuration.
    2.  **OCSP Responder:** Enable the OCSP responder functionality in `step-ca`.  This allows clients to query the real-time status of a certificate.
    3.  **Certificate Contents:** Ensure that issued certificates include the necessary information for revocation checks:
        *   **CRL Distribution Points (CDP):**  The certificate must include the URL(s) where the CRL can be downloaded.
        *   **Authority Information Access (AIA):**  The certificate must include the URL of the OCSP responder.
    4. **OCSP Must-Staple (Highly Recommended):** When issuing certificates, include the "OCSP Must-Staple" extension. This *requires* clients to receive a valid, stapled OCSP response; otherwise, they will reject the certificate. This is configured during certificate issuance.

*   **Threats Mitigated:**
    *   **Use of Revoked Certificates (Severity: High):**  Allows clients to determine if a certificate has been revoked before trusting it.
    *   **Compromised Certificate Misuse (Severity: High):**  Reduces the window of opportunity for an attacker to use a compromised certificate after it has been revoked.

*   **Impact:**
    *   **Revoked Certificates:** Prevents the acceptance of revoked certificates by properly configured clients.
    *   **Compromise Mitigation:** Reduces the impact of a certificate compromise by enabling timely revocation.

*   **Currently Implemented:**
    *   `smallstep/certificates` supports both CRLs and OCSP.  `step-ca` can generate CRLs and act as an OCSP responder.  The `step certificate create` command and `ca.json` configuration allow for including CDP and AIA extensions.  "OCSP Must-Staple" can be included.

*   **Missing Implementation:**
    *   "OCSP Must-Staple" is often *not* included in issued certificates, weakening the revocation mechanism.  The configuration for CRL generation and OCSP might be incomplete or incorrect.

## Mitigation Strategy: [Strong Cryptographic Algorithms (in Certificates)](./mitigation_strategies/strong_cryptographic_algorithms__in_certificates_.md)

*   **Mitigation Strategy:** Enforce the use of strong cryptographic algorithms *within* the certificates themselves.

*   **Description:**
    1.  **CA Configuration:** Configure `step-ca` to only accept and use strong algorithms for signing certificates.  This is typically done in the `ca.json` configuration.  Specify allowed key types (e.g., RSA, ECDSA), minimum key sizes (e.g., RSA 2048, RSA 4096, ECDSA P-256), and hashing algorithms (e.g., SHA-256, SHA-384).
    2.  **CSR Validation:**  `step-ca` should validate Certificate Signing Requests (CSRs) to ensure they use allowed algorithms and key sizes.  Reject CSRs that use weak algorithms.
    3. **Certificate Issuance:** When issuing certificates, `step-ca` will use the configured strong algorithms.

*   **Threats Mitigated:**
    *   **Cryptographic Attacks (Severity: High):**  Protects against attacks that exploit weaknesses in cryptographic algorithms used *within the certificate*.
    *   **Algorithm Downgrade Attacks (Severity: High):** Prevents attackers from forcing the use of weaker algorithms during certificate issuance.

*   **Impact:**
    *   **Cryptographic Attacks:** Significantly reduces the risk of successful attacks against the certificate's cryptographic integrity.
    *   **Downgrade Attacks:** Prevents downgrade attacks during certificate issuance.

*   **Currently Implemented:**
    *   `smallstep/certificates` supports modern cryptographic algorithms.  The `ca.json` configuration allows specifying allowed algorithms and key sizes.  `step-ca` validates CSRs.

*   **Missing Implementation:**
    *   The `ca.json` configuration might not be set up to explicitly *restrict* algorithms, allowing weaker algorithms to be used.  Administrators might not be aware of the need to configure these restrictions.

## Mitigation Strategy: [Subject Alternative Name (SAN) Validation](./mitigation_strategies/subject_alternative_name__san__validation.md)

*   **Mitigation Strategy:** Strictly validate and sanitize Subject Alternative Names (SANs) in certificate requests.

*   **Description:**
    1.  **Policy Enforcement:** Define clear policies for what SANs are allowed in certificates.  For example, you might restrict SANs to specific domains or subdomains, or require specific formats for email addresses.
    2.  **Provisioner Configuration:** Configure `step-ca` provisioners to enforce these SAN policies.  `smallstep`'s policy engine allows for fine-grained control over SANs.  You can use regular expressions or other rules to validate SANs.
    3.  **CSR Inspection:**  `step-ca` should inspect the SANs in incoming CSRs and reject any requests that violate the defined policies.
    4. **Wildcard Restrictions:** Be very careful with wildcard certificates (e.g., `*.example.com`).  Limit their use and scope as much as possible.  Consider using separate certificates for different subdomains instead of a single wildcard certificate.

*   **Threats Mitigated:**
    *   **Phishing Attacks (Severity: High):** Prevents attackers from obtaining certificates for domains they don't control, which could be used for phishing.
    *   **Man-in-the-Middle (MITM) Attacks (Severity: High):**  Reduces the risk of attackers obtaining certificates that could be used to intercept traffic.
    *   **Certificate Misuse (Severity: Medium):**  Prevents certificates from being used for unintended purposes.

*   **Impact:**
    *   **Phishing/MITM:** Significantly reduces the risk of successful phishing and MITM attacks that rely on fraudulently obtained certificates.
    *   **Misuse:**  Limits the potential for certificate misuse.

*   **Currently Implemented:**
    *   `smallstep/certificates` provides a powerful policy engine that allows for fine-grained control over SANs.  Provisioners can be configured with rules to validate SANs.

*   **Missing Implementation:**
    *   Often, SAN validation policies are not implemented or are too permissive.  This allows attackers to request certificates with SANs that they should not be allowed to have.  Wildcard certificates are often overused, increasing the risk.

## Mitigation Strategy: [Require Proof of Possession](./mitigation_strategies/require_proof_of_possession.md)

* **Mitigation Strategy:** Enforce proof of possession of the private key during certificate issuance.

* **Description:**
    1. **CSR Validation:** The Certificate Signing Request (CSR) contains a signature created using the private key corresponding to the public key in the CSR. `step-ca` *must* verify this signature before issuing a certificate. This proves that the requester possesses the private key.
    2. **Challenge-Response Mechanisms (For Automated Provisioning):** For automated provisioning methods (like ACME), use challenge-response mechanisms to verify that the requester controls the domain or identifier for which they are requesting a certificate. `step-ca` supports ACME challenges (HTTP-01, DNS-01, TLS-ALPN-01).

* **Threats Mitigated:**
    * **Unauthorized Certificate Issuance (Severity: High):** Prevents an attacker from obtaining a certificate for a key they don't control.
    * **Man-in-the-Middle (MITM) Attacks (Severity: High):** Makes it more difficult for an attacker to intercept a certificate request and substitute their own public key.

* **Impact:**
    * **Unauthorized Issuance:** Ensures that only the legitimate owner of the private key can obtain a certificate.
    * **MITM:** Reduces the risk of certain MITM attacks during certificate issuance.

* **Currently Implemented:**
    * `step-ca` automatically verifies the signature on CSRs. This is a fundamental part of the certificate issuance process.
    * `step-ca` supports ACME challenges for automated proof-of-possession.

* **Missing Implementation:**
    * This is generally *not* missing, as it's a core security requirement of the certificate issuance process. However, if custom, non-standard provisioning methods are used, developers must ensure they include a robust proof-of-possession mechanism.

