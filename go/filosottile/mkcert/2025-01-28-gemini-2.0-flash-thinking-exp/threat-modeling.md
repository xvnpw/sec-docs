# Threat Model Analysis for filosottile/mkcert

## Threat: [Local CA Private Key Compromise](./threats/local_ca_private_key_compromise.md)

* **Description:** An attacker gains unauthorized access to a developer's machine and extracts the private key of the local Certificate Authority (CA) created by `mkcert`. This could be done through malware, exploiting vulnerabilities, or social engineering.
* **Impact:** The attacker can issue trusted certificates for any domain, impersonating legitimate websites and services. This enables Man-in-the-Middle (MITM) attacks, allowing them to intercept sensitive data, inject malicious content, or gain unauthorized access to systems that trust the compromised local CA. The impact can extend beyond the development environment if the attacker targets other systems trusting the same CA.
* **Affected mkcert component:**  `mkcert` generated Local CA (private key stored on developer machine).
* **Risk Severity:** High
* **Mitigation Strategies:**
    * Secure developer workstations with strong passwords and multi-factor authentication.
    * Implement full disk encryption on developer machines.
    * Keep operating systems and software up-to-date with security patches.
    * Use Endpoint Detection and Response (EDR) solutions to detect and prevent malicious activities.
    * Regularly review and enforce workstation security policies.

## Threat: [Misuse of `mkcert` Certificates in Production](./threats/misuse_of__mkcert__certificates_in_production.md)

* **Description:** Developers mistakenly deploy or rely on `mkcert`-generated certificates in staging or production environments. This could be due to lack of awareness, oversight in deployment processes, or accidental configuration errors.
* **Impact:**  Users accessing the application in non-development environments will encounter browser security warnings or connection failures because `mkcert` certificates are not trusted by default outside of environments where the local CA is installed. This damages user trust, disrupts service availability, and indicates a serious security misconfiguration.
* **Affected mkcert component:** Misuse of `mkcert` generated certificates in incorrect environments (not a component of `mkcert` itself, but a consequence of its use).
* **Risk Severity:** High
* **Mitigation Strategies:**
    * Clearly document and communicate that `mkcert` is strictly for development use only.
    * Implement automated checks in deployment pipelines to prevent the use of `mkcert`-generated certificates in non-development environments.
    * Enforce the use of certificates from publicly trusted Certificate Authorities for staging and production environments.
    * Conduct regular security audits of environment configurations to detect and rectify misconfigurations.

