# Attack Surface Analysis for filosottile/mkcert

## Attack Surface: [Root CA Compromise](./attack_surfaces/root_ca_compromise.md)

*   **Description:** An attacker gains unauthorized access to the `mkcert` root CA private key (`rootCA-key.pem`).
    *   **How `mkcert` Contributes:** `mkcert` generates this root CA and its private key, which is the foundation of trust for all certificates it issues.
    *   **Example:** An attacker compromises a developer's laptop and finds the `rootCA-key.pem` file in the default `mkcert` directory.
    *   **Impact:**
        *   The attacker can issue trusted certificates for *any* domain.
        *   Enables Man-in-the-Middle (MITM) attacks on any machine trusting the compromised CA.
        *   Potential for code signing of malicious software (if the CA is misused for that purpose).
    *   **Risk Severity:** **Critical**
    *   **Mitigation Strategies:**
        *   **Restrict File Permissions:** Use the most restrictive file system permissions possible on the `rootCA-key.pem` file and its containing directory (read-only for the owning user, no access for others).
        *   **Avoid Sharing:** Never share the `rootCA-key.pem` file or the machine where it resides without extreme caution and sanitization.
        *   **Dedicated Development Machines:** Use separate, dedicated machines for development that are not used for accessing sensitive production data or systems.
        *   **Regular Audits:** Periodically review the trusted root CAs on development machines to detect any unexpected or unauthorized `mkcert` CAs.

## Attack Surface: [Accidental Production Deployment](./attack_surfaces/accidental_production_deployment.md)

*   **Description:** `mkcert`-generated certificates are mistakenly deployed to a production environment.
    *   **How `mkcert` Contributes:** `mkcert` makes it easy to generate certificates, increasing the risk of accidental misuse if proper procedures aren't followed.
    *   **Example:** A developer copies a configuration file from their development environment to the production server, inadvertently including the path to an `mkcert`-generated certificate.
    *   **Impact:**
        *   Browser security warnings for users (invalid certificate).
        *   Loss of user trust and potential abandonment of the application.
        *   Security monitoring alerts and potential service disruption.
        *   False sense of security among developers.
    *   **Risk Severity:** **High**
    *   **Mitigation Strategies:**
        *   **Strict Code Review:** Implement code reviews that specifically check for the presence of `mkcert` certificates or CA references in production configurations.
        *   **Automated Checks:** Use linters, build scripts, or CI/CD pipelines to automatically detect and prevent the deployment of `mkcert` certificates (e.g., by filename or content patterns).
        *   **Separate Configuration:** Maintain distinct configuration files for development and production, with no overlap.
        *   **Environment Variables:** Use environment variables to manage certificate paths, ensuring different values for development and production.
        *   **Infrastructure as Code (IaC):** Use IaC to enforce the use of valid, publicly trusted certificates in production and explicitly exclude `mkcert` configurations.

## Attack Surface: [Misuse for Non-Development Environments](./attack_surfaces/misuse_for_non-development_environments.md)

*   **Description:** `mkcert` is used in environments other than local development (e.g., staging, internal testing, or publicly accessible servers).
    *   **How `mkcert` Contributes:** The ease of use of `mkcert` might tempt developers to use it inappropriately.
    *   **Example:** A team uses `mkcert` to generate certificates for an internal testing server, installing the `mkcert` root CA on multiple team members' machines.
    *   **Impact:**
        *   Expands the attack surface: If the `mkcert` root CA is compromised, all machines trusting it are vulnerable.
        *   Creates a false sense of security, as the certificates are not truly secure for non-local use.
    *   **Risk Severity:** **High**
    *   **Mitigation Strategies:**
        *   **Clear Policy and Documentation:** Establish a clear policy that `mkcert` is *only* for local development and document this explicitly.
        *   **Developer Training:** Educate developers on the proper use of `mkcert` and the risks of misuse.
        *   **Use Appropriate Alternatives:** For staging or internal testing, use a proper internal CA or a service like Let's Encrypt (if publicly accessible).  Never use `mkcert` for these purposes.

