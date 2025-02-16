# Attack Surface Analysis for dani-garcia/vaultwarden

## Attack Surface: [Compromised Master Password](./attack_surfaces/compromised_master_password.md)

*   **Description:** An attacker gains access to the user's master password, granting them access to all stored credentials.
    *   **Vaultwarden Contribution:** Vaultwarden centralizes all credentials behind a single master password, making it a high-value target. This is *the* core risk of using a password manager.
    *   **Example:** An attacker uses a phishing attack mimicking the Vaultwarden login page to steal a user's master password.
    *   **Impact:** Complete compromise of all accounts and data stored within Vaultwarden.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **User Education:** Train users on strong password practices, phishing awareness (specifically targeting Vaultwarden), and the critical importance of the master password.
        *   **Strong Password Enforcement:** Enforce strong master password policies (length, complexity, and disallow reuse) within Vaultwarden's configuration.
        *   **Two-Factor Authentication (2FA):** *Mandate* 2FA for all users. Educate users on secure 2FA methods (prioritize hardware tokens or TOTP over SMS).
        *   **Brute-Force Protection:** Configure the KDF (Argon2id) with high iteration counts, memory usage, and parallelism. Monitor for failed login attempts and implement strict account lockout policies (with appropriate safeguards against denial-of-service).
        *   **Client-Side Security:** Encourage users to use secure, up-to-date devices and avoid accessing Vaultwarden from public or untrusted computers/networks. Promote the use of security software (antivirus, firewall).

## Attack Surface: [Compromised Organization Administrator (Organizations Feature)](./attack_surfaces/compromised_organization_administrator__organizations_feature_.md)

*   **Description:** An attacker gains control of an organization administrator account within Vaultwarden.
    *   **Vaultwarden Contribution:** Vaultwarden's *organization feature* allows sharing credentials, and administrators have broad access to manage these shared credentials and users. This is a Vaultwarden-specific feature.
    *   **Example:** An attacker phishes the credentials of an organization administrator or exploits a vulnerability in their Vaultwarden account (e.g., weak 2FA, reused password).
    *   **Impact:** The attacker gains access to all credentials shared within the organization, potentially affecting multiple users and systems.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Strict Access Controls:** Implement the principle of least privilege for organization administrators. Grant *only* the absolutely necessary permissions.
        *   **Mandatory, Strong 2FA:** Enforce strong 2FA (hardware token or TOTP) for *all* organization members, *especially* administrators.
        *   **Regular Audits of Organization Permissions:** Regularly review and audit organization permissions to ensure they are appropriate and no excessive privileges exist.
        *   **User Education:** Train organization members (and especially administrators) on security best practices, phishing awareness, and the risks associated with shared credentials.
        *   **Separation of Duties:** Consider separating administrative duties among multiple users to reduce the impact of a single compromised account.  Avoid having a single "super-admin."

## Attack Surface: [API Key Compromise](./attack_surfaces/api_key_compromise.md)

*   **Description:** An attacker gains access to a Vaultwarden API key.
    *   **Vaultwarden Contribution:** Vaultwarden provides an *API* for programmatic access, and API keys are used for authentication. This is a feature specific to Vaultwarden (and other applications with APIs).
    *   **Example:** An attacker finds an API key exposed in a public code repository, through a misconfigured application, or by compromising a developer's machine.
    *   **Impact:** The attacker can use the API key to access and potentially modify data within Vaultwarden, depending on the key's permissions. This could lead to data breaches, unauthorized modifications, or denial of service.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Secure API Key Storage:** *Never* store API keys in source code or publicly accessible locations. Use environment variables, a secure secrets management system (e.g., HashiCorp Vault, AWS Secrets Manager), or the operating system's secure credential store.
        *   **Least Privilege for API Keys:** Create API keys with the *minimum* necessary permissions. Avoid granting overly broad access.
        *   **API Key Rotation:** Regularly rotate API keys to limit the impact of a potential compromise. Implement automated key rotation where possible.
        *   **API Rate Limiting:** Implement rate limiting to prevent abuse of the API and mitigate denial-of-service attacks.
        *   **Monitor API Usage:** Actively monitor API usage for suspicious activity, unusual patterns, or unauthorized access attempts.

