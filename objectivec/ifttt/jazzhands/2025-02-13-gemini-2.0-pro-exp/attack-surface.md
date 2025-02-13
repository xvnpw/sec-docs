# Attack Surface Analysis for ifttt/jazzhands

## Attack Surface: [Compromised `jazzhands` Configuration File](./attack_surfaces/compromised__jazzhands__configuration_file.md)

*   **Description:** The `jazzhands` configuration file, containing sensitive information for role assumption, is accessed by an unauthorized party.
    *   **How `jazzhands` Contributes:** `jazzhands` *requires* and directly uses this configuration file for all its operations.  The file's contents are essential to `jazzhands`' functionality.
    *   **Example:** An attacker gains access to a developer's laptop and copies the `~/.config/jazzhands.json` file, which contains role ARNs and MFA device serials.
    *   **Impact:** The attacker can directly use the stolen configuration *with `jazzhands`* to assume the configured roles and gain unauthorized access to AWS resources. This could lead to data breaches, service disruption, or complete account compromise.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **File Permissions:**  Strictly enforce file system permissions (e.g., `chmod 600 ~/.config/jazzhands.json`). Only the user running `jazzhands` should have access.
        *   **Environment Variables:** Store highly sensitive values (MFA device serials) in environment variables, *not* directly in the file.
        *   **No Version Control:**  Ensure the configuration file is *never* committed to version control (e.g., `.gitignore`).
        *   **Secure Storage:**  Avoid storing the file in shared locations, cloud storage without strong access controls, or easily accessible backups.
        *   **Regular Audits:**  Periodically review the configuration file for accuracy and to remove unnecessary entries.
        *   **Workstation Security:** Implement robust security on developer workstations (full-disk encryption, strong passwords, EDR).

## Attack Surface: [Overly Permissive IAM Roles](./attack_surfaces/overly_permissive_iam_roles.md)

*   **Description:** The IAM roles *configured for use within `jazzhands`* grant excessive AWS permissions.
    *   **How `jazzhands` Contributes:** `jazzhands` is the *direct mechanism* used to assume these overly permissive roles. The attack surface is the combination of `jazzhands` *and* the poorly configured roles.
    *   **Example:** A role configured in the `jazzhands` configuration file grants `s3:*` (full access to all S3 buckets) when the application only needs read access to a single, specific bucket.
    *   **Impact:** If `jazzhands` is compromised (e.g., configuration file leak), the attacker gains the excessive permissions of the role, leading to potentially widespread data access or modification. The impact is amplified by the overly permissive role.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Principle of Least Privilege:**  Grant *only* the minimum necessary permissions to each role defined *for use with `jazzhands`*. Use specific resource ARNs and actions.
        *   **IAM Conditions:**  Use IAM condition keys (e.g., `aws:SourceIp`, `aws:MultiFactorAuthPresent`) within the role definition to further restrict access.
        *   **Regular Role Reviews:**  Conduct periodic reviews of all IAM roles *referenced in the `jazzhands` configuration*.
        *   **AWS Organizations & SCPs:** Use SCPs to enforce organization-wide restrictions, preventing the creation of overly permissive roles that `jazzhands` could then assume.
        *   **Infrastructure as Code (IaC):** Define IAM roles using IaC to ensure consistency and facilitate auditing of roles used by `jazzhands`.

## Attack Surface: [MFA Bypass or Weak MFA](./attack_surfaces/mfa_bypass_or_weak_mfa.md)

*   **Description:** MFA is not enforced, is misconfigured *within the `jazzhands` context*, or uses a weak MFA method, allowing an attacker to bypass it during `jazzhands` operation.
    *   **How `jazzhands` Contributes:** `jazzhands` *directly handles* the MFA process during role assumption.  A misconfiguration *in `jazzhands`* or a weakness in the MFA method used *with `jazzhands`* creates the vulnerability.
    *   **Example:** `jazzhands` is configured (perhaps through an environment variable or a setting in the configuration file) to allow role assumption without MFA under certain conditions, or it's configured to use SMS-based MFA, which is vulnerable.
    *   **Impact:** An attacker can assume roles *using `jazzhands`* without a valid MFA code, significantly reducing security.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Mandatory MFA:**  Enforce MFA for *all* role assumptions *through `jazzhands`*.  Ensure there are no configuration options or workarounds that disable MFA.
        *   **Strong MFA Methods:**  Prefer hardware-based MFA tokens (e.g., YubiKey) over SMS or easily phishable TOTP apps *when configuring `jazzhands`*.
        *   **CloudTrail Monitoring:**  Monitor CloudTrail for failed MFA attempts and successful role assumptions *initiated by `jazzhands`* without MFA.
        *   **Session Management:** Implement short session durations and ensure sessions initiated *via `jazzhands`* are properly invalidated.

## Attack Surface: [Compromised Bootstrapping Credentials](./attack_surfaces/compromised_bootstrapping_credentials.md)

*   **Description:** The initial AWS credentials used to authenticate with `jazzhands` are compromised.
    *   **How `jazzhands` Contributes:** `jazzhands` *requires* these initial credentials to function and perform any actions.
    *   **Example:** An attacker obtains the long-term access key ID and secret access key used by a developer to initialize `jazzhands`.
    *   **Impact:** The attacker can use the compromised credentials to perform any actions allowed by those credentials, *including using `jazzhands` to assume other roles*.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Short-Lived Credentials:** Use temporary credentials (e.g., from AWS STS) for the initial `jazzhands` authentication instead of long-term access keys.
        *   **IAM Instance Profiles:** If running `jazzhands` on an EC2 instance, use an IAM instance profile to avoid managing explicit credentials.
        *   **Credential Rotation:** Regularly rotate the bootstrapping credentials, especially if long-term keys are unavoidable.
        *   **Access Control & Monitoring:** Implement strong access controls and monitoring for the bootstrapping credentials. Limit their use to only the necessary systems and users.
        *   **Secrets Management:** Use a secrets management service (e.g., AWS Secrets Manager, HashiCorp Vault) to securely store and manage the bootstrapping credentials.

