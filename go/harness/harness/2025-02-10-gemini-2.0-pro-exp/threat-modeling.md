# Threat Model Analysis for harness/harness

## Threat: [Compromised Harness API Key/Secret](./threats/compromised_harness_api_keysecret.md)

*   **Description:** An attacker obtains a valid Harness API key or secret through phishing, code repository leaks, compromised developer machines, or insecure storage. The attacker uses this key to interact with the Harness API, impersonating a legitimate user or service account.
*   **Impact:** The attacker can trigger deployments, modify configurations, access sensitive data stored within Harness (including other secrets), and potentially disrupt services. They could deploy malicious code, exfiltrate data, or sabotage deployments.
*   **Affected Component:** Harness API, Secrets Management, potentially all modules interacting with the API.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   Use Harness's built-in secrets management or integrate with a secure external secrets manager (Vault, AWS Secrets Manager, etc.).
    *   Implement strict secret rotation policies.
    *   Enforce least privilege for API keys and service accounts.
    *   Monitor Harness audit logs for unusual API key usage.
    *   *Never* store secrets in code or configuration files. Use environment variables or a secrets manager.
    *   Implement and enforce multi-factor authentication (MFA) for all Harness user accounts.
    *   Use short-lived credentials whenever possible.

## Threat: [Unauthorized Pipeline Modification](./threats/unauthorized_pipeline_modification.md)

*   **Description:** An attacker gains access to the Harness UI or API and modifies existing deployment pipelines or workflows.  They might add malicious steps, change deployment targets, disable security checks, or alter configurations.
*   **Impact:** The attacker can deploy malicious code, compromise the application, disrupt services, or exfiltrate data.  The integrity of the deployment process is compromised.
*   **Affected Component:** Harness Pipelines, Workflows, YAML definitions, Governance (if not enforced).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Implement strict Role-Based Access Control (RBAC) within Harness.
    *   Use pipeline-as-code (YAML) and store definitions in a version control system (Git) for auditing and rollback.
    *   Implement approval workflows for pipeline changes.
    *   Monitor Harness audit logs for unauthorized modifications.
    *   Use Harness's built-in change management features.
    *   Enforce GitOps principles for pipeline management.

## Threat: [Secrets Exposure in Logs/UI](./threats/secrets_exposure_in_logsui.md)

*   **Description:** Secrets (API keys, passwords) are accidentally logged or displayed in the Harness UI, delegate logs, or other output. This could happen due to misconfiguration, coding errors, or insufficient masking.
*   **Impact:** Attackers can gain access to sensitive credentials, leading to further compromise.
*   **Affected Component:** Harness UI, Delegate logs, Secrets Management (if misused), any component handling secrets.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Use Harness's secrets management features correctly.
    *   Configure log masking or redaction to prevent secrets from being logged.
    *   Train developers and operators on secure coding and configuration practices.
    *   Regularly review logs for exposed secrets.
    *   Use a secrets scanner to detect secrets in code and configuration files.

## Threat: [Exploiting Harness Software Vulnerabilities](./threats/exploiting_harness_software_vulnerabilities.md)

*   **Description:** An attacker exploits a vulnerability in the Harness Manager or Delegate software to gain unauthorized access or elevate privileges. This could involve exploiting a known vulnerability or a zero-day exploit.
*   **Impact:** The attacker could gain control of the Harness platform, modify deployments, access secrets, or compromise the environment where the delegate is running.
*   **Affected Component:** Harness Manager, Harness Delegate.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Regularly update and patch the Harness Manager and Delegate software.
    *   Subscribe to Harness security advisories and apply patches promptly.
    *   Conduct regular security assessments and penetration testing.
    *   Implement a vulnerability management program.

## Threat: [Fake Delegate Registration](./threats/fake_delegate_registration.md)

*   **Description:** An attacker registers a malicious delegate with the Harness Manager, impersonating a legitimate delegate. This allows the attacker to intercept deployment instructions or gain access to sensitive data.
*   **Impact:** The attacker can intercept and potentially modify deployment instructions, gain access to sensitive data passed through the delegate, or even execute arbitrary code.
*   **Affected Component:** Harness Delegate registration process, Harness Manager.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Use delegate approval workflows (require manual approval of new delegate registrations).
    *   Implement strong authentication for delegate registration.
    *   Monitor for unexpected delegate registrations.
    *   Use delegate identifiers and secrets that are difficult to guess or forge.

