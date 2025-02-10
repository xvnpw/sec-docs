# Attack Surface Analysis for harness/harness

## Attack Surface: [Unauthorized API Access](./attack_surfaces/unauthorized_api_access.md)

*   **Description:**  Attackers gain unauthorized access to the Harness Manager's API, allowing them to control the platform.
    *   **How Harness Contributes:** Harness exposes a comprehensive API for automation and management. This API is the primary control plane for Harness and is inherently a high-value target.
    *   **Example:** An attacker obtains a leaked API key and uses it to delete all deployment pipelines and secrets.
    *   **Impact:** Complete compromise of the Harness platform, including access to secrets, ability to modify pipelines, deploy malicious code, and exfiltrate data. Potential compromise of connected systems.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Strong Authentication:** Enforce multi-factor authentication (MFA) for *all* API access.
        *   **API Key Management:** Use short-lived API keys and rotate them frequently.  *Never* store API keys in source code. Use a dedicated secrets management solution.
        *   **RBAC:** Implement *strict* Role-Based Access Control (RBAC) to limit API access based on the principle of least privilege.  Regularly review and refine roles.
        *   **Rate Limiting:** Implement robust API rate limiting to prevent brute-force attacks and denial-of-service.
        *   **Audit Logging:** Enable comprehensive API audit logging, forwarding logs to a SIEM or log management system for analysis.
        *   **IP Whitelisting:** Restrict API access to known and trusted IP addresses/ranges where feasible.

## Attack Surface: [Delegate Compromise (Harness-Controlled Aspects)](./attack_surfaces/delegate_compromise__harness-controlled_aspects_.md)

*   **Description:** An attacker gains control of a Harness Delegate, allowing them to execute code and access secrets *managed by Harness*.
    *   **How Harness Contributes:** The Delegate is a Harness-provided component. While it runs on user infrastructure, its *functionality and communication with the Harness Manager* are core Harness attack surfaces.  The *code* of the Delegate itself is a Harness responsibility.
    *   **Example:** An attacker exploits a vulnerability *within the Delegate software itself* (e.g., a buffer overflow in a library used by the Delegate) to gain code execution and steal secrets passed to the Delegate by Harness.
    *   **Impact:** Access to secrets *provided to the Delegate by Harness*, ability to execute arbitrary code within the context of the Delegate's tasks, potential for lateral movement if the Delegate has excessive permissions on the host.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Harness-Provided Updates:** *Immediately* apply security updates and patches released by Harness for the Delegate. This is the most critical mitigation.
        *   **Least Privilege (Delegate Configuration):** Configure the Delegate within Harness to have the *absolute minimum* necessary permissions to perform its tasks.  Avoid granting overly broad access to cloud provider credentials, etc.
        *   **Network Segmentation (Harness Communication):** Ensure secure communication (mTLS) between the Delegate and the Harness Manager.  Validate that network policies prevent the Delegate from initiating connections to untrusted networks.
        *   **Monitoring (Harness-Specific):** Monitor the Delegate's communication with the Harness Manager for anomalies.  Look for unexpected API calls or data transfers.

## Attack Surface: [Secrets Exposure (Harness-Managed Secrets)](./attack_surfaces/secrets_exposure__harness-managed_secrets_.md)

*   **Description:** Secrets *stored and managed within Harness* (e.g., using Harness's built-in secrets management or an integrated secrets manager) are exposed.
    *   **How Harness Contributes:** Harness provides the mechanism for storing and distributing secrets to Delegates.  The security of this mechanism is entirely within Harness's control.
    *   **Example:** An attacker exploits a vulnerability in the Harness Manager's secrets management component to decrypt and exfiltrate all stored secrets.
    *   **Impact:** Compromise of connected systems and applications that rely on the exposed secrets. Data breaches, financial losses, reputational damage.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Encryption at Rest (Harness Configuration):** Ensure that secrets are encrypted at rest within the Harness Manager's database *and* within any integrated secrets manager. Verify encryption settings.
        *   **Encryption in Transit (Harness Configuration):** Enforce TLS for *all* communication between Harness components (Manager, Delegates, integrated services).
        *   **Secrets Management Integration (Best Practices):** If using an external secrets manager, follow *all* security best practices for the integration.  Use short-lived, tightly scoped credentials for the integration itself.
        *   **Least Privilege (Harness RBAC):** Grant access to secrets *only* to the specific pipelines and services that require them.  Use Harness's RBAC features to enforce this.
        *   **Regular Rotation (Harness Configuration):** Configure Harness to automatically rotate secrets at a defined frequency.
        *   **Audit Logging (Harness Configuration):** Enable and monitor audit logging for *all* secret access and modification events within Harness.

## Attack Surface: [Pipeline Manipulation (Within Harness)](./attack_surfaces/pipeline_manipulation__within_harness_.md)

*   **Description:** An attacker modifies a deployment pipeline *within the Harness UI or API* to inject malicious code or configurations.
    *   **How Harness Contributes:** Harness provides the interface and logic for defining and executing pipelines.  The security of this functionality is a core Harness responsibility.
    *   **Example:** An attacker with compromised Harness Manager credentials modifies a pipeline to include a step that exfiltrates environment variables to an attacker-controlled server.
    *   **Impact:** Deployment of malicious code, data exfiltration, compromise of applications and infrastructure.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **RBAC (Harness Configuration):** Implement *strict* RBAC within Harness to limit who can create, modify, and approve pipelines.  Regularly review and refine roles.
        *   **Approval Gates (Harness Configuration):** Use approval gates for *all* deployments to sensitive environments.  Require multiple approvers for critical changes.
        *   **Pipeline Templates (Secure Usage):** If using pipeline templates, ensure they are stored securely (e.g., in a version-controlled repository with access controls) and are regularly reviewed for security issues.
        *   **Audit Logging (Harness Configuration):** Enable and monitor audit logging for *all* pipeline modifications within Harness.
        *   **Infrastructure as Code (IaC) for Pipelines:** Manage pipeline definitions as code, using a version control system (Git) and a CI/CD process for pipeline changes. This allows for code reviews and automated testing of pipeline modifications. *This interacts with Harness but is not solely within Harness.*

