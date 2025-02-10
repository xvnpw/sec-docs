# Mitigation Strategies Analysis for harness/harness

## Mitigation Strategy: [Delegate Scoping and Least Privilege (Harness-Centric)](./mitigation_strategies/delegate_scoping_and_least_privilege__harness-centric_.md)

**Mitigation Strategy:** Enforce Least Privilege for Harness Delegates using Harness's built-in features.

**Description:**
1.  **Delegate Profiles (Optional):** If you have distinct sets of Delegate requirements, create Delegate Profiles to pre-define common configurations (e.g., selectors, hostnames).
2.  **Delegate Selectors:** Use Delegate Selectors effectively.  Assign tags to Delegates that reflect their capabilities and environment (e.g., `environment:production`, `cloud:aws`, `task:database`).
3.  **Harness Scoping Rules:** This is the core. Within the Harness UI (under "Setup" -> "Connectors" -> "Delegates" -> "Scoping Rules" or similar, depending on your Harness version):
    *   Create scoping rules that explicitly link specific Delegates (identified by selectors) to:
        *   **Environments:**  Limit which Delegates can deploy to which environments (e.g., only Delegates with `environment:production` can deploy to the production environment).
        *   **Services:**  Limit which Delegates can deploy which services.
        *   **Pipelines:**  Limit which Delegates can execute which pipelines.  This is *crucial* for preventing a compromised Delegate from running arbitrary pipelines.
        *   **Secrets:**  Limit which Delegates can access which secrets.  This is *essential* for protecting sensitive data.  Use the most restrictive scoping possible.
    *   Regularly review and audit these scoping rules.  Ensure they are up-to-date and reflect the current infrastructure and pipeline configurations.  Remove any unused or overly permissive rules.

**Threats Mitigated:**
*   **Delegate Compromise (Critical):** Limits the blast radius of a compromised Delegate.  It cannot access resources or execute pipelines it's not explicitly scoped to.
*   **Insider Threat (High):** Restricts the actions a malicious or negligent user can perform through a Delegate.
*   **Lateral Movement (High):** Prevents a compromised Delegate from being used to attack other parts of your infrastructure.
*   **Accidental Misconfiguration (Medium):** Reduces the risk of a misconfigured pipeline or Delegate causing unintended damage.

**Impact:**
*   **Delegate Compromise:** Risk reduction: High. This is the *primary* defense against a compromised Delegate.
*   **Insider Threat:** Risk reduction: High.
*   **Lateral Movement:** Risk reduction: High.
*   **Accidental Misconfiguration:** Risk reduction: Medium.

**Currently Implemented:**
*   Basic Delegate Scoping is used, but it's not comprehensive or fine-grained.

**Missing Implementation:**
*   Scoping rules need to be reviewed and refined to be as restrictive as possible.  Specifically, scoping to individual *pipelines* and *secrets* is often underutilized and needs to be implemented.
*   A regular review process (e.g., quarterly) for scoping rules needs to be formalized.

## Mitigation Strategy: [Harness RBAC and Secret Management](./mitigation_strategies/harness_rbac_and_secret_management.md)

**Mitigation Strategy:** Utilize Harness's built-in RBAC and Secret Management features.

**Description:**
1.  **Harness Roles and Permissions:**
    *   Use Harness's built-in roles (e.g., Account Admin, Project Admin, Pipeline Executor) as a starting point.
    *   Create *custom* roles with the *absolute minimum* necessary permissions.  Do *not* overuse the built-in roles if they grant more access than needed.  For example, create a role that can only *view* pipelines, not execute them.
    *   Assign users to the most restrictive role that allows them to perform their duties.
    *   Regularly review and audit user roles and permissions.  Remove any unnecessary permissions.
2.  **Harness Secret Management:**
    *   Use Harness's built-in secret management capabilities (or, ideally, integrate with an external secret manager like HashiCorp Vault, AWS Secrets Manager, etc.).
    *   Store *all* secrets (API keys, passwords, tokens, SSH keys) as secrets within Harness (or the integrated secret manager).
    *   *Never* hardcode secrets in pipeline definitions, scripts, or configuration files.
    *   Use Harness's secret *expressions* (e.g., `<+secrets.getValue("my_secret")>`) to reference secrets within pipelines.  This ensures that secrets are injected at runtime and are not exposed in the pipeline definition.
    *   Use secret *scoping* (as described in Strategy 1) to limit which Delegates and pipelines can access which secrets.
    *   Enable secret *masking* in logs and UI to prevent accidental exposure of secret values.
    *   Rotate secrets regularly, and update the corresponding secret references in Harness.

**Threats Mitigated:**
*   **Unauthorized Access (Critical):** RBAC prevents unauthorized users from accessing or modifying Harness resources.
*   **Data Breach (High):** Secret management protects sensitive data from being exposed.
*   **Insider Threat (High):** RBAC limits the actions a malicious or negligent user can perform.
*   **Credential Theft (High):** Secret management prevents secrets from being stolen from pipeline definitions or configuration files.

**Impact:**
*   **Unauthorized Access:** Risk reduction: High.
*   **Data Breach:** Risk reduction: High.
*   **Insider Threat:** Risk reduction: High.
*   **Credential Theft:** Risk reduction: High.

**Currently Implemented:**
*   Basic RBAC is implemented using built-in roles.
*   Secrets are stored within Harness (but not using an external secret manager).
*   Secret masking is enabled.

**Missing Implementation:**
*   Custom roles with fine-grained permissions are not fully utilized.  RBAC needs to be reviewed and refined.
*   Integration with an external secret manager is *highly recommended* and not currently implemented. This is a major gap.
*   Secret scoping is not fully utilized to limit access to secrets.
*   A formal process for regular secret rotation is not in place.

## Mitigation Strategy: [Harness Approval Stages and Governance](./mitigation_strategies/harness_approval_stages_and_governance.md)

**Mitigation Strategy:** Leverage Harness Approval Stages and Governance features.

**Description:**
1.  **Approval Stages:**
    *   Incorporate *manual* approval stages into your pipelines, especially before deployments to sensitive environments (e.g., production, staging).
    *   Define approvers or approver groups for each approval stage.  Ensure that approvers have the necessary knowledge and authority to approve deployments.
    *   Use Harness's built-in approval mechanisms (e.g., Jira approvals, ServiceNow approvals, custom shell script approvals) to integrate with your existing approval workflows.
2.  **Pipeline Governance (Optional):**
    *   If you have a large number of pipelines or complex governance requirements, consider using Harness's Pipeline Governance features (if available in your Harness edition).
    *   Define pipeline templates to enforce consistency and security best practices across all pipelines.
    *   Use pipeline policies to automatically enforce rules and restrictions on pipeline configurations (e.g., require approval stages, enforce naming conventions).

**Threats Mitigated:**
*   **Unauthorized Deployments (Medium):** Approval stages prevent unauthorized or accidental deployments to sensitive environments.
*   **Human Error (Medium):** Approval stages provide a second set of eyes to review deployments and catch potential errors.
*   **Compliance Violations (Medium):** Approval stages and pipeline governance can help ensure compliance with regulatory requirements.

**Impact:**
*   **Unauthorized Deployments:** Risk reduction: High.
*   **Human Error:** Risk reduction: Medium.
*   **Compliance Violations:** Risk reduction: Medium.

**Currently Implemented:**
*   Basic approval stages are used for production deployments.

**Missing Implementation:**
*   Approval stages are not consistently used for all sensitive environments (e.g., staging).
*   Pipeline Governance features are not utilized.
*   The approval process could be more robust (e.g., requiring multiple approvers, integrating with ticketing systems).

## Mitigation Strategy: [Harness Audit Trails](./mitigation_strategies/harness_audit_trails.md)

**Mitigation Strategy:** Utilize and Monitor Harness Audit Trails

**Description:**
1. **Enable Auditing:** Ensure that detailed auditing is enabled within Harness. This is usually on by default, but verify the settings.
2. **Review Audit Logs:** Regularly review the Harness audit trails for any suspicious activity, such as:
    - Unauthorized access attempts.
    - Changes to critical configurations (e.g., RBAC, Delegate scoping).
    - Execution of pipelines by unexpected users or Delegates.
    - Access to sensitive secrets.
3. **Integrate with SIEM (Optional but Recommended):** Integrate Harness audit logs with a Security Information and Event Management (SIEM) system for centralized monitoring, analysis, and alerting. This allows for correlation with other security events and automated threat detection.

**Threats Mitigated:**
* **Insider Threat (High):** Detect malicious or negligent actions by authorized users.
* **Unauthorized Access (Critical):** Identify attempts to access Harness resources without authorization.
* **Compromise Detection (Medium):** Help detect signs of a compromised account or Delegate.
* **Compliance (Medium):** Provide an audit trail for compliance purposes.

**Impact:**
* **Insider Threat:** Risk reduction: Medium (detection, not prevention).
* **Unauthorized Access:** Risk reduction: Medium (detection, not prevention).
* **Compromise Detection:** Risk reduction: Medium.
* **Compliance:** Risk reduction: High (provides necessary audit data).

**Currently Implemented:**
* Auditing is enabled.
* Logs are forwarded to a central logging system.

**Missing Implementation:**
* Regular, proactive review of audit logs is not consistently performed.
* Integration with a SIEM system for automated analysis and alerting is not implemented.

