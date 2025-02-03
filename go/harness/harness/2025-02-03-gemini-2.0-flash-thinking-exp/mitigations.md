# Mitigation Strategies Analysis for harness/harness

## Mitigation Strategy: [Leverage External Secret Managers](./mitigation_strategies/leverage_external_secret_managers.md)

*   **Mitigation Strategy:** Leverage External Secret Managers
    *   **Description:**
        1.  Identify all sensitive secrets currently stored directly within Harness Secret Manager.
        2.  Choose and configure an external secret management solution (e.g., HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, Google Secret Manager).
        3.  Create secrets in the external secret manager, mirroring those in Harness Secret Manager.
        4.  In Harness, create Secret Manager Connectors to your chosen external secret manager(s).
        5.  Modify Harness pipelines, services, and environments to use these Connectors to fetch secrets dynamically at runtime using Harness expressions (e.g., `${secrets.getValue("secretName")}`).
        6.  Test all pipelines and deployments after switching to external secret management.
        7.  Remove secrets from Harness Secret Manager after verification.
    *   **List of Threats Mitigated:**
        *   Hardcoded Secrets in Pipelines (High Severity)
        *   Exposure of Secrets in Harness UI/Logs (Medium Severity)
        *   Compromise of Harness Secret Manager (High Severity)
        *   Lack of Centralized Secret Management and Auditing (Medium Severity)
    *   **Impact:**
        *   Hardcoded Secrets in Pipelines: High Risk Reduction
        *   Exposure of Secrets in Harness UI/Logs: Medium to High Risk Reduction
        *   Compromise of Harness Secret Manager: High Risk Reduction
        *   Lack of Centralized Secret Management and Auditing: Medium Risk Reduction
    *   **Currently Implemented:** Partially implemented. AWS Secrets Manager is used for production database and some cloud provider credentials via Harness Secret Manager Connectors in Production project.
    *   **Missing Implementation:**  External secret managers are not consistently used across all projects. API keys and non-production database credentials are still largely in Harness Secret Manager. Need to expand external secret manager usage to all environments and secret types within Harness.

## Mitigation Strategy: [Implement Granular Role-Based Access Control (RBAC)](./mitigation_strategies/implement_granular_role-based_access_control__rbac_.md)

*   **Mitigation Strategy:** Implement Granular Role-Based Access Control (RBAC)
    *   **Description:**
        1.  Audit existing Harness user roles and permissions within Harness.
        2.  Define granular roles based on job functions within Harness (e.g., "Pipeline Creator," "Pipeline Approver," "Environment Admin").
        3.  Determine minimum necessary Harness permissions for each role.
        4.  Create custom roles in Harness matching these permission sets.
        5.  Assign users and service accounts to custom roles based on least privilege within Harness. Remove overly broad default roles.
        6.  Regularly review and audit user roles and permissions in Harness.
        7.  Document defined Harness roles and permissions.
    *   **List of Threats Mitigated:**
        *   Unauthorized Access to Pipelines and Configurations (High Severity)
        *   Accidental or Malicious Pipeline Modifications (Medium to High Severity)
        *   Data Breaches due to Unauthorized Access (Medium Severity)
        *   Privilege Escalation (Medium Severity)
    *   **Impact:**
        *   Unauthorized Access to Pipelines and Configurations: High Risk Reduction
        *   Accidental or Malicious Pipeline Modifications: Medium to High Risk Reduction
        *   Data Breaches due to Unauthorized Access: Medium Risk Reduction
        *   Privilege Escalation: Medium Risk Reduction
    *   **Currently Implemented:** Partially implemented. Custom roles for "Developers" and "Operations" exist in Production project, limiting developer access to production configurations within Harness.
    *   **Missing Implementation:** RBAC is not consistently applied across all Harness projects and environments. Many users still have default "Project Admin" roles in Harness. Role granularity can be improved, and a formal Harness RBAC policy is needed.

## Mitigation Strategy: [Enforce Multi-Factor Authentication (MFA)](./mitigation_strategies/enforce_multi-factor_authentication__mfa_.md)

*   **Mitigation Strategy:** Enforce Multi-Factor Authentication (MFA)
    *   **Description:**
        1.  Evaluate current authentication methods for accessing Harness.
        2.  Choose an MFA method supported by Harness and your organization (e.g., TOTP, push notifications).
        3.  Configure Harness to enforce MFA for all user logins, potentially integrating with your corporate IdP via Harness authentication settings.
        4.  Communicate MFA enforcement policy to all Harness users.
        5.  Provide support for Harness MFA setup and usage.
        6.  Monitor Harness MFA usage.
    *   **List of Threats Mitigated:**
        *   Credential Stuffing and Password Reuse Attacks (High Severity)
        *   Phishing Attacks (Medium to High Severity)
        *   Account Takeover (High Severity)
        *   Insider Threats (Medium Severity)
    *   **Impact:**
        *   Credential Stuffing and Password Reuse Attacks: High Risk Reduction
        *   Phishing Attacks: Medium to High Risk Reduction
        *   Account Takeover: High Risk Reduction
        *   Insider Threats: Medium Risk Reduction
    *   **Currently Implemented:** Partially implemented. MFA is enforced for Harness administrators and "Account Admin" roles.
    *   **Missing Implementation:** MFA is not mandatory for all regular Harness users. Need to enforce MFA for all Harness users to maximize platform security.

## Mitigation Strategy: [Pipeline as Code and Version Control](./mitigation_strategies/pipeline_as_code_and_version_control.md)

*   **Mitigation Strategy:** Pipeline as Code and Version Control
    *   **Description:**
        1.  Transition from UI-defined Harness pipelines to Pipeline as Code using YAML.
        2.  Store Harness pipeline definitions (YAML files) in a version control system (e.g., Git).
        3.  Establish a branching strategy for Harness pipeline code.
        4.  Implement code review for all Harness pipeline changes before merging.
        5.  Integrate version control with Harness using Git Connectors. Configure Harness to fetch pipelines from the repository.
        6.  Utilize Git webhooks to trigger Harness pipeline updates on repository changes.
        7.  Treat Harness pipeline code with security rigor.
    *   **List of Threats Mitigated:**
        *   Uncontrolled Pipeline Changes and Configuration Drift (Medium Severity)
        *   Lack of Audit Trail for Pipeline Modifications (Medium Severity)
        *   Accidental Pipeline Deletion or Corruption (Medium Severity)
        *   Difficulty in Reverting to Previous Pipeline States (Medium Severity)
        *   Limited Collaboration and Code Review for Pipelines (Low to Medium Severity)
    *   **Impact:**
        *   Uncontrolled Pipeline Changes and Configuration Drift: Medium Risk Reduction
        *   Lack of Audit Trail for Pipeline Modifications: Medium Risk Reduction
        *   Accidental Pipeline Deletion or Corruption: Medium Risk Reduction
        *   Difficulty in Reverting to Previous Pipeline States: Medium Risk Reduction
        *   Limited Collaboration and Code Review for Pipelines: Low to Medium Risk Reduction
    *   **Currently Implemented:** Partially implemented. Newer Harness pipelines are defined as code and version controlled in "New Application" project.
    *   **Missing Implementation:** Many older Harness pipelines in other projects are still UI-defined and not version controlled. Need to migrate all Harness pipelines to Pipeline as Code and enforce version control across all projects within Harness.

## Mitigation Strategy: [Secure Pipeline Execution Environments (Harness Delegates)](./mitigation_strategies/secure_pipeline_execution_environments__harness_delegates_.md)

*   **Mitigation Strategy:** Secure Pipeline Execution Environments (Harness Delegates)
    *   **Description:**
        1.  Harden the OS of Harness Delegate instances.
        2.  Minimize software on Harness Delegate instances.
        3.  Regularly update OS and software on Harness Delegates.
        4.  Isolate Harness Delegate instances in a dedicated network segment.
        5.  Restrict network access to/from Harness Delegate instances using network security groups.
        6.  Implement monitoring and logging for Harness Delegate instances.
        7.  Regularly review and audit Harness Delegate configurations.
    *   **List of Threats Mitigated:**
        *   Delegate Compromise Leading to Pipeline Manipulation (High Severity)
        *   Data Exfiltration via Compromised Delegate (Medium to High Severity)
        *   Lateral Movement from Delegate to Other Systems (Medium Severity)
        *   Denial of Service via Delegate Exploitation (Medium Severity)
    *   **Impact:**
        *   Delegate Compromise Leading to Pipeline Manipulation: High Risk Reduction
        *   Data Exfiltration via Compromised Delegate: Medium to High Risk Reduction
        *   Lateral Movement from Delegate to Other Systems: Medium Risk Reduction
        *   Denial of Service via Delegate Exploitation: Medium Risk Reduction
    *   **Currently Implemented:** Partially implemented. Harness Delegates are in dedicated VMs with basic OS hardening and network security groups limiting inbound traffic.
    *   **Missing Implementation:**  More comprehensive OS hardening for Harness Delegates, automated patching, deeper network segmentation, and regular vulnerability scanning of Harness Delegate environments are missing.

## Mitigation Strategy: [Pipeline Scanning for Vulnerabilities](./mitigation_strategies/pipeline_scanning_for_vulnerabilities.md)

*   **Mitigation Strategy:** Pipeline Scanning for Vulnerabilities
    *   **Description:**
        1.  Integrate security scanning tools into Harness pipelines (SAST, DAST, SCA, IaC scanning).
        2.  Configure scanning tools in Harness pipelines to automatically scan code, dependencies, images, and IaC.
        3.  Define vulnerability thresholds in Harness pipeline stages. Fail pipelines or trigger alerts for high severity vulnerabilities.
        4.  Implement automated vulnerability remediation workflows, integrating with vulnerability management platforms from Harness pipelines if possible.
        5.  Provide developer feedback on vulnerabilities detected in Harness pipelines.
        6.  Regularly update scanning tools integrated with Harness pipelines.
    *   **List of Threats Mitigated:**
        *   Deployment of Vulnerable Application Code (High Severity)
        *   Deployment of Vulnerable Dependencies (Medium to High Severity)
        *   Infrastructure Misconfigurations with Security Vulnerabilities (Medium Severity)
        *   Zero-Day Vulnerabilities (Low to Medium Severity)
    *   **Impact:**
        *   Deployment of Vulnerable Application Code: High Risk Reduction
        *   Deployment of Vulnerable Dependencies: Medium to High Risk Reduction
        *   Infrastructure Misconfigurations with Security Vulnerabilities: Medium Risk Reduction
        *   Zero-Day Vulnerabilities: Low to Medium Risk Reduction
    *   **Currently Implemented:** Partially implemented. Basic SAST tool is integrated into the build stage of the main application Harness pipeline.
    *   **Missing Implementation:** DAST, SCA, and IaC scanning are not implemented in Harness pipelines. Vulnerability scanning is not consistently applied across all Harness pipelines and projects. Pipeline gates based on vulnerability severity in Harness are not fully enforced. Automated remediation workflows from Harness are missing.

