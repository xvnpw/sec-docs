# Mitigation Strategies Analysis for aws/aws-cdk

## Mitigation Strategy: [Enforce Least Privilege with Granular IAM Policies (CDK-Specific)](./mitigation_strategies/enforce_least_privilege_with_granular_iam_policies__cdk-specific_.md)

*   **Description (Step-by-Step):**
    1.  **Identify Required Actions:** For each CDK construct, list the *exact* AWS API actions it needs. Consult AWS documentation. (e.g., Lambda reading from S3 needs *only* `s3:GetObject`, `s3:ListBucket`).
    2.  **`iam.PolicyStatement` Objects:** Use `iam.PolicyStatement` objects in your CDK code. *Avoid* wildcard actions (`*`) unless absolutely justified.
    3.  **Specify Resources:** Within each `PolicyStatement`, specify the *exact* resources (using ARNs) the actions apply to. Avoid wildcard resources (`*`).
    4.  **Attach to Roles:** Create `iam.Role` objects, attach the `PolicyStatement` objects, and assign these roles to your CDK constructs.
    5.  **Review (CDK Synth):** Regularly review generated CloudFormation templates (`cdk synth`) to ensure IAM policies are restrictive. Use IAM Access Analyzer.
    6.  **Test:** Test application functionality to ensure restricted permissions don't break operations.

*   **Threats Mitigated:**
    *   **Unauthorized Data Access (High Severity):** Prevents compromised resources from accessing unauthorized data.
    *   **Privilege Escalation (High Severity):** Limits attacker's ability to gain broader AWS access.
    *   **Accidental Data Modification/Deletion (Medium Severity):** Reduces risk of misconfigured resources causing data loss.
    *   **Insider Threats (Medium Severity):** Limits damage from malicious/negligent insiders.

*   **Impact:**
    *   **Unauthorized Data Access:** Risk significantly reduced (High to Low/Medium).
    *   **Privilege Escalation:** Risk significantly reduced (High to Low/Medium).
    *   **Accidental Data Modification/Deletion:** Risk reduced (Medium to Low).
    *   **Insider Threats:** Risk reduced (Medium to Low).

*   **Currently Implemented:** Partially. Granular policies for S3 in `DataProcessingStack`, broader permissions for DynamoDB in `ApiStack`.

*   **Missing Implementation:**  `ApiStack` needs DynamoDB permission refinement. Consistent review process for all new constructs.

## Mitigation Strategy: [Separate Bootstrap and Deployment Roles (CDK-Specific)](./mitigation_strategies/separate_bootstrap_and_deployment_roles__cdk-specific_.md)

*   **Description (Step-by-Step):**
    1.  **Bootstrap Role:** Create an IAM role with *minimum* permissions for CDK bootstrapping (creating the CDK toolkit stack, S3 bucket for state).
    2.  **Deployment Roles:** Create separate IAM roles for each CDK stack (or related groups) with *minimum* permissions to deploy resources in that stack.
    3.  **`--role-arn`:** Use the `--role-arn` option with `cdk deploy` to specify the correct deployment role for each stack.
    4.  **Avoid Default Roles:** *Do not* use the default AWS account administrator role for CDK deployments.
    5.  **Review Permissions:** Regularly review permissions of bootstrap and deployment roles.

*   **Threats Mitigated:**
    *   **Privilege Escalation (High Severity):** Prevents compromised deployment from gaining broad AWS access.
    *   **Unauthorized Resource Creation/Modification (High Severity):** Limits unauthorized resource changes.

*   **Impact:**
    *   **Privilege Escalation:** Risk significantly reduced (High to Low/Medium).
    *   **Unauthorized Resource Creation/Modification:** Risk significantly reduced (High to Low/Medium).

*   **Currently Implemented:** Partially. Separate deployment roles used, but bootstrap role has overly broad permissions.

*   **Missing Implementation:** Refine bootstrap role permissions to be least privilege.

## Mitigation Strategy: [CDK Construct Review and Security Audits (CDK-Focused)](./mitigation_strategies/cdk_construct_review_and_security_audits__cdk-focused_.md)

*   **Description (Step-by-Step):**
    1.  **Mandatory Code Reviews:** Enforce code reviews for *all* CDK code changes.
    2.  **CDK Security Checklist:** Create a checklist specific to CDK:
        *   Verify least privilege IAM policies (using `iam.PolicyStatement` as described above).
        *   Review construct configurations for security best practices (e.g., S3 bucket encryption, security group rules).  *This is CDK-specific because you're reviewing CDK construct properties.*
        *   Confirm secure secret retrieval (using CDK constructs like `secretsmanager.Secret.fromSecretNameV2`).
        *   Validate input/output handling (if applicable, within CDK-defined resources).
    3.  **Security Expert Involvement:** Include security experts in reviews, especially for complex/high-risk stacks.
    4.  **Regular Audits:** Conduct periodic security audits of CDK applications *and* deployed infrastructure.
    5.  **Automated Checks (CDK-Specific):** Use `cdk-nag` and `cfn_nag` to automatically identify potential problems in CDK code and CloudFormation. Integrate into CI/CD.

*   **Threats Mitigated:**
    *   **Deployment of Insecure Infrastructure (High Severity):** Identifies and prevents deployment of vulnerable resources.
    *   **Human Error (Medium Severity):** Reduces security flaws from human error in CDK development.
    *   **Insider Threats (Medium Severity):** Makes it harder for malicious insiders to introduce vulnerabilities.
    *   **Compliance Violations (Medium Severity):** Ensures compliance with security standards.

*   **Impact:**
    *   **Deployment of Insecure Infrastructure:** Risk significantly reduced (High to Low/Medium).
    *   **Human Error:** Risk reduced (Medium to Low).
    *   **Insider Threats:** Risk reduced (Medium to Low).
    *   **Compliance Violations:** Risk reduced (Medium to Low).

*   **Currently Implemented:** Partially. Code reviews are mandatory, but no CDK-specific checklist, inconsistent security expert involvement. `cdk-nag` not integrated.

*   **Missing Implementation:** Develop CDK security checklist. Ensure consistent security expert involvement. Integrate `cdk-nag` into CI/CD. Schedule regular audits.

## Mitigation Strategy: [Secure Secret Management using CDK Constructs](./mitigation_strategies/secure_secret_management_using_cdk_constructs.md)

* **Description (Step-by-Step):**
    1.  **Identify Secrets:** Identify all sensitive data used in your CDK application.
    2.  **Use Secrets Manager/Parameter Store:** Store secrets in AWS Secrets Manager or Parameter Store.
    3.  **Retrieve Secrets in CDK Code:** Use CDK constructs (e.g., `secretsmanager.Secret.fromSecretNameV2`, `ssm.StringParameter.valueForStringParameter`) to *dynamically* retrieve secrets within your CDK code. *Never* hardcode.
    4.  **Grant Access (CDK):** Use CDK to grant your constructs (e.g., Lambda functions) the *minimum* permissions to access *specific* secrets. This is done via IAM policies defined *within* the CDK.
    5.  **Audit Access:** Use CloudTrail (configured via CDK if desired) to monitor secret access.

* **Threats Mitigated:**
    *   **Credential Exposure (High Severity):** Prevents secrets from being exposed in code or configuration.
    *   **Unauthorized Access (High Severity):** Limits secret access to authorized resources.
    *   **Credential Theft (High Severity):** Reduces impact of credential theft.

* **Impact:**
    *   **Credential Exposure:** Risk significantly reduced (High to Low).
    *   **Unauthorized Access:** Risk significantly reduced (High to Low).
    *   **Credential Theft:** Risk reduced (High to Medium).

* **Currently Implemented:** Fully implemented. Secrets are in Secrets Manager; CDK constructs retrieve them securely.

* **Missing Implementation:** None.

