# Attack Surface Analysis for aws/aws-cdk

## Attack Surface: [1. Overly Permissive IAM Policies](./attack_surfaces/1__overly_permissive_iam_policies.md)

*Description:* IAM policies define permissions for AWS resources. Overly permissive policies grant excessive access.
*AWS CDK Contribution:* The CDK's ease of defining IAM policies, especially with higher-level constructs, can lead developers to inadvertently create overly broad permissions, obscuring the underlying IAM details.
*Example:* A CDK application grants `s3:*` (full S3 access) to a Lambda function that only needs read access to a specific bucket.
*Impact:* An attacker compromising the Lambda could gain full control over *all* S3 buckets.
*Risk Severity:* **Critical**
*Mitigation Strategies:*
    *   **Least Privilege:** Use `iam.Grant` methods with specific actions (e.g., `grantRead`, `grantWrite`) and resource ARNs, avoiding wildcards (`*`).
    *   **Code Reviews:** Mandatory code reviews focusing on IAM policy definitions.
    *   **Linters/Static Analysis:** Use tools like `cdk-nag` to automatically detect overly permissive policies.
    *   **IAM Access Analyzer:** Utilize AWS IAM Access Analyzer.
    *   **Policy Validation:** Integrate policy validation into the CI/CD pipeline.

## Attack Surface: [2. Insecure Resource Configurations](./attack_surfaces/2__insecure_resource_configurations.md)

*Description:* Misconfigured AWS resources (e.g., S3 buckets, databases) can expose data or allow unauthorized access.
*AWS CDK Contribution:* The CDK allows programmatic resource configuration. Incorrect configurations can be easily introduced through code, and the abstraction can make it harder to spot errors.
*Example:* A CDK application creates an S3 bucket without enabling encryption or a database with a public endpoint and default password.
*Impact:* Data breaches, unauthorized access, potential for complete system compromise.
*Risk Severity:* **Critical**
*Mitigation Strategies:*
    *   **Secure Defaults:** Use CDK constructs that enforce secure defaults (e.g., encryption).
    *   **Code Reviews:** Thorough code reviews focusing on resource configuration.
    *   **IaC Security Scanning:** Implement tools that scan CDK code for insecure configurations.
    *   **AWS Config:** Use AWS Config rules for detection and remediation.
    *   **Principle of Least Exposure:** Ensure resources are only accessible from necessary networks/services.

## Attack Surface: [3. Hardcoded Secrets](./attack_surfaces/3__hardcoded_secrets.md)

*Description:* Embedding sensitive information (API keys, passwords) directly in the CDK code.
*AWS CDK Contribution:* While the CDK doesn't encourage it, developers can make this mistake *within* their CDK code. The CDK *facilitates* infrastructure creation, and secrets are often needed for that infrastructure.
*Example:* A developer hardcodes a database password into an `rds.DatabaseInstance` construct.
*Impact:* Compromise of the code repository leads to access to secrets, potentially granting full control of resources.
*Risk Severity:* **Critical**
*Mitigation Strategies:*
    *   **Secrets Management:** Use AWS Secrets Manager or AWS Systems Manager Parameter Store.
    *   **CDK Integration:** Use `secretsmanager.Secret.fromSecretArn` or similar methods.
    *   **Code Scanning:** Employ pre-commit hooks or CI/CD pipeline checks (e.g., `git-secrets`).

## Attack Surface: [4. Unvalidated User Input](./attack_surfaces/4__unvalidated_user_input.md)

*Description:* Using user-supplied input without validation/sanitization when constructing resource names, ARNs, or policies *within the CDK code*.
*AWS CDK Contribution:* CDK code might process user input to dynamically create infrastructure. Unvalidated input can lead to injection vulnerabilities *within the CDK's CloudFormation generation process*.
*Example:* A CDK app takes a bucket name from an environment variable and uses it directly: `new s3.Bucket(this, process.env.BUCKET_NAME)`.  A malicious user could craft the input to alter the CloudFormation template.
*Impact:* Injection attacks leading to unauthorized resource creation, modification, or deletion.
*Risk Severity:* **High**
*Mitigation Strategies:*
    *   **Input Validation:** Strictly validate and sanitize all user-supplied input.
    *   **Parameterized Templates:** Leverage the CDK's use of parameterized CloudFormation templates.
    *   **Whitelisting:** Use whitelisting for input validation.
    *   **Avoid Direct Concatenation:** Do not directly concatenate user input into resource identifiers.

## Attack Surface: [5. Vulnerable Dependencies](./attack_surfaces/5__vulnerable_dependencies.md)

*Description:* The CDK itself, and any third-party CDK constructs or libraries, may contain vulnerabilities.
*AWS CDK Contribution:* The CDK is a software library and can have vulnerabilities. Using third-party constructs adds dependency risks *directly related to the CDK*.
*Example:* A CDK application uses an outdated version of a third-party construct with a known vulnerability.
*Impact:* Exploitation of vulnerabilities in the CDK or its dependencies could lead to compromise of the infrastructure.
*Risk Severity:* **High**
*Mitigation Strategies:*
    *   **Regular Updates:** Keep the CDK and all dependencies updated.
    *   **Dependency Scanning:** Use tools like `npm audit`, `yarn audit`, or `snyk`.
    *   **Vetting Third-Party Constructs:** Carefully evaluate third-party CDK constructs before use.

