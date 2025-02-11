# Attack Surface Analysis for opentofu/opentofu

## Attack Surface: [State File Exposure/Manipulation](./attack_surfaces/state_file_exposuremanipulation.md)

*   **Description:** The OpenTofu state file (`.tfstate`), *created and managed by OpenTofu*, contains a complete representation of the managed infrastructure, including sensitive data. Unauthorized access or modification of this file is a critical risk *directly impacting OpenTofu's operation*.
*   **How OpenTofu Contributes:** OpenTofu *generates, reads, writes, and depends entirely on* the state file for its core functionality. The state file is the single source of truth for OpenTofu.
*   **Example:** An attacker gains read access to an unencrypted S3 bucket containing the state file. They can then view database passwords, API keys, and other secrets *that OpenTofu uses to manage resources*. Alternatively, an attacker with write access modifies the state to remove security group rules, and *OpenTofu will then enforce this insecure state*, opening up resources.
*   **Impact:** Complete infrastructure compromise, data breaches, unauthorized resource creation/deletion/modification, denial of service. *OpenTofu will actively enforce the compromised state*.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Remote State:** *Always* use a secure remote state backend (e.g., AWS S3 with encryption and versioning, Azure Blob Storage, Google Cloud Storage, Terraform Cloud/Enterprise). This is *essential for secure OpenTofu operation*.
    *   **Encryption at Rest:** Enable encryption at rest for the remote state backend.
    *   **Strict Access Control:** Implement the principle of least privilege for access to the remote state backend using IAM roles/policies. Only the necessary OpenTofu execution environment should have read/write access.
    *   **State Locking:** Utilize the state locking mechanism provided by the remote backend to prevent concurrent modifications *that could corrupt OpenTofu's understanding of the infrastructure*.
    *   **Auditing:** Regularly audit access logs for the state file storage. Monitor for unauthorized access attempts.
    *   **Avoid Local State:** Do not store state files locally, especially in production. *Local state is inherently less secure and bypasses many of OpenTofu's protective mechanisms*.

## Attack Surface: [Insecure Configuration (Misconfigurations)](./attack_surfaces/insecure_configuration__misconfigurations_.md)

*   **Description:** OpenTofu configurations (HCL2) define the desired state of the infrastructure. Insecure configurations lead to vulnerable infrastructure *when OpenTofu applies them*.
*   **How OpenTofu Contributes:** OpenTofu *directly interprets and executes* the configurations provided. The configuration language allows for both secure and insecure setups; OpenTofu acts as the engine that brings these configurations (good or bad) to life.
*   **Example:** A configuration defines an AWS security group with an inbound rule allowing all traffic (0.0.0.0/0) on port 22 (SSH). *OpenTofu will create this security group and associate it with resources as instructed*.
*   **Impact:** Unauthorized access to resources, data breaches, denial of service, resource hijacking. *OpenTofu is the agent that creates and maintains these vulnerabilities*.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Code Review:** Conduct thorough code reviews of all OpenTofu configurations, focusing on security best practices.
    *   **Linting and Static Analysis:** Use linting tools (e.g., `tofu fmt`, `tflint`) and static analysis tools (e.g., `checkov`, `tfsec`) to automatically identify potential misconfigurations and security vulnerabilities *before OpenTofu applies them*.
    *   **Policy-as-Code:** Implement policy-as-code using tools like Open Policy Agent (OPA) or Sentinel to enforce security policies and prevent insecure configurations from being *applied by OpenTofu*.
    *   **Principle of Least Privilege:** Apply the principle of least privilege to all resources and configurations. *OpenTofu should only be allowed to create resources with the minimum necessary permissions*.
    *   **Secure Defaults:** Use secure defaults whenever possible. Avoid using default passwords or overly permissive settings *that OpenTofu will then implement*.
    *   **Regular Security Audits:** Conduct regular security audits of your infrastructure and configurations.
    *   **Infrastructure as Code (IaC) Scanning:** Integrate IaC scanning into your CI/CD pipeline to automatically detect vulnerabilities *before OpenTofu deploys them*.

## Attack Surface: [Secrets Management](./attack_surfaces/secrets_management.md)

*   **Description:** Hardcoding secrets directly into OpenTofu configurations or storing them insecurely exposes them to unauthorized access. *OpenTofu then uses these exposed secrets to interact with cloud providers*.
*   **How OpenTofu Contributes:** OpenTofu configurations often *require* secrets to authenticate with cloud providers and other services. The method of providing these secrets to OpenTofu is critical. OpenTofu *acts on these secrets*.
*   **Example:** A database password is hardcoded directly into a `resource` block. *OpenTofu will use this hardcoded password to connect to the database*.
*   **Impact:** Unauthorized access to sensitive resources, data breaches, complete system compromise. *OpenTofu becomes the unwitting conduit for attacks using stolen credentials*.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Secrets Management System:** *Always* use a dedicated secrets management system (e.g., HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, Google Secret Manager).
    *   **OpenTofu Data Sources:** Use OpenTofu data sources to dynamically retrieve secrets from the secrets management system at runtime. *This prevents secrets from being stored in the configuration or state file*.
    *   **Environment Variables (with Caution):** Environment variables can be used, but ensure the environment itself is secure. *OpenTofu will read these variables*.
    *   **Avoid `terraform.tfvars` for Secrets:** Do not store secrets in `terraform.tfvars` files.
    *   **Input Variables (with Caution):** If using input variables, mark them as `sensitive = true`. *OpenTofu will attempt to redact these, but this is not a foolproof solution*.

## Attack Surface: [Compromised Providers/Modules](./attack_surfaces/compromised_providersmodules.md)

*   **Description:** OpenTofu uses providers and modules to interact with different services. Compromised providers or modules can be used to gain unauthorized access or execute malicious code *through OpenTofu*.
*   **How OpenTofu Contributes:** OpenTofu's core functionality relies on loading and executing code from providers and modules. This is a *direct* dependency and a key part of OpenTofu's architecture.
*   **Example:** A malicious AWS provider is installed. *OpenTofu, when interacting with AWS, will execute the malicious code within this provider*, potentially granting the attacker access to the AWS account. A compromised module contains a backdoor; *OpenTofu will execute this backdoor when the module is used*.
*   **Impact:** Unauthorized access to cloud resources, data breaches, arbitrary code execution, complete system compromise. *OpenTofu is the execution engine for the compromised code*.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Verified Providers:** Use only verified providers from trusted sources. *OpenTofu's security is directly tied to the security of its providers*.
    *   **Provider Version Pinning:** Specify precise provider versions. *This prevents OpenTofu from automatically using a potentially compromised newer version*.
    *   **Provider Checksum Verification:** Use checksum verification (where supported) to ensure the integrity of provider binaries *that OpenTofu will load*.
    *   **Trusted Module Sources:** Use modules only from trusted sources.
    *   **Module Version Pinning:** Pin module versions to specific, known-good versions. *This prevents OpenTofu from using a compromised version*.
    *   **Module Code Review:** Thoroughly review the code of any modules before use. *Understand what code OpenTofu will be executing*.
    *   **Private Module Registry:** Consider using a private module registry to control the modules *that OpenTofu can access*.

