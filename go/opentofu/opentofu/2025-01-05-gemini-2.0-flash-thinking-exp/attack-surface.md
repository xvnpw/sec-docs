# Attack Surface Analysis for opentofu/opentofu

## Attack Surface: [Secrets in Plain Text in Configuration Files](./attack_surfaces/secrets_in_plain_text_in_configuration_files.md)

*   **Description:** Sensitive information like API keys, database credentials, and private keys are stored directly within OpenTofu configuration files (e.g., `.tf`, `.tfvars`).
*   **How OpenTofu Contributes:** OpenTofu relies on these files to define infrastructure, and developers might inadvertently include secrets directly for simplicity or lack of awareness.
*   **Example:** A developer hardcodes an AWS access key ID and secret access key in a `provider "aws"` block within a `.tf` file.
*   **Impact:** Unauthorized access to these files grants attackers full access to the corresponding resources and services.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   Utilize secrets management solutions (e.g., HashiCorp Vault, AWS Secrets Manager, Azure Key Vault) and reference secrets dynamically within OpenTofu configurations.
    *   Employ environment variables for sensitive data and access them using OpenTofu functions.
    *   Avoid committing sensitive data to version control systems.
    *   Implement code scanning tools to detect potential secrets in configuration files.

## Attack Surface: [State File Exposure and Tampering](./attack_surfaces/state_file_exposure_and_tampering.md)

*   **Description:** The OpenTofu state file contains a snapshot of the managed infrastructure, potentially including sensitive resource attributes. Unauthorized access or modification can lead to information disclosure or infrastructure disruption.
*   **How OpenTofu Contributes:** OpenTofu requires a state backend to track infrastructure, and if this backend is not secured, the state file is vulnerable.
*   **Example:** An S3 bucket used as the state backend has overly permissive access controls, allowing unauthorized users to download or modify the `terraform.tfstate` file.
*   **Impact:** Exposure of sensitive data within resource attributes (e.g., database passwords). Tampering can lead to resource deletion, misconfiguration, or the introduction of malicious resources.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Secure the state backend with strong access controls and authentication.
    *   Enable encryption at rest for the state backend storage.
    *   Implement state locking mechanisms to prevent concurrent modifications.
    *   Regularly backup the state file.
    *   Restrict access to the state backend to authorized personnel and systems.

## Attack Surface: [Supply Chain Risks from Untrusted Modules](./attack_surfaces/supply_chain_risks_from_untrusted_modules.md)

*   **Description:** Using community modules from the OpenTofu Registry or other sources introduces the risk of incorporating malicious or vulnerable code into the infrastructure deployment.
*   **How OpenTofu Contributes:** OpenTofu encourages the use of modules for code reusability, but this can introduce dependencies on external, potentially untrusted sources.
*   **Example:** A seemingly useful module contains code that exfiltrates sensitive data to an external server during resource provisioning.
*   **Impact:** Data breaches, unauthorized access, and compromise of the deployed infrastructure.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Thoroughly vet and review the code of external modules before using them.
    *   Pin module versions to avoid unexpected changes and potential introduction of vulnerabilities in newer versions.
    *   Prefer well-established and reputable modules with active community support.
    *   Consider creating and maintaining internal, verified modules for common infrastructure components.
    *   Use tools to scan module dependencies for known vulnerabilities.

## Attack Surface: [Insecure Use of Provisioners (local-exec, remote-exec)](./attack_surfaces/insecure_use_of_provisioners__local-exec__remote-exec_.md)

*   **Description:** Provisioners allow executing scripts locally or remotely on provisioned resources. Improper use can introduce command injection vulnerabilities or expose sensitive data.
*   **How OpenTofu Contributes:** OpenTofu provides these provisioners as a mechanism for customizing resources, but they require careful handling of user input and credentials.
*   **Example:** A `local-exec` provisioner uses unsanitized user input to construct a shell command, allowing an attacker to execute arbitrary commands on the OpenTofu host.
*   **Impact:** Compromise of the OpenTofu host or the provisioned resources. Potential for lateral movement within the infrastructure.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Minimize the use of provisioners. Explore alternative configuration management tools or cloud-native solutions.
    *   Avoid using user-supplied data directly in provisioner scripts. Sanitize and validate all inputs.
    *   Securely manage credentials used by provisioners. Avoid hardcoding credentials in the OpenTofu configuration.
    *   Restrict the permissions of the user executing provisioner scripts.

## Attack Surface: [Insecure Remote Operations and CI/CD Integration](./attack_surfaces/insecure_remote_operations_and_cicd_integration.md)

*   **Description:** Integrating OpenTofu with CI/CD pipelines or performing remote operations can introduce vulnerabilities if not secured properly.
*   **How OpenTofu Contributes:** OpenTofu is often used in automated workflows, requiring secure handling of credentials and access.
*   **Example:** OpenTofu provider credentials are stored directly in the CI/CD pipeline configuration, making them accessible if the CI/CD system is compromised.
*   **Impact:** Unauthorized infrastructure changes, credential theft, and potential compromise of the CI/CD environment.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Avoid storing credentials directly in CI/CD configurations. Utilize secure secret management integrations provided by the CI/CD platform.
    *   Implement strong authentication and authorization for accessing the CI/CD system.
    *   Secure the communication channels used for remote OpenTofu operations.
    *   Follow the principle of least privilege when granting permissions to CI/CD pipelines.

