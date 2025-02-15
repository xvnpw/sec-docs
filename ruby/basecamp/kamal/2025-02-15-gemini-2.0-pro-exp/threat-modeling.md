# Threat Model Analysis for basecamp/kamal

## Threat: [Secrets Exposure via Git Repository](./threats/secrets_exposure_via_git_repository.md)

*   **Description:** An attacker gains access to the Git repository containing the `kamal.yml` or `.env` files, which inadvertently include hardcoded secrets (database credentials, API keys, etc.). The attacker clones the repository and extracts the secrets.
    *   **Impact:** Compromise of connected services (databases, external APIs), data breaches, potential for lateral movement within the infrastructure.
    *   **Affected Kamal Component:** `kamal.yml` configuration file, `.env` file (if used and committed).  This affects the overall Kamal deployment process, as these files are central to its operation.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Never** commit secrets to Git. Use a `.gitignore` file to exclude `.env` files.
        *   Use environment variables loaded from a secure source at runtime (e.g., CI/CD secrets, a dedicated secrets manager).
        *   Educate developers on secure coding practices and the importance of not committing secrets.
        *   Implement pre-commit hooks to scan for potential secrets before committing.

## Threat: [Secrets Exposure via Unprotected Environment Variables](./threats/secrets_exposure_via_unprotected_environment_variables.md)

*   **Description:** An attacker gains access to the server where Kamal is executed (e.g., a CI/CD runner or a developer's machine) and can read environment variables.  These variables contain secrets used by Kamal.
    *   **Impact:** Similar to the previous threat: compromise of connected services, data breaches, etc.
    *   **Affected Kamal Component:** Kamal's reliance on environment variables for configuration (indirectly affects all commands that use these variables).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Secure the environment where Kamal is executed.  Limit access to CI/CD runners and developer machines.
        *   Use a secrets manager (e.g., HashiCorp Vault, AWS Secrets Manager) to inject secrets into the environment only when needed, and remove them afterward.
        *   If using a CI/CD system, use its built-in secrets management features.
        *   Avoid logging environment variables.

## Threat: [SSH Key Compromise (Kamal's Key)](./threats/ssh_key_compromise__kamal's_key_.md)

*   **Description:** An attacker steals the SSH private key used by Kamal to connect to the deployment servers.  The attacker uses this key to gain full SSH access to the servers.
    *   **Impact:** Complete control over the deployed application and the underlying server infrastructure.  The attacker can deploy malicious code, steal data, or disrupt services.
    *   **Affected Kamal Component:** Kamal's SSH connection mechanism (used by all commands that interact with remote servers: `kamal deploy`, `kamal rollback`, `kamal app exec`, etc.).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Protect the SSH private key with a strong passphrase.
        *   Store the key in a secure location (e.g., a hardware security module, a secure enclave, or an encrypted file system).
        *   Use short-lived SSH keys or certificates.
        *   Regularly rotate SSH keys.
        *   Implement multi-factor authentication for SSH access, if possible.

## Threat: [Man-in-the-Middle (MITM) Attack on SSH Connection](./threats/man-in-the-middle__mitm__attack_on_ssh_connection.md)

*   **Description:** An attacker intercepts the SSH connection between the machine running Kamal and the target servers.  The attacker can potentially inject malicious commands or steal data transmitted over the connection.
    *   **Impact:** Compromise of the deployment process, injection of malicious code into the deployed application, data exfiltration.
    *   **Affected Kamal Component:** Kamal's SSH connection mechanism (all commands interacting with remote servers).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Ensure SSH host key verification is enabled and *not* bypassed. Kamal does this by default, but it's crucial to verify this behavior.
        *   Deploy from a trusted network. Avoid deploying over public Wi-Fi or untrusted networks.
        *   Use a VPN or other secure tunnel for the deployment connection.

## Threat: [Exploitation of Vulnerable Base Docker Image](./threats/exploitation_of_vulnerable_base_docker_image.md)

*   **Description:** The Docker image specified in `kamal.yml` (the `image:` directive) contains known vulnerabilities. An attacker exploits these vulnerabilities to gain control of the running container.
    *   **Impact:** Container compromise, potential for privilege escalation to the host, data breaches, denial of service.
    *   **Affected Kamal Component:** The `image:` directive in `kamal.yml`, and the resulting Docker container deployed by Kamal.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Use official, well-maintained base images from trusted registries.
        *   Regularly update base images to the latest versions (e.g., using Dependabot or similar tools).
        *   Use a vulnerability scanner (e.g., Trivy, Clair, Snyk) to scan Docker images for vulnerabilities before deployment. Integrate this into the CI/CD pipeline.
        *   Use minimal base images (e.g., Alpine Linux) to reduce the attack surface.

## Threat: [Docker Socket Exposure Leading to Host Compromise](./threats/docker_socket_exposure_leading_to_host_compromise.md)

*   **Description:** The Docker socket (`/var/run/docker.sock`) is mounted inside the application container (often unintentionally). An attacker who compromises the container can use the Docker socket to gain root access to the host machine.
    *   **Impact:** Complete host compromise, allowing the attacker to control the entire server and potentially other containers.
    *   **Affected Kamal Component:**  The `volumes:` directive in `kamal.yml` (if misconfigured to mount the Docker socket), and the resulting Docker container.  This is *not* a default behavior of Kamal, but a potential misconfiguration.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Avoid** mounting the Docker socket into the container unless absolutely necessary.
        *   If the Docker socket *must* be mounted, use extreme caution and ensure the application running in the container is highly trusted and runs with minimal privileges.
        *   Use Docker's security features (user namespaces, seccomp profiles, AppArmor/SELinux) to limit the container's capabilities.

## Threat: [Insecure CI/CD Pipeline Compromising Kamal Deployments](./threats/insecure_cicd_pipeline_compromising_kamal_deployments.md)

* **Description:** The CI/CD pipeline that triggers Kamal deployments is compromised. An attacker can inject malicious code or modify the `kamal.yml` file before deployment.
    * **Impact:** Deployment of a compromised application, unauthorized access to infrastructure, data breaches.
    * **Affected Kamal Component:** Indirectly affects all Kamal deployments, as the CI/CD pipeline is the entry point.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * Secure the CI/CD pipeline itself (strong authentication, access controls, vulnerability scanning).
        * Use signed commits and verify signatures before deploying.
        * Implement least privilege access for the CI/CD system's credentials.
        * Regularly audit the CI/CD pipeline's configuration and security.

