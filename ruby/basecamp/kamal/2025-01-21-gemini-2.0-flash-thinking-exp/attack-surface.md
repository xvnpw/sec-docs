# Attack Surface Analysis for basecamp/kamal

## Attack Surface: [Compromised Kamal SSH Keys](./attack_surfaces/compromised_kamal_ssh_keys.md)

*   **Description:** The SSH keys used by Kamal to access target servers are compromised.
    *   **How Kamal Contributes:** Kamal relies on SSH for remote command execution and file transfer during deployment and management. The security of these keys is paramount for Kamal's operation.
    *   **Example:** An attacker gains access to the private SSH key used by Kamal (e.g., through a compromised CI/CD server or developer machine). They can then use this key to SSH into any server managed by Kamal and execute arbitrary commands.
    *   **Impact:** Full control over the target infrastructure, including the ability to deploy malicious code, access sensitive data, and disrupt services.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Store SSH keys securely, using secrets management tools or hardware security modules.
        *   Implement strict access controls on the systems where Kamal SSH keys are stored.
        *   Regularly rotate SSH keys used by Kamal.
        *   Utilize SSH agent forwarding with caution and understand its implications.
        *   Consider using short-lived SSH certificates instead of long-lived keys.

## Attack Surface: [Exposure of Kamal Configuration (`config/deploy.yml`)](./attack_surfaces/exposure_of_kamal_configuration___configdeploy_yml__.md)

*   **Description:** The `config/deploy.yml` file, containing sensitive information, is exposed.
    *   **How Kamal Contributes:** This file holds critical configuration details, including server credentials, Docker registry information, and potentially environment variables.
    *   **Example:** The `config/deploy.yml` file is accidentally committed to a public repository or is accessible due to misconfigured permissions on the system where Kamal is run. An attacker can extract server credentials and other sensitive information.
    *   **Impact:** Potential compromise of target servers, access to Docker registry credentials allowing for malicious image pushes, and exposure of sensitive environment variables.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Store `config/deploy.yml` securely with appropriate access controls.
        *   Avoid committing this file to version control directly. Consider using environment variables or secrets management for sensitive data within the configuration.
        *   Encrypt sensitive information within the configuration file if direct storage is unavoidable.
        *   Implement regular security audits of the systems where Kamal configuration is stored.

## Attack Surface: [Insecure Access to the Kamal Host](./attack_surfaces/insecure_access_to_the_kamal_host.md)

*   **Description:** The machine running the Kamal commands is compromised.
    *   **How Kamal Contributes:** This machine acts as the control plane for Kamal. If compromised, an attacker can leverage Kamal's capabilities.
    *   **Example:** A developer's laptop running Kamal is infected with malware. The attacker can then use Kamal to deploy malicious code to the managed infrastructure.
    *   **Impact:** Ability to manipulate the deployed application and infrastructure, potentially leading to data breaches, service disruption, and unauthorized access.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Harden the security of the machines running Kamal commands (e.g., strong passwords, up-to-date software, endpoint security).
        *   Implement multi-factor authentication for access to these machines.
        *   Restrict access to the Kamal host to authorized personnel only.
        *   Regularly scan the Kamal host for vulnerabilities and malware.

## Attack Surface: [Unauthorized Access to the Docker Registry](./attack_surfaces/unauthorized_access_to_the_docker_registry.md)

*   **Description:** Credentials for the Docker registry used by Kamal are compromised.
    *   **How Kamal Contributes:** Kamal pulls Docker images from a specified registry. Compromised registry credentials allow attackers to push malicious images.
    *   **Example:** An attacker gains access to the Docker registry credentials used in the `config/deploy.yml` or environment variables. They push a malicious image with the same tag as the legitimate application, which Kamal then deploys.
    *   **Impact:** Deployment of malicious code, potentially leading to data breaches, service disruption, and unauthorized access.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Securely store Docker registry credentials using secrets management.
        *   Implement strong access controls on the Docker registry.
        *   Utilize content trust or image signing to verify the integrity and authenticity of Docker images.
        *   Regularly scan Docker images for vulnerabilities.

