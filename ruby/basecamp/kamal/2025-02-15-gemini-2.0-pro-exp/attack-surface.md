# Attack Surface Analysis for basecamp/kamal

## Attack Surface: [Secret Exposure (Configuration Files)](./attack_surfaces/secret_exposure__configuration_files_.md)

*   **Description:** Sensitive information (API keys, database passwords, etc.) stored in configuration files like `.env` or `deploy.yml` are exposed.
*   **How Kamal Contributes:** Kamal *directly* relies on these files for configuration, and its workflow increases the risk if these files are not handled with extreme care. The core functionality of Kamal depends on reading these files.
*   **Example:** The `.env` file containing a database password is accidentally committed to a public GitHub repository because the developer forgot to add it to `.gitignore`.
*   **Impact:** Complete compromise of the application and its data, potential access to other connected systems.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Never Commit Secrets:** Use `.gitignore` and enforce this with pre-commit hooks to prevent accidental commits of `.env` and other sensitive files.
    *   **Secrets Management:** Employ a dedicated secrets manager (HashiCorp Vault, AWS Secrets Manager, etc.) and integrate it with Kamal. Utilize Kamal's built-in support for injecting secrets from these services.
    *   **Environment Variables:** Load secrets from environment variables, which are injected by the secrets manager or set securely on the server.  Kamal *directly* supports this.
    *   **Least Privilege:** Grant only the minimum necessary permissions to secrets.

## Attack Surface: [Docker Socket Exposure](./attack_surfaces/docker_socket_exposure.md)

*   **Description:** Unintentional or misconfigured access to the Docker socket (`/var/run/docker.sock`) is granted.
*   **How Kamal Contributes:** Kamal *directly* interacts with the Docker daemon on the host to manage containers. This interaction necessitates careful management of Docker socket access to prevent escalation of privileges.
*   **Example:** A container is misconfigured to mount the Docker socket, allowing a compromised container to gain root access to the host. While Kamal doesn't *force* this, its use of Docker makes this a relevant risk.
*   **Impact:** Complete host compromise, allowing attackers to control all containers and the underlying server.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Avoid Socket Mounting:** Never mount the Docker socket into containers unless absolutely necessary and with extreme caution.
    *   **Restricted Access:** Ensure the Docker socket is only accessible to authorized users (typically `root` and the `docker` group).
    *   **AppArmor/SELinux:** Use AppArmor or SELinux to enforce mandatory access controls and prevent containers from accessing the socket even if compromised.
    *   **Docker API Security:** If exposing the Docker API, use TLS and strong authentication.

## Attack Surface: [Traefik Misconfiguration](./attack_surfaces/traefik_misconfiguration.md)

*   **Description:** Incorrect configuration of the Traefik reverse proxy exposes vulnerabilities.
*   **How Kamal Contributes:** Kamal *directly* uses and configures Traefik as its default reverse proxy.  The security of Traefik is therefore directly tied to Kamal's deployment security.
*   **Example:** The Traefik dashboard is exposed to the public internet without authentication, allowing attackers to view and potentially modify routing configurations.
*   **Impact:** Exposure of internal application routing, potential modification of Traefik configuration, man-in-the-middle attacks (if TLS is misconfigured).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Secure Dashboard:** Protect the Traefik dashboard with strong authentication (basic auth or an external provider). Kamal provides options for this.
    *   **Strong TLS:** Configure Traefik to use strong TLS ciphers and protocols (TLS 1.3). Enable HSTS. Regularly update certificates.
    *   **Middleware Review:** Carefully review and test all Traefik middleware (rate limiting, security headers, etc.) to ensure they function as intended and don't introduce new vulnerabilities.
    *   **Change Default Credentials:** Always change default credentials.

## Attack Surface: [SSH Key Mismanagement](./attack_surfaces/ssh_key_mismanagement.md)

*   **Description:** Weak or compromised SSH keys, or insecure storage of private keys, allow unauthorized server access.
*   **How Kamal Contributes:** Kamal *directly* uses SSH for server access and to perform deployment operations. The security of the SSH keys used by Kamal is paramount.
*   **Example:** A developer's laptop containing an unencrypted SSH private key used by Kamal is stolen, granting the attacker access to the production server.
*   **Impact:** Unauthorized access to the server, potential for code modification, data theft, and lateral movement.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Strong Keys:** Use strong SSH key types (Ed25519) with sufficient key length.
    *   **Passphrase Protection:** Always protect private keys with a strong passphrase.
    *   **SSH Agent:** Use an SSH agent to securely manage private keys and avoid storing them directly on disk without encryption.
    *   **Key Rotation:** Regularly rotate SSH keys.
    *   **Dedicated Keys:** Use separate SSH keys specifically for Kamal deployments, not personal keys.

## Attack Surface: [Accessory Service Misconfiguration](./attack_surfaces/accessory_service_misconfiguration.md)

*   **Description:**  Databases or other services managed by Kamal as "accessories" are insecurely configured.
*   **How Kamal Contributes:** Kamal *directly* simplifies the deployment and management of accessory services. This ease of use can lead to overlooking crucial security configurations if users are not diligent.
*   **Example:** A database accessory is deployed with default credentials and is accessible from the application container (or worse, publicly).
*   **Impact:**  Data breach, data loss, potential for remote code execution within the accessory service.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Change Default Credentials:** *Always* change default credentials for all accessory services managed by Kamal.
    *   **Network Segmentation:** Use Docker networks (which Kamal configures) or firewalls to restrict access to accessory services to only the necessary containers and hosts. Do not expose them publicly unless absolutely required and with proper authentication and authorization.
    *   **Regular Updates:** Keep accessory services updated with the latest security patches.
    *   **Configuration Review:** Thoroughly review the configuration of each accessory service deployed via Kamal to ensure it adheres to security best practices.

