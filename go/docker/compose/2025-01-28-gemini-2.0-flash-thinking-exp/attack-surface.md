# Attack Surface Analysis for docker/compose

## Attack Surface: [Insecure Image Pulls](./attack_surfaces/insecure_image_pulls.md)

*   **Description:** Pulling Docker images from untrusted registries or without verifying image integrity can lead to running compromised software.
*   **Compose Contribution:** `docker-compose.yml` files specify image names and tags. If these are not carefully managed, Compose will pull potentially malicious images.
*   **Example:** Using `image: my-repo/my-app:latest` in `docker-compose.yml` allows pulling a potentially compromised "latest" image from `my-repo`.
*   **Impact:** Running malicious code within containers, potentially leading to data breaches, service disruption, or host compromise.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Use Image Digests:** Specify images using immutable digests (e.g., `image: my-repo/my-app@sha256:abcdefg...`).
    *   **Use Trusted Registries:** Pull images only from trusted and verified registries.
    *   **Image Scanning:** Implement automated image scanning to detect vulnerabilities in images.

## Attack Surface: [Privileged Containers](./attack_surfaces/privileged_containers.md)

*   **Description:** Running containers in privileged mode grants excessive host kernel capabilities, significantly increasing the risk of container escapes and host compromise.
*   **Compose Contribution:** The `privileged: true` directive in `docker-compose.yml` directly enables privileged mode.
*   **Example:** Setting `privileged: true` for a container in `docker-compose.yml` allows an attacker to escape the container and gain root access to the host if the container is compromised.
*   **Impact:** Full host compromise, data breaches, and complete system takeover.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Avoid Privileged Mode:** Never use `privileged: true` unless absolutely necessary and after careful security review.
    *   **Principle of Least Privilege:** Grant only necessary capabilities using `cap_add` and `cap_drop` in `docker-compose.yml`.
    *   **Security Context:** Utilize security context settings in `docker-compose.yml` to restrict container capabilities.

## Attack Surface: [Exposed Ports](./attack_surfaces/exposed_ports.md)

*   **Description:** Unnecessarily exposing container ports to the host or public networks increases the attack surface, making services directly accessible from outside the container environment.
*   **Compose Contribution:** The `ports` section in `docker-compose.yml` defines port mappings, directly controlling service exposure.
*   **Example:** Exposing a debugging port (e.g., 8080) using `ports: - "8080:8080"` in `docker-compose.yml` and leaving it in production makes it publicly accessible.
*   **Impact:** Unauthorized access to services, data breaches, and potential exploitation of vulnerabilities in exposed services.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Minimize Port Exposure:** Only expose necessary ports and avoid public exposure if possible.
    *   **Internal Networks:** Utilize Docker networks to isolate containers and restrict access within the container environment.
    *   **Firewalling:** Implement host-based firewalls to control access to exposed ports.

## Attack Surface: [Host Volume Mounts with Write Access](./attack_surfaces/host_volume_mounts_with_write_access.md)

*   **Description:** Mounting host directories into containers with write access can be exploited if the containerized application is compromised, allowing modification of host files.
*   **Compose Contribution:** The `volumes` section in `docker-compose.yml` defines volume mounts and their access modes.
*   **Example:** Mounting the host's root directory with write access using `volumes: - "/:/host"` allows an attacker in a compromised container to modify any file on the host.
*   **Impact:** Host file system compromise, data manipulation, privilege escalation, and potential host takeover.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Minimize Host Mounts:** Avoid mounting host directories unless absolutely necessary.
    *   **Read-Only Mounts:** Mount volumes as read-only whenever possible using `:ro` flag in `docker-compose.yml`.
    *   **Principle of Least Privilege (Volumes):** Only mount specific directories required by the application.

## Attack Surface: [Secrets in Configuration Files](./attack_surfaces/secrets_in_configuration_files.md)

*   **Description:** Storing secrets directly in `docker-compose.yml` or environment variables within the file is insecure as these files can be easily exposed.
*   **Compose Contribution:** `docker-compose.yml` allows defining environment variables directly or referencing `.env` files, leading to potential hardcoding of secrets.
*   **Example:** Hardcoding a database password in the `environment` section of `docker-compose.yml` exposes the password if the file is compromised.
*   **Impact:** Exposure of sensitive credentials, leading to unauthorized access to systems and data breaches.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Secret Management Tools:** Use dedicated secret management tools (e.g., Vault, Secrets Manager).
    *   **Docker Secrets:** Utilize Docker Secrets for managing secrets in Docker environments.
    *   **Environment Variables from External Sources:** Load environment variables from external sources at runtime.
    *   **Avoid Committing Secrets:** Never commit `docker-compose.yml` or `.env` files containing secrets to version control.

## Attack Surface: [Insufficient Access Control to Compose Commands](./attack_surfaces/insufficient_access_control_to_compose_commands.md)

*   **Description:** Lack of proper access control to Docker Compose commands in shared environments can allow unauthorized users to manage applications, leading to service disruption or data breaches.
*   **Compose Contribution:** Compose commands are executed with user's Docker permissions. Inadequate permission management can lead to unauthorized actions.
*   **Example:** In a shared environment, developers with broad Docker access can use Compose to disrupt or modify applications they shouldn't have access to.
*   **Impact:** Service disruption, unauthorized application management, data breaches, and potential privilege escalation.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Role-Based Access Control (RBAC):** Implement RBAC for Docker and Compose commands.
    *   **Least Privilege for Users:** Grant users only necessary Docker permissions.
    *   **Centralized Management:** Use orchestration platforms (like Kubernetes) for better access control.
    *   **Audit Logging:** Enable audit logging for Docker and Compose commands to track user actions.

