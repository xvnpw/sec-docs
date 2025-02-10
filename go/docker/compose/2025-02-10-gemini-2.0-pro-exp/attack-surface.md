# Attack Surface Analysis for docker/compose

## Attack Surface: [Unnecessary Port Exposure](./attack_surfaces/unnecessary_port_exposure.md)

*   **Description:** Exposing container ports to the host or wider network that are not strictly required for application functionality.
*   **How Compose Contributes:** Compose makes it very easy to map ports with the `ports:` directive, often leading to over-exposure, especially during development and through copy-pasting example configurations.
*   **Example:** A database container with port 5432 (PostgreSQL) exposed to the host, even though only the application container needs to access it.  Or exposing a debugging port that is not needed in production.
*   **Impact:** Direct access to internal services by attackers, bypassing application-level security.  Data breaches, unauthorized modifications, denial of service.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Minimize `ports:` mappings in `docker-compose.yml` to *only* essential external connections.  Remove any mappings that are only for development or debugging.
    *   Use internal Docker networks for *all* inter-container communication (see below).  Never expose internal service ports to the host.
    *   Regularly audit and review port mappings using automated tools and manual inspection.
    *   Employ a firewall on the host to further restrict access to exposed ports, even those intentionally exposed.

## Attack Surface: [Default Bridge Network Misuse](./attack_surfaces/default_bridge_network_misuse.md)

*   **Description:** All services residing on the default Docker bridge network without explicit network segmentation.
*   **How Compose Contributes:** Compose creates a default bridge network if no custom networks are defined in the `docker-compose.yml` file.  Developers often neglect to create custom networks, or misunderstand their purpose.
*   **Example:** A web server and a database container both running on the default bridge network, allowing direct communication if the web server is compromised.
*   **Impact:** Lateral movement within the application.  A compromised container can directly access *all other* containers on the same network, facilitating further attacks.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Define custom networks (`networks:` in `docker-compose.yml`) and *explicitly* assign *every* service to the appropriate network based on its communication needs.
    *   Isolate services that don't need to communicate directly.  Create separate networks for different application tiers (frontend, backend, database).
    *   Never rely on the default bridge network for anything other than the simplest, single-container deployments.

## Attack Surface: [Exposed Docker Socket](./attack_surfaces/exposed_docker_socket.md)

*   **Description:** Mounting the Docker socket (`/var/run/docker.sock`) into a container.
*   **How Compose Contributes:** Compose allows mounting volumes, including the Docker socket, using the `volumes:` directive.  This is often done carelessly to enable container management tools within other containers.
*   **Example:** A monitoring container or a CI/CD runner with the Docker socket mounted to manage other containers.
*   **Impact:** *Complete host system compromise.* A compromised container gains root access to the Docker daemon and, therefore, the *entire host operating system*.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Avoid mounting the Docker socket into containers whenever humanly possible.** This is the most important mitigation.
    *   If *absolutely* necessary (and you've exhausted all other options), use extreme caution and explore *safer* alternatives:
        *   Docker API with TLS authentication and authorization (requires careful configuration).
        *   Docker-in-Docker (dind) *with the understanding that it still presents significant risks and is not a perfect solution*.
    *   If you *must* mount the socket, implement *all* of the following:
        *   Use a minimal base image for the container with socket access.
        *   Drop *all* unnecessary capabilities using `cap_drop`.
        *   Implement robust monitoring and alerting for that specific container.
        *   Regularly audit the container's configuration and image.

## Attack Surface: [Hardcoded Secrets in Compose Files](./attack_surfaces/hardcoded_secrets_in_compose_files.md)

*   **Description:** Embedding sensitive information (passwords, API keys, tokens) directly in the `docker-compose.yml` file or associated environment files (`.env`).
*   **How Compose Contributes:** Compose uses the `environment:` directive and `.env` files to set environment variables, which are frequently misused to store secrets directly in plain text.
*   **Example:** `DATABASE_PASSWORD=mysecretpassword` directly in the `docker-compose.yml` file, or in a `.env` file that is accidentally committed to version control.
*   **Impact:** Secret exposure if the Compose file or environment files are leaked, accidentally committed to version control, or accessed by unauthorized individuals.  This can lead to complete application or infrastructure compromise.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Use Docker Secrets (`secrets:` in `docker-compose.yml` version 3+). This is the preferred method for managing secrets within Docker Compose.
    *   Use a secure, external secrets management service (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager) and load secrets as environment variables at *runtime*.  Do *not* store them in files read by Compose.
    *   *Never* commit secrets to version control. Use `.gitignore` to ensure `.env` files and any other files containing secrets are excluded.
    *   Regularly audit your Compose files and environment files for any hardcoded secrets.

## Attack Surface: [Overly Permissive Capabilities](./attack_surfaces/overly_permissive_capabilities.md)

*   **Description:** Containers running with more Linux capabilities than necessary for their intended function.
*   **How Compose Contributes:** Compose allows modifying container capabilities using the `cap_add` and `cap_drop` directives within the `docker-compose.yml` file.  Developers often fail to restrict capabilities, leaving containers with excessive privileges.
*   **Example:** A web server container running with `CAP_SYS_ADMIN` (which grants it broad system-level privileges), when it only needs `CAP_NET_BIND_SERVICE` to bind to a port.
*   **Impact:** A compromised container with excessive capabilities can perform actions it shouldn't, potentially escaping the container, accessing sensitive data, or affecting the host system in ways that would otherwise be prevented.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Use the principle of least privilege.  *Always* start by dropping *all* capabilities using `cap_drop: - ALL` in your `docker-compose.yml` file.
    *   Then, *only* add back the *specific* capabilities that are absolutely required for the container to function correctly, using `cap_add`.  Carefully research which capabilities are needed.
    *   Regularly review and audit the capabilities granted to each container.

