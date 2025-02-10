# Threat Model Analysis for docker/compose

## Threat: [Overly Permissive Network Exposure (via Compose)](./threats/overly_permissive_network_exposure__via_compose_.md)

*   **Threat:** Overly Permissive Network Exposure (via Compose)

    *   **Description:** An attacker scans for exposed ports on the host.  Due to misconfiguration *within the `docker-compose.yml` file* (e.g., using `ports: ["80:80"]` without proper host firewall rules, or using `network_mode: host`), a container's port is directly exposed. The attacker can interact with the service, bypassing Docker's network isolation, and potentially exploit vulnerabilities.
    *   **Impact:** Unauthorized access to the application, data breaches, denial-of-service, potential lateral movement.
    *   **Affected Compose Component:** `docker-compose.yml` - `services.<service_name>.ports` and `services.<service_name>.network_mode` configurations.
    *   **Risk Severity:** High to Critical (depending on the exposed service).
    *   **Mitigation Strategies:**
        *   Use Docker's bridge network or custom user-defined networks.
        *   Map container ports to specific, *different* host ports (e.g., `8080:80`).
        *   *Crucially, in conjunction with Compose configuration*, implement host-level firewall rules.
        *   Avoid `network_mode: host` unless absolutely necessary.
        *   Use internal networks for inter-container communication.

## Threat: [Sensitive Host Directory Mount (via Compose)](./threats/sensitive_host_directory_mount__via_compose_.md)

*   **Threat:** Sensitive Host Directory Mount (via Compose)

    *   **Description:**  An attacker compromises a container.  Because a sensitive host directory (e.g., `/etc`, `/root`, `/var/run/docker.sock`) is mounted with write access *due to the `docker-compose.yml` configuration*, the attacker modifies files on the host, gaining elevated privileges or control over the Docker daemon.
    *   **Impact:** Host system compromise, privilege escalation, complete control over the Docker environment.
    *   **Affected Compose Component:** `docker-compose.yml` - `services.<service_name>.volumes` configuration.
    *   **Risk Severity:** Critical.
    *   **Mitigation Strategies:**
        *   Avoid mounting sensitive host directories *through Compose*.
        *   Use read-only mounts (`:ro`) whenever possible.
        *   If mounting is necessary, mount only specific files or subdirectories.
        *   Use Docker volumes instead of bind mounts.
        *   *In conjunction with Compose configuration*, run the container process as a non-root user.

## Threat: [Secret Exposure in Environment Variables (via Compose)](./threats/secret_exposure_in_environment_variables__via_compose_.md)

*   **Threat:** Secret Exposure in Environment Variables (via Compose)

    *   **Description:** An attacker gains access to the `docker-compose.yml` file or a `.env` file *used by Compose*.  Hardcoded secrets (passwords, API keys) are extracted and used to access other services.  This is a direct threat because the secrets are exposed *due to their inclusion in Compose-related files*.
    *   **Impact:** Unauthorized access to sensitive data and services, data breaches.
    *   **Affected Compose Component:** `docker-compose.yml` - `services.<service_name>.environment` and `.env` files *as used by Compose*.
    *   **Risk Severity:** High to Critical.
    *   **Mitigation Strategies:**
        *   Use Docker Secrets: Reference secrets via the `secrets` configuration in the Compose file.
        *   Use a dedicated secrets management solution.
        *   Avoid committing `.env` files containing secrets to version control.
        *   If using environment variables, inject them securely at runtime, *not* directly in the Compose file.

## Threat: [Excessive Container Capabilities (via Compose)](./threats/excessive_container_capabilities__via_compose_.md)

*   **Threat:** Excessive Container Capabilities (via Compose)

    *   **Description:** An attacker compromises a container.  Because the `docker-compose.yml` file grants unnecessary Linux capabilities (e.g., `cap_add: ALL` or omits `cap_drop`), the attacker leverages these capabilities to escape the container and compromise the host.  The threat is direct because the capabilities are configured *within Compose*.
    *   **Impact:** Host system compromise, privilege escalation.
    *   **Affected Compose Component:** `docker-compose.yml` - `services.<service_name>.cap_add` and `services.<service_name>.cap_drop` configurations.
    *   **Risk Severity:** High.
    *   **Mitigation Strategies:**
        *   Follow the principle of least privilege: Grant only the *minimum* necessary capabilities *in the Compose file*.
        *   Use `cap_drop: ALL` to drop all capabilities by default, then selectively add back only the required ones using `cap_add`.

## Threat: [Using `privileged: true` (via Compose)](./threats/using__privileged_true___via_compose_.md)

* **Threat:** Using `privileged: true` (via Compose)

    * **Description:** An attacker exploits a vulnerability in a container that is running in privileged mode *as configured in the `docker-compose.yml` file*. Privileged mode gives the container almost the same access to the host as processes running outside containers.
    * **Impact:** Host compromise.
    * **Affected Compose Component:** `docker-compose.yml` - `services.<service_name>.privileged`.
    * **Risk Severity:** Critical.
    * **Mitigation Strategies:**
        * Avoid using `privileged: true` in the Compose file unless absolutely necessary.
        * If it is necessary, make sure that you understand all security implications.

